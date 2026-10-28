"""Quiet namespace lease guards, without Docker, BPF mutations or HTTP."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('association_lease', HERE / 'association-lease.py')
A = importlib.util.module_from_spec(spec)
spec.loader.exec_module(A)


class AssociationLeaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.root.chmod(0o700)
        lease = A.AssociationLease.__new__(A.AssociationLease)
        lease.root = self.root
        lease.control = self.root / 'control'
        lease.control.mkdir(mode=0o700)
        lease.evidence = self.root / 'evidence'
        lease.evidence.mkdir(mode=0o700)
        lease.name = 'traflens-association-fixture'
        lease.marker, lease.port, lease.phase = 'association-fixture', 18080, 0
        lease.lease_deadline, lease.cleanup_deadline = time.monotonic() + 360, time.monotonic() + 420
        lease.started = time.monotonic()
        lease.positive = {'pid': 100, 'inode': 101, 'fd': 51, 'source': '/proc/99/fd/51'}
        lease.negative = {'pid': 200, 'inode': 202, 'fd': 52, 'source': '/proc/99/fd/52'}
        lease.agent, lease.approved = None, False
        lease.workload, lease.workload_sha256 = Path('/new/association-workload'), 'a' * 64
        lease.baseline_bpf, lease.worker_metadata_ids = [1], {2, 3}
        lease.baseline_tracefs, lease.baseline_containers = {'kprobe_events': '', 'uprobe_events': ''}, {'old'}
        lease.result = {'scope_only': True, 'pass': False, 'error': None}
        lease.specs, lease.ids, lease.fds, lease.children = [], {}, [51, 52], []
        self.lease = lease

    def tearDown(self):
        self.tmp.cleanup()

    def test_default_plan_has_no_runtime_io_or_legacy_phase_claim(self):
        out = io.StringIO()
        with patch.object(A.M, 'run', side_effect=AssertionError('No Docker')), contextlib.redirect_stdout(out):
            self.assertEqual(A.main([]), 0)
        value = json.loads(out.getvalue())
        self.assertFalse(value['execute'])
        self.assertFalse(value['http_emitted'])
        self.assertFalse(value['phase_matrix_supported'])

    def test_metadata_is_compatible_but_does_not_claim_old_workload(self):
        self.lease.ids = {'positive': 'a' * 64, 'negative': 'b' * 64}
        value = self.lease.metadata('ready_waiting_root_commands')
        self.assertEqual((value['schema'], value['phase'], value['port']), ('traflens.managed-http.lease.v1', 0, 18080))
        self.assertIsNone(value['traffic_sha256'])
        self.assertEqual(value['workload_sha256'], 'a' * 64)
        self.assertTrue(value['scope_only'])
        self.assertFalse(value['workload_executed_by_lease'])
        self.assertNotIn('fd', value['positive'])
        self.assertEqual(value['positive']['container_id'], 'a' * 64)
        self.assertEqual(value['negative']['container_id'], 'b' * 64)
        self.assertEqual(value['positive']['source'], '/proc/99/fd/51')
        self.assertEqual(value['positive']['inode'], 101)

    def test_prepare_only_creates_two_quiet_holders(self):
        created, status = [], []
        with patch.object(self.lease, 'create', side_effect=created.append), \
             patch.object(self.lease, 'pin', side_effect=[self.lease.positive, self.lease.negative]), \
             patch.object(self.lease, 'publish_status', side_effect=status.append), \
             patch.object(A.M, 'bpf_ids', return_value=[1, 2, 3]), patch.object(A.W, 'program_type', return_value=15), \
             patch.object(self.lease, 'command', side_effect=AssertionError('No old traffic')):
            self.lease.prepare()
        self.assertEqual([(v.role, v.executable, v.argv, v.mounts) for v in created],
                         [('positive', '/usr/bin/sleep', ['240'], []), ('negative', '/usr/bin/sleep', ['240'], [])])
        self.assertEqual(status, ['ready_waiting_root_commands'])
        self.assertFalse((self.root / 'expected-positive.json').exists())
        self.assertFalse((self.root / 'expected-negative.json').exists())

    def test_holder_spec_rejects_privilege_or_network_change(self):
        value = {'Name': '/traflens-association-fixture-positive', 'Config': {
            'Image': 'sha256:' + '1' * 64, 'User': '0:0', 'Entrypoint': ['/usr/bin/sleep'], 'Cmd': ['240'],
            'Labels': {'io.traflens.purpose': A.PURPOSE, 'io.traflens.run': self.lease.name, 'io.traflens.role': 'positive'}},
            'Mounts': [], 'HostConfig': {'NetworkMode': 'none', 'PidMode': '', 'Privileged': False,
            'CapDrop': ['ALL'], 'CapAdd': [], 'Memory': 67108864, 'MemorySwap': 67108864, 'PidsLimit': 8,
            'NanoCpus': 250000000, 'ReadonlyRootfs': True, 'RestartPolicy': {'Name': 'no'}, 'PortBindings': {},
            'SecurityOpt': ['no-new-privileges']}}
        spec = A.HolderSpec(self.lease, 'positive', '/usr/bin/sleep', ['240'], [])
        with patch.object(A.M, 'IMAGE', value['Config']['Image']), patch.object(A.M, 'PURPOSE', A.PURPOSE):
            self.assertTrue(spec.matches(value))
            command = spec.create()
            self.assertIn('--read-only', command)
            self.assertNotIn('/traffic', command)
            for key, changed in [('NetworkMode', 'host'), ('Privileged', True), ('CapAdd', ['BPF']), ('ReadonlyRootfs', False)]:
                invalid = copy.deepcopy(value)
                invalid['HostConfig'][key] = changed
                self.assertFalse(spec.matches(invalid))

    def test_pin_uses_live_sleep_identity_and_nsfs_fd(self):
        self.lease.fds = []
        state = {'Running': True, 'Pid': 321}
        with patch.object(self.lease, 'state', return_value=state), patch.object(A, 'start_ticks', return_value='123'), \
             patch.object(Path, 'read_bytes', return_value=b'/usr/bin/sleep\x00240\x00'), \
             patch.object(Path, 'readlink', return_value=Path('/usr/bin/sleep')), \
             patch.object(A.os, 'open', return_value=77), patch.object(A.os, 'fstat', return_value=types.SimpleNamespace(st_ino=101)), \
             patch.object(A.os, 'stat', return_value=types.SimpleNamespace(st_ino=999)), \
             patch.object(A.fcntl, 'ioctl', return_value=A.W.CLONE_NEWNET), patch.object(A.W, 'sha', return_value='e' * 64):
            pin = self.lease.pin('positive')
        self.assertEqual(self.lease.fds, [77])
        self.assertEqual(pin['inode'], 101)
        self.assertEqual(pin['start_ticks'], '123')
        self.assertIn('/fd/77', pin['source'])

    def test_phase_requests_never_dispatch_old_workload(self):
        with patch.object(self.lease, 'emit_phase', side_effect=AssertionError('Old matrix forbidden')):
            with self.assertRaises(RuntimeError):
                self.lease.handle({'action': 'phase', 'phase': 'mixed'})
        self.assertEqual(self.lease.phase, 0)

    def test_release_reuses_agent_inventory_and_external_user_guards(self):
        for restored, external in [(False, True), (True, False)]:
            with patch.object(A.W.Lease, 'cleanup_ready', return_value=restored), \
                 patch.object(self.lease, 'external_users_absent', return_value=external):
                with self.assertRaises(RuntimeError):
                    self.lease.handle({'action': 'release'})
        self.assertEqual(self.lease.fds, [51, 52])
        with patch.object(A.W.Lease, 'cleanup_ready', return_value=True), patch.object(self.lease, 'external_users_absent', return_value=True):
            self.assertTrue(self.lease.handle({'action': 'release'}))

    def test_approval_keeps_exact_scope_map_protocol(self):
        proof = {'agent_container_id': 'a' * 64, 'scope_map': {'netns_id': 101, 'validated': 1},
                 'scope_fd_pinned': True, 'safe_profile_verified': True, 'agent_binary_sha256': 'b' * 64,
                 'source_commit': 'c' * 40, 'hard_timeout_seconds': 180, 'kill_grace_seconds': 40}
        with patch.object(self.lease, 'register_agent'), patch.object(self.lease, 'publish_status'):
            invalid = copy.deepcopy(proof)
            invalid['scope_map']['netns_id'] = 202
            with self.assertRaises(RuntimeError):
                self.lease.approve_agent(invalid)
            self.lease.approve_agent(proof)
        self.assertTrue(self.lease.approved)
        self.assertEqual(self.lease.result['coordinator_scope_proof']['scope_map']['netns_id'], 101)

    def test_stopped_external_container_reference_still_blocks_release(self):
        self.lease.ids = {'positive': 'a' * 64, 'negative': 'b' * 64}
        child = {'HostConfig': {'NetworkMode': 'container:' + 'a' * 64}, 'State': {'Running': False, 'Pid': 0}}
        with patch.object(A.M, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='external\n')), \
             patch.object(A.M, 'inspect', return_value=child):
            self.assertFalse(self.lease.external_users_absent())

    def test_timeout_preserves_pins_until_inventory_is_safe(self):
        self.lease.lease_deadline = self.lease.cleanup_deadline = time.monotonic() - 1
        checks = []
        def safe():
            checks.append(1)
            return len(checks) >= 3
        def clean(_lease):
            self.assertGreaterEqual(len(checks), 3)
            _lease.result['namespace_pins_released'] = True
            return []
        with patch.object(self.lease, 'prepare'), patch.object(self.lease, 'publish_status'), \
             patch.object(self.lease, 'cleanup_ready', side_effect=safe), patch.object(self.lease, 'receive', return_value=False), \
             patch.object(A.M.Case, 'cleanup', autospec=True, side_effect=clean), patch.object(A.time, 'sleep'), \
             patch.object(A.M, 'bpf_ids', return_value=[1]), patch.object(A.M, 'tracefs', return_value=self.lease.baseline_tracefs), \
             patch.object(A.M, 'run', return_value=types.SimpleNamespace(returncode=0, stdout='old\n')), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.lease.supervise(), 1)
        self.assertTrue((self.root / 'failure-pins-retained.json').exists())
        self.assertTrue(self.lease.result['namespace_pins_released'])
        self.assertFalse(self.lease.result['workload_complete'])


if __name__ == '__main__':
    unittest.main()
