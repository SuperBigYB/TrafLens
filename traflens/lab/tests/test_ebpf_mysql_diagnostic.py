"""Offline diagnostic gates; no Agent, native API, Docker, or workload runs."""
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('mysql_diagnostic_tested', LAB / 'ebpf-mysql-diagnostic.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)
from test_ebpf_mysql_runtime import receipt as paced_receipt


def binding():
    return {'container_id': 'a' * 64, 'pid': 123, 'start_ticks': '456', 'agent_id': 27,
            'hostname': 'traflens-my-' + '1' * 24, 'scope_inode': 101,
            'native_binary_sha256': 'b' * 64, 'native_source_commit': 'c' * 40,
            'scope_proof_sha256': 'd' * 64}


def make_state(work):
    return {'schema': diagnostic.SCHEMA, 'run': 'my-' + '1' * 24, 'output': str(work), 'workers': {},
            'args': {'observer_timeout_seconds': 5}}


def write_manifest(folder, request):
    data = folder / 'numeric-snapshot.json'
    diagnostic.CORE.write(data, {'samples': [], 'counter_completeness_claimed': False})
    meta = {'schema': 'traflens.scoped-observer-manifest.v1', 'run': request['run'], 'stage': request['stage'],
            'nonce': request['nonce'], 'agent': request['agent'], 'completed': True,
            'scope_profile_unchanged': True, 'old_server_unchanged': True, 'captured_at_unix_ns': time.time_ns(),
            'artifacts': [{'name': data.name, 'bytes': data.stat().st_size,
                           'sha256': hashlib.sha256(data.read_bytes()).hexdigest()}]}
    diagnostic.CORE.write(folder / 'manifest.json', meta)
    return meta


def observer_fixture(work):
    stage = 'before-first-wire'
    folder = work / 'observer' / stage
    folder.mkdir(mode=0o700, parents=True)
    # parents=True creates the immediate observer directory under an existing
    # private test directory; explicitly preserve the production0700 contract.
    folder.parent.chmod(0o700)
    state = make_state(work)
    diagnostic.CORE.write(work / 'state.json', state)
    now = time.time_ns()
    request = {'schema': 'traflens.scoped-observer-request.v1', 'run': state['run'], 'stage': stage,
               'nonce': 'e' * 32, 'agent': binding(), 'requested_at_unix_ns': now,
               'deadline_unix_ns': now + 30_000_000_000}
    diagnostic.CORE.write(folder / 'request.json', request)
    return folder, request, write_manifest(folder, request)


class DiagnosticRuntimeGuards(unittest.TestCase):
    def test_namespace_pin_needs_actual_live_netns_fd_not_every_old_descriptor(self):
        fd = os.open('/proc/self/ns/net', os.O_RDONLY | os.O_CLOEXEC)
        try:
            inode = os.fstat(fd).st_ino
            self.assertTrue(diagnostic.pinned_namespace_fd(os.getpid(), [9999999, fd], inode))
            self.assertFalse(diagnostic.pinned_namespace_fd(os.getpid(), [9999999], inode))
            self.assertFalse(diagnostic.pinned_namespace_fd(os.getpid(), [fd], inode + 1))
        finally:
            os.close(fd)

    def test_default_run_and_ack_plans_never_read_artifacts_or_touch_resources(self):
        with mock.patch.object(diagnostic.CORE, 'file_hash', side_effect=AssertionError('artifact')), \
                mock.patch.object(diagnostic.CORE, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(diagnostic, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(diagnostic.main(['run', '--work', '/not-created']), 0)
            plan = json.loads(out.getvalue())
            self.assertFalse(plan['starts_network'])
            self.assertTrue(plan['diagnostic_only'])
            self.assertFalse(plan['integrity_qualified'])
            out.seek(0); out.truncate(0)
            self.assertEqual(diagnostic.main(['ack', '--stage', 'before-first-wire']), 0)
            self.assertFalse(json.loads(out.getvalue())['writes_files'])

    def test_qualified_paced_and_dns_contracts_stay_distinct_and_observer_free(self):
        self.assertTrue(diagnostic.CONTRACT.diagnostic)
        self.assertEqual(diagnostic.CONTRACT.schema, 'traflens.ebpf-mysql-diagnostic.capture.v1')
        self.assertEqual(diagnostic.CONTRACT.script, 'ebpf-mysql-diagnostic.py')
        self.assertFalse(diagnostic.PACED.CONTRACT.diagnostic)
        self.assertIsNone(diagnostic.PACED.CONTRACT.observer_gate)
        self.assertEqual(diagnostic.PACED.CONTRACT.schema, 'traflens.ebpf-mysql.capture.v1')
        self.assertFalse(diagnostic.RUNTIME.DNS_CONTRACT.diagnostic)
        self.assertIsNone(diagnostic.RUNTIME.DNS_CONTRACT.observer_gate)

    def test_archive_preflight_pins_original_artifact_and_source_with_bounded_timeout(self):
        args = types.SimpleNamespace(workload_sha256=diagnostic.ARCHIVED_ARTIFACT_SHA256,
                                    workload_source='/owned/unpaced.c', observer_timeout_seconds=30)
        with mock.patch.object(diagnostic.CORE, 'file_hash', return_value=diagnostic.ARCHIVED_SOURCE_SHA256) as read:
            diagnostic.preflight(args)
            read.assert_called_once_with('/owned/unpaced.c')
            for field, value in [('workload_sha256', 'f' * 64), ('observer_timeout_seconds', 46), ('observer_timeout_seconds', 0)]:
                changed = copy.copy(args); setattr(changed, field, value)
                with self.assertRaises(RuntimeError):
                    diagnostic.preflight(changed)
        with mock.patch.object(diagnostic.CORE, 'file_hash', return_value='f' * 64):
            with self.assertRaises(RuntimeError):
                diagnostic.preflight(args)
        with mock.patch.object(diagnostic.CORE, 'file_hash', side_effect=AssertionError('URL must fail first')):
            with self.assertRaises((RuntimeError, ValueError)):
                diagnostic.RUNTIME.execute(types.SimpleNamespace(controller_url='http://user:secret@127.0.0.1:20417'), diagnostic.CONTRACT)

    def test_archived_unpaced_receipt_is_not_fabricated_as_paced_qualified(self):
        paced = paced_receipt('my-' + '1' * 24, 'client')
        unpaced = {key: value for key, value in paced.items()
                   if key not in ('pacing_only_qualification', 'pacing_ms', 'pacing_waits', 'pacing_duration_ns', 'waits_sha256')}
        diagnostic.validate_receipt(unpaced, unpaced['run'], 'client')
        with self.assertRaises(RuntimeError):
            diagnostic.validate_receipt(paced, paced['run'], 'client')
        with self.assertRaises(RuntimeError):
            diagnostic.PACED.validate_receipt(unpaced, unpaced['run'], 'client')

    def test_manifest_binds_nonce_agent_identity_and_real_private_data_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, request, manifest = observer_fixture(Path(tmp))
            self.assertEqual(diagnostic.validate_manifest(folder, request), diagnostic.CORE.file_hash(folder / 'manifest.json'))
            changed = copy.deepcopy(request); changed['agent']['pid'] += 1
            with self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(folder, changed)
            changed = copy.deepcopy(request); changed['nonce'] = 'f' * 32
            with self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(folder, changed)
            (folder / 'numeric-snapshot.json').write_text('changed')
            with self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(folder, request)

    def test_observer_data_symlink_or_public_permissions_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder, request, manifest = observer_fixture(Path(tmp))
            data = folder / 'numeric-snapshot.json'
            data.chmod(0o644)
            with self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(folder, request)
            data.chmod(0o600)
            outside = Path(tmp) / 'outside.json'
            outside.write_bytes(data.read_bytes()); outside.chmod(0o600)
            data.unlink(); data.symlink_to(outside)
            with self.assertRaises(RuntimeError):
                diagnostic.validate_manifest(folder, request)

    def test_acknowledgment_is_explicit_idempotent_and_does_not_claim_zero_loss(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); folder, request, _ = observer_fixture(work)
            with mock.patch.object(diagnostic, 'live_agent_binding', return_value=(binding(), {})), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(diagnostic.acknowledge(work, 'before-first-wire'), 0)
                original = (folder / 'ack.json').read_bytes()
                self.assertEqual(diagnostic.acknowledge(work, 'before-first-wire'), 0)
            self.assertEqual((folder / 'ack.json').read_bytes(), original)
            ack = diagnostic.validate_ack(folder, request)
            self.assertEqual(ack['agent'], binding())
            self.assertNotIn('zero_lost', ack)
            self.assertNotIn('counter_complete', ack)

    def test_stale_or_wrong_live_agent_cannot_release_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); folder, request, _ = observer_fixture(work)
            wrong = binding(); wrong['start_ticks'] = '999'
            with mock.patch.object(diagnostic, 'live_agent_binding', return_value=(wrong, {})):
                with self.assertRaises(RuntimeError):
                    diagnostic.acknowledge(work, 'before-first-wire')
            self.assertFalse((folder / 'ack.json').exists())
            request['deadline_unix_ns'] = time.time_ns() - 1
            diagnostic.CORE.write(folder / 'request.json', request, True)
            with mock.patch.object(diagnostic, 'live_agent_binding', side_effect=AssertionError('expired first')):
                with self.assertRaises(RuntimeError):
                    diagnostic.acknowledge(work, 'before-first-wire')

    def test_before_gate_waits_for_matching_evidence_before_marking_completed(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); state = make_state(work)
            current = {'started_at_unix': time.time(), 'hard_timeout_seconds': 180}
            def observe(_):
                folder = work / 'observer/before-first-wire'
                request = diagnostic.CORE.read(folder / 'request.json')
                write_manifest(folder, request)
                with contextlib.redirect_stdout(io.StringIO()):
                    diagnostic.acknowledge(work, 'before-first-wire')
            with mock.patch.object(diagnostic, 'live_agent_binding', return_value=(binding(), current)), \
                    mock.patch.object(diagnostic.CORE.UTIL, 'process_start', return_value='456'), \
                    mock.patch.object(diagnostic.time, 'sleep', side_effect=observe), mock.patch.object(diagnostic.CORE, 'event'):
                diagnostic.observer_gate(work, state, 'before-first-wire')
            self.assertEqual(state['observer_gates']['before-first-wire']['status'], 'completed')
            request = diagnostic.CORE.read(work / 'observer/before-first-wire/request.json')
            self.assertFalse(request['counter_completeness_claimed'])

    def test_missing_observer_ack_is_bounded_and_preserves_incomplete_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); state = make_state(work)
            current = {'started_at_unix': time.time(), 'hard_timeout_seconds': 180}
            with mock.patch.object(diagnostic, 'live_agent_binding', return_value=(binding(), current)), \
                    mock.patch.object(diagnostic.CORE.UTIL, 'process_start', return_value='456'), \
                    mock.patch.object(diagnostic.time, 'monotonic', side_effect=[0, 0, 6]), \
                    mock.patch.object(diagnostic.time, 'sleep'), mock.patch.object(diagnostic.CORE, 'event'):
                with self.assertRaisesRegex(RuntimeError, 'gate timed out'):
                    diagnostic.observer_gate(work, state, 'before-first-wire')
            self.assertEqual(state['observer_gates']['before-first-wire']['status'], 'waiting')
            self.assertFalse((work / 'observer/before-first-wire/ack.json').exists())

    def test_gate_cannot_start_after_work_or_without_sufficient_agent_lifetime(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp); state = make_state(work)
            state['workers']['positive-server'] = {}
            with mock.patch.object(diagnostic, 'live_agent_binding', side_effect=AssertionError('before identity read')):
                with self.assertRaises(RuntimeError):
                    diagnostic.observer_gate(work, state, 'before-first-wire')
            state['workers'] = {}
            current = {'started_at_unix': time.time() - 170, 'hard_timeout_seconds': 180}
            with mock.patch.object(diagnostic, 'live_agent_binding', return_value=(binding(), current)):
                with self.assertRaisesRegex(RuntimeError, 'lifetime'):
                    diagnostic.observer_gate(work, state, 'before-first-wire')
            self.assertFalse((work / 'observer').exists())


if __name__ == '__main__':
    unittest.main()
