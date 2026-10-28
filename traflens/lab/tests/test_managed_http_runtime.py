import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('managed_http_agent', LAB / 'managed-http-agent.py')
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class ManagedHTTPRuntimeTests(unittest.TestCase):
    def test_default_and_unconfirmed_actions_do_not_run_docker(self):
        with tempfile.TemporaryDirectory() as root:
            for script in ['managed-http-agent.py', 'managed_http_workload.py']:
                for action in [[], ['start'] if script.endswith('agent.py') else ['prepare']]:
                    result = subprocess.run([sys.executable, str(LAB / script)] + action,
                        cwd=root, text=True, capture_output=True, timeout=5, check=True)
                    plan = json.loads(result.stdout)
                    self.assertFalse(plan.get('starts_agent', plan.get('execute')))
                    self.assertEqual(list(Path(root).iterdir()), [])

    def test_preparation_requires_hashes_and_restricted_semantics(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / 'prepared'
            agent.preparation.prepare(output, controller_ip='203.0.113.1', group_id='g-test')
            agent.verified_preparation(output)
            profile_path = output / 'group-profile.json'
            profile = json.loads(profile_path.read_text())
            profile['inputs']['cbpf']['af_packet']['interface_regex'] = '.*'
            profile_path.write_text(json.dumps(profile))
            with self.assertRaises(ValueError):
                agent.verified_preparation(output)
            manifest = json.loads((output / 'manifest.json').read_text())
            manifest['files']['group-profile.json'] = {'sha256': agent.sha(profile_path), 'bytes': profile_path.stat().st_size}
            (output / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                agent.verified_preparation(output)

    def test_artifact_hash_failure_precedes_any_runtime_action(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            (root / 'libs').mkdir()
            libraries = {}
            for name in ('libz.so.1', 'libstdc++.so.6', 'libgcc_s.so.1'):
                path = root / 'libs' / name
                path.write_bytes(b'fixture')
                libraries[name] = {'sha256': agent.sha(path)}
            binary = root / 'deepflow-agent'
            binary.write_bytes(b'fixture')
            value = {'image_id': 'sha256:' + 'a' * 64, 'source': 'b' * 40,
                     'binary_sha256': agent.sha(binary), 'libraries': libraries}
            manifest = root / 'runtime.json'
            agent.save(manifest, value)
            agent.verified_artifacts(manifest)
            binary.write_bytes(b'modified')
            with self.assertRaises(ValueError):
                agent.verified_artifacts(manifest)

    def test_only_explicit_loopback_controller_allowed(self):
        with patch.object(agent.urllib.request, 'build_opener') as opener:
            for endpoint in ('https://127.0.0.1:1234', 'http://example.invalid:80',
                             'http://user:pass@127.0.0.1:80', 'http://127.0.0.1:80/path',
                             'http://127.0.0.1:80?other=1', 'http://127.0.0.1'):
                with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                    agent.controller_readback(endpoint, {}, {}, 1)
            opener.assert_not_called()

    def test_cleanup_allows_only_baseline_and_owned_worker_metadata(self):
        receipt = {'baseline': {'bpf_program_ids': [1, 2, 3]}, 'worker_inventory': {
            'original_bpf_ids': [1, 2], 'owned_worker_cgroup_device_ids': [3]}}
        self.assertTrue(agent.restored_programs([1, 2, 3], receipt))
        self.assertTrue(agent.restored_programs([1, 2], receipt))
        self.assertFalse(agent.restored_programs([1, 2, 4], receipt))
        self.assertFalse(agent.restored_programs([2, 3], receipt))
        receipt['worker_inventory']['owned_worker_cgroup_device_ids'] = [2, 3]
        with self.assertRaises(RuntimeError):
            agent.restored_programs([1, 2, 3], receipt)

    def test_container_ownership_rejects_changed_identity_scope_or_limits(self):
        receipt = {'id': 'a' * 64, 'name': 'owned', 'image': 'sha256:' + 'b' * 64,
                   'run': 'test', 'hostname': 'test-agent', 'command': ['bounded'],
                   'mounts': [('/owned/ns', '/run/traflens/target.netns', False)]}
        info = {'Id': receipt['id'], 'Name': '/owned', 'Image': receipt['image'],
                'Config': {'Image': receipt['image'], 'Hostname': 'test-agent',
                           'Labels': {'io.traflens.purpose': agent.PURPOSE, 'io.traflens.run': 'test'},
                           'Entrypoint': ['/usr/bin/timeout'], 'Cmd': ['bounded'], 'Env': ['IN_CONTAINER=yes']},
                'HostConfig': {'NetworkMode': 'host', 'PidMode': 'host', 'Privileged': False,
                               'Memory': 1073741824, 'MemorySwap': 1073741824, 'NanoCpus': 2000000000,
                               'PidsLimit': 384, 'CapAdd': agent.CAPS, 'CapDrop': ['ALL'],
                               'SecurityOpt': ['no-new-privileges', 'apparmor=unconfined']},
                'Mounts': [{'Type': 'bind', 'Source': '/owned/ns', 'Destination': '/run/traflens/target.netns', 'RW': False}]}
        self.assertTrue(agent.owned(info, receipt))
        for section, key, value in [(None, 'Id', 'c' * 64), (None, 'Image', 'other'),
                                     ('Config', 'Cmd', ['unbounded']), ('HostConfig', 'Privileged', True),
                                     ('HostConfig', 'Memory', 0), ('HostConfig', 'CapAdd', ['SYS_ADMIN'])]:
            altered = copy.deepcopy(info)
            (altered if section is None else altered[section])[key] = value
            self.assertFalse(agent.owned(altered, receipt))
        altered = copy.deepcopy(info)
        altered['Mounts'][0]['RW'] = True
        self.assertFalse(agent.owned(altered, receipt))

    def test_repeated_start_never_stops_a_previous_run(self):
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / 'agent').mkdir()
            with patch.object(sys, 'argv', ['managed-http-agent.py', 'start', '--execute', '--work', root]), \
                    patch.object(agent, 'start') as start, patch.object(agent, 'stop') as stop:
                with self.assertRaisesRegex(RuntimeError, 'fresh private'):
                    agent.main()
                start.assert_not_called()
                stop.assert_not_called()

    def test_workload_refuses_http_before_independent_approval(self):
        lease = object.__new__(agent.workload.Lease)
        lease.approved = False
        with self.assertRaisesRegex(RuntimeError, 'verified Agent'):
            lease.emit_phase('mixed')


if __name__ == '__main__':
    unittest.main()
