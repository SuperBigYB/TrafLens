import argparse
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
spec = importlib.util.spec_from_file_location('profile_query_runtime', LAB / 'profile-query-runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)


class ProfileQueryRuntimeTests(unittest.TestCase):
    def state(self, root='/private/owned'):
        return {'work': root, 'image': 'sha256:' + 'a' * 64, 'seconds': 120,
                'run': 'b' * 20, 'lab_root': '/private', 'network_name': 'owned-lab',
                'query_port': 20818, 'console_port': 20880, 'scope': None}

    def info(self, value):
        return {'Id': 'c' * 64, 'Name': '/' + value['name'], 'Image': value['image'],
                'Config': {'Image': value['image'], 'Entrypoint': value['entrypoint'], 'Cmd': value['command'], 'Labels': value['labels']},
                'HostConfig': {'NetworkMode': value['network'], 'PidMode': '', 'Privileged': False,
                               'ReadonlyRootfs': True, 'NanoCpus': value['cpus'] * 1000000000,
                               'Memory': value['memory'], 'MemorySwap': value['memory'], 'PidsLimit': value['pids'],
                               'CapDrop': ['ALL'], 'CapAdd': [], 'SecurityOpt': ['no-new-privileges'], 'PortBindings': value['ports']},
                'Mounts': [{'Source': source, 'Destination': target, 'RW': rw, 'Type': 'bind'} for source, target, rw in value['mounts']],
                'State': {'Running': True}}

    def native(self, count):
        return {'OPT_STATUS': 'SUCCESS', 'result': {'bounds_applied': True, 'max_rows': 256,
                'input_rows': count, 'budgets': {'compressed_bytes': 4194304, 'decoded_stack_bytes': 1048576,
                'total_decoded_stack_bytes': 8388608, 'nodes': 8192, 'stack_depth': 512}}}

    def test_default_run_and_stop_plans_do_not_start_or_create_files(self):
        with tempfile.TemporaryDirectory() as folder:
            for action in [[], ['run'], ['stop']]:
                p = subprocess.run([sys.executable, str(LAB / 'profile-query-runtime.py')] + action,
                                   cwd=folder, check=True, capture_output=True, text=True, timeout=5)
                plan = json.loads(p.stdout)
                self.assertFalse(plan['execute'])
                self.assertFalse(plan['starts_runtime'])
                self.assertEqual(list(Path(folder).iterdir()), [])

    def test_restricted_specs_use_default_query_config_and_loopback(self):
        state = self.state()
        query = runtime.spec(state, 'querier')
        console = runtime.spec(state, 'console')
        self.assertEqual(query['network'], 'owned-lab')
        self.assertEqual(console['network'], 'host')
        self.assertEqual(query['ports'], {'20416/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '20818'}]})
        self.assertEqual(console['ports'], {})
        self.assertIn(('/private/owned/querier.yaml', '/etc/server.yaml', False), query['mounts'])
        self.assertEqual(query['command'][-1], '/opt/querier-candidate')
        self.assertNotIn('-f', query['command'])
        self.assertIn('127.0.0.1:20880', console['command'])
        command = runtime.create_command(console)
        for expected in ['--cap-drop', 'ALL', '--read-only', '--security-opt', 'no-new-privileges', '--pids-limit']:
            self.assertIn(expected, command)
        self.assertFalse(any('/proc' in x or '/dev' in x for x in command))

    def test_config_is_only_explicit_password_free_whitelist(self):
        args = argparse.Namespace(clickhouse_host='clickhouse', clickhouse_port=9000, clickhouse_user='default')
        text = runtime.config(args)
        self.assertIn('host: clickhouse', text)
        self.assertIn('log-file: /tmp/querier.log', text)
        self.assertNotIn('password', text.lower())
        self.assertNotIn('mysql', text.lower())
        for key, value in [('clickhouse_host', 'host\npassword: secret'), ('clickhouse_user', 'a:b'), ('clickhouse_port', 65536)]:
            bad = copy.copy(args)
            setattr(bad, key, value)
            with self.assertRaises(ValueError):
                runtime.config(bad)

    def test_artifact_hash_failure_and_scope_validation_precede_runtime(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder).resolve() / 'binary'
            path.write_bytes(b'fixture')
            path.chmod(0o700)
            with self.assertRaises(ValueError):
                runtime.verify_artifact(path, 'a' * 64)
        empty = argparse.Namespace(app=None, time_from=None, time_to=None, agent=None)
        self.assertIsNone(runtime.scope(empty))
        for key, value in [('app', "unsafe'"), ('agent', 17), ('time_from', 100)]:
            bad = copy.copy(empty)
            setattr(bad, key, value)
            with self.assertRaises(ValueError):
                runtime.scope(bad)

    def test_stop_rejects_changed_id_labels_resources_and_fingerprint(self):
        state = self.state()
        value = runtime.spec(state, 'querier')
        original = self.info(value)
        self.assertTrue(runtime.expected(original, value))
        for mutation in ['label', 'ports', 'capabilities', 'writable']:
            changed = copy.deepcopy(original)
            if mutation == 'label':
                changed['Config']['Labels']['io.traflens.run'] = 'another-run'
            elif mutation == 'ports':
                changed['HostConfig']['PortBindings']['20416/tcp'][0]['HostIp'] = '0.0.0.0'
            elif mutation == 'capabilities':
                changed['HostConfig']['CapAdd'] = ['SYS_ADMIN']
            else:
                changed['HostConfig']['ReadonlyRootfs'] = False
            self.assertFalse(runtime.expected(changed, value), mutation)
        with tempfile.TemporaryDirectory() as folder:
            entry = {'spec': value, 'id': original['Id'], 'fingerprint': runtime.fingerprint(original)}
            state['resources'] = {'querier': entry}
            changed = copy.deepcopy(original)
            changed['Id'] = 'd' * 64
            with patch.object(runtime, 'inspect', return_value=changed), patch.object(runtime, 'call') as call:
                with self.assertRaises(ValueError):
                    runtime.cleanup(Path(folder), state)
                call.assert_not_called()
            changed = copy.deepcopy(original)
            changed['HostConfig']['SecurityOpt'].append('apparmor=unconfined')
            with patch.object(runtime, 'inspect', return_value=changed), patch.object(runtime, 'call') as call:
                with self.assertRaises(ValueError):
                    runtime.cleanup(Path(folder), state)
                call.assert_not_called()

    def test_native_bounds_and_actual_scope_readiness_never_fallback(self):
        state = self.state()
        state['scope'] = {'app': 'cpu-fixture', 'from': 100, 'to': 110, 'agent': 17}
        responses = [(200, self.native(2)), (400, {'OPT_STATUS': 'RESOURCE_NUM_EXCEEDED'}),
                     (200, {'app': 'cpu-fixture', 'agent_id': 17, 'language': 'Golang', 'event': 'cpu', 'unit': 'samples',
                            'bounds_applied': True, 'max_rows': 256, 'input_rows': 2, 'total_samples': '800'})]
        with patch.object(runtime, 'request', side_effect=responses) as request:
            result = runtime.readiness(state)
            self.assertTrue(result['actual_scope_checked'])
            self.assertTrue(result['actual_max_rows_rejection_checked'])
            self.assertEqual(result['total_samples'], '800')
            self.assertTrue(all('/ProfileTracingBounded' in call.args[1] for call in request.call_args_list[:2]))
        for status, document in [(404, {}), (200, {'OPT_STATUS': 'SUCCESS', 'result': {}}), (200, self.native(257))]:
            with self.assertRaises(ValueError):
                runtime.native_ready(status, document, 256)
        wrong = self.native(0)
        wrong['result']['budgets']['nodes'] = 1000000
        with self.assertRaises(ValueError):
            runtime.native_ready(200, wrong, 256)

    def test_empty_readiness_is_not_reported_as_functional_acceptance(self):
        state = self.state()
        def fake(port, path, payload=None):
            if payload:
                return 200, self.native(0)
            values = dict(__import__('urllib.parse', fromlist=['parse_qs']).parse_qsl(path.split('?', 1)[1]))
            return 200, {'app': values['app'], 'language': 'Golang', 'event': 'cpu', 'unit': 'samples',
                         'bounds_applied': True, 'max_rows': 256, 'input_rows': 0, 'total_samples': '0'}
        with patch.object(runtime, 'request', side_effect=fake):
            result = runtime.readiness(state)
            self.assertFalse(result['actual_scope_checked'])
            self.assertFalse(result['actual_max_rows_rejection_checked'])
            self.assertTrue(result['empty_readiness_only'])

    def test_server_identity_survives_receipt_roundtrip_without_reading_yaml(self):
        value = self.info(runtime.spec(self.state(), 'querier'))
        value['State']['Running'] = True
        identity = runtime.server_identity(value)
        self.assertEqual(identity, json.loads(json.dumps(identity)))
        self.assertIn('image', identity)
        self.assertNotIn('configuration', identity)
