"""Offline MySQL specialization guards; never execute network/capture workloads."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
import cpu_profile_controller as controller
from test_cpu_profile import FakeAPI


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, LAB / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


prepare = load('mysql_prepare_tested', 'managed-mysql.py')
runtime = load('mysql_capture_tested', 'ebpf-mysql.py')
agent = load('mysql_agent_tested', 'managed-http-agent.py')


def state(work):
    return {'schema': runtime.SCHEMA, 'run': 'my-' + '1' * 24, 'negative_run': 'my-' + '2' * 24,
            'output': str(work), 'workers': {}, 'args': {'image': 'sha256:' + 'a' * 64,
            'workload_bin': '/owned/ebpf-mysql', 'workload_sha256': 'b' * 64},
            'scope': {'positive': {'container_id': 'c' * 64, 'netns': 'net:[101]'},
                      'negative': {'container_id': 'd' * 64, 'netns': 'net:[102]'}, 'agent_container_id': 'e' * 64}}


def receipt(run, role):
    return {'run': run, 'role': role, 'pass': True, 'completed_requests': 3, 'expected_requests': 3,
            'wire_events': 21, 'classic_packets': 26, 'owned_sockets_closed': True, 'listener_closed': True,
            'single_threaded': True, 'error': '', 'wire_fixture': True, 'sql_executed': False,
            'pacing_only_qualification': True, 'pacing_ms': 100,
            'pacing_waits': 21, 'pacing_duration_ns': 2_100_000_000, 'waits_sha256': 'a' * 64,
            'comm': 'mysqld' if role == 'server' else 'traflens-mysql',
            'connections': [{'complete': True, 'closed': True} for _ in range(3)]}


class MySQLRuntimeGuards(unittest.TestCase):
    def test_explicit_contract_is_immutable_and_leaves_dns_default_unchanged(self):
        self.assertEqual(runtime.CONTRACT.name, 'mysql')
        self.assertEqual(runtime.CONTRACT.prefix, 'my-')
        self.assertEqual(runtime.CONTRACT.protocol_id, 60)
        self.assertIsNone(runtime.CONTRACT.expected_observations)
        self.assertEqual(runtime.RUNTIME.DNS_CONTRACT.name, 'dns')
        self.assertEqual(runtime.RUNTIME.DNS_CONTRACT.prefix, 'dns-')
        self.assertEqual(runtime.RUNTIME.DNS_CONTRACT.expected_observations, 6)
        with self.assertRaises(AttributeError):
            runtime.CONTRACT.name = 'dns'
        with self.assertRaises(RuntimeError):
            runtime.RUNTIME.validate_contract(runtime.CONTRACT._replace(prefix='mysql-'))

    def test_mysql_documents_narrow_only_protocol_without_mutating_http_or_dns_factories(self):
        before_http = controller.kernel_http_profile('192.0.2.24', 20035, 20033)
        before_dns = controller.kernel_dns_profile('192.0.2.24', 20035, 20033)
        profile, boot = prepare.documents('192.0.2.24', 'g-MiXeD123', 20035, ingester_port=20033)
        request = profile['processors']['request_log']
        self.assertEqual(profile, controller.kernel_mysql_profile('192.0.2.24', 20035, 20033))
        self.assertEqual(request['application_protocol_inference']['enabled_protocols'], ['MySQL'])
        self.assertEqual(request['filters']['port_number_prefilters'], {'MySQL': '18080'})
        self.assertEqual(request['filters']['tag_filters'], {'MySQL': []})
        self.assertTrue(request['filters']['cbpf_disabled'])
        self.assertEqual(profile['inputs']['cbpf']['af_packet']['interface_regex'], '')
        self.assertFalse(profile['inputs']['proc']['enabled'])
        self.assertFalse(profile['inputs']['integration']['enabled'])
        self.assertTrue(profile['inputs']['ebpf']['profile']['on_cpu']['disabled'])
        self.assertTrue(profile['inputs']['ebpf']['profile']['unwinding']['dwarf_disabled'])
        self.assertEqual(boot['ebpf-socket-netns-scope'], '/run/traflens/target.netns')
        self.assertEqual(boot['vtap-group-id-request'], 'g-MiXeD123')
        self.assertEqual(controller.kernel_http_profile('192.0.2.24', 20035, 20033), before_http)
        self.assertEqual(controller.kernel_dns_profile('192.0.2.24', 20035, 20033), before_dns)

    def test_mysql_manifest_is_independent_and_rehashed_scope_widening_still_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp) / 'prepared'
            manifest = prepare.prepare(folder, controller_ip='192.0.2.24', group_id='g-test')
            boot, profile = agent.verified_preparation(folder)
            self.assertEqual(manifest['schema'], 'traflens.managed-mysql-preparation.v1')
            self.assertFalse(manifest['runtime_qualified'])
            self.assertNotIn('http_port', manifest)
            self.assertNotIn('dns_port', manifest)
            self.assertEqual(agent.prepared_protocol(profile), ('MySQL/TCP', 18080))
            profile['inputs']['cbpf']['af_packet']['interface_regex'] = '.*'
            path = folder / 'group-profile.json'
            path.write_text(json.dumps(profile))
            manifest['files'][path.name] = {'sha256': agent.sha(path), 'bytes': path.stat().st_size}
            (folder / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                agent.verified_preparation(folder)
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'never-created'
            with self.assertRaises(ValueError):
                prepare.prepare(target, controller_ip='192.0.2.24', group_id='g-test', mysql_port=3306)
            self.assertFalse(target.exists())

    def test_kernel_mysql_only_my_prefix_normal_features_and_exact_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'controller-events').mkdir(mode=0o700)
            controller.WORK = work
            api = FakeAPI()
            value = {'integration_mode': 'kernel_mysql', 'run': 'my-' + '1' * 24,
                     'ctrl_ip': '172.29.0.2', 'ctrl_mac': '02:00:00:00:00:02',
                     'controller_ip': '192.0.2.24', 'controller_port': 20035, 'ingester_port': 20033,
                     'profile': controller.kernel_mysql_profile('192.0.2.24', 20035, 20033)}
            self.assertEqual(controller.license_functions(value), [2, 4, 5])
            for changed in [dict(value, run='mysql-' + '1' * 24), dict(value, run='dns-' + '1' * 24),
                            dict(value, LICENSE_FUNCTIONS=[11])]:
                with self.assertRaises(RuntimeError):
                    controller.validate_metadata(changed)
            changed = copy.deepcopy(value)
            changed['profile']['processors']['request_log']['filters']['port_number_prefilters'] = {'MySQL': '1-65535'}
            with self.assertRaises(RuntimeError):
                controller.validate_metadata(changed)
            with contextlib.redirect_stdout(io.StringIO()):
                controller.prepare(api, types.SimpleNamespace(check_keys=lambda *_: None), value)
                self.assertEqual(api.agents[0]['LICENSE_FUNCTIONS'], [2, 4, 5])
                controller.cleanup(api, {'run': value['run'], 'agent_stopped': True, 'owned_agent_removed': True})
            self.assertEqual(api.agents, [])
            self.assertEqual([group['LCUUID'] for group in api.groups], ['old-group'])

    def test_default_and_unsafe_controller_do_not_touch_resources_or_outputs(self):
        with mock.patch.object(runtime.CORE, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(runtime.RUNTIME, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as out:
            self.assertEqual(runtime.main(['run', '--work', '/not-created']), 0)
            plan = json.loads(out.getvalue())
            self.assertFalse(plan['starts_network'])
            self.assertEqual(plan['protocol'], 'MySQL/TCP')
            with self.assertRaises((RuntimeError, ValueError)):
                runtime.execute(types.SimpleNamespace(controller_url='http://user:secret@127.0.0.1:20417'))
        with mock.patch.object(prepare, 'prepare', side_effect=AssertionError('output')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(prepare.main([]), 0)

    def test_mysql_workers_bind_correct_namespace_nonce_and_typed_purpose(self):
        value = state(Path('/owned/capture'))
        for role in runtime.ROLES:
            spec = runtime.worker_spec(value, role)
            phase, kind, run = runtime.RUNTIME.worker_selection(value, role)
            self.assertEqual(spec['network_mode'], 'container:' + value['scope'][phase]['container_id'])
            self.assertEqual(spec['labels']['io.traflens.purpose'], 'traflens.ebpf-mysql.worker')
            self.assertEqual(spec['labels']['io.traflens.run'], value['run'])
            self.assertEqual(spec['command'][spec['command'].index('--run') + 1], run)
            self.assertEqual(spec['command'][spec['command'].index('--role') + 1], kind)
            self.assertEqual(spec['pid_mode'], 'host')
            self.assertEqual(spec['cap_drop'], ['ALL'])
            self.assertEqual(spec['cap_add'], [])
            self.assertTrue(spec['read_only'])
            self.assertEqual(spec['port_bindings'], {})

    def test_actual_comm_is_only_direction_hint_after_process_identity_and_is_not_inferred(self):
        actual = {'pid': 123}
        with mock.patch.object(runtime.RUNTIME.Path, 'read_text', return_value='mysqld\n'):
            self.assertEqual(runtime.RUNTIME.comm_direction_hint(actual, {'comm': 'mysqld'}, 'server', runtime.CONTRACT), 'mysqld')
            with self.assertRaises(RuntimeError):
                runtime.RUNTIME.comm_direction_hint(actual, {'comm': 'other'}, 'server', runtime.CONTRACT)
        with mock.patch.object(runtime.RUNTIME.Path, 'read_text', return_value='other\n'):
            with self.assertRaises(RuntimeError):
                runtime.RUNTIME.comm_direction_hint(actual, {'comm': 'mysqld'}, 'server', runtime.CONTRACT)
        with mock.patch.object(runtime.RUNTIME.Path, 'read_text', side_effect=AssertionError('DNS must keep existing contract')):
            self.assertIsNone(runtime.RUNTIME.comm_direction_hint(actual, {}, 'server'))

    def test_mysql_pass_requires_complete_handshake_query_quit_and_clean_actual_sockets(self):
        value = receipt('my-' + '1' * 24, 'client')
        runtime.validate_receipt(value, value['run'], value['role'])
        changes = [lambda v: v.update(wire_events=6), lambda v: v.update(classic_packets=25),
                   lambda v: v.update(sql_executed=True), lambda v: v.update(wire_fixture=False),
                   lambda v: v.update(comm='mysqld'), lambda v: v.update(error='timeout'),
                   lambda v: v['connections'][0].update(closed=False)]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(RuntimeError):
                runtime.validate_receipt(changed, value['run'], value['role'])

    def test_paced_support_slice_rejects_unpaced_missing_or_inconsistent_wait_metadata(self):
        value = receipt('my-' + '1' * 24, 'client')
        runtime.validate_receipt(value, value['run'], value['role'])
        changes = [lambda v: v.pop('pacing_only_qualification'), lambda v: v.update(pacing_only_qualification=False),
                   lambda v: v.update(pacing_ms=99), lambda v: v.update(pacing_ms=100.0),
                   lambda v: v.update(pacing_waits=20), lambda v: v.update(pacing_waits='21'),
                   lambda v: v.pop('waits_sha256'), lambda v: v.update(waits_sha256='unrecorded'),
                   lambda v: v.update(pacing_duration_ns=0), lambda v: v.update(pacing_duration_ns=91_000_000_000)]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(RuntimeError):
                runtime.validate_receipt(changed, value['run'], value['role'])

    def test_mysql_public_stop_cannot_reinterpret_dns_lifecycle_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            runtime.CORE.write(folder / 'state.json', {'schema': runtime.RUNTIME.SCHEMA, 'run': 'dns-' + '1' * 24, 'output': str(folder)})
            with mock.patch.object(runtime.RUNTIME.os, 'kill', side_effect=AssertionError('must not signal')):
                with self.assertRaisesRegex(RuntimeError, 'Invalid scoped protocol lifecycle receipt'):
                    runtime.stop(folder)


if __name__ == '__main__':
    unittest.main()
