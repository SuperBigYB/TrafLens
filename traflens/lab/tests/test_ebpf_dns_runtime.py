"""Offline scoped DNS guards; never start Docker, sockets, or collection."""
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


prepare = load('dns_prepare_tested', 'managed-dns.py')
agent = load('dns_managed_agent_tested', 'managed-http-agent.py')
runtime = load('dns_coordinator_tested', 'ebpf-dns.py')


def state_fixture(work):
    return {'schema': runtime.SCHEMA, 'run': 'dns-' + '1' * 24, 'negative_run': 'dns-' + '2' * 24,
            'output': str(work), 'workers': {}, 'args': {'image': 'sha256:' + 'a' * 64,
            'workload_bin': '/owned/ebpf-dns', 'workload_sha256': 'b' * 64},
            'scope': {'positive': {'container_id': 'c' * 64, 'netns': 'net:[101]'},
                      'negative': {'container_id': 'd' * 64, 'netns': 'net:[102]'}, 'agent_container_id': 'e' * 64}}


def receipt(run, role):
    return {'run': run, 'role': role, 'pass': True, 'completed_requests': 3, 'expected_requests': 3,
            'wire_events': 6, 'owned_sockets_closed': True, 'listener_closed': True,
            'single_threaded': True, 'error': '', 'connections': [{'complete': True, 'closed': True} for _ in range(3)]}


class DNSRuntimeGuards(unittest.TestCase):
    def test_live_executable_kernel_handle_accepts_only_stable_named_process(self):
        pid = os.getpid()
        actual = {'pid': pid, 'start_ticks': runtime.CORE.UTIL.process_start(pid)}
        path = Path('/proc', str(pid), 'exe')
        self.assertTrue(path.is_symlink())
        self.assertEqual(runtime.live_executable_sha(actual), hashlib.sha256(path.read_bytes()).hexdigest())
        # This dedicated live-process proof must not relax artifact validation.
        with self.assertRaises(RuntimeError):
            runtime.CORE.file_hash(path)
        with self.assertRaises(RuntimeError):
            runtime.live_executable_sha(dict(actual, start_ticks='0'))
        with self.assertRaises(RuntimeError):
            runtime.live_executable_sha({'pid': '/tmp/untrusted-exe', 'start_ticks': actual['start_ticks']})

    def test_live_executable_proof_rejects_pid_generation_change_during_read(self):
        pid = os.getpid()
        ticks = runtime.CORE.UTIL.process_start(pid)
        with mock.patch.object(runtime.CORE.UTIL, 'process_start', side_effect=[ticks, str(int(ticks) + 1)]):
            with self.assertRaisesRegex(RuntimeError, 'changed during SHA proof'):
                runtime.live_executable_sha({'pid': pid, 'start_ticks': ticks})

    def test_dns_factory_and_documents_preserve_exact_scope_and_disable_other_inputs(self):
        profile, boot = prepare.documents('192.0.2.24', 'g-MiXeD123', 20035, ingester_port=20033)
        self.assertEqual(profile, controller.kernel_dns_profile('192.0.2.24', 20035, 20033))
        self.assertEqual(boot['vtap-group-id-request'], 'g-MiXeD123')
        self.assertEqual(boot['ebpf-socket-netns-scope'], '/run/traflens/target.netns')
        request = profile['processors']['request_log']
        self.assertEqual(request['application_protocol_inference']['enabled_protocols'], ['DNS'])
        self.assertEqual(request['filters']['port_number_prefilters'], {'DNS': '18080'})
        self.assertTrue(request['filters']['cbpf_disabled'])
        self.assertEqual(profile['inputs']['cbpf']['af_packet']['interface_regex'], '')
        self.assertFalse(profile['inputs']['ebpf']['disabled'])
        self.assertFalse(profile['inputs']['proc']['enabled'])
        self.assertFalse(profile['inputs']['integration']['enabled'])
        self.assertTrue(profile['inputs']['ebpf']['profile']['on_cpu']['disabled'])
        self.assertTrue(profile['inputs']['ebpf']['profile']['unwinding']['dwarf_disabled'])
        self.assertEqual(agent.prepared_protocol(profile), ('DNS/TCP', 18080))

    def test_kernel_dns_normal_features_exact_prefix_profile_and_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'controller-events').mkdir(mode=0o700)
            controller.WORK = work
            api = FakeAPI()
            value = {'integration_mode': 'kernel_dns', 'run': 'dns-' + '1' * 24,
                     'ctrl_ip': '172.29.0.2', 'ctrl_mac': '02:00:00:00:00:02',
                     'controller_ip': '192.0.2.24', 'controller_port': 20035, 'ingester_port': 20033,
                     'profile': controller.kernel_dns_profile('192.0.2.24', 20035, 20033)}
            self.assertEqual(controller.license_functions(value), [2, 4, 5])
            for changed in [dict(value, run='nh-' + '1' * 24), dict(value, LICENSE_FUNCTIONS=[11])]:
                with self.assertRaises(RuntimeError):
                    controller.validate_metadata(changed)
            changed = copy.deepcopy(value)
            changed['profile']['processors']['request_log']['application_protocol_inference']['enabled_protocols'].append('HTTP')
            with self.assertRaises(RuntimeError):
                controller.validate_metadata(changed)
            with contextlib.redirect_stdout(io.StringIO()):
                controller.prepare(api, types.SimpleNamespace(check_keys=lambda *_: None), value)
                self.assertEqual(api.agents[0]['LICENSE_FUNCTIONS'], [2, 4, 5])
                controller.cleanup(api, {'run': value['run'], 'agent_stopped': True, 'owned_agent_removed': True})
            self.assertEqual(api.agents, [])
            self.assertEqual([group['LCUUID'] for group in api.groups], ['old-group'])

    def test_dns_manifest_semantics_remain_strict_even_when_tamper_is_rehashed(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'prepared'
            manifest = prepare.prepare(output, controller_ip='192.0.2.24', group_id='g-MiXeD123')
            boot, profile = agent.verified_preparation(output)
            self.assertEqual(manifest['schema'], 'traflens.managed-dns-preparation.v1')
            self.assertNotIn('http_port', manifest)
            self.assertFalse(manifest['runtime_qualified'])
            self.assertEqual(agent.prepared_protocol(profile), ('DNS/TCP', 18080))
            profile['inputs']['cbpf']['af_packet']['interface_regex'] = '.*'
            path = output / 'group-profile.json'
            path.write_text(json.dumps(profile))
            manifest['files'][path.name] = {'sha256': agent.sha(path), 'bytes': path.stat().st_size}
            (output / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                agent.verified_preparation(output)
            # A declared DNS schema cannot pass as an old HTTP preparation.
            manifest['schema'] = 'traflens.managed-http-preparation.v1'
            manifest['http_port'] = 18080
            (output / 'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                agent.verified_preparation(output)

    def test_dns_preparation_rejects_unbounded_ports_before_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'never-created'
            for port in [53, 18081, True, 0]:
                with self.assertRaises(ValueError):
                    prepare.prepare(target, controller_ip='192.0.2.24', group_id='g-test', dns_port=port)
                self.assertFalse(target.exists())

    def test_default_plans_and_unsafe_controller_url_have_no_side_effects(self):
        with mock.patch.object(runtime.CORE, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(runtime.CORE, 'helper_hashes', side_effect=AssertionError('SSH')), \
                mock.patch.object(runtime, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(runtime.main(['run', '--work', '/not-created']), 0)
            self.assertFalse(json.loads(output.getvalue())['starts_network'])
            with self.assertRaises((ValueError, RuntimeError)):
                runtime.execute(types.SimpleNamespace(controller_url='http://user:secret@127.0.0.1:20417'))
        with mock.patch.object(prepare, 'prepare', side_effect=AssertionError('output')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(prepare.main([]), 0)

    def test_workers_use_distinct_namespace_nonce_but_identical_restricted_docker_envelopes(self):
        state = state_fixture(Path('/owned/capture'))
        for role in runtime.ROLES:
            spec = runtime.worker_spec(state, role)
            phase, mode, run = runtime.worker_selection(state, role)
            self.assertEqual(spec['network_mode'], 'container:' + state['scope'][phase]['container_id'])
            self.assertEqual(spec['labels']['io.traflens.run'], state['run'])
            self.assertEqual(spec['labels']['io.traflens.purpose'], 'traflens.ebpf-dns.worker')
            self.assertEqual(spec['command'][spec['command'].index('--run') + 1], run)
            self.assertEqual(spec['command'][spec['command'].index('--role') + 1], mode)
            self.assertEqual(spec['entrypoint'], ['/workload'])
            self.assertEqual(spec['pid_mode'], 'host')
            self.assertTrue(spec['read_only'])
            self.assertFalse(spec['privileged'])
            self.assertEqual(spec['cap_add'], [])
            self.assertEqual(spec['cap_drop'], ['ALL'])
            self.assertEqual((spec['memory_bytes'], spec['memory_swap_bytes'], spec['pids_limit']), (67108864, 67108864, 16))
            self.assertEqual(spec['port_bindings'], {})
            argv = runtime.CORE.docker_argv(spec)
            self.assertEqual(argv[:2], ['docker', 'create'])
            self.assertEqual(argv[-len(spec['command']):], spec['command'])
        self.assertNotEqual(runtime.worker_spec(state, 'positive-client')['network_mode'], runtime.worker_spec(state, 'negative-client')['network_mode'])

    def test_uncertain_docker_create_keeps_full_intent_before_any_success_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            with mock.patch.object(runtime.CORE, 'inspect', return_value=None), \
                    mock.patch.object(runtime.CORE, 'call', side_effect=TimeoutError('create response lost')):
                with self.assertRaises(TimeoutError):
                    runtime.create_worker(work, state, 'positive-server')
            intent = json.loads((work / 'positive-server-intent.json').read_text())
            self.assertEqual(intent['spec'], state['workers']['positive-server']['spec'])
            self.assertEqual(intent['argv_sha256'], runtime.CORE.digest(intent['argv']))
            self.assertNotIn('id', intent)
            self.assertFalse((work / 'positive-server-created.json').exists())
            self.assertIn('positive-server', json.loads((work / 'state.json').read_text())['workers'])

    def test_changed_or_unknown_worker_retains_agent_namespace_and_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            state['workers']['positive-client'] = {'spec': runtime.worker_spec(state, 'positive-client')}
            with mock.patch.object(runtime, 'worker_info', side_effect=RuntimeError('identity changed')), \
                    mock.patch.object(runtime.CORE, 'cleanup') as shared:
                result = runtime.cleanup(work, state)
            self.assertFalse(result['cleaned'])
            self.assertFalse(result['collector_stopped'])
            self.assertFalse(result['lease_restored'])
            shared.assert_not_called()

    def test_all_workers_are_removed_before_shared_agent_scope_controller_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            for role in runtime.ROLES:
                state['workers'][role] = {'id': role, 'spec': runtime.worker_spec(state, role)}
            removed, order = set(), []
            def info(s, role):
                return None if role in removed else {'Id': role, 'State': {'Running': False, 'Paused': False, 'ExitCode': 0, 'OOMKilled': False}}
            def call(argv):
                self.assertEqual(argv[:2], ['docker', 'rm'])
                removed.add(argv[2])
                order.append(argv[2])
            def shared(w, s):
                self.assertEqual(removed, set(runtime.ROLES))
                order.append('shared-agent-scope-controller-forward')
                return {'cleaned': True}
            with mock.patch.object(runtime, 'worker_info', side_effect=info), \
                    mock.patch.object(runtime.CORE, 'call', side_effect=call), \
                    mock.patch.object(runtime.CORE, 'cleanup', side_effect=shared):
                self.assertTrue(runtime.cleanup(work, state)['cleaned'])
            self.assertEqual(order, list(runtime.ROLES) + ['shared-agent-scope-controller-forward'])

    def test_nominal_pass_cannot_hide_missing_wire_or_unclosed_actual_connections(self):
        value = receipt('dns-' + '1' * 24, 'client')
        runtime.validate_receipt(value, value['run'], value['role'])
        changes = [lambda v: v.update(wire_events=5), lambda v: v.update(completed_requests=2),
                   lambda v: v.update(owned_sockets_closed=False), lambda v: v.update(error='timeout'),
                   lambda v: v['connections'][0].update(closed=False)]
        for change in changes:
            changed = copy.deepcopy(value)
            change(changed)
            with self.assertRaises(RuntimeError):
                runtime.validate_receipt(changed, value['run'], value['role'])

    def test_client_start_failure_still_unpauses_exact_owned_server(self):
        calls = []
        def create(w, s, role, contract=runtime.DNS_CONTRACT):
            if role.endswith('-client'):
                raise RuntimeError('client startup failed')
        with mock.patch.object(runtime, 'create_worker', side_effect=create), \
                mock.patch.object(runtime, 'pause_server', side_effect=lambda w, s, p, paused: calls.append(paused)), \
                mock.patch.object(runtime.signal, 'signal'), mock.patch.object(runtime.signal, 'setitimer'), \
                mock.patch.object(runtime.CORE, 'event'):
            with self.assertRaises(RuntimeError):
                runtime.run_phase(Path('/unused'), {}, 'positive')
        self.assertEqual(calls, [True, False])


if __name__ == '__main__':
    unittest.main()
