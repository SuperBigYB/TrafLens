"""Offline guards only: no containers, collection, HTTP or SSH are executed."""
import argparse
import copy
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location('public_ebpf_capture', LAB / 'ebpf-association.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def state_fixture(work):
    return {'schema': runtime.SCHEMA, 'run': 'nh-' + '1' * 24, 'output': str(work), 'workers': {},
            'anchor': 'b' * 64, 'args': {'image': 'sha256:' + 'a' * 64, 'workload_bin': '/owned/workload'},
            'controller_attempted': True, 'agent_attempted': False, 'lease_attempted': False}


def info_fixture(spec, running=True, paused=False):
    return {'Id': 'c' * 64, 'Image': spec['image'], 'Name': '/' + spec['name'],
            'Config': {'Image': spec['image'], 'Labels': copy.deepcopy(spec['labels']),
                       'Entrypoint': spec['entrypoint'], 'Cmd': spec['command']},
            'HostConfig': {'PidMode': 'host', 'NetworkMode': spec['network_mode'], 'ReadonlyRootfs': True,
                           'CapDrop': ['ALL'], 'CapAdd': [], 'NanoCpus': 500000000, 'Memory': 67108864,
                           'MemorySwap': 67108864, 'PidsLimit': 16, 'Privileged': False, 'PortBindings': {},
                           'PublishAllPorts': False, 'SecurityOpt': ['no-new-privileges'], 'RestartPolicy': {'Name': 'no'}},
            'Mounts': [{'Type': 'bind', 'Source': s, 'Destination': t, 'RW': rw} for s, t, rw in spec['mounts']],
            'State': {'Running': running, 'Paused': paused, 'Pid': 1234, 'StartedAt': '2026-10-28T00:00:00Z', 'ExitCode': 0, 'OOMKilled': False}}


class PublicCaptureGuards(unittest.TestCase):
    def test_default_plan_reads_no_artifacts_and_performs_no_tools(self):
        with mock.patch.object(runtime, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(runtime, 'call', side_effect=AssertionError('SSH')), \
                mock.patch.object(runtime, 'file_hash', side_effect=AssertionError('artifact')), \
                mock.patch.object(runtime, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(runtime.main(['run', '--work', '/never-read-or-created']), 0)
            plan = json.loads(output.getvalue())
            self.assertFalse(plan['execute'])
            self.assertFalse(plan['starts_network'])
            self.assertEqual(plan['requests'], 2)

    def test_credential_url_rejected_before_output_or_remote_hash_probe(self):
        with mock.patch.object(runtime, 'helper_hashes', side_effect=AssertionError('remote access')), \
                mock.patch.object(runtime, 'private_dir', side_effect=AssertionError('receipt')), \
                mock.patch.object(runtime, 'inspect', side_effect=AssertionError('Docker')):
            for url in ['http://user:secret@127.0.0.1:20417', 'http://127.0.0.1:20417?token=secret', 'http://192.0.2.1:20417']:
                with self.assertRaises((RuntimeError, ValueError)):
                    runtime.execute(argparse.Namespace(controller_url=url))

    def test_worker_inspect_matches_real_docker_spec_not_worker_flags(self):
        state = state_fixture('/owned/capture')
        spec = runtime.worker_spec(state, 'frontend')
        intent = {'id': 'c' * 64, 'spec': spec}
        info = info_fixture(spec)
        self.assertTrue(runtime.owned_worker(info, intent))
        argv = runtime.docker_argv(spec)
        self.assertEqual(argv[:2], ['docker', 'create'])
        self.assertEqual(argv[-len(spec['command']) - 1:], [spec['image'], *spec['command']])
        self.assertIn('--pid', argv)
        self.assertEqual(argv[argv.index('--pid') + 1], 'host')
        changes = [lambda v: v.update(Id='d' * 64),
                   lambda v: v['HostConfig'].update(PidMode=''),
                   lambda v: v['HostConfig'].update(NetworkMode='host'),
                   lambda v: v['HostConfig'].update(CapAdd=['SYS_ADMIN']),
                   lambda v: v['HostConfig'].update(MemorySwap=0),
                   lambda v: v['HostConfig'].update(PublishAllPorts=True),
                   lambda v: v['HostConfig'].update(Privileged=True),
                   lambda v: v['HostConfig'].update(SecurityOpt=['no-new-privileges', 'apparmor=unconfined']),
                   lambda v: v['Config'].update(Cmd=['--role', 'unrelated']),
                   lambda v: v['Mounts'][0].update(RW=not v['Mounts'][0]['RW'])]
        for change in changes:
            changed = copy.deepcopy(info)
            change(changed)
            self.assertFalse(runtime.owned_worker(changed, intent))

    def test_host_pid_label_disable_requires_live_no_selinux_proof(self):
        state = state_fixture('/owned/capture')
        spec = runtime.worker_spec(state, 'frontend')
        intent = {'id': 'c' * 64, 'spec': spec}
        info = info_fixture(spec)
        info['HostConfig']['SecurityOpt'] = ['no-new-privileges', 'label=disable']
        proof = {'selinux_enabled': False, 'host_selinux_fs_present': False, 'host_selinux_enforce_present': False,
                 'daemon_security_options': ['name=seccomp,profile=builtin'], 'ignored_daemon_options': ['label=disable'],
                 'reason': 'SELinux unavailable; Docker hostPID label disable'}
        with mock.patch.object(runtime, 'selinux_context', return_value=proof):
            self.assertTrue(runtime.owned_worker(info, intent))
            canonical, actual_proof = runtime.worker_security(info['HostConfig']['SecurityOpt'])
            self.assertEqual(canonical, ['no-new-privileges'])
            self.assertEqual(actual_proof, proof)
        with mock.patch.object(runtime, 'selinux_context', side_effect=RuntimeError('SELinux available')):
            self.assertFalse(runtime.owned_worker(info, intent))
        for unsafe in [['no-new-privileges', 'label=disable', 'label=disable'],
                       ['no-new-privileges', 'apparmor=unconfined'], ['label=disable'],
                       ['no-new-privileges:false', 'label=disable'], ['no-new-privileges', 'label=other']]:
            with self.assertRaises(RuntimeError):
                runtime.worker_security(unsafe)

    def test_selinux_context_rejects_daemon_or_host_security_presence(self):
        for options, present in [(['name=selinux'], False), (['name=seccomp,profile=builtin'], True)]:
            with mock.patch.object(runtime, '_SELINUX_CONTEXT', None), \
                    mock.patch.object(runtime, 'call', return_value=types.SimpleNamespace(stdout=json.dumps(options))), \
                    mock.patch.object(Path, 'exists', return_value=present):
                with self.assertRaises(RuntimeError):
                    runtime.selinux_context()
        with mock.patch.object(runtime, '_SELINUX_CONTEXT', None), \
                mock.patch.object(runtime, 'call', return_value=types.SimpleNamespace(stdout='["name=seccomp,profile=builtin"]')) as command, \
                mock.patch.object(Path, 'exists', return_value=False):
            proof = runtime.selinux_context()
            self.assertFalse(proof['selinux_enabled'])
            self.assertFalse(proof['host_selinux_fs_present'])
            runtime.selinux_context()
            self.assertEqual(command.call_count, 1)

    def test_uncertain_worker_create_persists_complete_docker_intent_before_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            with mock.patch.object(runtime, 'inspect', return_value=None), \
                    mock.patch.object(runtime, 'call', side_effect=subprocess.TimeoutExpired('docker', 20)) as call:
                with self.assertRaises(subprocess.TimeoutExpired):
                    runtime.create_worker(work, state, 'frontend')
            saved = json.loads((work / 'state.json').read_text())['workers']['frontend']
            self.assertNotIn('id', saved)
            self.assertEqual(saved['argv'][:2], ['docker', 'create'])
            self.assertEqual(saved['argv_sha256'], runtime.digest(saved['argv']))
            self.assertEqual(saved['spec']['pid_mode'], 'host')
            self.assertEqual(saved['spec']['network_mode'], 'container:' + state['anchor'])
            self.assertEqual(call.call_count, 1)

    def test_unknown_or_unavailable_worker_keeps_agent_lease_and_controller(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            spec = runtime.worker_spec(state, 'frontend')
            state['workers']['frontend'] = {'id': 'c' * 64, 'spec': spec}
            foreign = info_fixture(spec)
            foreign['Id'] = 'd' * 64
            for kwargs in [{'side_effect': RuntimeError('Docker unavailable')}, {'return_value': foreign}]:
                with mock.patch.object(runtime, 'inspect', **kwargs), \
                        mock.patch.object(runtime, 'agent_restore') as agent, \
                        mock.patch.object(runtime, 'backend') as backend, \
                        mock.patch.object(runtime, 'stop_process') as stop, \
                        mock.patch.object(runtime, 'call') as call:
                    result = runtime.cleanup(work, copy.deepcopy(state))
                self.assertFalse(result['cleaned'])
                agent.assert_not_called()
                backend.assert_not_called()
                stop.assert_not_called()
                call.assert_not_called()

    def test_cleanup_recovers_uncertain_create_and_actual_pause_in_required_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            spec = runtime.worker_spec(state, 'frontend')
            state['workers']['frontend'] = {'spec': spec}  # No successful create stdout/ID.
            current = [info_fixture(spec, paused=True)]
            order = []
            lease = work / 'managed-unit'
            lease.mkdir(mode=0o700)
            def command(argv, **kwargs):
                action = argv[1]
                order.append(action)
                if action == 'unpause':
                    current[0]['State']['Paused'] = False
                elif action == 'stop':
                    current[0]['State']['Running'] = False
                elif action == 'rm':
                    current[0] = None
                return types.SimpleNamespace(stdout='', returncode=0)
            def agent(*_):
                order.append('agent-bpf-tracefs-restored')
                return True
            def logged(*_):
                order.append('lease-release')
                runtime.write(lease / 'result.json', {'pass': False, 'namespace_pins_released': True,
                    'external_agent_exit_and_inventory_restored': True, 'original_host_bpf_inventory_restored': True,
                    'original_tracefs_restored': True, 'preexisting_containers_still_running': True, 'cleanup_errors': []})
            with mock.patch.object(runtime, 'inspect', side_effect=lambda *_: current[0]), \
                    mock.patch.object(runtime, 'call', side_effect=command), \
                    mock.patch.object(runtime, 'agent_restore', side_effect=agent), \
                    mock.patch.object(runtime, 'locate_lease', return_value=lease), \
                    mock.patch.object(runtime, 'logged', side_effect=logged), \
                    mock.patch.object(runtime, 'backend', side_effect=lambda *_: order.append('controller-cleanup')), \
                    mock.patch.object(runtime, 'stop_process', side_effect=lambda *_: order.append('forward-close')):
                result = runtime.cleanup(work, state)
            self.assertTrue(result['cleaned'])
            self.assertEqual(order, ['unpause', 'stop', 'rm', 'agent-bpf-tracefs-restored', 'lease-release', 'controller-cleanup', 'forward-close'])
            self.assertEqual(state['workers']['frontend']['id'], 'c' * 64)
            # An early-failed lease remains pass:false while concrete restoration
            # is accepted; cleanup must not manufacture a successful old run.
            self.assertFalse(json.loads((work / 'scope-restoration.json').read_text())['pass'])

    def test_agent_uncertain_create_uses_unique_full_intent_then_public_stop(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            folder = work / 'agent' / 'abc'
            folder.mkdir(parents=True, mode=0o700)
            intent = {'name': 'owned-agent', 'folder': str(folder), 'baseline': {'tracefs': {}}}
            runtime.write(folder / 'intent.json', intent)
            state = state_fixture(work)
            state['agent_attempted'] = True
            current = [{'Id': 'a' * 64}]
            managed = types.SimpleNamespace(WORK=None, owned=mock.Mock(return_value=True), ids=lambda: [],
                    restored_programs=lambda *_: True, tracefs=lambda: {})
            def public_stop(*_):
                current[0] = None
            with mock.patch.object(runtime, 'module', return_value=managed), \
                    mock.patch.object(runtime, 'inspect', side_effect=lambda *_: current[0]), \
                    mock.patch.object(runtime, 'logged', side_effect=public_stop) as logged:
                self.assertTrue(runtime.agent_restore(work, state))
            self.assertEqual(json.loads((work / 'agent/current.json').read_text())['id'], 'a' * 64)
            self.assertTrue(managed.owned.called)
            self.assertEqual(logged.call_args.args[1], 'agent-stop')
            self.assertTrue(json.loads((folder / 'stopped.json').read_text())['bpf_inventory_restored'])

    def test_source_peer_code_mismatch_stops_before_runtime(self):
        args = argparse.Namespace(backend_host='dev-240', backend_code='/owned/code')
        remote = {name: 'a' * 64 for name in runtime.CODE}
        remote['cpu_profile_controller.py'] = 'b' * 64
        with mock.patch.object(runtime, 'file_hash', return_value='a' * 64), \
                mock.patch.object(runtime, 'call', return_value=types.SimpleNamespace(stdout=json.dumps(remote))):
            with self.assertRaises(RuntimeError):
                runtime.helper_hashes(args)


if __name__ == '__main__':
    unittest.main()
