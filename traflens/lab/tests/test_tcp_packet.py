"""Offline packet-only Controller/runtime/filter guards; no capture is started."""
import contextlib
import copy
import ctypes.util
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
import tcp_packet_filter as filters
from test_cpu_profile import FakeAPI

SPEC = importlib.util.spec_from_file_location('packet_agent_tested', LAB / 'tcp-packet-agent.py')
agent = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(agent)


def example_spec():
    image = 'sha256:' + 'a' * 64
    return {'name': 'owned-packet', 'image': image, 'config_image': image, 'hostname': 'traflens-tcp-' + '1' * 24,
            'user': '0:0', 'entrypoint': ['/usr/bin/timeout'], 'command': ['180', '/opt/agent'],
            'network': 'host', 'pid_mode': '', 'readonly': True, 'privileged': False, 'cap_add': ['NET_RAW'], 'cap_drop': ['ALL'],
            'nano_cpus': 2000000000, 'memory': 1073741824, 'memory_swap': 1073741824, 'pids_limit': 384,
            'ports': {}, 'publish_all': False, 'restart': 'no', 'security': ['no-new-privileges'],
            'labels': {'io.traflens.purpose': agent.PURPOSE, 'io.traflens.run': 'tcp-' + '1' * 24, 'io.traflens.output': '/owned/work'},
            'mounts': [['/owned/agent', '/opt/agent', False]]}


def example_info(spec):
    return {'Id': 'b' * 64, 'Name': '/' + spec['name'], 'Image': spec['image'],
            'Config': {'Image': spec['image'], 'Hostname': spec['hostname'], 'User': '0:0', 'Entrypoint': spec['entrypoint'],
                       'Cmd': spec['command'], 'Labels': spec['labels']},
            'HostConfig': {'NetworkMode': 'host', 'PidMode': '', 'ReadonlyRootfs': True, 'Privileged': False,
                           'CapAdd': ['CAP_NET_RAW'], 'CapDrop': ['ALL'], 'NanoCpus': 2000000000,
                           'Memory': 1073741824, 'MemorySwap': 1073741824, 'PidsLimit': 384,
                           'PortBindings': {}, 'PublishAllPorts': False, 'RestartPolicy': {'Name': 'no'},
                           'SecurityOpt': ['no-new-privileges']},
            'Mounts': [{'Type': 'bind', 'Source': s, 'Destination': t, 'RW': rw} for s, t, rw in spec['mounts']],
            'State': {'Running': True}}


class PacketTCPGuards(unittest.TestCase):
    def test_actual_exit_proof_is_immutable_and_survives_absent_container_resume(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            spec = example_spec()
            info = example_info(spec)
            info['State'].update(Running=False, ExitCode=0, OOMKilled=False, FinishedAt='2026-10-29T01:02:03.123456789Z')
            receipt = {'id': info['Id'], 'spec': spec}
            with mock.patch.object(agent.time, 'time_ns', side_effect=[123456789, 987654321]):
                proof = agent.record_exit_state(work, receipt, info)
                original = (work / 'exit-state.json').read_bytes()
                self.assertEqual(agent.record_exit_state(work, receipt, info), proof)
            self.assertEqual((work / 'exit-state.json').read_bytes(), original)
            self.assertEqual(proof['container_id'], info['Id'])
            self.assertEqual(proof['image_id'], info['Image'])
            self.assertEqual(proof['finished_at'], info['State']['FinishedAt'])
            with mock.patch.object(agent, 'private_dir', return_value=work), \
                    mock.patch.object(agent, 'recover', return_value=(receipt, None)), \
                    mock.patch.object(agent, 'inspect', return_value=None), \
                    mock.patch.object(agent, 'wait_restoration', return_value={'journal': '/private/polls', 'final': {'elapsed_seconds': 1}}), \
                    mock.patch.object(agent, 'call') as tool, \
                    contextlib.redirect_stdout(io.StringIO()):
                stopped = agent.stop(work)
            tool.assert_not_called()
            self.assertEqual(stopped['exit'], proof)
            self.assertEqual((work / 'exit-state.json').read_bytes(), original)
            with self.assertRaises(RuntimeError):
                agent.read_exit_state(work, dict(receipt, id='c' * 64))

    def test_old_absent_container_without_actual_exit_cannot_gain_exit_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            self.assertIsNone(agent.read_exit_state(work, {'id': 'b' * 64, 'spec': example_spec()}))
            self.assertFalse((work / 'exit-state.json').exists())

    def test_restoration_pending_then_exact_baseline_retains_private_poll_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            pending = {'restored': False, 'bpf_missing': [], 'bpf_new': [{'id': 71, 'type': None}],
                       'tracefs_restored': True, 'lo_ifindex_restored': True, 'lo_flags_restored': True}
            restored = dict(pending, restored=True, bpf_new=[])
            with mock.patch.object(agent, 'restoration_snapshot', side_effect=[pending, restored]), \
                    mock.patch.object(agent.time, 'monotonic', side_effect=[0, 0, .1, .2]), \
                    mock.patch.object(agent.time, 'sleep') as sleep:
                result = agent.wait_restoration(work, {}, 90)
            lines = [json.loads(line) for line in Path(result['journal']).read_text().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertFalse(lines[0]['restored'])
            self.assertEqual(lines[0]['bpf_new'], [{'id': 71, 'type': None}])
            self.assertTrue(lines[1]['restored'])
            self.assertEqual(Path(result['journal']).stat().st_mode & 0o777, 0o600)
            sleep.assert_called_once()

    def test_restoration_timeout_keeps_failed_polls_and_never_writes_stopped_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            pending = {'restored': False, 'bpf_missing': [{'id': 13, 'type': 1}], 'bpf_new': [],
                       'tracefs_restored': True, 'lo_ifindex_restored': True, 'lo_flags_restored': True}
            with mock.patch.object(agent, 'restoration_snapshot', side_effect=lambda _: dict(pending)), \
                    mock.patch.object(agent.time, 'monotonic', side_effect=[0, 0, .1, .3, .3]), \
                    mock.patch.object(agent.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'did not restore within bounded wait'):
                    agent.wait_restoration(work, {}, .3)
            journals = list(work.glob('restoration-polls-*.jsonl'))
            self.assertEqual(len(journals), 1)
            lines = [json.loads(line) for line in journals[0].read_text().splitlines()]
            self.assertEqual(len(lines), 2)
            self.assertTrue(all(not line['restored'] for line in lines))
            self.assertFalse((work / 'stopped.json').exists())

    def test_restoration_snapshot_preserves_unknown_added_bpf_program_as_pending(self):
        receipt = {'baseline': {'bpf_ids': [13], 'bpf_types': {'13': 1}, 'tracefs': ['original'],
                                'lo_ifindex': 1, 'lo_flags': '0x9\n'}}
        with mock.patch.object(agent.MANAGED, 'ids', return_value=[71]), \
                mock.patch.object(agent.MANAGED, 'tracefs', return_value=['original']), \
                mock.patch.object(agent, 'program_type', return_value=None), \
                mock.patch.object(agent.socket, 'if_nametoindex', return_value=1), \
                mock.patch.object(agent.Path, 'read_text', return_value='0x9\n'):
            result = agent.restoration_snapshot(receipt)
        self.assertEqual(result['bpf_missing'], [{'id': 13, 'type': 1, 'type_source': 'baseline'}])
        self.assertEqual(result['bpf_new'], [{'id': 71, 'type': None}])
        self.assertFalse(result['restored'])
        self.assertTrue(result['tracefs_restored'])

    def test_readiness_uses_owned_rotation_files_without_following_latest_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / 'fresh'
            logs = work / 'logs'
            native = logs / 'native'
            native.mkdir(parents=True, mode=0o700)
            rotation = native / 'deepflow-agent_r2026-10-29_00-31-00'
            rotation.write_text('Start dispatcher 0\n')
            outside = Path(tmp) / 'outside'
            outside.mkdir(mode=0o700)
            secret = outside / 'deepflow-agent_rCURRENT.log'
            secret.write_text('on 3 listener\nDO_NOT_READ_OUTSIDE\n')
            (logs / 'deepflow-agent.log').symlink_to(secret)
            (logs / 'linked-directory').symlink_to(outside, target_is_directory=True)
            (logs / 'unrelated.log').write_text('on 3 listener\nDO_NOT_READ_UNRELATED\n')
            snapshot = agent.readiness_logs(work, '')
            self.assertTrue(snapshot['native_dispatcher_started'])
            self.assertFalse(snapshot['fresh_three_listener_sync'])
            self.assertEqual(len(snapshot['sources']), 2)  # stdout + actual rotation.
            self.assertNotIn('DO_NOT_READ', json.dumps(snapshot))
            rotation.write_text('Start dispatcher 0\non 3 listener\n')
            snapshot = agent.readiness_logs(work, '')
            self.assertTrue(snapshot['native_dispatcher_started'])
            self.assertTrue(snapshot['fresh_three_listener_sync'])
            self.assertEqual(snapshot['sources'][1]['source'], 'logs/native/' + rotation.name)
            self.assertEqual(snapshot['sources'][1]['sha256'], agent.sha(rotation))
            self.assertLessEqual(snapshot['bytes_read'], 4 << 20)

    def test_readiness_log_snapshots_reject_over_budget_before_reading(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'logs').mkdir(mode=0o700)
            path = work / 'logs' / 'deepflow-agent_rCURRENT.log'
            with path.open('wb') as stream:
                stream.truncate((4 << 20) + 1)
            with self.assertRaises(RuntimeError):
                agent.readiness_logs(work, '')

    def test_fixed_profile_only_lo_owned_addresses_ports_and_no_other_collection(self):
        profile = controller.packet_tcp_profile('192.0.2.24', 20035, 20033)
        inputs = profile['inputs']
        packet = inputs['cbpf']['af_packet']
        self.assertEqual(packet['interface_regex'], '^lo$')
        self.assertFalse(packet['inner_interface_capture_enabled'])
        self.assertFalse(packet['bpf_filter_disabled'])
        self.assertFalse(packet['tunning']['interface_promisc_enabled'])
        self.assertEqual(packet['extra_bpf_filter'], controller.PACKET_TCP_FILTER)
        self.assertTrue(inputs['ebpf']['disabled'])
        self.assertTrue(inputs['ebpf']['profile']['on_cpu']['disabled'])
        self.assertTrue(inputs['ebpf']['profile']['unwinding']['dwarf_disabled'])
        self.assertFalse(inputs['proc']['enabled'])
        self.assertFalse(inputs['integration']['enabled'])
        self.assertNotIn('vector', inputs)  # Not exposed; native default disabled.
        self.assertEqual(profile['processors']['request_log']['filters']['port_number_prefilters'], {'HTTP': '18081'})
        self.assertFalse(profile['processors']['request_log']['filters']['cbpf_disabled'])
        self.assertTrue(profile['outputs']['flow_metrics']['enabled'])
        self.assertTrue(profile['outputs']['flow_metrics']['filters']['npm_metrics'])
        self.assertEqual(profile['outputs']['flow_log']['filters']['l4_capture_network_types'], [0])

    def test_profile_uses_actual_controller_exposed_input_and_af_packet_keys(self):
        profile = controller.packet_tcp_profile('192.0.2.24', 20035, 20033)
        packet = profile['inputs']['cbpf']['af_packet']
        # Keys observed from the actual owned Controller template. These are
        # schema names only, not a copy of site configuration or credentials.
        supported = {'bond_interfaces', 'bpf_filter_disabled', 'extra_bpf_filter',
                     'inner_interface_capture_enabled', 'inner_interface_regex', 'interface_regex',
                     'skip_npb_bpf', 'src_interfaces', 'tunning'}
        self.assertLessEqual(set(packet), supported)
        self.assertNotIn('extra_netns_regex', packet)
        self.assertNotIn('vector', profile['inputs'])
        self.assertFalse(packet['inner_interface_capture_enabled'])
        self.assertEqual(packet['interface_regex'], '^lo$')

    def test_packet_mode_uses_new_tcp_identity_normal_features_and_restores(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'controller-events').mkdir(mode=0o700)
            controller.WORK = work
            api = FakeAPI()
            value = {'integration_mode': 'packet_tcp', 'run': 'tcp-' + '1' * 24,
                     'ctrl_ip': '172.29.0.2', 'ctrl_mac': '02:00:00:00:00:02',
                     'controller_ip': '192.0.2.24', 'controller_port': 20035, 'ingester_port': 20033,
                     'profile': controller.packet_tcp_profile('192.0.2.24', 20035, 20033)}
            for changes in [{'run': 'nh-' + '1' * 24}, {'LICENSE_FUNCTIONS': [11]}]:
                with self.assertRaises(RuntimeError):
                    controller.validate_metadata(dict(value, **changes))
            changed = copy.deepcopy(value)
            changed['profile']['inputs']['cbpf']['af_packet']['interface_regex'] = '.*'
            with self.assertRaises(RuntimeError):
                controller.validate_metadata(changed)
            with contextlib.redirect_stdout(io.StringIO()):
                controller.prepare(api, types.SimpleNamespace(check_keys=lambda *_: None), value)
                self.assertEqual(api.agents[0]['LICENSE_FUNCTIONS'], [2, 4, 5])
                controller.cleanup(api, {'run': value['run'], 'agent_stopped': True, 'owned_agent_removed': True})
            self.assertEqual(api.agents, [])
            self.assertEqual([g['LCUUID'] for g in api.groups], ['old-group'])

    def test_default_and_credential_url_are_side_effect_free(self):
        with mock.patch.object(agent, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(agent, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch.object(agent.MANAGED, 'verified_artifacts', side_effect=AssertionError('artifact')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            self.assertEqual(agent.main(['start', '--work', '/never-created']), 0)
            self.assertFalse(json.loads(stdout.getvalue())['starts_network'])
            with self.assertRaises((RuntimeError, ValueError)):
                agent.start(types.SimpleNamespace(controller_api='http://user:secret@127.0.0.1:20417'))

    def test_mixed_case_controller_short_uuid_is_accepted_without_case_rewrite(self):
        group = 'g-AbC123dEf'
        args = types.SimpleNamespace(controller_api='http://127.0.0.1:20417', group_id=group, agent_id=19,
                    controller_ip='192.0.2.24', controller_port=20035, ingester_port=20033,
                    artifacts=Path('/not-read'), work=Path('/never-created'))
        image = 'sha256:' + 'a' * 64
        def readback(endpoint, boot, profile, agent_id):
            self.assertEqual(boot['vtap-group-id-request'], group)
            self.assertEqual(agent_id, 19)
            raise RuntimeError('offline readback boundary reached')
        with mock.patch.object(agent.os, 'geteuid', return_value=0), \
                mock.patch.object(agent.os, 'uname', return_value=types.SimpleNamespace(machine='x86_64')), \
                mock.patch.object(agent, 'packet_tcp_profile', return_value={}), \
                mock.patch.object(agent.MANAGED, 'verified_artifacts', return_value=({'image_id': image}, Path('/agent'), Path('/libs'))), \
                mock.patch.object(agent.MANAGED, 'controller_readback', side_effect=readback) as checked, \
                mock.patch.object(agent, 'inspect', return_value={'Id': image}), \
                mock.patch.object(agent, 'private_dir', side_effect=AssertionError('unexpected output')):
            with self.assertRaisesRegex(RuntimeError, 'offline readback boundary reached'):
                agent.start(args)
            self.assertEqual(checked.call_count, 1)

    def test_actual_container_scope_is_net_raw_only_without_host_pid(self):
        spec = example_spec()
        info = example_info(spec)
        receipt = {'id': info['Id'], 'spec': spec}
        self.assertTrue(agent.owned(info, receipt))
        changes = [lambda v: v.update(Id='c' * 64), lambda v: v['HostConfig'].update(PidMode='host'),
                   lambda v: v['HostConfig'].update(CapAdd=['NET_RAW', 'SYS_ADMIN']),
                   lambda v: v['HostConfig'].update(Privileged=True),
                   lambda v: v['HostConfig'].update(ReadonlyRootfs=False),
                   lambda v: v['HostConfig'].update(PortBindings={'80/tcp': [{}]}),
                   lambda v: v['Mounts'][0].update(RW=True), lambda v: v['Config'].update(Cmd=['unrelated'])]
        for change in changes:
            changed = copy.deepcopy(info)
            change(changed)
            self.assertFalse(agent.owned(changed, receipt))

    def test_uncertain_create_is_recovered_only_by_exact_spec_and_stop_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            spec = example_spec()
            info = example_info(spec)
            receipt = {'schema': 'traflens.packet-tcp-agent.v1', 'output': str(work), 'spec': spec}
            agent.write(work / 'intent.json', receipt)
            with mock.patch.object(agent, 'inspect', return_value=info):
                recovered, _ = agent.recover(work)
            self.assertEqual(recovered['id'], info['Id'])
            foreign = copy.deepcopy(info)
            foreign['Id'] = 'c' * 64
            with mock.patch.object(agent, 'inspect', return_value=foreign), mock.patch.object(agent, 'call') as call:
                with self.assertRaises(RuntimeError):
                    agent.stop(work)
                call.assert_not_called()
            with mock.patch.object(agent, 'inspect', side_effect=RuntimeError('Docker unavailable')), mock.patch.object(agent, 'call') as call:
                with self.assertRaises(RuntimeError):
                    agent.stop(work)
                call.assert_not_called()

    def test_custom_prefix_mirrors_native_ret_transformation_without_broad_fallback(self):
        words = [[0x28, 0, 0, 12], [0x15, 0, 1, 0x0800], [0x06, 0, 0, 65535], [0x06, 0, 0, 0]]
        self.assertEqual(filters.native_custom_prefix(words), words[:2] + [[0x15, 1, 1, 0], [0x06, 0, 0, 0]])
        self.assertEqual(filters.native_custom_prefix([[0x06, 0, 0, 0], [0x06, 0, 0, 65535]]), [[0x06, 0, 0, 0]])
        for invalid in [[], [[0x06, 0, 0, 0]], [[0x20, 0, 0, 12], [0x06, 0, 0, 0]]]:
            with self.assertRaises(RuntimeError):
                filters.native_custom_prefix(invalid)

    def test_fixed_filter_compiles_offline_to_bounded_nonempty_prefix(self):
        if not ctypes.util.find_library('pcap'):
            self.skipTest('Host libpcap missing; actual ready is intentionally fail closed')
        prefix = filters.compile_prefix(controller.PACKET_TCP_FILTER)
        self.assertGreater(len(prefix), 4)
        self.assertLessEqual(len(prefix), 4096)
        self.assertTrue(any(row[0] & 7 == 6 and row[3] == 0 for row in prefix))

    def test_installed_forward_cfg_proves_lo_guard_for_native_bind_zero_shape(self):
        tail = [[0x20, 0, 0, 0xfffff008], [0x15, 1, 0, 1],
                [0x06, 0, 0, 0], [0x06, 0, 0, 128], [0x06, 0, 0, 65535]]
        words = [[0x00, 0, 0, 0]] + tail
        proof = filters.prove_lo_guard(words, 1)
        self.assertTrue(proof['effective_kernel_lo_only'])
        self.assertFalse(proof['non_lo_accept_reachable'])
        self.assertTrue(proof['load_ifindex_dominates_accept'])
        self.assertTrue(proof['lo_test_dominates_accept'])
        other = copy.deepcopy(words)
        other[-4][1] = 2
        self.assertTrue(filters.prove_lo_guard(other, 1)['effective_kernel_lo_only'])

    def test_interface_proof_rejects_bypass_extra_accept_wrong_interface_and_unknown_code(self):
        tail = [[0x20, 0, 0, 0xfffff008], [0x15, 1, 0, 1],
                [0x06, 0, 0, 0], [0x06, 0, 0, 128], [0x06, 0, 0, 65535]]
        invalid = [
            [[0x05, 0, 0, 3]] + tail,  # Jump straight to accepting RET.
            [[0x05, 0, 0, 1]] + tail,  # Bypass IFINDEX load into JEQ.
            [[0x06, 0, 0, 65535]] + tail,
            [[0x16, 0, 0, 0]] + tail,
            [[0xffff, 0, 0, 0]] + tail,
            [[0x05, 0, 0, 10000]] + tail,
        ]
        wrong = [[0x00, 0, 0, 0]] + copy.deepcopy(tail)
        wrong[-4][3] = 2
        invalid.append(wrong)
        for words in invalid:
            with self.assertRaises(RuntimeError):
                filters.prove_lo_guard(words, 1)

    def test_ready_failure_saves_private_stage_and_partial_filter_without_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            def failed(args, diagnostics):
                diagnostics.update(stage='actual_packet_filter', filter={'stage': 'verify_effective_lo_scope',
                    'sockets': [{'fd': 7, 'ifindex': 0, 'instruction_count': 6, 'filter_sha256': 'a' * 64}]})
                raise filters.FilterProofError('Installed accepting path bypasses actual lo interface guard')
            with mock.patch.object(agent, '_ready', side_effect=failed):
                with self.assertRaises(agent.ReadyFailure) as caught:
                    agent.ready(types.SimpleNamespace(work=work))
            self.assertEqual(caught.exception.stage, 'actual_packet_filter.verify_effective_lo_scope')
            files = list(work.glob('ready-failure-*.json'))
            self.assertEqual(len(files), 1)
            saved = json.loads(files[0].read_text())
            self.assertFalse(saved['passed'])
            self.assertFalse(saved['packet_payload_read'])
            self.assertEqual(saved['error_class'], 'FilterProofError')
            self.assertEqual(saved['reason_code'], 'installed_accepting_path_bypasses_actual_lo_interface_guard')
            self.assertEqual(saved['filter']['sockets'][0]['ifindex'], 0)
            self.assertFalse((work / 'packet-bpf-proof.json').exists())


if __name__ == '__main__':
    unittest.main()
