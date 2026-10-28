"""Offline public TCP orchestration guards; no sockets or collection start."""
import argparse
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
SPEC = importlib.util.spec_from_file_location('tcp_coordinator_tested', LAB / 'tcp-connections.py')
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def state_fixture(work):
    return {'schema': runtime.SCHEMA, 'run': 'tcp-' + '1' * 24, 'negative_run': 'tcp-' + '2' * 24,
            'output': str(work), 'fixtures': {}, 'controller_attempted': True, 'agent_attempted': True}


def stopped_proof():
    return {key: True for key in ('agent_stopped', 'container_removed', 'bpf_inventory_restored',
                                 'tracefs_restored', 'lo_identity_and_flags_restored')}


class TCPConnectionsRuntime(unittest.TestCase):
    def test_default_plan_never_reads_artifacts_or_uses_tools(self):
        with mock.patch.object(runtime.CORE, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(runtime.CORE, 'helper_hashes', side_effect=AssertionError('SSH')), \
                mock.patch.object(runtime, 'private_dir', side_effect=AssertionError('output')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as output:
            self.assertEqual(runtime.main(['run', '--work', '/not-created']), 0)
            plan = json.loads(output.getvalue())
            self.assertFalse(plan['execute'])
            self.assertFalse(plan['starts_network'])
            self.assertEqual(plan['positive_ports'], [18081, 18082, 18083])
            self.assertEqual(plan['negative_ports'], [18084, 18085, 18086])
            self.assertEqual(plan['natural_drain_seconds'], 50)

    def test_fixed_natural_drain_records_start_and_completion_without_timeout_changes(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            events = []
            with mock.patch.object(runtime.time, 'time_ns', side_effect=[100, 200]), \
                    mock.patch.object(runtime.time, 'sleep') as sleep, \
                    mock.patch.object(runtime, 'persist', side_effect=lambda w, s: (w / 'state.json').write_text(json.dumps(s))), \
                    mock.patch.object(runtime.CORE, 'event', side_effect=lambda w, name, value: events.append((name, dict(value)))):
                runtime.natural_drain(work, state)
            sleep.assert_called_once_with(50)
            self.assertEqual(state['natural_drain'], {'seconds': 50, 'started_unix_ns': 100, 'completed_unix_ns': 200})
            self.assertEqual(events[0], ('natural-drain-started', {'seconds': 50, 'started_unix_ns': 100}))
            self.assertEqual(events[1], ('natural-drain-completed', state['natural_drain']))
            self.assertEqual(json.loads((work / 'state.json').read_text())['natural_drain'], state['natural_drain'])

    def test_credential_or_nonloopback_controller_is_rejected_before_output(self):
        with mock.patch.object(runtime.CORE, 'helper_hashes', side_effect=AssertionError('SSH')), \
                mock.patch.object(runtime, 'private_dir', side_effect=AssertionError('output')):
            for endpoint in ['http://user:secret@127.0.0.1:20417', 'http://127.0.0.1:20417?token=secret', 'http://192.0.2.1:20417']:
                with self.assertRaises((RuntimeError, ValueError)):
                    runtime.execute(argparse.Namespace(controller_url=endpoint))

    def test_fixture_nonces_ports_and_complete_socket_receipts_remain_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            calls = []
            def spawned(directory, name, argv):
                calls.append((name, argv))
                output = Path(argv[argv.index('--output') + 1])
                output.mkdir(mode=0o700)
                receipt = {'run': argv[argv.index('--run') + 1], 'pass': True, 'expected_connections': 3,
                    'source': 'actual Python stdlib/Linux TCP sockets', 'synthetic_tcp_packets': False,
                    'thread_errors': [], 'owned_sockets_closed': True, 'owned_threads_exited': True,
                    'completed': {key: True for key in runtime.COMPLETED}}
                runtime.CORE.write(output / 'receipt.json', receipt)
                return types.SimpleNamespace(wait=lambda timeout: 0)
            with mock.patch.object(runtime.CORE, 'spawn', side_effect=spawned):
                runtime.fixture(work, state, 'negative')
                runtime.fixture(work, state, 'positive')
            self.assertEqual([name for name, _ in calls], ['fixture-negative', 'fixture-positive'])
            for phase, (_, argv), ports in zip(['negative', 'positive'], calls, [(18084, 18085, 18086), (18081, 18082, 18083)]):
                self.assertEqual(argv[argv.index('--run') + 1], state['fixtures'][phase]['run'])
                self.assertEqual([int(argv[argv.index('--' + kind + '-port') + 1]) for kind in ('normal', 'reset', 'refused')], list(ports))
                self.assertTrue(state['fixtures'][phase]['completed'])
            self.assertNotEqual(state['fixtures']['negative']['run'], state['fixtures']['positive']['run'])
            # Exit0 and a nominal pass are insufficient without every actual
            # socket/thread completion result.
            receipt = json.loads((work / 'positive/receipt.json').read_text())
            receipt['owned_sockets_closed'] = False
            (work / 'positive/receipt.json').write_text(json.dumps(receipt))
            with mock.patch.object(runtime.CORE, 'spawn', return_value=types.SimpleNamespace(wait=lambda timeout: 0)):
                with self.assertRaises(RuntimeError):
                    runtime.fixture(work, state, 'positive')

    def test_cleanup_orders_fixture_exit_then_actual_packet_restore_then_controller_forward(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'packet-agent').mkdir(mode=0o700)
            runtime.CORE.write(work / 'packet-agent/intent.json', {})
            state = state_fixture(work)
            order = []
            def packet_stop(directory, name, argv, timeout):
                self.assertEqual(name, 'packet-agent-stop')
                self.assertEqual(argv[2:4], ['stop', '--execute'])
                self.assertGreaterEqual(timeout, 160)
                runtime.CORE.write(work / 'packet-agent/stopped.json', stopped_proof())
                order.append('packet-restored')
            def backend(s, action, proof):
                self.assertEqual(action, 'cleanup')
                self.assertTrue(proof['agent_stopped'])
                self.assertFalse(proof['collector_never_started'])
                order.append('controller-cleaned')
            with mock.patch.object(runtime.CORE, 'stop_process', side_effect=lambda w, name: order.append(name)), \
                    mock.patch.object(runtime.CORE, 'find_process', return_value=None), \
                    mock.patch.object(runtime.CORE, 'logged', side_effect=packet_stop), \
                    mock.patch.object(runtime.CORE, 'backend', side_effect=backend):
                result = runtime.cleanup(work, state)
            self.assertTrue(result['cleaned'])
            self.assertEqual(order, ['fixture-positive', 'fixture-negative', 'packet-restored', 'controller-cleaned', 'forward'])

    def test_unproven_fixture_identity_retains_capture_and_registration(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            state = state_fixture(work)
            with mock.patch.object(runtime.CORE, 'stop_process', side_effect=RuntimeError('PID identity changed')) as stop, \
                    mock.patch.object(runtime.CORE, 'logged') as packet, \
                    mock.patch.object(runtime.CORE, 'backend') as backend:
                result = runtime.cleanup(work, state)
            self.assertFalse(result['cleaned'])
            self.assertFalse(result['collector_stopped'])
            packet.assert_not_called()
            backend.assert_not_called()
            self.assertNotIn('forward', [c.args[1] for c in stop.call_args_list])

    def test_missing_packet_restore_field_prevents_controller_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            (work / 'packet-agent').mkdir(mode=0o700)
            runtime.CORE.write(work / 'packet-agent/intent.json', {})
            proof = stopped_proof()
            proof['bpf_inventory_restored'] = False
            runtime.CORE.write(work / 'packet-agent/stopped.json', proof)
            state = state_fixture(work)
            with mock.patch.object(runtime.CORE, 'stop_process') as stop, \
                    mock.patch.object(runtime.CORE, 'find_process', return_value=None), \
                    mock.patch.object(runtime.CORE, 'logged'), \
                    mock.patch.object(runtime.CORE, 'backend') as backend:
                result = runtime.cleanup(work, state)
            self.assertFalse(result['cleaned'])
            self.assertFalse(result['collector_stopped'])
            backend.assert_not_called()
            self.assertNotIn('forward', [c.args[1] for c in stop.call_args_list])


if __name__ == '__main__':
    unittest.main()
