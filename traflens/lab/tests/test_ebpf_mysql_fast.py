"""Offline explicit fast contracts; no Docker, collector, network or fixture executes."""
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


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, LAB/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


F = load('explicit_fast_runtime_tested', 'ebpf-mysql-fast.py')
V = load('explicit_fast_verifier_tested', 'verify-ebpf-mysql-fast.py')
from test_ebpf_mysql_runtime import receipt as paced_receipt, state as original_state
from test_ebpf_mysql_acceptance import fixture, paced_fixture, expected_observations, native_rows, table
from test_ebpf_mysql_diagnostic import binding, observer_fixture
RUN = 'my-'+'1'*24


def unpaced_receipt():
    value = paced_receipt(RUN, 'client')
    for key in ('pacing_only_qualification', 'pacing_ms', 'pacing_waits', 'pacing_duration_ns', 'waits_sha256'):
        value.pop(key)
    value.update(wire_data_events=18, tcp_eof_events=3)
    return value


class ExplicitFastRuntimeTests(unittest.TestCase):
    def test_offline_run_and_ack_never_touch_files_or_resources(self):
        with mock.patch.object(F.CORE, 'file_hash', side_effect=AssertionError('artifact read')), \
                mock.patch.object(F.CORE, 'inspect', side_effect=AssertionError('Docker')), \
                mock.patch.object(F.RUNTIME, 'execute', side_effect=AssertionError('execution')):
            for args in ([], ['run', '--work', '/not-created'], ['ack', '--stage', 'before-first-wire']):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(F.main(args), 0)
                value = json.loads(output.getvalue())
                self.assertTrue(value['unpaced_fast_candidate'])
                self.assertFalse(value.get('starts_network', False))
                self.assertFalse(value.get('writes_files', False))

    def test_fixed_fast_contract_does_not_change_paced_dns_or_diagnostic_defaults(self):
        self.assertEqual(F.SCHEMA, 'traflens.ebpf-mysql-fast.capture.v1')
        self.assertEqual(F.CONTRACT.role_schema, 'traflens.ebpf-mysql-fast.worker-runtime.v1')
        self.assertEqual(F.PURPOSE, 'traflens.ebpf-mysql-fast.worker')
        self.assertTrue(F.CONTRACT.fast)
        self.assertFalse(F.DIAGNOSTIC.CONTRACT.fast)
        self.assertFalse(F.DIAGNOSTIC.PACED.CONTRACT.fast)
        self.assertFalse(F.RUNTIME.DNS_CONTRACT.fast)
        self.assertEqual(F.DIAGNOSTIC.CONTRACT.script, 'ebpf-mysql-diagnostic.py')
        self.assertEqual(F.DIAGNOSTIC.PACED.CONTRACT.script, 'ebpf-mysql.py')
        with self.assertRaises(AttributeError): F.CONTRACT.fast = False
        with self.assertRaises(RuntimeError):
            F.RUNTIME.validate_contract(F.RUNTIME.DNS_CONTRACT._replace(fast=True))

    def test_fast_receipt_is_strictly_unpaced_and_never_uses_paced_validator(self):
        value = unpaced_receipt()
        with mock.patch.object(F.DIAGNOSTIC.PACED, 'validate_receipt', side_effect=AssertionError('paced validator')):
            F.validate_receipt(value, RUN, 'client')
        for field, extra in [('pacing_ms', 0), ('pacing_only_qualification', False), ('pacing_waits', 0),
                             ('pacing_duration_ns', 0), ('waits_sha256', 'a'*64), ('wire_data_events', 17), ('tcp_eof_events', 2)]:
            changed = dict(value); changed[field] = extra
            with self.assertRaises(RuntimeError, msg=field): F.validate_receipt(changed, RUN, 'client')
        with self.assertRaises(RuntimeError): F.validate_receipt(paced_receipt(RUN, 'client'), RUN, 'client')

    def test_preflight_pins_original_unpaced_artifacts_and_refuses_old_native(self):
        args = types.SimpleNamespace(workload_sha256=F.ARCHIVED_ARTIFACT_SHA256,
            workload_source='/owned/original.c', observer_timeout_seconds=30, artifacts='/owned/new/prepared.json')
        artifact = {'source': 'c'*40, 'binary_sha256': 'd'*64}
        agent = types.SimpleNamespace(verified_artifacts=mock.Mock(return_value=(artifact, None, None)))
        with mock.patch.object(F.CORE, 'file_hash', return_value=F.ARCHIVED_SOURCE_SHA256), \
                mock.patch.object(F.RUNTIME, 'module', return_value=agent):
            F.preflight(args)
            for key, bad in [('source', F.OLD_NATIVE_SOURCE), ('binary_sha256', F.OLD_NATIVE_SHA256)]:
                previous = artifact[key];artifact[key] = bad
                with self.assertRaises(RuntimeError): F.preflight(args)
                artifact[key] = previous
            changed = copy.copy(args);changed.workload_sha256 = 'a'*64
            with self.assertRaises(RuntimeError): F.preflight(changed)
        with mock.patch.object(F.CORE, 'file_hash', side_effect=AssertionError('unsafe URL must fail first')):
            with self.assertRaises((ValueError, RuntimeError)):
                F.RUNTIME.execute(types.SimpleNamespace(controller_url='http://u:p@127.0.0.1:20417'), F.CONTRACT)

    def test_fast_workers_keep_original_network_pid_command_and_minimum_limits(self):
        state = original_state(Path('/owned/fresh'))
        state['schema'] = F.SCHEMA
        spec = F.RUNTIME.worker_spec(state, 'positive-server', F.CONTRACT)
        self.assertEqual(spec['network_mode'], 'container:'+state['scope']['positive']['container_id'])
        self.assertEqual(spec['pid_mode'], 'host')
        self.assertEqual(spec['labels']['io.traflens.purpose'], F.PURPOSE)
        self.assertEqual(spec['command'], ['--execute', '--role', 'server', '--run', state['run'],
                         '--output', '/output', '--seconds', '90', '--port', '18080'])
        self.assertEqual((spec['nano_cpus'], spec['memory_bytes'], spec['pids_limit']), (500000000, 67108864, 16))
        self.assertTrue(spec['read_only']);self.assertEqual(spec['cap_drop'], ['ALL'])

    def test_fast_ack_uses_explicit_schema_and_cannot_ack_old_diagnostic_state(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); folder, request, _ = observer_fixture(root)
            with mock.patch.object(F.DIAGNOSTIC, 'live_agent_binding', return_value=(binding(), {})):
                with self.assertRaises(RuntimeError):
                    F.DIAGNOSTIC.acknowledge(root, 'before-first-wire', F.CONTRACT)
                state = F.CORE.read(root/'state.json');state['schema'] = F.SCHEMA
                F.CORE.write(root/'state.json', state, True)
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(F.main(['ack', '--execute', '--work', str(root), '--stage', 'before-first-wire']), 0)
            self.assertTrue((folder/'ack.json').is_file())


class ExplicitFastAcceptanceTests(unittest.TestCase):
    def test_default_oracle_plan_never_reads_or_queries(self):
        with mock.patch.object(V.BASE, 'read_file', side_effect=AssertionError('file read')), \
                mock.patch.object(V.BASE, 'Client', side_effect=AssertionError('network')), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(V.main([]), 0)
        plan = json.loads(output.getvalue())
        self.assertTrue(plan['unpaced_fast_contract']);self.assertFalse(plan['unpaced_completeness_proven'])
        self.assertEqual((plan['max_rows'], plan['max_requests'], plan['total_seconds']), (64, 48, 60))

    def test_actual_new_native_identity_is_mandatory_for_fast_acceptance(self):
        V.BASE.validate_acceptance_contract(V.CONTRACT)
        with self.assertRaises(ValueError): V.BASE.validate_acceptance_contract(V.CONTRACT, True)
        new = V.CONTRACT._replace(native_source='a'*40, native_sha256='b'*64)
        V.BASE.validate_acceptance_contract(new, True)
        for contract in (new._replace(native_source=V.BASE.OLD_NATIVE_SOURCE),
                         new._replace(native_sha256=V.BASE.OLD_NATIVE_SHA256),
                         new._replace(native_source='test-executable')):
            with self.assertRaises(ValueError): V.BASE.validate_acceptance_contract(contract, True)
        self.assertEqual(V.BASE.DEFAULT_CONTRACT.stem, 'mysql')

    def test_full_unpaced_wire_is_independently_checked_and_pacing_or_fake_waits_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); folder = root/'positive-client'
            process, receipt, events = fixture(folder)
            V.BASE.workload_oracle(folder, 'positive-client', process['run'])
            V.BASE.require_unpaced_workload(folder, process, receipt)
            (folder/'waits.jsonl').write_text('')
            with self.assertRaises(ValueError): V.BASE.require_unpaced_workload(folder, process, receipt)
            (folder/'waits.jsonl').unlink()
            events[0]['wire_hex'] = '00'
            (folder/'wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            with self.assertRaises(ValueError): V.BASE.workload_oracle(folder, 'positive-client', process['run'])
            paced = root/'paced'; p, r, _, _, _ = paced_fixture(paced)
            with self.assertRaises(ValueError): V.BASE.require_unpaced_workload(paced, p, r)

    def test_whole_population_still_requires_all18_and_rejects_historical_orphan_or_missing_quit(self):
        expected = expected_observations(); rows = native_rows(expected)
        count = table([{'records': 18}], ['records'])
        actual, _, _ = V.BASE.native_population(count, table(rows), expected, 14, 1700000000, 1700000002)
        self.assertEqual(len(actual), 18)
        missing = [r for r in rows if not (r['tap_side']=='s-p' and r['request_type']=='COM_QUIT' and r['client_port']==30001)]
        with self.assertRaises(ValueError):
            V.BASE.native_population(table([{'records': 17}], ['records']), table(missing), expected, 14, 1700000000, 1700000002)
        orphan = copy.deepcopy(rows);orphan[0].update(type=0, response_status=5)
        with self.assertRaises(ValueError): V.BASE.native_population(count, table(orphan), expected, 14, 1700000000, 1700000002)


if __name__ == '__main__':
    unittest.main()
