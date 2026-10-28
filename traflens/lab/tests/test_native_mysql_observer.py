"""Constructed header/receipt unit fixtures only; never starts native observation."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SOURCE = Path(__file__).resolve().parents[1]/'native-mysql-observer.py'
spec = importlib.util.spec_from_file_location('native_mysql_observer', SOURCE)
M = importlib.util.module_from_spec(spec)
spec.loader.exec_module(M)
IDENTITIES = {101: ('server', 'mysqld'), 102: ('client', 'traflens-mysql')}


def header(seq=0, pid=101, tid=None, socket=9007199254740999, cap=1, close=False, proto='MySQL'):
    role, comm = IDENTITIES.get(pid, ('server', 'foreign-process'))
    tuple_text = 'Unknow 0.0.0.0.0 > 0.0.0.0.0' if close else 'TCP 127.0.0.1.49152 > 127.0.0.2.18080'
    return (f'2026-10-29 00:00:00 [datadump] SEQ {seq} <{proto}> DIR in TYPE unknown({10 if close else 12}) '
            f'PID {pid} THREAD_ID {tid or pid} COROUTINE_ID 0 FD 3 ROLE {"unknown" if close else role} '
            f'CONTAINER_ID null SOURCE 0 COMM {comm} {tuple_text} LEN {0 if close else 11} '
            f'SYSCALL_LEN {0 if close else 11} SOCKET_ID {socket} TRACE_ID 0 TCP_SEQ 123 DATA_SEQ {cap} '
            'TLS false SyscallTime 2026-10-29 00:00:00.001 SyscallMonoTime 123456789 us '
            'CapTime 2026-10-29 00:00:00.002 CapMonoTime 123456790 us')


def tracer(lost=0):
    return ('Tracer             socket-trace\nWorkers            1\n'
            f'Events Lost        {lost}\n'
            'worker 0 for queue, de 10 en 11 lost 2 alloc failed 3 burst 4 queue size 1 cap 64\n'
            'SUM dequeue 10 enqueue 11 lost 2 alloc failed 3 burst count 4\n')


def constructed_capture(folder, diagnostic=False, fast=False):
    """Only synthetic local unit documents; never runtime/native qualification."""
    root = Path(folder)
    run = 'my-'+'a'*24
    schema = 'traflens.ebpf-mysql'+('-fast' if fast else '-diagnostic' if diagnostic else '')
    cid = 'a'*64
    anchor = 'b'*64
    def write(path, value):
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(json.dumps(value));path.chmod(0o600)
    write(root/'state.json', {'schema': schema+'.capture.v1', 'output': str(root), 'run': run})
    binary = root/'constructed-never-execute'
    binary.write_bytes(b'unit-test binary bytes; never executed');binary.chmod(0o700)
    scope = {'schema': schema+'.scope.v1', 'agent_container_id': cid,
             'positive': {'inode': 11, 'netns': 'net:[11]', 'container_id': anchor}}
    write(root/'scope-runtime.json', scope)
    runtime_folder = root/'agent/runtime-unit'
    current = {'id': cid, 'folder': str(runtime_folder), 'binary_sha256': 'd'*64,
               'source': '3dec20af5ce6ff25c696d136b5477f5310b4962c'}
    write(root/'agent/current.json', current)
    # Field names match the original R21 proof, not a synthetic replacement schema.
    proof = {'agent_container_id': cid, 'agent_binary_sha256': current['binary_sha256'],
             'source_commit': current['source'], 'af_packet_socket_count': 0,
             'agent_pid': 100, 'agent_scope_fds': [5], 'scope_map': {'constructed_unit_value': True}}
    proof.update({k: True for k in ['scope_fd_pinned', 'safe_profile_verified',
                                  'native_collector_started', 'fresh_three_listener_sync']})
    write(runtime_folder/'coordinator-scope-proof.json', proof)
    for pid, (role, comm) in IDENTITIES.items():
        name = 'positive-'+role
        process = {'role': role, 'run': run, 'pid': pid, 'tid': pid, 'start_ticks': '42',
                   'netns': 'net:[11]', 'pidns': 'pid:[1]', 'comm': comm, 'single_threaded': True,
                   'wire_fixture': True, 'sql_executed': False}
        labels = {'io.traflens.purpose': schema+'.worker', 'io.traflens.run': run,
                  'io.traflens.role': name, 'io.traflens.output': str(root)}
        mounts = [[str(binary), '/workload', False], [str(root/name), '/output', True]]
        actual = {k: process[k] for k in ['pid', 'start_ticks', 'netns', 'pidns', 'comm']}
        actual.update({'running': True, 'id': ('e' if role == 'server' else 'f')*64,
                       'pid_mode': 'host', 'network_mode': 'container:'+anchor, 'mounts': mounts,
                       'labels': labels, 'executable_sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
        runtime = {'schema': schema+'.worker-runtime.v1', 'role': name, 'scope_role': 'positive',
                   'run': run, 'workload_run': run, 'scope_receipt': 'scope-runtime.json',
                   'agent_container_id': cid, 'create': {'normalized': {'mounts': mounts, 'labels': labels}},
                   'inspect': actual}
        write(root/name/'process.json', process);write(root/(name+'-runtime.json'), runtime)
    return root, cid, scope


class NativeObserverTests(unittest.TestCase):
    def test_default_plan_no_io_or_native_execution(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(SOURCE)], cwd=folder, check=True,
                                    capture_output=True, text=True, timeout=3)
            plan = json.loads(result.stdout)
            self.assertFalse(plan['executes_commands'])
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertIn('Agent stdout', plan['dump_destination'])

    def test_plan_preserves_close_and_targets_only_exact_container(self):
        plan = M.command_plan('a'*64, 30)
        self.assertEqual(plan['start'], ['docker', 'exec', 'a'*64, '/usr/bin/deepflow-ebpfctl',
                                        'datadump', 'on', '--only-stdout', '--timeout', '30'])
        self.assertEqual(plan['set'][4:], ['datadump', 'set', '--pid', '0', '--comm', '', '--l7-proto', '0', '--port', '0'])
        self.assertEqual(plan['stop'][-2:], ['datadump', 'off'])
        self.assertFalse(plan['execution_cpu_available'])
        for cid, duration in [('short', 30), ('a'*64, 31), ('a'*64, 0)]:
            with self.assertRaises(ValueError): M.command_plan(cid, duration)

    def test_real_decimal_precision_and_only_anonymous_metadata_is_retained(self):
        events, counts = M.parse_datadump(header(), IDENTITIES)
        self.assertEqual(events[0]['socket_id'], '9007199254740999')
        self.assertEqual(events[0]['syscall_mono_us'], '123456789')
        self.assertEqual(events[0]['execution_cpu'], None)
        self.assertNotIn('127.0.0.', json.dumps(events))
        self.assertNotIn('PID', json.dumps(events))
        self.assertEqual(counts['data_records'], 1)
        self.assertFalse(counts['scope_or_storage_completeness_proved'])

    def test_actual_observed_first_cap_zero_is_a_legal_socket_start(self):
        # Constructed anonymous header reproduces the observed numeric shape;
        # it is not a substitute for the retained private runtime evidence.
        first = header(cap=0).replace('DIR in', 'DIR out').replace('unknown(12)', 'unknown(7)')
        first = first.replace('TCP 127.0.0.1.49152 > 127.0.0.2.18080', 'TCP 127.0.0.2.18080 > 127.0.0.1.49152')
        first = first.replace('LEN 11 SYSCALL_LEN 11', 'LEN 78 SYSCALL_LEN 78')
        events, counts = M.parse_datadump(first, IDENTITIES)
        self.assertEqual(events[0]['cap_seq'], '0')
        self.assertEqual(events[0]['capture_bytes'], 78)
        self.assertEqual(events[0]['msg_type'], 7)
        self.assertEqual(counts['data_records'], 1)

    def test_legal_zero_cap_never_accepts_negative_cap_or_discontinuous_print_sequence(self):
        for value in [header(cap=-1), header(cap=0)+'\n'+header(2, cap=1)]:
            with self.assertRaises(ValueError): M.parse_datadump(value, IDENTITIES)

    def test_close_zero_tuple_is_bound_after_all_data_and_uid0_is_count_only(self):
        text = '\n'.join([header(0, cap=2, close=True), header(1, cap=1),
                          header(2, socket=0, cap=0, close=True, proto='Unknown')])
        events, counts = M.parse_datadump(text, IDENTITIES)
        self.assertEqual(len(events), 2)
        self.assertEqual(counts['anonymous_unknown_uid0_close_count'], 1)
        self.assertEqual(counts['close_without_prior_printed_data'], 1)
        self.assertEqual(counts['apparent_per_socket_cap_seq_backtracks'], 1)
        self.assertTrue(events[0]['is_close'])

    def test_unbound_nonzero_close_is_only_counted_not_persisted(self):
        events, counts = M.parse_datadump(header(close=True), IDENTITIES)
        self.assertEqual(events, [])
        self.assertEqual(counts['anonymous_unbound_nonzero_close_count'], 1)

    def test_unowned_or_unsupported_headers_fail_without_echoing_input(self):
        for value in [header(pid=999), header(tid=103), header(proto='DNS'),
                      header().replace('18080', '3306'), header().replace('SOURCE 0', 'SOURCE 3'),
                      header().replace('LEN 11 SYSCALL_LEN 11', 'LEN 10 SYSCALL_LEN 11')]:
            with self.assertRaises(ValueError) as caught: M.parse_datadump(value, IDENTITIES)
            self.assertNotIn('127.', str(caught.exception))
            self.assertNotIn('foreign-process', str(caught.exception))

    def test_no_empty_gap_reset_overflow_or_malformed_header_success(self):
        for value in ['', header(1), header()+'\n'+header(), header().replace('SOCKET_ID', 'BAD_ID')]:
            with self.assertRaises(ValueError): M.parse_datadump(value, IDENTITIES)
        with mock.patch.object(M, 'MAX_RECORDS', 1):
            with self.assertRaises(ValueError): M.parse_datadump(header()+'\n'+header(1), IDENTITIES)

    def test_tracer_show_all_queues_and_actual_resettable_counters(self):
        snapshot = M.parse_tracer(tracer(7))
        self.assertEqual(snapshot['perf_lost_snapshot'], 7)
        self.assertEqual(snapshot['totals'], {'dequeue': 10, 'enqueue': 11, 'lost': 2, 'alloc_failed': 3, 'burst': 4})
        self.assertIn('not cumulative', snapshot['semantics'])
        for text in ['', tracer().replace('SUM dequeue 10', 'SUM dequeue 9'),
                     tracer().replace('Workers            1', 'Workers            2')]:
            with self.assertRaises(ValueError): M.parse_tracer(text)

    def test_stream_discards_original_payload_and_retains_only_owned_header_metadata(self):
        raw = (header()+'\nOWNED-MOCK-PAYLOAD-NEVER-PERSIST\n'+header(1, cap=2, close=True)+'\n').encode()
        read, write = os.pipe()
        os.write(write, raw);os.close(write)
        with os.fdopen(read, 'rb') as stream, mock.patch.object(M, 'roster', return_value=(IDENTITIES, {'constructed_roster': 'unit-test'})):
            events, counts, hashes, observed, error = M.stream_metadata(stream, Path('/unused'), 'a'*64, {}, 1)
        self.assertEqual(error, '')
        self.assertEqual(observed['agent_stdout_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertFalse(observed['original_stdout_or_payload_saved'])
        self.assertEqual(counts['data_records'], 1)
        self.assertNotIn('OWNED-MOCK', json.dumps(events))
        self.assertNotIn('127.', json.dumps(events))

    def test_stream_excludes_unowned_metadata_and_keeps_prior_owned_prefix_on_failure(self):
        raw = (header()+'\n'+header(1, pid=999)+'\n').encode()
        read, write = os.pipe();os.write(write, raw);os.close(write)
        with os.fdopen(read, 'rb') as stream, mock.patch.object(M, 'roster', return_value=(IDENTITIES, {})):
            events, _, _, _, error = M.stream_metadata(stream, Path('/unused'), 'a'*64, {}, 1)
        self.assertIn('unowned process', error)
        self.assertEqual(len(events), 1)
        self.assertNotIn('"pid"', json.dumps(events))
        self.assertNotIn('foreign-process', json.dumps(events))

    def test_explicit_old_and_diagnostic_actual_runtime_binding(self):
        for diagnostic in [False, True]:
            with tempfile.TemporaryDirectory() as folder:
                root, cid, original_scope = constructed_capture(folder, diagnostic)
                scope, proof_hashes = M.capture_binding(root, cid)
                self.assertEqual(scope, original_scope)
                self.assertIn('coordinator_scope_proof', proof_hashes)
                identities, hashes = M.roster(root, cid, scope)
                self.assertEqual(identities, IDENTITIES)
                self.assertIn('positive-client_runtime', hashes)
                path = root/'positive-server-runtime.json'
                runtime = json.loads(path.read_text())
                runtime['inspect']['labels']['io.traflens.purpose'] = 'traflens.ebpf-mysql.worker' if diagnostic else 'wrong-purpose'
                path.write_text(json.dumps(runtime))
                with self.assertRaises(ValueError): M.roster(root, cid, scope)

    def test_diagnostic_never_falls_back_to_old_worker_schema_or_suffix_match(self):
        with tempfile.TemporaryDirectory() as folder:
            root, cid, scope = constructed_capture(folder, True)
            path = root/'positive-server-runtime.json'
            runtime = json.loads(path.read_text())
            runtime['schema'] = 'traflens.ebpf-mysql.worker-runtime.v1'
            path.write_text(json.dumps(runtime))
            with self.assertRaises(ValueError): M.roster(root, cid, scope)
            state = json.loads((root/'state.json').read_text())
            for schema in ['prefix.'+state['schema'], state['schema']+'.extra', 'traflens.ebpf-dns.capture.v1']:
                with self.assertRaises(ValueError): M.capture_contract(dict(state, schema=schema), root)

    def test_fast_has_its_own_exact_scope_worker_and_purpose_without_fallback(self):
        with tempfile.TemporaryDirectory() as folder:
            root, cid, original_scope = constructed_capture(folder, fast=True)
            scope, _ = M.capture_binding(root, cid)
            self.assertEqual(scope, original_scope)
            self.assertEqual(M.roster(root, cid, scope)[0], IDENTITIES)
            path = root/'positive-server-runtime.json'
            original = json.loads(path.read_text())
            for field, value in [('schema', 'traflens.ebpf-mysql.worker-runtime.v1'),
                                 ('schema', 'traflens.ebpf-mysql-diagnostic.worker-runtime.v1')]:
                changed = json.loads(json.dumps(original));changed[field] = value
                path.write_text(json.dumps(changed))
                with self.assertRaises(ValueError): M.roster(root, cid, scope)
            changed = json.loads(json.dumps(original))
            changed['inspect']['labels']['io.traflens.purpose'] = 'traflens.ebpf-mysql-diagnostic.worker'
            path.write_text(json.dumps(changed))
            with self.assertRaises(ValueError): M.roster(root, cid, scope)
            for suffix in ['.extra', '-extra']:
                state = json.loads((root/'state.json').read_text())
                state['schema'] += suffix
                with self.assertRaises(ValueError): M.capture_contract(state, root)

    def test_first_unowned_uid0_close_requires_no_roster_and_saves_only_anonymous_count(self):
        raw = (header(0, pid=999, socket=0, cap=0, close=True, proto='Unknown')+'\n'+header(1)+'\n').encode()
        read, write = os.pipe();os.write(write, raw);os.close(write)
        with os.fdopen(read, 'rb') as stream, mock.patch.object(M, 'roster', return_value=(IDENTITIES, {})) as lookup:
            events, counts, _, _, error = M.stream_metadata(stream, Path('/unused'), 'a'*64, {}, 1)
        self.assertEqual(error, '')
        lookup.assert_called_once()
        self.assertEqual(counts['anonymous_unknown_uid0_close_count'], 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['print_sequence'], 1)
        self.assertNotIn('foreign-process', json.dumps(events))
        self.assertNotIn('"pid"', json.dumps(events))


if __name__ == '__main__':
    unittest.main()
