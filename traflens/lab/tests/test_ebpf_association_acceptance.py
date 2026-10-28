"""Offline acceptance-oracle adversarial checks; no capture/query/container."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-ebpf-association.py'
if not SCRIPT.is_file():
    SCRIPT = Path(__file__).with_name('verify-ebpf-association.py')
spec = importlib.util.spec_from_file_location('ebpf_acceptance', SCRIPT)
v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(v)
RUN = 'nh-' + 'a' * 24


def example():
    expected, rows, counter = [], [], 100
    for ci, chain in enumerate(('main', 'control')):
        for role, stage, side, client_ip, client_port, server_ip, pid in [
                ('generate', 'root-request', 'c-p', '127.0.0.1', 30000+ci, '127.0.0.2', 101),
                ('frontend', 'incoming-request', 's-p', '127.0.0.1', 30000+ci, '127.0.0.2', 102),
                ('frontend', 'outgoing-request', 'c-p', '127.0.0.2', 40000+ci, '127.0.0.3', 102),
                ('backend', 'incoming-request', 's-p', '127.0.0.2', 40000+ci, '127.0.0.3', 103)]:
            downstream = stage == 'outgoing-request' or role == 'backend'
            expected.append(dict(chain=chain, role=role, stage=stage, side=side,
                tuple=(client_ip, client_port, server_ip, 18080), pid=pid, tid=pid))
            row = dict.fromkeys(v.COLUMNS, 0)
            counter += 1
            row.update(id=str(counter), start_us='100000000', end_us='100100000', agent_id=22, signal_source=3,
                type=2, protocol=6, l7_protocol=20, tap_side=side, l3_epc_id_0=-1, l3_epc_id_1=-1,
                ip_0=client_ip, ip_1=server_ip, client_port=client_port, server_port=18080,
                req_tcp_seq=1000+ci*10+int(downstream), resp_tcp_seq=2000+ci*10+int(downstream),
                syscall_trace_id_request=str(3000+ci*10+(0 if role=='frontend' else pid)),
                syscall_trace_id_response=str(4000+ci*10+(0 if role=='frontend' else pid)),
                process_id_0=pid if side=='c-p' else 0, process_id_1=pid if side=='s-p' else 0,
                syscall_thread_0=pid, syscall_thread_1=pid, flow_id=str(5000+ci*10+int(downstream)),
                request_resource='/traflens-no-header/%s/%s' % (RUN, chain), trace_id='', span_id='', parent_span_id='')
            rows.append(row)
    document = {'columns': v.COLUMNS, 'values': [[row[k] for k in v.COLUMNS] for row in rows]}
    count = {'columns': ['records'], 'values': [[8]]}
    return expected, rows, document, count


class AcceptanceTests(unittest.TestCase):
    def test_default_plan_has_no_file_or_network_side_effect(self):
        with tempfile.TemporaryDirectory() as directory:
            completed = subprocess.run([sys.executable, str(SCRIPT), '--capture-dir', '/does-not-exist',
                '--query-base', 'http://example.invalid', '--output', directory+'/unused'], cwd=directory,
                check=True, capture_output=True, text=True, timeout=3)
            plan = json.loads(completed.stdout)
            self.assertFalse(plan['reads_files'])
            self.assertFalse(plan['starts_network'])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_actual_header_bytes_hashes_and_whitelist(self):
        header = 'GET /traflens-no-header/%s/main HTTP/1.1\r\nHost: 127.0.0.2:18080\r\nConnection: close\r\n\r\n' % RUN
        raw = header.encode()
        event = dict(header=header, body='', header_bytes=len(raw), bytes=len(raw),
            header_sha256=hashlib.sha256(raw).hexdigest(), message_sha256=hashlib.sha256(raw).hexdigest(),
            complete_http_message=True, tracing_and_custom_headers_absent=True)
        self.assertEqual(v.header_oracle(event, RUN, 'main', True), raw)
        traced = dict(event, header=header.replace('Connection:', 'traceparent: hidden\r\nConnection:'))
        with self.assertRaisesRegex(ValueError, 'whitelist'):
            v.header_oracle(traced, RUN, 'main', True)
        event['header_sha256'] = '0'*64
        with self.assertRaisesRegex(ValueError, 'hash'):
            v.header_oracle(event, RUN, 'main', True)

    def test_two_chains_map_by_actual_tuple_pid_and_side(self):
        expected, _, document, count = example()
        rows, mapping, fingerprint = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        self.assertEqual(len(mapping), 8)
        self.assertEqual(len(fingerprint), 64)
        main, edges = v.expected_edges(mapping, 'main')
        control, _ = v.expected_edges(mapping, 'control')
        self.assertEqual([e['kind'] for e in edges], ['network_pair', 'network_pair', 'syscall_handoff'])
        self.assertTrue({n['id'] for n in main}.isdisjoint(n['id'] for n in control))
        # Permuting the response preserves the canonical complete raw fingerprint.
        document['values'].reverse()
        self.assertEqual(v.snapshot(count, document, expected, RUN, 22, 100, 101)[2], fingerprint)
        self.assertEqual(len(rows), 8)

    def test_population_filter_never_hides_wrong_source_agent_or_trace(self):
        expected, _, document, count = example()
        for key, value in [('signal_source', 4), ('agent_id', 1), ('trace_id', 'b'*32),
                           ('end_us', '102000000'), ('process_id_0', 999), ('syscall_thread_1', 999)]:
            bad = copy.deepcopy(document)
            bad['values'][0][v.COLUMNS.index(key)] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                v.snapshot(count, bad, expected, RUN, 22, 100, 101)
        incomplete = copy.deepcopy(document)
        incomplete['values'].pop()
        with self.assertRaises(ValueError):
            v.snapshot(count, incomplete, expected, RUN, 22, 100, 101)

    def test_url_and_time_alone_cannot_make_a_handoff(self):
        expected, _, document, count = example()
        _, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        outgoing = mapping[('main', 'frontend', 'outgoing-request')]
        outgoing['syscall_trace_id_response'] = '99999'
        with self.assertRaisesRegex(ValueError, 'handoff'):
            v.expected_edges(mapping, 'main')

    def test_missing_endpoint_syscall_id_is_retained_and_never_weakens_handoff(self):
        expected, _, document, count = example()
        document['values'][0][v.COLUMNS.index('syscall_trace_id_request')] = '0'
        rows, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        self.assertEqual(rows[0]['syscall_trace_id_request'], '0')
        self.assertEqual(len(v.expected_edges(mapping, 'main')[1]), 3)
        # A missing frontend identifier must still refuse the causal handoff.
        mapping[('main', 'frontend', 'incoming-request')]['syscall_trace_id_request'] = '0'
        mapping[('main', 'frontend', 'outgoing-request')]['syscall_trace_id_request'] = '0'
        with self.assertRaises(ValueError):
            v.expected_edges(mapping, 'main')

    def test_component_checks_exact_edges_all_original_fields_and_unrelated_nodes(self):
        expected, _, document, count = example()
        _, mapping, _ = v.snapshot(count, document, expected, RUN, 22, 100, 101)
        nodes, edges = v.expected_edges(mapping, 'main')
        value = dict(seed_id=nodes[0]['id'], **{'from':100, 'to':101}, agent_id=22, signal_source=3,
            limit=64, records='4', window_records='8', scope={'org_id':1, 'user_id':1},
            nodes=[dict({k:x for k,x in n.items() if k not in ('trace_id','span_id','parent_span_id')}, in_seed_component=True) for n in nodes],
            edges=edges, candidates=[dict(kind='syscall_handoff',record_ids=[n['id']],reason='missing_counterpart',
                evidence=dict({key:str(n[key]) for key in v.HANDOFF},process_id=str(n['process_id_0' if n['tap_side']=='c-p' else 'process_id_1'])))
                for n in (nodes[0],nodes[3])], diagnostics={'seed_found':True,'ambiguous_groups':0,'missing_fields':[]})
        v.validate_component(value, nodes[0]['id'], nodes, edges, 100, 101, 22)
        for mutate in ('edge', 'pid', 'scope', 'ambiguity'):
            bad = copy.deepcopy(value)
            if mutate == 'edge':
                bad['edges'][0]['evidence']['resp_tcp_seq'] = '0'
            elif mutate == 'pid':
                bad['nodes'][0]['process_id_0'] = 999
            elif mutate == 'scope':
                bad['agent_id'] = 1
            else:
                bad['diagnostics']['ambiguous_groups'] = 1
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                v.validate_component(bad, nodes[0]['id'], nodes, edges, 100, 101, 22)

    def test_schema_null_duplicates_and_proxyable_urls_fail(self):
        for value in [None, {}, {'columns':['records','records'], 'values':[[8,8]]},
                      {'columns':['records'], 'values':None}]:
            with self.assertRaises(ValueError):
                v.table(value, ['records'])
        self.assertEqual(v.loopback('http://127.0.0.1:20819'), 'http://127.0.0.1:20819')
        for value in ['http://localhost:20819', 'http://127.0.0.1', 'https://127.0.0.1:20819',
                      'http://127.0.0.1:20819/other', 'http://user@127.0.0.1:20819']:
            with self.assertRaises(ValueError):
                v.loopback(value)


if __name__ == '__main__':
    unittest.main()
