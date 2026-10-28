"""Synthetic offline guards; these fixtures are never runtime Span evidence."""
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
import urllib.parse
from unittest import mock

SPEC = importlib.util.spec_from_file_location('otel_acceptance', Path(__file__).resolve().parents[1] / 'verify-otel-spans.py')
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)
RUN = 'span-' + 'a' * 24


def write(path, value):
    path.write_text(json.dumps(value))


def artifacts(root):
    work = root / 'work'
    work.mkdir(mode=0o700)
    write(work / 'ingestion-metadata.json', {'run': RUN, 'integration_mode': 'otel_trace', 'agent_id': 19})
    write(work / 'result.json', {'run': RUN, 'pass': True, 'cleaned': True})
    spans, responses = {'frontend': [], 'backend': []}, []
    traces = ['1' * 32, '2' * 32]
    for index, (kind, trace) in enumerate(zip(['main', 'control'], traces)):
        ids = ['%016x' % (index * 4 + n) for n in range(1, 5)]
        chain = [('frontend', 'frontend.server', 2, ids[0], '', False),
                 ('frontend', 'frontend.client', 3, ids[1], ids[0], False),
                 ('backend', 'backend.server', 2, ids[2], ids[1], True),
                 ('backend', 'backend.work', 1, ids[3], ids[2], False)]
        for offset, (role, name, span_kind, span, parent, remote) in enumerate(chain):
            stamp = 1793181022000000001 + index * 10000000 + offset * 1000
            suffix = 'front' if role == 'frontend' else 'back'
            spans[role].append({'source': oracle.SOURCE, 'name': name, 'trace_id': trace, 'span_id': span,
                'parent_span_id': parent, 'parent_remote': remote, 'span_kind': span_kind,
                'start_unix_ns': stamp, 'end_unix_ns': stamp + 1234567, 'status_code': 'Ok',
                'attributes': {'traflens.run': RUN, 'http.target': '/traflens-span/' + RUN + '/' + kind,
                               'http.method': 'GET', 'http.status_code': 200},
                'resource': {'service.name': RUN + '-' + suffix, 'service.instance.id': RUN + '-' + role, 'traflens.run': RUN}})
        responses.append({'kind': kind, 'http_status': 200, 'actual_response': {'run': RUN, 'kind': kind, 'trace_id': trace,
            'server_span_id': ids[0], 'client_span_id': ids[1], 'backend': {'run': RUN, 'kind': kind, 'trace_id': trace,
            'server_span_id': ids[2], 'internal_span_id': ids[3], 'received_parent_span_id': ids[1], 'checksum': '123'}}})
    for role in ['frontend', 'backend']:
        directory = work / role
        directory.mkdir(mode=0o700)
        (directory / 'exports').mkdir(mode=0o700)
        # Deliberately reverse records: the real witness also emits children first.
        (directory / 'spans.jsonl').write_text(''.join(json.dumps(span) + '\n' for span in reversed(spans[role])))
        receipt = {'source': oracle.SOURCE, 'run': RUN, 'role': role, 'mode': 'serve', 'pass': True,
                   'stop_reason': 'requests_completed', 'request_contract_completed': True,
                   'completed_requests': 2, 'sdk_exported_spans': 4, 'wire_batches': 4,
                   'http_acknowledged_batches': 4, 'export_errors': [], 'request_errors': []}
        write(directory / 'receipt.json', receipt)
        wires = []
        for n in range(1, 5):
            payload = b'offline synthetic bytes; never an actual SDK export' + bytes([n])
            name = 'exports/%04d.pb' % n
            (directory / name).write_bytes(payload)
            wires.append({'batch': n, 'file': name, 'bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
                          'http_acknowledged': True, 'http_status': 200})
        (directory / 'wire.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in wires))
    (work / 'generate').mkdir(mode=0o700)
    write(work / 'generate' / 'receipt.json', {'source': oracle.SOURCE, 'run': RUN, 'mode': 'generate', 'pass': True,
          'completed_requests': 2, 'trace_ids': traces})
    (work / 'generate' / 'requests.jsonl').write_text(''.join(json.dumps(row) + '\n' for row in responses))
    return work


def table(columns, records):
    return {'OPT_STATUS': 'SUCCESS', 'result': {'columns': columns,
            'values': [[row[column] for column in columns] for row in records]}}


def stored_rows(expected):
    result = []
    for index, span in enumerate(expected['spans'].values()):
        row = {key: span[key] for key in oracle.FIELDS[1:]}
        row['id'] = str(18446744073709551615 - index)
        result.append(row)
    return sorted(result, key=lambda row: int(row['id']))


def graph(expected, stored, trace, empty=False):
    value = {'trace': trace, 'signal_source': 4, 'time_unit': 'microseconds', 'limit': 256,
             'scope': {'org_id': 1, 'user_id': 1}, 'records': '0' if empty else '4', 'nodes': [], 'edges': [],
             'diagnostics': {key: [] for key in ['duplicate_span_ids', 'conflicting_span_ids', 'missing_parent_records',
                                              'ambiguous_parent_records', 'cycle_records', 'invalid_span_records']}}
    by_key = {(row['trace_id'], row['span_id']): row for row in stored}
    if not empty:
        for row in stored:
            if row['trace_id'] != trace:
                continue
            node = {key: row[key] for key in ['id', 'span_id', 'parent_span_id', 'app_service', 'app_instance', 'span_kind', 'endpoint', 'agent_id']}
            node.update(start_us=str(row['start_us']), end_us=str(row['end_us']), duration_us=str(row['response_duration']))
            parent = by_key[trace, row['parent_span_id']]['id'] if row['parent_span_id'] else None
            node.update(parent_record_id=parent, states=['linked'] if parent else ['root'])
            value['nodes'].append(node)
            if parent:
                value['edges'].append({'parent_record_id': parent, 'child_record_id': row['id']})
    return value


class AcceptanceGuards(unittest.TestCase):
    def test_default_is_offline_and_urls_reject_credentials_or_nonloopback(self):
        with mock.patch.object(oracle, 'read', side_effect=AssertionError('input read')), \
                mock.patch.object(oracle, 'base_url', side_effect=AssertionError('network setup')), \
                mock.patch('sys.stdout', new_callable=io.StringIO) as stdout:
            self.assertEqual(oracle.main(['--work', '/does-not-exist']), 0)
            self.assertFalse(json.loads(stdout.getvalue())['starts_network'])
        for value in ['http://user:password@127.0.0.1:20819', 'http://127.0.0.1:20819?token=secret',
                      'http://192.0.2.240:20416', 'http://localhost:20416', 'https://127.0.0.1:20416',
                      'http://127.0.0.1', 'http://127.0.0.1:20416/path']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                oracle.base_url(value)
        self.assertEqual(oracle.base_url('http://127.0.0.1:20819/'), 'http://127.0.0.1:20819')

    def test_sdk_receipts_actual_response_parents_and_wire_hashes_are_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = artifacts(Path(tmp))
            expected = oracle.expected_artifacts(work)
            self.assertEqual(len(expected['spans']), 8)
            self.assertEqual(len(expected['traces']), 2)
            receipt_path = work / 'frontend' / 'receipt.json'
            receipt = json.loads(receipt_path.read_text())
            write(receipt_path, dict(receipt, **{'pass': False}))
            with self.assertRaises(ValueError):
                oracle.expected_artifacts(work)
            write(receipt_path, receipt)
            payload = work / 'backend' / 'exports' / '0001.pb'
            original = payload.read_bytes()
            payload.write_bytes(b'changed bytes')
            with self.assertRaises(ValueError):
                oracle.expected_artifacts(work)
            payload.write_bytes(original)
            request_path = work / 'generate' / 'requests.jsonl'
            requests = [json.loads(line) for line in request_path.read_text().splitlines()]
            requests[0]['actual_response']['backend']['received_parent_span_id'] = 'f' * 16
            request_path.write_text(''.join(json.dumps(row) + '\n' for row in requests))
            with self.assertRaises(ValueError):
                oracle.expected_artifacts(work)

    def test_unfiltered_native_population_keeps_uint64_and_checks_every_sdk_field(self):
        with tempfile.TemporaryDirectory() as tmp:
            expected = oracle.expected_artifacts(artifacts(Path(tmp)))
            stored = stored_rows(expected)
            summary = table(['records'], [{'records': 8}])
            result = oracle.snapshot(summary, table(oracle.FIELDS, stored), expected)
            self.assertIn('18446744073709551615', result['ids'])
            self.assertEqual(result, oracle.snapshot(summary, table(oracle.FIELDS, stored), expected))
            for field, bad in [('signal_source', 3), ('agent_id', 18), ('type', 1), ('start_us', stored[0]['start_us'] + 1),
                               ('response_duration', 0), ('parent_span_id', 'f' * 16), ('app_service', RUN + '-other')]:
                changed = copy.deepcopy(stored)
                changed[0][field] = bad
                with self.subTest(field=field), self.assertRaises(ValueError):
                    oracle.snapshot(summary, table(oracle.FIELDS, changed), expected)
            with self.assertRaises(oracle.PendingPopulation):
                oracle.snapshot(table(['records'], [{'records': 7}]), table(oracle.FIELDS, stored[:7]), expected)
            with self.assertRaises(ValueError):
                oracle.snapshot(table(['records'], [{'records': 9}]), table(oracle.FIELDS, stored + [stored[0]]), expected)
            for malformed in [{'OPT_STATUS': 'SUCCESS'}, table(['id'], [{'id': '1'}])]:
                with self.assertRaises(ValueError):
                    oracle.snapshot(summary, malformed, expected)

    def test_console_graph_matches_exact_record_parents_and_distinguishes_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            expected = oracle.expected_artifacts(artifacts(Path(tmp)))
            stored = stored_rows(expected)
            trace = expected['traces'][0]
            actual = graph(expected, stored, trace)
            oracle.validate_graph(actual, trace, expected, stored)
            changed = copy.deepcopy(actual)
            changed['edges'][0]['parent_record_id'] = '9007199254740993'
            with self.assertRaises(ValueError):
                oracle.validate_graph(changed, trace, expected, stored)
            changed = copy.deepcopy(actual)
            changed['nodes'][0]['start_us'] = int(changed['nodes'][0]['start_us'])
            with self.assertRaises(ValueError):
                oracle.validate_graph(changed, trace, expected, stored)
            oracle.validate_graph(graph(expected, stored, trace, True), trace, expected, stored, True)
            with self.assertRaises(ValueError):
                oracle.validate_graph({'records': '0'}, trace, expected, stored, True)

    def test_complete_read_only_acceptance_queries_whole_marker_without_hidden_filters(self):
        with tempfile.TemporaryDirectory() as tmp:
            expected = oracle.expected_artifacts(artifacts(Path(tmp)))
            stored = stored_rows(expected)
            calls = []
            class FakeClient:
                deadline = time.monotonic() + 60
                def request(self, base, name, path, fields=None):
                    calls.append((name, path, fields))
                    if fields is not None:
                        sql = fields['sql']
                        self.assert_marker(sql)
                        if 'Count(row)' in sql:
                            count = 0 if 'signal_source = 0' in sql or 'signal_source = 3' in sql else 8
                            return table(['records'], [{'records': count}])
                        return table(oracle.FIELDS, stored)
                    query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
                    trace = query['trace'][0]
                    if path.startswith('/api/spans'):
                        return graph(expected, stored, trace, name.startswith('empty-'))
                    row = next(row for row in stored if row['id'] == query['id'][0])
                    return table(oracle.FIELDS, [row])['result']
                @staticmethod
                def assert_marker(sql):
                    if "app_service LIKE '" + RUN + "%'" not in sql or any(text in sql for text in ['time >=', 'agent_id =', 'trace_id =']):
                        raise AssertionError('Hidden filter on whole-marker population')
            report = {'attempts': []}
            with mock.patch.object(oracle.time, 'sleep'):
                oracle.accept(FakeClient(), 'http://127.0.0.1:20819', 'http://127.0.0.1:20820', expected, report)
            self.assertTrue(report['all_sdk_fields_and_microseconds_match'])
            self.assertTrue(report['both_actual_parent_graphs_match'])
            self.assertTrue(report['all_actual_record_details_match'])
            self.assertEqual(report['source4_records'], 8)
            self.assertEqual(len(calls), 22)

    def test_http_failure_and_row_budget_are_preserved_and_never_fall_back(self):
        class Response(io.BytesIO):
            code = 500
        class Opener:
            calls = 0
            def open(self, request, timeout):
                self.calls += 1
                if not 0 < timeout <= 12:
                    raise AssertionError('Unbounded timeout')
                return Response(b'{"OPT_STATUS":"SERVER_ERROR"}')
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            client = oracle.Client(output, time.monotonic() + 60)
            client.opener = Opener()
            with self.assertRaises(ValueError):
                client.request('http://127.0.0.1:20819', 'expression-failed', '/v1/query/', {'db': 'flow_log', 'sql': 'fixed'})
            self.assertEqual(client.opener.calls, 1)
            self.assertEqual(len(list(output.glob('*.body'))), 1)
            self.assertEqual(json.loads(next(output.glob('*.response.json')).read_text())['http'], 500)
        with self.assertRaises(ValueError):
            oracle.rows(table(['id'], [{'id': str(i)} for i in range(65)]), ['id'])
        with self.assertRaises(ValueError):
            oracle.integer(True)


if __name__ == '__main__':
    unittest.main()
