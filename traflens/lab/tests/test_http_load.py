import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('http_load', Path(__file__).resolve().parents[1] / 'verify-http-load.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


class HTTPReportTests(unittest.TestCase):
    def fixture(self):
        c = dict(Mode='client', Marker='synthetic', Execute=True, Rate=1, Seconds=1, Concurrency=1, TimeoutMS=1000,
                 Port=18080, Interface='ethA', Bind='fe80::1', Peer='fe80::2')
        client = dict(schema='traflens.http-load.v1', mode='client', marker='synthetic', **{'pass': True}, private_config=c,
                      scheduled=1, attempted=1, completed=1, failed=0, skipped=0, elapsed_seconds=.1,
                      process_cpu_user_seconds=.01, process_cpu_system_seconds=.01, process_peak_rss_kib=10000,
                      service_p50_ns=100, service_p99_ns=100, offered_p99_ns=200,
                      records=[dict(sequence=0, state='completed', scheduled_ns=0, started_ns=100, service_ns=100, offered_latency_ns=200)])
        server = copy.deepcopy(client); server.update(mode='server', records=None)
        server['private_config'].update(Mode='server', Bind='fe80::2', Peer='fe80::1')
        query = {'OPT_STATUS': 'SUCCESS', 'result': {'columns': m.FIELDS, 'values': [
            ['/traflens-load/synthetic/0', 'GET', 200, 0, 20, 2, 0, 'c', 42, 6]]}}
        return client, server, query

    def test_valid_pair_and_single_endpoint_whole_marker_reads(self):
        c, s, q = self.fixture(); self.assertEqual(m.verify(c, s)['packet_exact_query_reads'], 0)
        out = m.verify(c, s, [q, q], 42)
        self.assertEqual(out['packet_exact_query_reads'], 2)
        for private in ('synthetic', 'fe80::', 'ethA'):
            self.assertNotIn(private, json.dumps(out))

    def test_rejects_failed_skipped_false_pass_and_wrong_pair(self):
        for key, value in (('pass', False), ('failed', 1), ('skipped', 1), ('completed', 0), ('marker', 'other')):
            c, s, _ = self.fixture(); c[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.verify(c, s)
        c, s, _ = self.fixture(); s['private_config']['Peer'] = 'fe80::3'
        with self.assertRaises(ValueError): m.verify(c, s)

    def test_rejects_wrong_sequence_schedule_latency_and_percentile(self):
        for key, value in (('sequence', 1), ('scheduled_ns', 5), ('started_ns', -1), ('offered_latency_ns', 2000000), ('state', 'failed')):
            c, s, _ = self.fixture(); c['records'][0][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): m.verify(c, s)
        c, s, _ = self.fixture(); c['service_p99_ns'] = 2
        with self.assertRaises(ValueError): m.verify(c, s)

    def test_rejects_missing_extra_wrong_source_endpoint_and_coerced_query(self):
        for action in ('missing', 'extra', 'source', 'endpoint', 'boolean', 'schema', 'null'):
            c, s, q = self.fixture(); rows = q['result']['values']
            if action == 'missing': rows.clear()
            if action == 'extra': rows.append(list(rows[0]))
            if action == 'source': rows[0][6] = 3
            if action == 'endpoint': rows[0][7] = 's'
            if action == 'boolean': rows[0][2] = True
            if action == 'schema': q['result']['columns'] = m.FIELDS[:-1]
            if action == 'null': q['result']['values'] = None
            with self.subTest(action=action), self.assertRaises(ValueError): m.verify(c, s, [q, q], 42)
        c, s, q = self.fixture()
        with self.assertRaises(ValueError): m.verify(c, s, [q], 42)

    def test_rejects_duplicate_json_keys_and_nonfinite(self):
        with tempfile.TemporaryDirectory() as directory:
            p = Path(directory) / 'bad.json'
            for text in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
                p.write_text(text)
                with self.assertRaises(ValueError): m.load(p)


if __name__ == '__main__': unittest.main()
