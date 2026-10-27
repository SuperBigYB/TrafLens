import copy
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('http_pages', Path(__file__).resolve().parents[1] / 'verify-http-pages.py')
m = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(m)


def response(columns, rows):
    return {'OPT_STATUS': 'SUCCESS', 'result': {'columns': columns, 'values': rows}}


class Backend:
    def __init__(self, count):
        self.rows = sorted([['/traflens-load/synthetic/' + str(i), 'GET', 200, 0, 20, 2, 0, 'c', 42, 6]
                            for i in range(count)])
        self.queries = []
        self.counts = []
        self.transform = lambda document: document

    def __call__(self, sql):
        self.queries.append(sql)
        if sql.startswith('SELECT Count(row)'):
            count = self.counts.pop(0) if self.counts else len(self.rows)
            return response(['row_count'], [[count]])
        limit = int(sql.rsplit(' LIMIT ', 1)[1])
        cursor = re.search(" AND request_resource > '([^']+)'", sql)
        rows = [copy.deepcopy(r) for r in self.rows if cursor is None or r[0] > cursor[1]][:limit]
        return self.transform(response(m.reports.FIELDS, rows))


def pair(count):
    c = dict(Mode='client', Marker='synthetic', Execute=True, Rate=count, Seconds=1, Concurrency=1,
             TimeoutMS=1000, Port=18080, Interface='ethA', Bind='fe80::1', Peer='fe80::2')
    client = dict(schema='traflens.http-load.v1', mode='client', marker='synthetic', **{'pass': True}, private_config=c,
                  scheduled=count, attempted=count, completed=count, failed=0, skipped=0, elapsed_seconds=1,
                  process_cpu_user_seconds=.01, process_cpu_system_seconds=.01, process_peak_rss_kib=10000,
                  service_p50_ns=100, service_p99_ns=100, offered_p99_ns=200,
                  records=[dict(sequence=i, state='completed', scheduled_ns=i * (1000000000 // count),
                                started_ns=i * (1000000000 // count) + 100, service_ns=100, offered_latency_ns=200)
                           for i in range(count)])
    server = copy.deepcopy(client); server.update(mode='server', records=None)
    server['private_config'].update(Mode='server', Bind='fe80::2', Peer='fe80::1')
    return client, server


class HTTPPagesTests(unittest.TestCase):
    def test_two_exact_scans_above_old_limit_and_lexical_order(self):
        c, s = pair(2000); backend = Backend(2000)
        out = m.verify(backend, c, s, 42, 64)
        self.assertEqual(out['packet_exact_query_reads'], 2)
        self.assertEqual(out['scans'], [dict(pages=32, rows=2000, count_reads=2)] * 2)
        self.assertEqual(len(backend.queries), 68)
        self.assertTrue(all('LIMIT 65' in q for q in backend.queries if 'ORDER BY' in q))
        self.assertTrue(all('signal_source =' not in q and 'agent_id =' not in q for q in backend.queries))
        for private in ('synthetic', 'fe80::', 'ethA', 'request_resource', 'agent_id'):
            self.assertNotIn(private, json.dumps(out))
        self.assertFalse(out['transactional_snapshot_proven'])

    def test_exact_multiple_and_small_workload(self):
        for count in (1, 64, 128, 129, 1000, 2001):
            with self.subTest(count=count):
                out = m.scan(Backend(count), 'synthetic', count, 42, 64)
                self.assertEqual(out['rows'], count)
                self.assertEqual(out['pages'], (count + 63) // 64)

    def test_bounded_ingest_poll_and_count_change_rejected(self):
        b = Backend(80); b.counts = [0, 40, 80, 80]
        polls = []; out = m.scan(b, 'synthetic', 80, 42, 64, await_count=lambda: polls.append(1))
        self.assertEqual(len(polls), 2); self.assertEqual(out['count_reads'], 4)
        for counts in ([79], [81], [80, 81], [80, 79]):
            b = Backend(80); b.counts = list(counts)
            with self.subTest(counts=counts), self.assertRaises(ValueError): m.scan(b, 'synthetic', 80, 42, 64)
        b = Backend(80); b.counts = [80, 80, 79]
        with self.assertRaises(ValueError): m.verify(b, *pair(80), 42, 64)

    def test_second_scan_rows_are_independently_verified(self):
        b = Backend(80)
        def changed(document):
            if len(b.queries) > 4: document['result']['values'][0][1] = 'POST'
            return document
        b.transform = changed
        with self.assertRaises(ValueError): m.verify(b, *pair(80), 42, 64)

    def test_query_failure_and_redirect_rejection(self):
        b = Backend(80); b.transform = lambda _: {'OPT_STATUS': 'FAILED', 'DESCRIPTION': 'synthetic'}
        with self.assertRaises(ValueError): m.scan(b, 'synthetic', 80, 42, 64)
        with self.assertRaises(ValueError): m.NoRedirect().redirect_request(None, None, 302, '', {}, 'http://example.invalid')

    def test_duplicate_straddling_page_boundary_and_missing_rows(self):
        for offset in (0, 63, 64, 65, 129):
            b = Backend(130); b.rows.insert(offset, copy.deepcopy(b.rows[offset]))
            # Falsified counts cannot conceal the duplicate during paging.
            b.counts = [130, 130]
            with self.subTest(offset=offset), self.assertRaises(ValueError): m.scan(b, 'synthetic', 130, 42, 64)
        b = Backend(130); b.rows.pop(64); b.counts = [130, 130]
        with self.assertRaises(ValueError): m.scan(b, 'synthetic', 130, 42, 64)

    def test_wrong_fields_including_lookahead_and_extra_marker_row(self):
        for index, value in ((0, '/traflens-load/synthetic/01'), (0, '/traflens-load/synthetic/999'),
                             (0, "/traflens-load/synthetic/1'"), (0, '/traflens-load/another/1'),
                             (1, 'POST'), (2, True), (2, 200.0), (2, None), (3, 1), (4, 120),
                             (5, 0), (6, 3), (7, 's'), (8, 43), (9, 17)):
            b = Backend(130); b.rows[64][index] = value
            with self.subTest(index=index, value=value), self.assertRaises(ValueError):
                m.scan(b, 'synthetic', 130, 42, 64)

    def test_clamped_unsorted_regressing_and_oversized_pages(self):
        for kind in ('clamp', 'empty', 'reverse', 'over-limit', 'ignored-cursor'):
            b = Backend(130)
            if kind == 'clamp': b.transform = lambda d: response(m.reports.FIELDS, d['result']['values'][:63])
            if kind == 'empty': b.transform = lambda d: response(m.reports.FIELDS, [])
            if kind == 'reverse': b.transform = lambda d: response(m.reports.FIELDS, d['result']['values'][::-1])
            if kind == 'over-limit': b.transform = lambda d: response(m.reports.FIELDS, b.rows[:66])
            if kind == 'ignored-cursor': b.transform = lambda d: response(m.reports.FIELDS, b.rows[:65])
            with self.subTest(kind=kind), self.assertRaises(ValueError): m.scan(b, 'synthetic', 130, 42, 64)

    def test_malformed_queries_counts_and_rows(self):
        documents = [None, {}, {'OPT_STATUS': 'FAILED'}, response([], []), response(['row_count'], []),
                     response(['row_count'], [[True]]), response(['row_count'], [[1.0]]),
                     response(['row_count'], [[None]]), response(['row_count'], [[-1]]),
                     response(['row_count'], [[1, 2]])]
        for doc in documents:
            with self.subTest(doc=doc), self.assertRaises(ValueError): m.scan(lambda _: doc, 'synthetic', 1, 42)
        for row in (None, [], ['one'], tuple(Backend(1).rows[0])):
            b = Backend(1); b.transform = lambda d: response(m.reports.FIELDS, [row])
            with self.subTest(row=row), self.assertRaises(ValueError): m.scan(b, 'synthetic', 1, 42)

    def test_bounds_and_invalid_reports(self):
        for marker, count, agent, size in (("bad'", 1, 42, 64), ('bad_', 1, 42, 64), ('synthetic', 0, 42, 64),
                                          ('synthetic', 200001, 42, 64), ('synthetic', 1, True, 64),
                                          ('synthetic', 1, 42, 63), ('synthetic', 1, 42, 1001)):
            with self.subTest(args=(marker, count, agent, size)), self.assertRaises(ValueError):
                m.scan(lambda _: self.fail('Invalid plan queried backend'), marker, count, agent, size)
        c, s = pair(2000); c['skipped'] = 1
        with self.assertRaises(ValueError): m.verify(lambda _: self.fail('Invalid report queried backend'), c, s, 42)

    def test_archive_replay_rejects_incomplete_tampered_and_extra(self):
        c, s = pair(130); b = Backend(130)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); calls = []
            def query(sql):
                d = b(sql); path = root / ('query-%06d.json' % (len(calls) + 1)); calls.append(path)
                m.save(path, {'sql': sql, 'response': d}); return d
            out = m.verify(query, c, s, 42, 64)
            self.assertEqual(m.replay(root, c, s, 42, 64), out)
            extra = root / 'query-999999.json'; m.save(extra, {'sql': 'irrelevant'})
            with self.assertRaises(ValueError): m.replay(root, c, s, 42, 64)
            extra.unlink()
            original = calls[-1].read_text(); calls[-1].unlink()
            with self.assertRaises(ValueError): m.replay(root, c, s, 42, 64)
            calls[-1].write_text(original)
            first = json.loads(calls[0].read_text()); first['sql'] += ' LIMIT 1'; calls[0].write_text(json.dumps(first))
            with self.assertRaises(ValueError): m.replay(root, c, s, 42, 64)

    def test_plan_creates_no_output_and_json_rejects_coercion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); c, s = pair(2000)
            m.save(root / 'c.json', c); m.save(root / 's.json', s)
            command = [sys.executable, str(Path(m.__file__)), '--client', str(root / 'c.json'),
                       '--server', str(root / 's.json'), '--agent-id', '42', '--output', str(root / 'unused')]
            result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
            self.assertFalse(json.loads(result.stdout)['execute']); self.assertFalse((root / 'unused').exists())
            with self.assertRaises(FileExistsError): m.save(root / 'c.json', c)
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): m.decode(raw)

    @unittest.skipUnless(hasattr(m.signal, 'setitimer'), 'POSIX deadline execution requires Linux')
    def test_absolute_deadline_restores_timer_and_handler(self):
        previous = m.signal.getsignal(m.signal.SIGALRM)
        with self.assertRaises(TimeoutError):
            with m.deadline(.02): m.time.sleep(.2)
        self.assertEqual(m.signal.getitimer(m.signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(m.signal.getsignal(m.signal.SIGALRM), previous)

    @unittest.skipUnless(hasattr(m.signal, 'setitimer'), 'POSIX private collector execution requires Linux')
    def test_collector_persists_success_and_malformed_response_failure(self):
        import io
        from contextlib import redirect_stdout
        class HTTPResponse:
            def __init__(self, raw): self.raw = raw
            def __enter__(self): return self
            def __exit__(self, *args): return False
            def read(self, bound):
                self.bound = bound
                return self.raw
        for malformed in (False, True):
            with self.subTest(malformed=malformed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory); c, s = pair(130)
                m.save(root / 'c.json', c); m.save(root / 's.json', s)
                backend = Backend(130)
                class Opener:
                    def open(self, request, timeout):
                        self.url = request.full_url
                        if self.url != 'http://127.0.0.1:20416/v1/query/': raise AssertionError(self.url)
                        payload = m.urllib.parse.parse_qs(request.data.decode('ascii'))
                        if payload['db'] != ['flow_log']: raise AssertionError(payload)
                        if not 0 < timeout <= 15: raise AssertionError(timeout)
                        raw = b'{"x":NaN}' if malformed else json.dumps(backend(payload['sql'][0])).encode()
                        return HTTPResponse(raw)
                args = ['verify-http-pages.py', '--client', str(root / 'c.json'), '--server', str(root / 's.json'),
                        '--agent-id', '42', '--page-size', '64', '--output', str(root / 'capture'), '--execute']
                with patch.object(sys, 'argv', args), patch.object(m.urllib.request, 'build_opener', return_value=Opener()), redirect_stdout(io.StringIO()):
                    if malformed:
                        with self.assertRaises(SystemExit): m.main()
                    else: m.main()
                archive = root / 'capture'
                if malformed:
                    self.assertTrue((archive / 'failure.json').exists())
                    self.assertIn('invalid_response_base64', m.reports.load(archive / 'query-000001.json'))
                    self.assertFalse((archive / 'summary.json').exists())
                else:
                    self.assertEqual(m.replay(archive, c, s, 42, 64), m.reports.load(archive / 'summary.json'))
                self.assertEqual(archive.stat().st_mode & 0o077, 0)
                for path in archive.iterdir(): self.assertEqual(path.stat().st_mode & 0o077, 0)


if __name__ == '__main__': unittest.main()
