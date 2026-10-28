import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'verify-cpu-profile.py'
SPEC = importlib.util.spec_from_file_location('cpu_profile_acceptance', SCRIPT)
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)

APP = 'cpu-' + 'a' * 24
RAW = ('''PeriodType: cpu nanoseconds
Period: 10000000
Time: 1970-01-01 00:33:20 +0000 UTC
Duration: 0.04
Samples:
samples/count cpu/nanoseconds
          3   30000000: 1 2
                traflens_run:[APP]
          1   10000000: 3 1 2
                traflens_run:[APP]
Locations
     1: 0x100 M=1 main.hot fixture.go:10:0 s=9
     2: 0x200 M=1 main.root fixture.go:20:0 s=19
     3: 0x300 M=1 runtime.asyncPreempt runtime.go:30:0 s=29
Mappings
1: 0x100/0x400/0x0 /synthetic/unit-fixture [FN]
'''.replace('APP', APP)).encode()


def envelope(columns, values):
    return {'OPT_STATUS': 'SUCCESS', 'result': {'columns': columns, 'values': values}}


class CPUProfileAcceptanceTests(unittest.TestCase):
    def original(self):
        return m.parse_raw(RAW, APP)

    def snapshot(self):
        values = []
        for identity, weight in [('9007199254740993', 3), ('9007199254740994', 1)]:
            row = {'id': identity, 'time': '1970-01-01T00:33:20+00:00', 'agent_id': 7,
                   'app_service': APP, 'profile_event_type': 'cpu', 'profile_value_unit': 'samples',
                   'profile_value': weight, 'profile_language_type': 'Golang',
                   'profile_create_timestamp': '1970-01-01T00:33:20+00:00', 'process_id': 0,
                   'compression_algo': 'zstd'}
            values.append([row[key] for key in m.FIELDS])
        return envelope(['records', 'samples'], [[2, 4]]), envelope(m.FIELDS, values)

    def tree(self):
        return {'OPT_STATUS': 'SUCCESS', 'result': {'bounds_applied': True, 'max_rows': 2,
            'input_rows': 2, 'budgets': dict(m.BUDGETS),
            'functions': [APP, 'main.root', 'main.hot', 'runtime.asyncPreempt'],
            'function_types': ['app', 'user', 'user', 'runtime'],
            'function_values': {'columns': ['self_value', 'total_value'], 'values': [[0, 4], [0, 4], [3, 4], [1, 1]]},
            'node_values': {'columns': ['function_id', 'parent_node_id', 'self_value', 'total_value'],
                            'values': [[0, -1, 0, 4], [1, 0, 0, 4], [2, 1, 3, 4], [3, 2, 1, 1]]}}}

    def test_default_is_offline_and_creates_no_files(self):
        with tempfile.TemporaryDirectory() as root:
            run = subprocess.run([sys.executable, str(SCRIPT), '--output', str(Path(root) / 'unused')],
                                 cwd=root, text=True, capture_output=True, timeout=5, check=True)
            self.assertFalse(json.loads(run.stdout)['execute'])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_go_raw_stacks_are_reversed_and_counts_are_not_nanoseconds(self):
        original = self.original()
        self.assertEqual(original['samples'], 4)
        self.assertEqual(original['cpu_nanoseconds'], 40000000)
        self.assertEqual(original['stacks'][('main.root', 'main.hot')], 3)
        self.assertEqual(original['stacks'][('main.root', 'main.hot', 'runtime.asyncPreempt')], 1)
        for raw in [RAW.replace(b'samples/count cpu/nanoseconds', b'cpu/nanoseconds'),
                    RAW.replace(b'30000000:', b'30000001:'),
                    RAW.replace(APP.encode(), ('cpu-' + 'b'*24).encode()),
                    RAW.replace(b'1 2\n', b'9 2\n')]:
            with self.assertRaises(ValueError):
                m.parse_raw(raw, APP)

    def test_whole_marker_preserves_exact_ids_and_rejects_hidden_metadata(self):
        summary, data = self.snapshot()
        snapshot = m.snapshot(summary, data, APP, 7, self.original(), 256)
        self.assertIn('9007199254740993', snapshot['ids'])
        for key, value in [('agent_id', 8), ('profile_event_type', 'inuse_space'),
                           ('profile_value_unit', 'nanoseconds'), ('profile_language_type', 'eBPF'),
                           ('process_id', 9), ('compression_algo', ''),
                           ('profile_create_timestamp', '1970-01-01T00:33:21+00:00')]:
            changed = copy.deepcopy(data)
            changed['result']['values'][0][m.FIELDS.index(key)] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.snapshot(summary, changed, APP, 7, self.original(), 256)
        duplicate = copy.deepcopy(data)
        duplicate['result']['values'][1][0] = duplicate['result']['values'][0][0]
        with self.assertRaises(ValueError):
            m.snapshot(summary, duplicate, APP, 7, self.original(), 256)

    def test_metadata_weight_fingerprint_catches_even_equal_total_changes(self):
        summary, data = self.snapshot()
        before = m.snapshot(summary, data, APP, 7, self.original(), 256)
        data['result']['values'][0][m.FIELDS.index('profile_value')] = 2
        data['result']['values'][1][m.FIELDS.index('profile_value')] = 2
        after = m.snapshot(summary, data, APP, 7, self.original(), 256)
        self.assertNotEqual(before['fingerprint'], after['fingerprint'])

    def test_bounded_tree_requires_all_stacks_and_conserved_values(self):
        original = self.original()
        self.assertEqual(m.validate_tree(self.tree(), original['stacks'], APP, 2, 2), original['stacks'])
        for mode in ['bounds', 'rows', 'budget', 'cycle', 'self', 'functions', 'stack']:
            tree = self.tree()
            d = tree['result']
            if mode == 'bounds':
                d['bounds_applied'] = False
            elif mode == 'rows':
                d['input_rows'] = 1
            elif mode == 'budget':
                d['budgets']['nodes'] += 1
            elif mode == 'cycle':
                d['node_values']['values'][2][1] = 3
            elif mode == 'self':
                d['node_values']['values'][2][2] += 1
            elif mode == 'functions':
                d['function_values']['values'][2][0] += 1
            elif mode == 'stack':
                d['functions'][2] = 'main.notTheObservedFunction'
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                m.validate_tree(tree, original['stacks'], APP, 2, 2)

    def test_empty_control_is_not_a_partial_or_missing_tree(self):
        tree = self.tree()
        for key in ['functions', 'function_types']:
            tree['result'][key] = []
        for key in ['function_values', 'node_values']:
            tree['result'][key]['values'] = []
        tree['result']['input_rows'] = 0
        self.assertEqual(m.validate_tree(tree, m.Counter(), APP, 2, 0), {})
        tree['result']['node_values']['values'] = [[0, -1, 0, 0]]
        with self.assertRaises(ValueError):
            m.validate_tree(tree, m.Counter(), APP, 2, 0)
        for missing in [{'OPT_STATUS': 'SUCCESS'}, {'OPT_STATUS': 'SUCCESS', 'result': None}]:
            with self.assertRaises(ValueError):
                m.validate_tree(missing, m.Counter(), APP, 2, 0)

    def test_only_explicit_loopback_query_and_complete_schema_are_accepted(self):
        self.assertEqual(m.query_base('http://127.0.0.1:20819/'), 'http://127.0.0.1:20819')
        for base in ['http://localhost:20416', 'http://203.0.113.1:20416',
                     'http://127.0.0.1', 'http://user@127.0.0.1:20416',
                     'http://127.0.0.1:20416/other', 'http://127.0.0.1:20416?sql=x']:
            with self.subTest(base=base), self.assertRaises(ValueError):
                m.query_base(base)
        for result in [{'OPT_STATUS': 'SUCCESS'}, envelope(['records', 'records'], [[1, 1]]),
                       envelope(['records'], [[1, 2]])]:
            with self.assertRaises(ValueError):
                m.rows(result, ['records'])

    def test_original_sampling_run_is_separate_from_fresh_transport_app(self):
        receipt = {'run': APP, 'profile_sha256': '1' * 64, 'profile_bytes': 42,
                   'source': 'go_runtime_pprof_self', 'sampling_scope': 'current process only',
                   'completed_duration': True, 'started_unix_ns': 2000 * 10**9,
                   'finished_unix_ns': 2001 * 10**9}
        run, _, _ = m.sampling_receipt(receipt, '1' * 64, 42, 2000, 2001)
        self.assertNotEqual(run, 'cpu-' + 'b' * 24)
        self.assertEqual(m.parse_raw(RAW, run)['samples'], 4)
        for key, bad in [('run', 'fabricated'), ('profile_sha256', '2' * 64),
                         ('profile_bytes', 43), ('source', 'eBPF'), ('completed_duration', False)]:
            changed = dict(receipt, **{key: bad})
            with self.subTest(key=key), self.assertRaises(ValueError):
                m.sampling_receipt(changed, '1' * 64, 42, 2000, 2001)
        with self.assertRaises(ValueError):
            m.sampling_receipt(receipt, '1' * 64, 42, 2001, 2002)


if __name__ == '__main__':
    unittest.main()
