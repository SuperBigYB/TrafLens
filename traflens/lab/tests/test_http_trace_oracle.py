import copy
import importlib.util
from pathlib import Path
import sys
import unittest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('http_trace_oracle', LAB / 'verify-http-trace.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class HTTPTraceOracleTests(unittest.TestCase):
    def manifest(self):
        value = {'marker': 'trace-' + 'c' * 24, 'primary_trace': 'a' * 32,
                 'unrelated_trace': 'b' * 32, 'records': []}
        for leg, port, offset in [('front', 18080, 0x1000), ('back', 18081, 0x2000)]:
            for sequence in range(2):
                value['records'].append({'request_resource': '/traflens-trace/' + value['marker'] + '/' + leg + '/' + str(sequence),
                    'trace_id': value['primary_trace'] if sequence == 0 else value['unrelated_trace'],
                    'span_id': format(offset + sequence + 1, '016x'), 'server_port': port})
        return value

    def test_receipts_cannot_relax_independent_wire_contract(self):
        manifest = self.manifest()
        self.assertEqual(len(oracle.expected_records(manifest)), 4)
        for key, value in [('trace_id', 'b' * 32), ('span_id', '1' * 16), ('server_port', 1)]:
            changed = copy.deepcopy(manifest)
            changed['records'][0][key] = value
            with self.assertRaises(ValueError):
                oracle.expected_records(changed)

    def test_whole_marker_rejects_wrong_trace_metadata_missing_or_duplicate(self):
        expected = oracle.expected_records(self.manifest())
        rows = []
        for index, value in enumerate(expected.values()):
            rows.append(dict(value, id=str(18446744073709551615 - index), agent_id=7,
                signal_source=0, l7_protocol=20, type=2, response_code=200, response_status=0))
        def result(values):
            columns = list(rows[0])
            return {'columns': columns, 'values': [[row[key] for key in columns] for row in values]}
        self.assertEqual(len(oracle.validate_rows(result(rows), expected, 7)), 4)
        with self.assertRaises(ValueError):
            oracle.validate_rows(result(rows[:-1]), expected, 7)
        with self.assertRaises(ValueError):
            oracle.validate_rows(result(rows[:3] + [rows[0]]), expected, 7)
        for key, value in [('trace_id', 'd' * 32), ('signal_source', 3), ('agent_id', 8), ('response_code', 500)]:
            changed = copy.deepcopy(rows)
            changed[0][key] = value
            with self.assertRaises(ValueError):
                oracle.validate_rows(result(changed), expected, 7)


if __name__ == '__main__':
    unittest.main()
