import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('protocol_oracle', LAB / 'verify-protocol-product.py')
oracle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oracle)


class ProtocolProductTests(unittest.TestCase):
    def contract(self):
        return {'marker': 'p6-' + 'a' * 24, 'count': 4}

    def query(self):
        expected = oracle.expected_records(self.contract())
        rows = [dict(row, id=str(2**63 + index), agent_id=7, signal_source=0, type=2)
                for index, row in enumerate(expected.values())]
        columns = list(dict.fromkeys(key for row in rows for key in row))
        return expected, {'columns': columns, 'values': [[row.get(key) for key in columns] for row in rows]}

    def test_two_protocols_and_answers_from_independent_contract(self):
        expected, result = self.query()
        self.assertEqual(len(oracle.validate_rows(result, expected, 7)), 8)
        self.assertEqual({r['l7_protocol'] for r in expected.values()}, {60, 120})
        self.assertEqual(next(iter(expected.values()))['response_result'], 'A=198.18.0.1 TTL=60')

    def test_rejects_wrong_metadata_response_and_negative_control(self):
        expected, base = self.query()
        for key, bad in [('agent_id', 8), ('signal_source', 3), ('l7_protocol', 20),
                         ('type', 0), ('response_status', 3), ('response_code', 1),
                         ('response_result', 'A=198.18.0.9 TTL=60'), ('server_port', 18054),
                         ('request_resource', 'q0.' + self.contract()['marker'] + '-dns-negative.traflens.invalid')]:
            result = copy.deepcopy(base)
            result['values'][0][result['columns'].index(key)] = bad
            with self.subTest(field=key), self.assertRaises(ValueError):
                oracle.validate_rows(result, expected, 7)

    def test_duplicate_missing_extra_and_inexact_ids_fail(self):
        expected, base = self.query()
        variants = [base['values'][:-1], base['values'] + [base['values'][0]],
                    [base['values'][0]] + base['values'][0:-1]]
        for rows in variants:
            with self.assertRaises(ValueError):
                oracle.validate_rows(dict(base, values=rows), expected, 7)
        for bad in [2**63, '0', str(2**64), '1.0']:
            result = copy.deepcopy(base)
            result['values'][0][result['columns'].index('id')] = bad
            with self.assertRaises(ValueError):
                oracle.validate_rows(result, expected, 7)

    def test_plan_is_offline_and_rejects_unbounded_or_injected_contracts(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([sys.executable, str(LAB / 'verify-protocol-product.py')],
                cwd=root, check=True, text=True, capture_output=True, timeout=5)
            self.assertFalse(json.loads(result.stdout)['execute'])
            self.assertEqual(list(Path(root).iterdir()), [])
        for value in [dict(self.contract(), count=0), dict(self.contract(), count=21),
                      dict(self.contract(), count=True), dict(self.contract(), marker="p6-' OR 1=1")]:
            with self.assertRaises(ValueError):
                oracle.expected_records(value)
