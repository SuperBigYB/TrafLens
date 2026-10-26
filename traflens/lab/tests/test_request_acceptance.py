from copy import deepcopy
import importlib.util
from pathlib import Path
import sys
import unittest

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
spec = importlib.util.spec_from_file_location('verify_requests', LAB / 'verify-requests.py')
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class RequestAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.expected = {"marker": "case-one", "protocol": 120, "records": [
            {"request_resource": "q0.case-one.invalid", "request_type": "A", "response_code": 0, "response_status": 0, "response_result": "A=198.18.0.1 TTL=60"},
            {"request_resource": "q1.case-one.invalid", "request_type": "A", "response_code": 0, "response_status": 0, "response_result": "A=198.18.0.2 TTL=60"}]}
        self.fields = verify.validate_expected(self.expected)
        self.query = {"OPT_STATUS": "SUCCESS", "result": {"columns": list(reversed(self.fields)),
                      "values": [[record[field] for field in reversed(self.fields)]
                                 for record in reversed(self.expected["records"])]}}

    def test_exact_records_ignore_order_and_column_order(self):
        self.assertTrue(verify.compare_records(self.expected["records"], self.query, self.fields)["exact_match"])

    def test_duplicate_cannot_hide_missing_resource(self):
        self.query["result"]["values"][1] = self.query["result"]["values"][0]
        result = verify.compare_records(self.expected["records"], self.query, self.fields)
        self.assertFalse(result["exact_match"])
        self.assertEqual(result["missing_rows"], 1)
        self.assertEqual(result["unexpected_or_duplicate_rows"], 1)

    def test_error_status_or_null_code_does_not_match_success(self):
        for field, value in (("response_status", 2), ("response_code", None)):
            query = deepcopy(self.query)
            query["result"]["values"][0][query["result"]["columns"].index(field)] = value
            with self.subTest(field=field):
                self.assertFalse(verify.compare_records(self.expected["records"], query, self.fields)["exact_match"])

    def test_query_failure_or_missing_fields_fail_closed(self):
        with self.assertRaises(RuntimeError):
            verify.compare_records(self.expected["records"], {"OPT_STATUS": "FAIL"}, self.fields)
        for query in ({"OPT_STATUS": "SUCCESS", "result": {"columns": [], "values": []}},
                      {"OPT_STATUS": "SUCCESS", "result": {"columns": list(self.fields), "values": [[1]]}}):
            with self.assertRaises(ValueError):
                verify.compare_records(self.expected["records"], query, self.fields)

    def test_dns_requires_exact_answer_and_ttl(self):
        expected = deepcopy(self.expected)
        for record in expected["records"]:
            del record["response_result"]
        with self.assertRaises(ValueError):
            verify.validate_expected(expected)
        query = deepcopy(self.query)
        query["result"]["values"][0][query["result"]["columns"].index("response_result")] = "A=203.0.113.1 TTL=60"
        self.assertFalse(verify.compare_records(self.expected["records"], query, self.fields)["exact_match"])

    def test_marker_injection_and_duplicate_expectations_rejected(self):
        for marker in ("x' OR 1=1", "a%b", "a_b"):
            expected = dict(self.expected, marker=marker)
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                verify.validate_expected(expected)
        self.expected["records"][1] = self.expected["records"][0]
        with self.assertRaises(ValueError):
            verify.validate_expected(self.expected)


if __name__ == '__main__':
    unittest.main()
