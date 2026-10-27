import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('managed_ebpf_oracle', Path(__file__).resolve().parents[1] / 'verify-managed-ebpf.py')
oracle = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oracle)
MARKER = 'managed-unit-1'
AGENT = 7
PID = 1234
PORT = 18089
CLIENT_FLOW = 2 ** 63 + 1
SERVER_FLOW = 2 ** 63 + 2


def valid_rows():
    rows = oracle.expected_rows(MARKER, AGENT, PORT)
    for row in rows:
        client = row['observation_point'] == 'c-p'
        row.update(flow_id=CLIENT_FLOW if client else SERVER_FLOW, client_port=45678,
                   process_id_0=PID if client else 0, process_id_1=0 if client else PID)
    return rows


def response(rows):
    return {'OPT_STATUS': 'SUCCESS', 'result': {'columns': list(oracle.FIELDS),
            'values': [[r[k] for k in oracle.FIELDS] for r in rows]}}


def receipt(role):
    count = 20 if role == 'positive' else 40
    return {'pass': True, 'marker': MARKER, 'role': role, 'roundtrips': count,
            'records': [dict(request_resource=oracle.resource(MARKER, role, i),
                request_type='GET', response_code=200, request_bytes=140, response_bytes=110)
                for i in range(1, count + 1)]}


class ManagedEbpfOracleTests(unittest.TestCase):
    def compare(self, rows):
        return oracle.compare_positive(response(rows), MARKER, AGENT, PID, PORT)

    def test_both_same_pid_endpoints_need40_sessions(self):
        result = self.compare(valid_rows())
        self.assertTrue(result['passed'])
        self.assertEqual(result['rows'], 40)
        self.assertEqual(result['observation_point_counts'], {'c-p': 20, 's-p': 20})
        self.assertEqual(result['flow_ids'], {'c-p': [str(CLIENT_FLOW)], 's-p': [str(SERVER_FLOW)]})

    def test_single_endpoint20_is_not_this_topology(self):
        result = self.compare([r for r in valid_rows() if r['observation_point'] == 's-p'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['missing_rows'], 20)

    def test_duplicate_cannot_cover_missing_resource(self):
        rows = valid_rows()
        rows[-1] = copy.deepcopy(rows[1])
        result = self.compare(rows)
        self.assertFalse(result['passed'])
        self.assertEqual((result['missing_rows'], result['unexpected_or_duplicate_rows']), (1, 1))

    def test_wrong_source_agent_point_type_or_application_fails(self):
        for field, value in [('signal_source', 0), ('agent_id', AGENT + 1),
                ('observation_point', 's'), ('type', 0), ('response_code', 201),
                ('response_status', 2), ('request_domain', 'other.invalid'),
                ('server_port', 18080), ('l7_protocol', 21), ('protocol', 17), ('ip_1', '127.0.0.2')]:
            with self.subTest(field=field):
                rows = valid_rows(); rows[0][field] = value
                self.assertFalse(self.compare(rows)['passed'])

    def test_one_flow_id_cannot_stand_for_two_observation_points(self):
        rows = valid_rows()
        for row in rows:
            row['flow_id'] = CLIENT_FLOW
        self.assertFalse(self.compare(rows)['passed'])

    def test_endpoint_process_identity_and_other_side_zero(self):
        for index, field, value in [(0, 'process_id_0', PID + 1),
                (0, 'process_id_1', PID), (1, 'process_id_1', 1), (1, 'process_id_0', PID)]:
            with self.subTest(index=index, field=field):
                rows = valid_rows(); rows[index][field] = value
                self.assertFalse(self.compare(rows)['passed'])

    def test_more_than_one_client_port_or_socket_per_point_fails(self):
        for field, value in [('client_port', 45679), ('client_port', PORT), ('flow_id', CLIENT_FLOW + 20)]:
            with self.subTest(field=field, value=value):
                rows = valid_rows(); rows[0][field] = value
                self.assertFalse(self.compare(rows)['passed'])

    def test_full_precision_uint64_decimal_strings_are_valid(self):
        rows = valid_rows()
        for row in rows:
            row['flow_id'] = str(row['flow_id'])
        self.assertTrue(self.compare(rows)['passed'])

    def test_flow_float_bool_overflow_and_lossy_strings_rejected(self):
        for value in [float(CLIENT_FLOW), True, 0, -1, 2 ** 64, '01', '1.0', str(2 ** 64)]:
            with self.subTest(value=value):
                rows = valid_rows(); rows[0]['flow_id'] = value
                with self.assertRaises(ValueError):
                    self.compare(rows)

    def test_integer_fields_do_not_coerce_bool_float_or_strings(self):
        for field, value in [('response_status', False), ('response_code', 200.0),
                ('process_id_0', str(PID)), ('client_port', True)]:
            with self.subTest(field=field):
                rows = valid_rows(); rows[0][field] = value
                with self.assertRaises(ValueError):
                    self.compare(rows)

    def test_negative_empty_is_success_only_with_valid_schema(self):
        empty = response([])
        empty['result']['values'] = None
        self.assertEqual(oracle.query_rows(empty), [])
        for doc in [{'OPT_STATUS': 'FAIL', 'result': None}, {'OPT_STATUS': 'SUCCESS', 'result': None},
                    {'OPT_STATUS': 'SUCCESS', 'result': {'columns': [], 'values': None}},
                    {'OPT_STATUS': 'SUCCESS', 'result': {'columns': list(oracle.FIELDS), 'values': [None]}}]:
            with self.subTest(doc=doc):
                with self.assertRaises(ValueError):
                    oracle.query_rows(doc)

    def test_missing_values_key_is_not_a_successful_empty_result(self):
        missing = {'OPT_STATUS': 'SUCCESS', 'result': {'columns': list(oracle.FIELDS)}}
        with self.assertRaises(ValueError):
            oracle.query_rows(missing)
        for values in (None, []):
            with self.subTest(values=values):
                explicit = copy.deepcopy(missing)
                explicit['result']['values'] = values
                self.assertEqual(oracle.query_rows(explicit), [])

    def test_worker_receipts_exact20_and40(self):
        for role in ('positive', 'negative'):
            oracle.validate_receipt(receipt(role), MARKER, role)
            bad = receipt(role); bad['records'][-1] = copy.deepcopy(bad['records'][0])
            with self.assertRaises(ValueError):
                oracle.validate_receipt(bad, MARKER, role)

    def test_worker_failed_or_boolean_count_cannot_pass(self):
        for field, value in [('pass', False), ('roundtrips', True), ('role', 'negative')]:
            bad = receipt('positive'); bad[field] = value
            with self.assertRaises(ValueError):
                oracle.validate_receipt(bad, MARKER, 'positive')

    def test_sql_is_marker_only_and_rejects_injection(self):
        for negative in (False, True):
            where = oracle.sql_for(MARKER, negative).split(' WHERE ')[1]
            for field in ('signal_source', 'agent_id', 'observation_point', 'l7_protocol', 'response_status'):
                self.assertNotIn(field, where)
        self.assertIn("LIKE '%" + MARKER + "%'", oracle.sql_for(MARKER))
        self.assertIn('/negative/%', oracle.sql_for(MARKER, True))
        for mark in ["x' OR 1=1--", 'x_y', 'x%', '', 'a' * 25]:
            with self.assertRaises(ValueError):
                oracle.sql_for(mark)

    def test_strict_single_json_no_duplicates_nonfinite_or_bad_utf8(self):
        self.assertEqual(oracle.strict_json(b'{"id":9223372036854775809}'), {'id': CLIENT_FLOW})
        for raw in [b'{}{}', b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":"\xff"}', b'']:
            with self.subTest(raw=raw):
                with self.assertRaises((ValueError, UnicodeError)):
                    oracle.strict_json(raw)

    def test_wrong_owner_or_query_binding_fails_before_any_http(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            (root / 'owner.json').write_text(json.dumps({'owner': 'traflens-lab', 'root': str(root)}))
            good = {'Config': {'Labels': {'io.traflens.lab': str(root)}},
                    'State': {'Running': True, 'StartedAt': 'same'}, 'Id': 'same', 'Image': 'same',
                    'HostConfig': {'PortBindings': {'20416/tcp': [{'HostIp': '127.0.0.1', 'HostPort': '20416'}]}}}
            for change in ('owner', 'binding', 'stopped'):
                info = copy.deepcopy(good)
                if change == 'owner': info['Config']['Labels']['io.traflens.lab'] = '/other'
                if change == 'binding': info['HostConfig']['PortBindings']['20416/tcp'][0]['HostIp'] = '0.0.0.0'
                if change == 'stopped': info['State']['Running'] = False
                result = mock.Mock(stdout=json.dumps([info]))
                with mock.patch.object(oracle.subprocess, 'run', return_value=result), self.assertRaises(ValueError):
                    oracle.owned_scope(root, 1)


if __name__ == '__main__':
    unittest.main()
