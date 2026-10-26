import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

LAB = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(LAB))
SPEC = importlib.util.spec_from_file_location("verify_tunnels", LAB / "verify-tunnels.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def manifest():
    value = {"marker": "tunnelcase1", "outer": {"source_ip": "198.18.0.240", "destination_ip": "198.18.0.79"}, "requests": []}
    for index, (flavor, decoded, policy, application) in enumerate([
        ("tencent-v0", 3, "retain", 20), ("nsh-md2", 5, "retain", 120), ("erspan-ii", 6, "trim", 20)]):
        resource = ("/tunnelcase1/%d" % index) if application == 20 else "q1.tunnelcase1.invalid"
        record = {"flavor": flavor, "protocol": application, "request_resource": resource,
                  "inner_5tuple": {"client_ip": "198.19.0.%d" % (index + 1), "server_ip": "198.18.1.79",
                                   "client_port": 41000 + index, "server_port": 18080 if application == 20 else 18053,
                                   "ip_protocol": 6 if application == 20 else 17},
                  "tunnel": {"decoded_type_id": decoded, "id": 0x123456, "policy": policy},
                  "expected_l7": {"request_resource": resource,
                                  "request_domain": "traflens-tunnel.invalid" if application == 20 else resource,
                                  "request_type": "GET" if application == 20 else "A", "response_status": 0,
                                  "response_code": 200 if application == 20 else 0,
                                  "response_result": "" if application == 20 else "A=198.18.2.2 TTL=60"}}
        if application == 120:
            record["dns"] = {"name": resource, "type": "A", "address": "198.18.2.2", "ttl": 60, "rcode": 0}
        value["requests"].append(record)
    return value


def response(fields, records):
    # Deliberately reorder columns to avoid positional implementation assumptions.
    columns = tuple(reversed(fields))
    return {"OPT_STATUS": "SUCCESS", "result": {"columns": columns,
            "values": [[record[name] for name in columns] for record in records]}}


class TunnelAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.document = manifest()
        _, self.expected = verify.normalize_manifest(self.document)
        self.ids = [(1 << 63) + index + 1 for index in range(3)]
        self.l7 = [dict(record["l7"], flow_id=ident) for ident, record in zip(self.ids, self.expected)]
        self.flows = dict(zip(self.ids, self.expected))
        self.l4 = [dict(record["inner"], **record["metadata"], flow_id=ident,
                        l7_protocol=record["l7"]["l7_protocol"], close_type=1,
                        total_packet_tx=2, total_packet_rx=2) for ident, record in self.flows.items()]

    def test_complete_l7_and_l4_contract_passes_independent_of_order(self):
        result, flows = verify.compare_l7(self.expected, response(verify.L7_FIELDS, list(reversed(self.l7))))
        self.assertTrue(result["exact_match"])
        self.assertEqual(set(flows), set(self.ids))
        result = verify.compare_l4(flows, response(verify.L4_FIELDS, list(reversed(self.l4))))
        self.assertTrue(result["passed"])
        self.assertEqual(result["complete_bidirectional_closing_flows"], 3)

    def test_duplicate_cannot_cover_missing_application_record(self):
        rows = [self.l7[0], self.l7[0], self.l7[2]]
        result, _ = verify.compare_l7(self.expected, response(verify.L7_FIELDS, rows))
        self.assertFalse(result["exact_match"])
        self.assertEqual((result["missing_rows"], result["unexpected_or_duplicate_rows"]), (1, 1))

    def test_wrong_l7_type_inner_tuple_status_and_dns_answer_fail(self):
        for field, value in (("tunnel_type", 0), ("ip_0", "198.19.99.1"), ("server_port", 18080),
                             ("protocol", 6), ("l7_protocol", 20), ("request_domain", "wrong.invalid"),
                             ("response_status", 3), ("response_code", 2),
                             ("response_result", "A=198.18.2.99 TTL=60")):
            rows = copy.deepcopy(self.l7)
            rows[1][field] = value
            with self.subTest(field=field):
                result, _ = verify.compare_l7(self.expected, response(verify.L7_FIELDS, rows))
                self.assertFalse(result["exact_match"])

    def test_partial_forced_report_is_allowed_but_not_sufficient(self):
        partial = copy.deepcopy(self.l4[0])
        partial.update(tunnel_rx_id=0, tunnel_rx_ip_0="::", tunnel_rx_ip_1="::",
                       total_packet_rx=0, close_type=5)
        result = verify.compare_l4(self.flows, response(verify.L4_FIELDS, [partial] + self.l4))
        self.assertTrue(result["passed"])
        self.assertEqual(result["rows_per_flow"][str(self.ids[0])], 2)
        result = verify.compare_l4(self.flows, response(verify.L4_FIELDS, [partial] + self.l4[1:]))
        self.assertFalse(result["passed"])
        self.assertEqual(result["missing_complete_flow_ids"], [str(self.ids[0])])

    def test_wrong_nonzero_metadata_fails_even_with_a_good_closing_report(self):
        for field, value in (("tunnel_tx_id", 999), ("tunnel_rx_id", 999),
                             ("tunnel_type", 5), ("tunnel_tier", 2),
                             ("tunnel_tx_ip_0", "198.18.0.12"), ("tunnel_rx_ip_1", "198.18.0.12")):
            bad = copy.deepcopy(self.l4[0])
            bad[field] = value
            bad["close_type"] = 5
            with self.subTest(field=field):
                result = verify.compare_l4(self.flows, response(verify.L4_FIELDS, [bad] + self.l4))
                self.assertFalse(result["passed"])
                self.assertTrue(result["contradictions"])

    def test_trim_discards_wire_id_and_requires_stored_zero_metadata(self):
        self.assertEqual(self.document["requests"][2]["tunnel"]["id"], 0x123456)
        expected = self.expected[2]["metadata"]
        self.assertEqual(expected["tunnel_type"], 0)
        self.assertEqual(expected["tunnel_tx_id"], 0)
        self.assertEqual(expected["tunnel_rx_ip_1"], "::")
        bad = copy.deepcopy(self.l4[2])
        bad["tunnel_tx_id"] = 0x123456
        result = verify.compare_l4(self.flows, response(verify.L4_FIELDS, [bad] + self.l4))
        self.assertFalse(result["passed"])

    def test_only_forced_reports_or_one_direction_cannot_prove_closure(self):
        for field, value in (("close_type", 5), ("close_type", 0), ("total_packet_tx", 0), ("total_packet_rx", 0)):
            rows = copy.deepcopy(self.l4)
            rows[0][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(verify.compare_l4(self.flows, response(verify.L4_FIELDS, rows))["passed"])

    def test_uint64_flow_ids_are_exact_and_floats_never_coerced(self):
        self.assertEqual(verify.flow_id(str((1 << 64) - 1)), (1 << 64) - 1)
        for value in (float(self.ids[0]), float(1 << 63), True, 0, -1, 1 << 64, "1) OR 1=1", "01"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                verify.flow_id(value)
        rows = copy.deepcopy(self.l7)
        rows[0]["flow_id"] = float(self.ids[0])
        with self.assertRaises(ValueError):
            verify.compare_l7(self.expected, response(verify.L7_FIELDS, rows))
        rows = copy.deepcopy(self.l7)
        rows[0]["flow_id"] = self.ids[1]
        with self.assertRaises(ValueError):
            verify.compare_l7(self.expected, response(verify.L7_FIELDS, rows))

    def test_unrelated_l4_flow_and_malformed_query_fail_closed(self):
        bad = copy.deepcopy(self.l4[0])
        bad["flow_id"] = (1 << 63) + 100
        with self.assertRaises(ValueError):
            verify.compare_l4(self.flows, response(verify.L4_FIELDS, [bad]))
        for query in ({"OPT_STATUS": "FAIL"}, {"OPT_STATUS": "SUCCESS", "result": {"columns": [], "values": []}},
                      {"OPT_STATUS": "SUCCESS", "result": {"columns": list(verify.L7_FIELDS), "values": [[1]]}}):
            with self.assertRaises(ValueError):
                verify.compare_l7(self.expected, query)

    def test_manifest_rejects_sql_injection_duplicate_resources_and_inner_tuple(self):
        for change in ("marker", "resource", "tuple", "policy"):
            value = copy.deepcopy(self.document)
            if change == "marker":
                value["marker"] = "a' OR 1=1"
            elif change == "resource":
                value["requests"][1] = copy.deepcopy(value["requests"][0])
            elif change == "tuple":
                value["requests"][2]["inner_5tuple"] = dict(value["requests"][0]["inner_5tuple"])
            else:
                value["requests"][0]["tunnel"]["policy"] = "unknown"
            with self.subTest(change=change), self.assertRaises(ValueError):
                verify.normalize_manifest(value)

    def test_owned_lab_scope_is_read_only_and_rejects_foreign_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "owner.json").write_text(json.dumps({"owner": verify.lab.PREFIX, "root": str(root)}))
            foreign = {"Config": {"Labels": {verify.lab.LABEL: "/foreign/lab"}}}
            with mock.patch.object(verify.subprocess, "run", return_value=mock.Mock(stdout=json.dumps([foreign]))) as run:
                with self.assertRaises(RuntimeError):
                    verify.owned_lab(root, 5)
                self.assertEqual(run.call_args.args[0][:3], ["docker", "container", "inspect"])


if __name__ == "__main__":
    unittest.main()
