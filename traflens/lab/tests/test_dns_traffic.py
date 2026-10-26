import importlib.util
import ipaddress
from pathlib import Path
import struct
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("dns_traffic", Path(__file__).resolve().parents[1] / "dns-traffic.py")
dns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dns)


class DNSWireTests(unittest.TestCase):
    def setUp(self):
        self.value = dns.workload("test-20261026", 20)[0]
        self.query = dns.build_query(self.value["id"], self.value["name"])
        self.response = dns.build_response(self.query, self.value["address"])

    def test_independent_wire_vectors(self):
        query = bytes.fromhex("123401000001000000000000076578616d706c6504746573740000010001")
        response = bytes.fromhex(
            "123481800001000100000000076578616d706c6504746573740000010001"
            "c00c000100010000003c0004c6120001")
        self.assertEqual(dns.build_query(0x1234, "example.test"), query)
        self.assertEqual(dns.build_response(query, "198.18.0.1"), response)
        self.assertEqual(dns.parse_query(query), {"id": 0x1234, "name": "example.test"})
        self.assertEqual(dns.parse_response(response), {
            "id": 0x1234, "name": "example.test", "answer_name": "example.test",
            "address": "198.18.0.1", "rcode": 0, "ttl": 60})

    def test_twenty_unique_queries_and_compressed_a_answers(self):
        values = dns.workload("test-20261026", 20)
        self.assertEqual(len({value["name"] for value in values}), 20)
        self.assertEqual(len({value["id"] for value in values}), 20)
        self.assertEqual(values[0]["address"], "198.18.0.1")
        self.assertEqual(values[-1]["address"], "198.18.0.20")
        for value in values:
            with self.subTest(sequence=value["sequence"]):
                query = dns.build_query(value["id"], value["name"])
                self.assertEqual(dns.parse_query(query), {"id": value["id"], "name": value["name"]})
                response = dns.build_response(query, value["address"])
                self.assertEqual(response[len(query):len(query) + 2], b"\xc0\x0c")
                parsed = dns.verify_response(response, value["id"], value["name"], value["address"])
                self.assertEqual(parsed["rcode"], 0)
                self.assertEqual(parsed["ttl"], 60)

    def test_accepts_uncompressed_answer_name(self):
        response = (self.response[:len(self.query)] + dns.encode_name(self.value["name"])
                    + self.response[len(self.query) + 2:])
        self.assertEqual(dns.parse_response(response)["answer_name"], self.value["name"])

    def test_name_wire_roundtrip_and_limits(self):
        encoded = dns.encode_name("Example.TEST.")
        self.assertEqual(dns.decode_name(encoded, 0), ("example.test", len(encoded)))
        for name in ("", "bad..test", "-bad.test", "bad-.test", "x" * 64 + ".test",
                     ".".join(["a" * 63] * 4), "not_ascii_\u00e9.test"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                dns.encode_name(name)

    def test_rejects_truncated_and_cyclic_compression(self):
        for payload, offset in ((b"\xc0", 0), (b"\xc0\x00", 0),
                                (b"\xc0\xff", 0), (b"\x00\xc0\x02", 1),
                                (b"\x40x", 0), (b"\x03ab", 0),
                                (b"\x01\xff\x00", 0), (b"\0", -1)):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                dns.decode_name(payload, offset)

    def test_rejects_expansion_beyond_dns_limit(self):
        payload = (b"\x3f" + b"a" * 63) * 4 + b"\0"
        with self.assertRaises(ValueError):
            dns.decode_name(payload, 0)

    def test_rejects_truncated_queries_and_trailing_data(self):
        for payload in (self.query[:11], self.query[:-1], self.query + b"x", b"x" * 513):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                dns.parse_query(payload)

    def test_rejects_wrong_query_header_type_and_class(self):
        variants = []
        for offset, value in ((2, 0x8100), (2, 0x0300), (4, 2), (6, 1),
                              (8, 1), (10, 1), (len(self.query) - 4, 28),
                              (len(self.query) - 2, 3)):
            payload = bytearray(self.query)
            struct.pack_into("!H", payload, offset, value)
            variants.append(bytes(payload))
        for payload in variants:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                dns.parse_query(payload)

    def test_rejects_response_truncation_and_bad_a_record(self):
        variants = [self.response[:11], self.response[:-1], self.response + b"x"]
        for offset, value in ((2, 0x8380), (6, 0), (len(self.query) + 2, 28),
                              (len(self.response) - 6, 3)):
            payload = bytearray(self.response)
            struct.pack_into("!H", payload, offset, value)
            variants.append(bytes(payload))
        for payload in variants:
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                dns.parse_response(payload)

    def test_verification_rejects_wrong_id_name_address_and_rcode(self):
        expected = (self.value["id"], self.value["name"], self.value["address"])
        for args in ((expected[0] + 1, expected[1], expected[2]),
                     (expected[0], "other.test", expected[2]),
                     (expected[0], expected[1], "198.18.0.99")):
            with self.subTest(args=args), self.assertRaises(ValueError):
                dns.verify_response(self.response, *args)
        for flags in (0x8182, 0x8183):
            payload = bytearray(self.response)
            struct.pack_into("!H", payload, 2, flags)
            self.assertNotEqual(dns.parse_response(payload)["rcode"], 0)
            with self.assertRaises(ValueError):
                dns.verify_response(payload, *expected)

    def test_verification_rejects_wrong_answer_name_and_ttl(self):
        answer = dns.encode_name("other.test") + self.response[len(self.query) + 2:]
        with self.assertRaises(ValueError):
            dns.verify_response(self.response[:len(self.query)] + answer,
                                self.value["id"], self.value["name"], self.value["address"])
        payload = bytearray(self.response)
        struct.pack_into("!I", payload, len(self.query) + 6, 123)
        with self.assertRaises(ValueError):
            dns.verify_response(payload, self.value["id"], self.value["name"], self.value["address"])

    def test_workload_and_ids_are_bounded(self):
        for marker, count in (("Bad", 20), ("bad.name", 20), ("-bad", 20),
                              ("good", 0), ("good", 1001)):
            with self.subTest(marker=marker, count=count), self.assertRaises(ValueError):
                dns.workload(marker, count)
        for ident in (-1, 65536):
            with self.assertRaises(ValueError):
                dns.build_query(ident, "test.invalid")
        self.assertTrue(ipaddress.IPv4Address(dns.workload("good", 1000)[-1]["address"]) in
                        ipaddress.IPv4Network("198.18.0.0/15"))

    def test_scoped_endpoint_requires_linklocal_and_explicit_interface(self):
        with mock.patch.object(dns.socket, "if_nametoindex", return_value=17) as interface:
            self.assertEqual(dns.scoped_endpoint("fe80::1", 18053, "enp1s0f0"),
                             ("fe80::1", 18053, 0, 17))
            interface.assert_called_once_with("enp1s0f0")
        for address in ("::1", "2001:db8::1", "192.168.1.240", "fe80::1%enp1s0f0"):
            with self.subTest(address=address), self.assertRaises(ValueError):
                dns.scoped_endpoint(address, 18053, "enp1s0f0")


if __name__ == "__main__":
    unittest.main()
