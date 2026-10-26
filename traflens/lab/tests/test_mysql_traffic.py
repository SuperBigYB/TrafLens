import importlib.util
from pathlib import Path
import socket
import struct
import threading
import time
import unittest

SPEC = importlib.util.spec_from_file_location("mysql_traffic", Path(__file__).resolve().parents[1] / "mysql-traffic.py")
mysql = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mysql)


class PacketContractTests(unittest.TestCase):
    def test_classic_header_length_excludes_header_and_command_resets_sequence(self):
        self.assertEqual(mysql.packet(b"\x03SELECT 1", 0), b"\x09\x00\x00\x00\x03SELECT 1")
        self.assertEqual(mysql.packet(mysql.EOF, 5), bytes.fromhex("05000005fe00000200"))

    def test_protocol41_login_offsets_empty_auth_and_no_tls(self):
        login = mysql.login()
        self.assertEqual(login[:9], bytes.fromhex("05a20800000001002d"))
        self.assertEqual(login[9:32], bytes(23))
        self.assertEqual(login[32:], b"traflens_fixture\0\0mysql_native_password\0")
        self.assertFalse(int.from_bytes(login[:4], "little") & 0x800)
        mysql.verify_login(login)

    def test_greeting_protocol10_scramble_and_plugin_layout(self):
        greeting = mysql.greeting()
        self.assertEqual(greeting[:8], b"\x0a5.7.44\0")
        self.assertEqual(greeting[8:21], b"\x01\x00\x00\x0012345678\0")
        self.assertEqual(greeting[21:39], bytes.fromhex("05a22d020008001500000000000000000000"))
        self.assertEqual(greeting[39:], b"abcdefghijkl\0mysql_native_password\0")
        self.assertEqual(mysql.verify_greeting(greeting)["protocol_version"], 10)

    def test_login_rejects_tls_nonempty_auth_and_missing_terminator(self):
        login = mysql.login()
        for invalid in (struct.pack("<I", mysql.CAPABILITIES | 0x800) + login[4:],
                        login[:49] + b"\x01x" + login[50:], login[:-1],
                        login[:9] + b"\x01" + login[10:]):
            with self.subTest(invalid=invalid[:9]), self.assertRaises(mysql.ProtocolError):
                mysql.verify_login(invalid)

    def test_one_column_text_result_layout_and_packet_sequences(self):
        record = mysql.query_record("contract", 7)
        self.assertEqual(record["request_resource"], "SELECT 'traflens-mysql-contract-0007' traflens_mysql_contract_0007")
        self.assertEqual(record["expected_response_code"], None)
        definition = mysql.column_definition("marker")
        self.assertEqual(definition, b"\x03def\0\0\0\x06marker\0\x0c" + bytes.fromhex("2d0000040000fd0000000000"))
        frames = mysql.result_frames(record)
        self.assertEqual([frame[3] for frame in frames], [1, 2, 3, 4, 5])
        self.assertEqual(frames[0], b"\x01\0\0\x01\x01")
        self.assertEqual(frames[2], bytes.fromhex("05000003fe00000200"))
        self.assertEqual(frames[4], bytes.fromhex("05000005fe00000200"))


@unittest.skipUnless(hasattr(socket, "socketpair"), "socketpair required")
class TransportTests(unittest.TestCase):
    def wire_pair(self):
        first, second = socket.socketpair()
        self.addCleanup(first.close)
        self.addCleanup(second.close)
        return first, second, mysql.Wire(first, time.monotonic() + 2)

    def test_receives_fragmented_header_and_body(self):
        unused_first, second, wire = self.wire_pair()
        frame = mysql.packet(b"\x03SELECT 1", 0)

        def fragmented_send():
            for byte in frame:
                second.sendall(bytes([byte]))
                time.sleep(0.001)

        sender = threading.Thread(target=fragmented_send)
        sender.start()
        self.assertEqual(wire.receive(0), b"\x03SELECT 1")
        sender.join(1)
        self.assertFalse(sender.is_alive())

    def test_rejects_wrong_sequence_oversize_and_truncated_packet(self):
        for frame in (b"\x01\0\0\x02x", b"\x01\0\x01\x00", b"\x03\0\0\0x"):
            with self.subTest(frame=frame):
                first, second = socket.socketpair()
                with first, second:
                    second.sendall(frame)
                    second.shutdown(socket.SHUT_WR)
                    with self.assertRaises(mysql.ProtocolError):
                        mysql.Wire(first, time.monotonic() + 1).receive(0)

    def test_total_deadline_stops_idle_peer(self):
        first, unused_second, unused_wire = self.wire_pair()
        started = time.monotonic()
        with self.assertRaises(TimeoutError):
            mysql.Wire(first, started + 0.03).receive(0)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_result_verification_rejects_wrong_row_or_column(self):
        record = mysql.query_record("negative", 0)
        for mutated in (dict(record, row_value="wrong"), dict(record, column_name="wrong")):
            with self.subTest(mutated=mutated):
                unused_first, second, wire = self.wire_pair()
                second.sendall(b"".join(mysql.result_frames(mutated)))
                with self.assertRaises(mysql.ProtocolError):
                    mysql.verify_result(wire, record)

    def test_full_handshake_twenty_unique_queries_results_and_quit(self):
        first, second = socket.socketpair()
        server_result, client_result, errors = {"records": []}, {"records": []}, []
        deadline = time.monotonic() + 3

        def server():
            try:
                with second:
                    mysql.serve_connection(second, "twenty", 20, deadline, server_result)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=server)
        worker.start()
        try:
            with first:
                mysql.client_connection(first, "twenty", 20, deadline, 0, client_result)
        finally:
            worker.join(4)
        self.assertFalse(worker.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(client_result["records"]), 20)
        resources = [record["request_resource"] for record in client_result["records"]]
        self.assertEqual(len(set(resources)), 20)
        self.assertEqual(resources, [record["request_resource"] for record in server_result["records"]])
        self.assertTrue(client_result["quit_verified"] and server_result["quit_verified"])

    def test_server_rejects_wrong_marker_query_after_valid_login(self):
        first, second = socket.socketpair()
        errors = []
        result = {"records": []}
        deadline = time.monotonic() + 2

        def server():
            try:
                with second:
                    mysql.serve_connection(second, "expected", 1, deadline, result)
            except Exception as error:
                errors.append(error)

        worker = threading.Thread(target=server)
        worker.start()
        try:
            with first:
                wire = mysql.Wire(first, deadline)
                wire.receive(0)
                wire.send(mysql.packet(mysql.login(), 1))
                self.assertEqual(wire.receive(2), mysql.OK)
                wire.send(mysql.packet(b"\x03SELECT 'wrong' unexpected", 0))
                wire.expect_close()
        finally:
            worker.join(3)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], mysql.ProtocolError)
        self.assertEqual(result["records"], [])


if __name__ == "__main__":
    unittest.main()
