import copy
import hashlib
import importlib.util
import ipaddress
import io
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


DIRECTORY = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, DIRECTORY / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


tunnel = load("tunnel_traffic", "tunnel-traffic.py")
dns = load("tunnel_traffic_dns_reference", "dns-traffic.py")


def sum16(data):
    """Independent residual checksum checker, not the generator's function."""
    total = 0
    for offset in range(0, len(data), 2):
        total += (data[offset] << 8) | (data[offset + 1] if offset + 1 < len(data) else 0)
        total = (total & 0xffff) + (total >> 16)
    return (total & 0xffff) + (total >> 16)


def read_ip(packet):
    version = packet[0] >> 4
    if version == 4:
        size = (packet[0] & 15) * 4
        assert size >= 20 and len(packet) >= size
        assert int.from_bytes(packet[2:4], "big") == len(packet)
        assert sum16(packet[:size]) == 0xffff
        source, destination, protocol = packet[12:16], packet[16:20], packet[9]
    else:
        assert version == 6 and len(packet) >= 40
        size = 40
        assert int.from_bytes(packet[4:6], "big") + 40 == len(packet)
        source, destination, protocol = packet[8:24], packet[24:40], packet[6]
    payload = packet[size:]
    if protocol in (6, 17):
        pseudo = source + destination
        pseudo += (b"\0" + bytes([protocol]) + struct.pack("!H", len(payload)) if version == 4
                   else struct.pack("!I", len(payload)) + b"\0\0\0" + bytes([protocol]))
        assert sum16(pseudo + payload) == 0xffff
    return version, str(ipaddress.ip_address(source)), str(ipaddress.ip_address(destination)), protocol, payload


def peel(frame):
    """Decode actual wire discriminators, independently of flavor names."""
    assert frame[:6] == bytes.fromhex("5847ca7766e2")
    assert frame[6:12] == bytes.fromhex("5847ca7c7859")
    assert frame[12:14] == b"\x08\0"
    _, source, destination, protocol, body = read_ip(frame[14:])
    assert source == "198.18.0.240" and destination == "198.18.0.79"
    ident = 0
    if protocol == 17:
        assert struct.unpack_from("!H", body, 2)[0] == 4790
        assert struct.unpack_from("!H", body, 4)[0] == len(body)
        gpe = body[8:]
        assert gpe[0] == 0x0c
        ident, next_protocol = int.from_bytes(gpe[4:7], "big"), gpe[3]
        content = gpe[8:]
        if next_protocol == 4:
            size = (content[1] & 63) * 4
            assert content[0] >> 6 == 0
            assert content[2] == 1 and size == 24 or content[2] == 2 and size >= 8
            next_protocol, content = content[3], content[size:]
        if next_protocol == 3:
            assert content[12:14] in (b"\x08\0", b"\x86\xdd")
            content = content[14:]
        else:
            assert next_protocol in (1, 2)
            assert content[0] >> 4 == (4 if next_protocol == 1 else 6)
        return read_ip(content), 5, ident
    assert protocol == 47
    flags, ether_type = struct.unpack_from("!HH", body)
    pos = 4
    if flags & 0x8000:
        pos += 4
    if flags & 0x2000:
        ident = int.from_bytes(body[pos:pos + 4], "big")
        pos += 4
    if flags & 0x1000:
        pos += 4
    if ether_type in (0x0800, 0x86dd):
        assert flags & 7 in (0, 1) and flags & 0x2000
        assert body[pos] >> 4 == (4 if ether_type == 0x0800 else 6)
        return read_ip(body[pos:]), 3, ident
    if ether_type in (0x88be, 0x22eb):
        if flags & 0x1000:
            header = body[pos:]
            assert header[0] >> 4 == (1 if ether_type == 0x88be else 2)
            ident = int.from_bytes(header[2:4], "big") & 0x3ff
            pos += 8 if ether_type == 0x88be else 12
        decoded_type = 6
    else:
        assert ether_type == 0x6558
        decoded_type = 7
    assert body[pos + 12:pos + 14] in (b"\x08\0", b"\x86\xdd")
    return read_ip(body[pos + 14:]), decoded_type, ident


class TunnelWireTests(unittest.TestCase):
    def test_independent_checksum_and_dns_vectors(self):
        self.assertEqual(tunnel.checksum(bytes.fromhex("0001f203f4f5f6f7")), 0x220d)
        query, response = tunnel.dns_pair(0x1234, "example.test", "198.18.0.1")
        self.assertEqual(query.hex(), "123401000001000000000000076578616d706c6504746573740000010001")
        self.assertEqual(response.hex(),
            "123481800001000100000000076578616d706c6504746573740000010001"
            "c00c000100010000003c0004c6120001")
        self.assertEqual(dns.verify_response(response, 0x1234, "example.test", "198.18.0.1")["ttl"], 60)

    def test_basic_and_full_matrix_counts_and_unique_five_tuples(self):
        for flavors, request_count, frame_count in [(tunnel.BASIC_FLAVORS, 16, 104),
                                                   (tunnel.FLAVORS, 40, 260)]:
            frames, expected, manifest = tunnel.generate("tn-wire-test", flavors)
            self.assertEqual((len(frames), len(manifest["requests"])), (frame_count, request_count))
            self.assertEqual(len(expected["http"]["records"]), request_count // 2)
            self.assertEqual(len(expected["dns"]["records"]), request_count // 2)
            tuples = [tuple(sorted(row["inner_5tuple"].items())) for row in manifest["requests"]]
            self.assertEqual(len(set(tuples)), request_count)
            resources = [row["request_resource"] for row in manifest["requests"]]
            self.assertEqual(len(set(resources)), request_count)
            self.assertEqual(sorted(i for row in manifest["requests"] for i in row["frame_indices"]),
                             list(range(frame_count)))

    def test_all_encapsulations_checksums_metadata_and_application_groundtruth(self):
        frames, _, manifest = tunnel.generate("tn-all-wire", tunnel.FLAVORS)
        for record in manifest["requests"]:
            with self.subTest(flavor=record["flavor"], ip=record["ip_version"],
                              application=record["protocol"]):
                flow = record["inner_5tuple"]
                rows = []
                for index in record["frame_indices"]:
                    parsed, decoded_type, ident = peel(frames[index])
                    self.assertEqual((decoded_type, ident), (record["tunnel"]["decoded_type_id"],
                                                           record["tunnel"]["id"]))
                    version, source, destination, protocol, body = parsed
                    self.assertEqual((version, protocol), (record["ip_version"], flow["ip_protocol"]))
                    self.assertEqual({source, destination}, {flow["client_ip"], flow["server_ip"]})
                    sport, dport = struct.unpack_from("!HH", body)
                    reverse = source == flow["server_ip"]
                    self.assertEqual((sport, dport),
                        (flow["server_port"], flow["client_port"]) if reverse
                        else (flow["client_port"], flow["server_port"]))
                    rows.append((reverse, body))
                application = record["expected_l7"]
                self.assertEqual(application["request_resource"], record["request_resource"])
                if record["protocol"] == 120:
                    self.assertEqual(len(rows), 2)
                    self.assertEqual([r[0] for r in rows], [False, True])
                    query, response = [body[8:] for _, body in rows]
                    wanted = record["dns"]
                    self.assertEqual(dns.parse_query(query), {"id": wanted["id"], "name": wanted["name"]})
                    parsed = dns.verify_response(response, wanted["id"], wanted["name"], wanted["address"])
                    self.assertEqual(parsed["rcode"], 0)
                    self.assertEqual(application["response_result"], "A=%s TTL=60" % wanted["address"])
                else:
                    self.assertEqual(len(rows), 11)
                    next_sequence = {}
                    payloads = {}
                    fins = []
                    for reverse, body in rows:
                        seq, ack = struct.unpack_from("!II", body, 4)
                        flags = body[13]
                        data = body[(body[12] >> 4) * 4:]
                        if reverse in next_sequence:
                            self.assertEqual(seq, next_sequence[reverse])
                        else:
                            self.assertTrue(flags & 2)
                        if flags & 0x10:
                            self.assertEqual(ack, next_sequence[not reverse])
                        else:
                            self.assertEqual(ack, 0)
                        next_sequence[reverse] = seq + len(data) + bool(flags & 2) + bool(flags & 1)
                        if data:
                            self.assertNotIn(reverse, payloads)
                            payloads[reverse] = data
                        if flags & 1:
                            fins.append(reverse)
                    self.assertEqual(fins, [False, True])
                    self.assertTrue(payloads[False].startswith(
                        ("GET %s HTTP/1.1\r\n" % record["request_resource"]).encode("ascii")))
                    self.assertIn(b"\r\nHost: traflens-tunnel.invalid\r\n", payloads[False])
                    header, body = payloads[True].split(b"\r\n\r\n", 1)
                    self.assertTrue(header.startswith(b"HTTP/1.1 200 OK\r\n"))
                    length = re_header(header, b"Content-Length")
                    self.assertEqual(int(length), len(body))
                    self.assertIn(manifest["marker"].encode("ascii"), body)

    def test_deterministic_json_and_pcap_packet_boundaries(self):
        left = tunnel.generate("tn-deterministic", tunnel.FLAVORS)
        right = tunnel.generate("tn-deterministic", tunnel.FLAVORS)
        self.assertEqual(left, right)
        pcap = tunnel.pcap_bytes(left[0])
        self.assertEqual(pcap, tunnel.pcap_bytes(right[0]))
        self.assertEqual(struct.unpack_from("<IHHIIII", pcap),
                         (0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        pos, timestamps, decoded = 24, [], []
        while pos < len(pcap):
            seconds, micros, captured, wire = struct.unpack_from("<IIII", pcap, pos)
            self.assertEqual(captured, wire)
            decoded.append(pcap[pos + 16:pos + 16 + captured])
            timestamps.append(seconds * 1000000 + micros)
            pos += 16 + captured
        self.assertEqual(decoded, left[0])
        self.assertTrue(all(b - a == 50000 for a, b in zip(timestamps, timestamps[1:])))
        self.assertEqual(pos, len(pcap))

    def test_markers_flavors_counts_and_aggregate_caps(self):
        for marker in ("", "UPPER", "bad.name", "-bad", "bad-", "a" * 25):
            with self.subTest(marker=marker), self.assertRaises(ValueError):
                tunnel.generate(marker)
        for flavors in ((), ("unknown",), ("teb", "teb")):
            with self.assertRaises(ValueError):
                tunnel.generate("tn-good", flavors)
        for count in (0, 21, 1.5):
            with self.assertRaises(ValueError):
                tunnel.generate("tn-good", count=count)
        with self.assertRaises(ValueError):
            tunnel.generate("tn-good", tunnel.FLAVORS, 4)
        self.assertEqual(len(tunnel.generate("tn-good", tunnel.FLAVORS, 3)[0]), 780)
        for pps, timeout in ((0, 120), (21, 120), (float("nan"), 120), (20, 121), (20, 0)):
            with self.assertRaises(ValueError):
                tunnel.validate_limits(1, pps, timeout)
        for value in ("teb,teb", "unknown", ""):
            with self.assertRaises(ValueError):
                tunnel.select_flavors(value)

    def test_scope_and_execute_rejections_never_open_a_socket(self):
        frames, _, _ = tunnel.generate("tn-scope", ("teb",))
        with mock.patch.object(tunnel.socket, "socket") as raw:
            with self.assertRaises(ValueError):
                tunnel.emit(frames)
            with self.assertRaises(ValueError):
                tunnel.emit(frames, execute=True, pps=21)
            with self.assertRaises(ValueError):
                tunnel.emit(frames, execute=True, pps=1, timeout=1)
            corrupted = bytearray(frames[0])
            corrupted[0] ^= 1
            with self.assertRaises(ValueError):
                tunnel.emit([bytes(corrupted)], execute=True)
            self.assertEqual(raw.call_count, 0)
        with mock.patch.object(tunnel.socket, "socket") as raw, \
             mock.patch.object(tunnel.Path, "read_text", return_value="00:00:00:00:00:00\n"):
            with self.assertRaises(ValueError):
                tunnel.emit(frames, execute=True)
            raw.assert_not_called()
        with self.assertRaises(ValueError):
            tunnel.check_interface("eth0")

    def test_send_failure_is_incomplete_and_never_retried(self):
        frames, _, _ = tunnel.generate("tn-failed", ("teb",))
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender
        sender.send.side_effect = OSError("injected link failure")
        with mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket", return_value=sender):
            result = tunnel.emit(frames, execute=True)
        self.assertFalse(result["complete"])
        self.assertEqual(result["sent_frames"], 0)
        self.assertIsNone(result["backend_acceptance"])
        self.assertEqual(len(result["errors"]), 1)
        self.assertEqual(sender.send.call_count, 1)

    def test_partial_send_stops_and_returns_failure(self):
        frames, _, _ = tunnel.generate("tn-partial", ("teb",))
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender
        sender.send.return_value = len(frames[0]) - 1
        with mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket", return_value=sender):
            result = tunnel.emit(frames, execute=True)
        self.assertFalse(result["complete"])
        self.assertEqual(result["sent_frames"], 0)
        self.assertEqual(sender.send.call_count, 1)

    def test_rate_limit_never_catches_up_with_a_burst(self):
        frames = tunnel.generate("tn-clock", ("teb",))[0][:3]
        clock = [10.0]
        sends = []
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender

        def send(frame):
            sends.append(clock[0])
            return len(frame)

        sender.send.side_effect = send
        with mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket", return_value=sender), \
             mock.patch.object(tunnel.time, "monotonic", side_effect=lambda: clock[0]), \
             mock.patch.object(tunnel.time, "sleep", side_effect=lambda delay: clock.__setitem__(0, clock[0] + delay)):
            result = tunnel.emit(frames, execute=True, pps=20)
        self.assertTrue(result["complete"])
        self.assertEqual(result["sent_frames"], 3)
        self.assertTrue(all(b - a >= 0.05 - 1e-9 for a, b in zip(sends, sends[1:])))
        sender.bind.assert_called_once_with(("enp2s0f0", 0))

    def test_send_exceeding_total_deadline_is_never_complete(self):
        frames = tunnel.generate("tn-deadline", ("teb",))[0][:2]
        clock = [10.0]
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender

        def late_send(frame):
            clock[0] += 2
            return len(frame)

        sender.send.side_effect = late_send
        with mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket", return_value=sender), \
             mock.patch.object(tunnel.time, "monotonic", side_effect=lambda: clock[0]):
            result = tunnel.emit(frames, execute=True, timeout=1)
        self.assertFalse(result["complete"])
        self.assertEqual(result["sent_frames"], 1)
        self.assertEqual(sender.send.call_count, 1)
        self.assertIn("deadline", result["errors"][0])

    def test_cli_invalid_execute_modes_and_wrong_interface_have_no_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "must-not-exist"
            base = ["tunnel-traffic.py", "--marker", "tn-no-send", "--output-dir", str(output)]
            for additions in (["plan", "--execute"], ["emit"], ["plan", "--interface", "eth0"]):
                with mock.patch.object(tunnel.sys, "argv", base + additions), \
                     mock.patch.object(tunnel.socket, "socket") as raw, \
                     mock.patch.object(tunnel.sys, "stderr"):
                    self.assertEqual(tunnel.main(), 1)
                raw.assert_not_called()
                self.assertFalse(output.exists())

    def test_checksum_valid_out_of_scope_outer_addresses_are_rejected(self):
        frame = tunnel.generate("tn-address", ("teb",))[0][0]
        for offset in (26, 30):
            bad = bytearray(frame)
            bad[offset:offset + 4] = ipaddress.IPv4Address("192.0.2.1").packed
            bad[24:26] = b"\0\0"
            bad[24:26] = struct.pack("!H", tunnel.checksum(bytes(bad[14:34])))
            self.assertEqual(sum16(bad[14:34]), 0xffff)
            with self.assertRaises(ValueError):
                tunnel.validate_frames([bytes(bad)])

    def test_cli_plan_has_no_socket_and_exports_compatible_documents(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "offline"
            command = [sys.executable, str(DIRECTORY / "tunnel-traffic.py"), "plan",
                       "--marker", "tn-cli", "--flavors", "basic", "--output-dir", str(output)]
            result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertEqual(result.returncode, 0, result.stderr)
            document = json.loads(result.stdout)
            self.assertFalse(document["executed"])
            self.assertEqual(document["sent_frames"], 0)
            for name, protocol in (("http", 20), ("dns", 120)):
                expected = json.loads((output / ("expected-" + name + ".json")).read_text())
                self.assertEqual(expected["protocol"], protocol)
                self.assertEqual(expected["marker"], "tn-cli")
                self.assertEqual(len(expected["records"]), 8)
                keys = {"request_resource", "request_type", "response_code", "response_status"}
                if name == "dns":
                    keys.add("response_result")
                self.assertTrue(all(set(record) == keys for record in expected["records"]))
            manifest = json.loads((output / "manifest.json").read_text())
            self.assertEqual(manifest["pcap_sha256"],
                             hashlib.sha256((output / "traffic.pcap").read_bytes()).hexdigest())
            # Existing output cannot be silently overwritten, including result.json.
            repeat = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(repeat.returncode, 0)


class LocalLeaseTests(unittest.TestCase):
    def setUp(self):
        self.marker = "tn-lease"
        self.lease = {"role": "dev-240", "status": "ready", "marker": self.marker,
                      "local": "198.18.0.240", "peer": "198.18.0.79",
                      "interface": "enp2s0f0", "mac": "58:47:ca:7c:78:59",
                      "lease_dir": "/tmp/traflens-tunnel-link-tn-lease",
                      "deadline_monotonic": 200,
                      "interface_identity": {"ifindex": 9, "ifname": "enp2s0f0",
                                            "address": "58:47:ca:7c:78:59"}}
        self.link = [{"ifindex": 9, "ifname": "enp2s0f0", "address": "58:47:ca:7c:78:59",
                      "flags": ["UP"], "operstate": "UP"}]
        self.addresses = [{"ifname": "enp2s0f0", "addr_info": [{
            "family": "inet", "local": "198.18.0.240", "prefixlen": 32, "label": "enp2s0f0:tlens"}]}]
        self.routes = [{"dst": "198.18.0.79", "dev": "enp2s0f0", "prefsrc": "198.18.0.240",
                        "metric": 42796, "protocol": "static", "table": "main"}]

    def guard(self):
        with mock.patch.object(tunnel.Path, "read_text", return_value=json.dumps(self.lease)), \
             mock.patch.object(tunnel, "ip_json", side_effect=[self.link, self.addresses, self.routes]), \
             mock.patch.object(tunnel.time, "monotonic", return_value=100):
            return tunnel.guard_local_lease(self.marker, 104, 20)

    def test_valid_lease_requires_exact_live_objects_and_documents_remote_limit(self):
        value = self.guard()
        self.assertEqual(value["ifindex"], 9)
        self.assertEqual(value["estimated_send_seconds"], 5.15)
        self.assertIn("dev-79", value["remote_readiness"])
        self.assertEqual(value["deadline_monotonic"], 200)

    def test_missing_finished_expired_or_wrong_role_lease_prevents_raw_socket(self):
        frames = tunnel.generate(self.marker, ("teb",))[0][:2]
        for field, value in (("role", "dev-79"), ("status", "finished"),
                             ("local", "192.0.2.1"), ("peer", "192.0.2.2"),
                             ("interface", "eth0"), ("mac", "00:00:00:00:00:00"),
                             ("marker", "other"), ("deadline_monotonic", 105),
                             ("deadline_monotonic", float("nan")), ("deadline_monotonic", True)):
            before = copy.deepcopy(self.lease)
            self.lease[field] = value
            with self.subTest(field=field, value=value), \
                 mock.patch.object(tunnel, "check_interface", return_value=9), \
                 mock.patch.object(tunnel.socket, "socket") as raw:
                with self.assertRaises(ValueError):
                    tunnel.emit(frames, execute=True, preflight=self.guard)
                raw.assert_not_called()
            self.lease = before
        with mock.patch.object(tunnel.Path, "read_text", side_effect=FileNotFoundError), \
             mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket") as raw:
            with self.assertRaises(FileNotFoundError):
                tunnel.emit(frames, execute=True,
                    preflight=lambda: tunnel.guard_local_lease(self.marker, len(frames), 20))
            raw.assert_not_called()

    def test_address_route_and_interface_ownership_changes_are_rejected(self):
        changes = [
            (self.link[0], "ifindex", 10), (self.link[0], "ifname", "management"),
            (self.link[0], "address", "00:00:00:00:00:00"),
            (self.addresses[0], "ifname", "management"),
            (self.addresses[0]["addr_info"][0], "prefixlen", 24),
            (self.addresses[0]["addr_info"][0], "label", "foreign"),
            (self.addresses[0]["addr_info"][0], "peer", "198.18.0.79"),
            (self.routes[0], "dst", "198.18.0.0/24"),
            (self.routes[0], "dev", "management"), (self.routes[0], "metric", 1),
            (self.routes[0], "prefsrc", "192.0.2.1"), (self.routes[0], "protocol", "kernel"),
            (self.routes[0], "table", 200), (self.routes[0], "gateway", "198.18.0.1"),
        ]
        for container, key, value in changes:
            had_key, old = key in container, container.get(key)
            container[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                self.guard()
            if had_key:
                container[key] = old
            else:
                del container[key]
        self.routes.append(copy.deepcopy(self.routes[0]))
        with self.assertRaises(ValueError):
            self.guard()

    def test_cli_plan_never_calls_lease_or_ip_inspection(self):
        with tempfile.TemporaryDirectory() as temporary, \
             mock.patch.object(tunnel.sys, "argv", ["tunnel-traffic.py", "plan", "--marker", self.marker,
                 "--output-dir", str(Path(temporary) / "plan")]), \
             mock.patch.object(tunnel.sys, "stdout", new_callable=io.StringIO), \
             mock.patch.object(tunnel, "guard_local_lease") as guard, \
             mock.patch.object(tunnel, "ip_json") as inspect, \
             mock.patch.object(tunnel.socket, "socket") as raw:
            self.assertEqual(tunnel.main(), 0)
        guard.assert_not_called()
        inspect.assert_not_called()
        raw.assert_not_called()

    def test_lease_remaining_time_caps_emit_even_if_requested_timeout_is_longer(self):
        frames = tunnel.generate(self.marker, ("teb",))[0][:2]
        clock = [100.0]
        sender = mock.MagicMock()
        sender.__enter__.return_value = sender

        def send(frame):
            clock[0] += 2
            return len(frame)

        sender.send.side_effect = send
        with mock.patch.object(tunnel, "check_interface", return_value=9), \
             mock.patch.object(tunnel.socket, "socket", return_value=sender), \
             mock.patch.object(tunnel.time, "monotonic", side_effect=lambda: clock[0]):
            result = tunnel.emit(frames, execute=True, timeout=120,
                preflight=lambda: {"ifindex": 9, "deadline_monotonic": 106})
        self.assertFalse(result["complete"])
        self.assertEqual(result["sent_frames"], 1)
        self.assertEqual(sender.send.call_count, 1)
        self.assertIn("deadline", result["errors"][0])

    def test_lease_expiry_or_ifindex_race_is_rechecked_before_opening_packet_socket(self):
        frames = tunnel.generate(self.marker, ("teb",))[0][:2]
        for lease in ({"ifindex": 9, "deadline_monotonic": 104},
                      {"ifindex": 10, "deadline_monotonic": 200}):
            with mock.patch.object(tunnel, "check_interface", return_value=9), \
                 mock.patch.object(tunnel.time, "monotonic", return_value=100), \
                 mock.patch.object(tunnel.socket, "socket") as raw:
                with self.assertRaises(ValueError):
                    tunnel.emit(frames, execute=True, preflight=lambda: lease)
                raw.assert_not_called()


def re_header(header, name):
    for line in header.split(b"\r\n")[1:]:
        key, value = line.split(b":", 1)
        if key.lower() == name.lower():
            return value.strip()
    raise AssertionError("Missing header " + name.decode())


if __name__ == "__main__":
    unittest.main()
