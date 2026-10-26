#!/usr/bin/env python3
"""Bounded synthetic tunnel wire fixture: offline plan/PCAP, explicit raw emit.

This constructs both directions of HTTP and DNS conversations; there is no real
HTTP server/browser or DNS resolver. Successful send() is not backend acceptance.
Only emit --execute can open AF_PACKET, on dev-240's known enp2s0f0/MAC toward
the fixed directly connected dev-79 MAC. CLI emit requires a matching, live local
tunnel-link lease and verifies its exact benchmark address/route before AF_PACKET.
The coordinator must independently prove dev-79 is ready for the entire send;
this local check cannot prove remote readiness. No network settings change.

Primary wire references:
https://www.rfc-editor.org/rfc/rfc1035.html
https://www.rfc-editor.org/rfc/rfc768.html
https://www.rfc-editor.org/rfc/rfc9293.html
https://www.rfc-editor.org/rfc/rfc8200.html
https://www.rfc-editor.org/rfc/rfc9112.html
https://www.rfc-editor.org/rfc/rfc2784.html
https://www.rfc-editor.org/rfc/rfc2890.html
https://datatracker.ietf.org/doc/html/draft-foschiano-erspan-03 (expired draft)
https://www.ietf.org/archive/id/draft-ietf-nvo3-vxlan-gpe-13.html (expired draft)
https://www.rfc-editor.org/rfc/rfc8300.html
Tencent version one/key-to-pseudo-MAC follows the repository's existing Apache
Go decoder and tencent-gre.pcap, not the standard PPTP version-one GRE format.
"""

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import time


INTERFACE = "enp2s0f0"
SOURCE_MAC = "58:47:ca:7c:78:59"
DESTINATION_MAC = "58:47:ca:77:66:e2"
OUTER_SOURCE = "198.18.0.240"
OUTER_DESTINATION = "198.18.0.79"
CLIENT_MAC = bytes.fromhex("02746c000001")
SERVER_MAC = bytes.fromhex("02746c000002")
MAX_FRAMES = 1000
MAX_PPS = 20
MAX_TIMEOUT = 120
MAX_FRAME_BYTES = 1514
TTL = 60
BASIC_FLAVORS = ("erspan-ii", "teb", "tencent-v0", "gpe-ethernet")
FLAVORS = (
    "erspan-i", "erspan-ii", "erspan-iii", "teb", "tencent-v0",
    "tencent-v1", "gpe-ethernet", "gpe-raw-ipv4", "gpe-raw-ipv6",
    "nsh-md1", "nsh-md2",
)
MARKER = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,22}[a-z0-9])?", re.ASCII)


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def mac_bytes(value):
    return bytes.fromhex(value.replace(":", ""))


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def pseudo_header(source, destination, protocol, size):
    source = ipaddress.ip_address(source)
    destination = ipaddress.ip_address(destination)
    if source.version != destination.version:
        raise ValueError("Mixed IP families")
    if source.version == 4:
        return source.packed + destination.packed + struct.pack("!BBH", 0, protocol, size)
    return source.packed + destination.packed + struct.pack("!I3xB", size, protocol)


def ip_packet(source, destination, protocol, payload, ident):
    source = ipaddress.ip_address(source)
    destination = ipaddress.ip_address(destination)
    if source.version != destination.version or len(payload) > 1400:
        raise ValueError("IP family mismatch or payload exceeds fixture MTU")
    if source.version == 6:
        return struct.pack("!IHBB16s16s", 6 << 28, len(payload), protocol, 64,
                           source.packed, destination.packed) + payload
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload),
                         ident & 0xffff, 0x4000, 64, protocol, 0,
                         source.packed, destination.packed)
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + payload


def udp_packet(source, destination, source_port, destination_port, payload):
    value = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    check = checksum(pseudo_header(source, destination, 17, len(value)) + value) or 0xffff
    return value[:6] + struct.pack("!H", check) + value[8:]


def tcp_packet(source, destination, source_port, destination_port, seq, ack, flags, payload=b""):
    value = struct.pack("!HHIIBBHHH", source_port, destination_port, seq, ack,
                        0x50, flags, 32768, 0, 0) + payload
    check = checksum(pseudo_header(source, destination, 6, len(value)) + value)
    return value[:16] + struct.pack("!H", check) + value[18:]


def dns_pair(ident, name, address):
    labels = name.split(".")
    if any(not re.fullmatch(r"[a-z0-9-]{1,63}", label) for label in labels):
        raise ValueError("Invalid fixture DNS name")
    question = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    question += struct.pack("!HH", 1, 1)
    query = struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + question
    response = (struct.pack("!6H", ident, 0x8180, 1, 1, 0, 0) + question + b"\xc0\x0c"
                + struct.pack("!HHIH", 1, 1, TTL, 4) + ipaddress.IPv4Address(address).packed)
    return query, response


def http_conversation(path, token, ordinal):
    request = ("GET %s HTTP/1.1\r\nHost: traflens-tunnel.invalid\r\n"
               "Connection: close\r\n\r\n" % path).encode("ascii")
    body = (token + "\n").encode("ascii")
    response = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode("ascii") + body
    client, server = 0x10000000 + ordinal * 65536, 0x70000000 + ordinal * 65536
    cnext, snext = client + 1, server + 1
    cend, send = cnext + len(request), snext + len(response)
    # SYN and FIN each consume one sequence number; all ACKs cover actual bytes.
    return [
        (False, client, 0, 0x02, b""),
        (True, server, cnext, 0x12, b""),
        (False, cnext, snext, 0x10, b""),
        (False, cnext, snext, 0x18, request),
        (True, snext, cend, 0x10, b""),
        (True, snext, cend, 0x18, response),
        (False, cend, send, 0x10, b""),
        (False, cend, send, 0x11, b""),
        (True, send, cend + 1, 0x10, b""),
        (True, send, cend + 1, 0x11, b""),
        (False, cend + 1, send + 1, 0x10, b""),
    ]


def tunnel_properties(flavor):
    if flavor.startswith("erspan"):
        ident = {"erspan-i": 0, "erspan-ii": 0x12a, "erspan-iii": 0x155}[flavor]
        return {"decoded_type": "ERSPAN", "decoded_type_id": 6,
                "id": ident, "policy": "trim"}
    if flavor == "teb":
        return {"decoded_type": "TEB", "decoded_type_id": 7,
                "id": 0x1234abcd, "policy": "trim"}
    if flavor.startswith("tencent"):
        return {"decoded_type": "TencentGre", "decoded_type_id": 3,
                "id": 0x00010285 if flavor == "tencent-v0" else 0x9abc1234,
                "policy": "retain"}
    return {"decoded_type": "VxlanNsh", "decoded_type_id": 5,
            "id": 0x123450 + FLAVORS.index(flavor), "policy": "retain"}


def encapsulate(flavor, inner_ip, reverse, sequence):
    version = inner_ip[0] >> 4
    if flavor not in FLAVORS or version not in (4, 6):
        raise ValueError("Unsupported tunnel or inner IP family")
    if (flavor == "gpe-raw-ipv4" and version != 4
            or flavor == "gpe-raw-ipv6" and version != 6):
        raise ValueError("GPE raw flavor must agree with the actual IP family")
    ether_type = 0x0800 if version == 4 else 0x86dd
    source_mac, destination_mac = ((SERVER_MAC, CLIENT_MAC) if reverse
                                   else (CLIENT_MAC, SERVER_MAC))
    ethernet = destination_mac + source_mac + struct.pack("!H", ether_type) + inner_ip
    props = tunnel_properties(flavor)
    ident = props["id"]
    if flavor == "erspan-i":
        payload = struct.pack("!HH", 0, 0x88be) + ethernet
    elif flavor in ("erspan-ii", "erspan-iii"):
        protocol = 0x88be if flavor == "erspan-ii" else 0x22eb
        gre = struct.pack("!HHI", 0x1000, protocol, sequence)
        if flavor == "erspan-ii":
            header = struct.pack("!HHI", 0x1000, ident, 0)
        else:
            # FT=0 (Ethernet), O=0 (no platform-specific eight-byte subheader).
            header = struct.pack("!HHII", 0x2000, ident, sequence * 100, 0)
        payload = gre + header + ethernet
    elif flavor == "teb":
        payload = struct.pack("!HHI", 0x2000, 0x6558, ident) + ethernet
    elif flavor.startswith("tencent"):
        flags = 0x2000 if flavor == "tencent-v0" else 0x3001
        payload = struct.pack("!HHI", flags, ether_type, ident)
        if flags & 0x1000:
            payload += struct.pack("!I", sequence)
        payload += inner_ip
    else:
        next_protocol = 3 if flavor == "gpe-ethernet" else (1 if version == 4 else 2)
        content = ethernet if next_protocol == 3 else inner_ip
        if flavor.startswith("nsh"):
            if flavor == "nsh-md1":
                metadata = struct.pack("!4I", 1, 2, 3, 4)
                md_type = 1
            else:
                metadata = b"\xff\xf5\x01\x03\x01\x02\x03\0"
                md_type = 2
                next_protocol, content = 3, ethernet
            nsh = bytes([0x0f, 0xc0 | ((8 + len(metadata)) // 4), md_type, next_protocol])
            nsh += b"\x12\x34\x56\xff" + metadata
            content = nsh + content
            next_protocol = 4
        gpe = bytes([0x0c, 0, 0, next_protocol]) + ident.to_bytes(3, "big") + b"\0"
        payload = udp_packet(OUTER_SOURCE, OUTER_DESTINATION, 40000, 4790, gpe + content)
    outer_protocol = 17 if flavor.startswith(("gpe", "nsh")) else 47
    outer = ip_packet(OUTER_SOURCE, OUTER_DESTINATION, outer_protocol, payload, sequence)
    frame = mac_bytes(DESTINATION_MAC) + mac_bytes(SOURCE_MAC) + b"\x08\0" + outer
    if len(frame) > MAX_FRAME_BYTES:
        raise ValueError("Fixture frame exceeds the link MTU")
    return frame


def select_flavors(value):
    if value == "basic":
        return BASIC_FLAVORS
    if value == "all":
        return FLAVORS
    values = tuple(value.split(","))
    if not values or len(set(values)) != len(values) or any(v not in FLAVORS for v in values):
        raise ValueError("Use basic, all, or a comma-separated unique known flavor list")
    return values


def validate_limits(count, pps, timeout):
    if type(count) is not int or not 1 <= count <= 20:
        raise ValueError("Count must be 1-20 per flavor/IP/protocol")
    if not isinstance(pps, (int, float)) or not 1 <= pps <= MAX_PPS:
        raise ValueError("Frame rate must be 1-20 packets/second")
    if not isinstance(timeout, (int, float)) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ValueError("Timeout must be 1-120 seconds")


def generate(marker, flavors=BASIC_FLAVORS, count=1):
    if not isinstance(marker, str) or not MARKER.fullmatch(marker):
        raise ValueError("Marker must be a lowercase DNS label of 1-24 characters")
    validate_limits(count, MAX_PPS, MAX_TIMEOUT)
    if not flavors or len(set(flavors)) != len(flavors) or any(f not in FLAVORS for f in flavors):
        raise ValueError("Invalid or repeated tunnel flavors")
    frames, requests = [], []
    expected = {"http": {"marker": marker, "protocol": 20, "records": []},
                "dns": {"marker": marker, "protocol": 120, "records": []}}
    seed = int.from_bytes(hashlib.sha256(marker.encode("ascii")).digest()[:2], "big")
    for flavor in flavors:
        for version in (4, 6):
            if (flavor == "gpe-raw-ipv4" and version != 4
                    or flavor == "gpe-raw-ipv6" and version != 6):
                continue
            for protocol in ("http", "dns"):
                for number in range(count):
                    ordinal = len(requests)
                    suffix = "%s.v%d.%d" % (flavor, version, number)
                    token = marker + "." + suffix
                    port = 30000 + (seed % 20000) + ordinal
                    host = ((seed + ordinal) % 65534) + 1
                    client = (str(ipaddress.IPv4Address("198.19.0.0") + host) if version == 4
                              else "fd00:7472:%x::%x" % (seed, ordinal + 1))
                    server = "198.18.1.79" if version == 4 else "fd00:7472::79"
                    server_port = 18080 if protocol == "http" else 18053
                    resource = ("/traflens-tunnel/%s/%s/v%d/%d" % (marker, flavor, version, number)
                                if protocol == "http" else token + ".traflens.invalid")
                    expected_record = {"request_resource": resource,
                                       "request_type": "GET" if protocol == "http" else "A",
                                       "response_code": 200 if protocol == "http" else 0,
                                       "response_status": 0}
                    address = str(ipaddress.IPv4Address("198.18.2.1") + ordinal)
                    if protocol == "dns":
                        expected_record["response_result"] = "A=%s TTL=60" % address
                    expected[protocol]["records"].append(expected_record)
                    begin = len(frames)
                    application = dict(expected_record,
                        request_domain="traflens-tunnel.invalid" if protocol == "http" else resource)
                    application.setdefault("response_result", "")
                    info = {"request_resource": resource, "protocol": expected[protocol]["protocol"],
                            "expected_l7": application,
                            "flavor": flavor, "ip_version": version, "sequence": number,
                            "inner_5tuple": {"client_ip": client, "server_ip": server,
                                "client_port": port, "server_port": server_port,
                                "ip_protocol": 6 if protocol == "http" else 17},
                            "tunnel": tunnel_properties(flavor)}
                    if protocol == "http":
                        wire = http_conversation(resource, token, ordinal)
                    else:
                        ident = 0xa000 + ordinal
                        query, response = dns_pair(ident, resource, address)
                        wire = [(False, 0, 0, 0, query), (True, 0, 0, 0, response)]
                        info["dns"] = {"id": ident, "name": resource, "type": "A",
                                       "rcode": 0, "address": address, "ttl": TTL}
                    for reverse, seq, ack, flags, data in wire:
                        source, destination = (server, client) if reverse else (client, server)
                        sport, dport = (server_port, port) if reverse else (port, server_port)
                        transport = (tcp_packet(source, destination, sport, dport, seq, ack, flags, data)
                                     if protocol == "http"
                                     else udp_packet(source, destination, sport, dport, data))
                        inner = ip_packet(source, destination, 6 if protocol == "http" else 17,
                                          transport, len(frames) + 1)
                        frames.append(encapsulate(flavor, inner, reverse, len(frames) + 1))
                    info["frame_indices"] = list(range(begin, len(frames)))
                    requests.append(info)
                    if len(frames) > MAX_FRAMES:
                        raise ValueError("Aggregate workload exceeds 1000 frames")
    manifest = {"schema_version": 1, "marker": marker, "flavors": list(flavors),
                "count_per_flavor_ip_protocol": count, "frame_count": len(frames),
                "request_count": len(requests), "real_http_service": False,
                "synthetic_wire": True,
                "pcap_timestamps": "Deterministic synthetic epoch 1700000000; actual emit UTC times are in result.json",
                "scope": "Synthetic wire conversations; send success is not backend acceptance",
                "outer": {"interface": INTERFACE, "source_mac": SOURCE_MAC,
                          "destination_mac": DESTINATION_MAC, "source_ip": OUTER_SOURCE,
                          "destination_ip": OUTER_DESTINATION,
                          "receiver_interface": "enp1s0f0"},
                "acceptance_files": {"http": "expected-http.json", "dns": "expected-dns.json"},
                "requests": requests}
    return frames, expected, manifest


def pcap_bytes(frames, pps=MAX_PPS):
    value = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(frames):
        micros = round(index * 1000000 / pps)
        value.extend(struct.pack("<IIII", 1700000000 + micros // 1000000,
                                 micros % 1000000, len(frame), len(frame)))
        value.extend(frame)
    return bytes(value)


def validate_frames(frames):
    if not 1 <= len(frames) <= MAX_FRAMES:
        raise ValueError("Raw send requires 1-1000 frames")
    prefix = mac_bytes(DESTINATION_MAC) + mac_bytes(SOURCE_MAC) + b"\x08\0"
    for frame in frames:
        if not 34 <= len(frame) <= MAX_FRAME_BYTES or frame[:14] != prefix:
            raise ValueError("Frame escaped the fixed Ethernet scope")
        if (frame[14] != 0x45 or frame[23] not in (17, 47)
                or frame[26:30] != ipaddress.IPv4Address(OUTER_SOURCE).packed
                or frame[30:34] != ipaddress.IPv4Address(OUTER_DESTINATION).packed
                or int.from_bytes(frame[16:18], "big") != len(frame) - 14
                or checksum(frame[14:34]) != 0):
            raise ValueError("Frame escaped the fixed benchmark IPv4 scope")


def check_interface(interface):
    if interface != INTERFACE or sys.platform != "linux":
        raise ValueError("Raw emit is limited to Linux enp2s0f0 on the known dev-240 link")
    path = Path("/sys/class/net") / interface
    if (path / "address").read_text().strip().lower() != SOURCE_MAC:
        raise ValueError("Interface MAC is not the known dev-240 direct-link MAC")
    if (path / "operstate").read_text().strip() != "up" or (path / "carrier").read_text().strip() != "1":
        raise ValueError("Direct-link interface is not up with carrier")
    if (path / "master").exists():
        raise ValueError("Raw emit refuses an interface attached to a bridge/bond master")
    return socket.if_nametoindex(interface)


def ip_json(*arguments):
    result = subprocess.run(["ip", "-j", *arguments], check=False, capture_output=True,
                            text=True, timeout=5)
    if result.returncode:
        raise ValueError("Read-only ip inspection failed")
    value = json.loads(result.stdout)
    if not isinstance(value, list):
        raise ValueError("Unexpected ip inspection JSON")
    return value


def guard_local_lease(marker, frame_count, pps):
    """Read-only local guard; the coordinator must also prove remote readiness."""
    if not isinstance(marker, str) or not MARKER.fullmatch(marker):
        raise ValueError("Invalid local lease marker")
    directory = Path("/tmp/traflens-tunnel-link-" + marker)
    path = directory / "lease.json"
    if directory.is_symlink() or path.is_symlink():
        raise ValueError("Refusing a symlinked local lease")
    document = json.loads(path.read_text(encoding="utf-8"))
    expected = {"role": "dev-240", "status": "ready", "local": OUTER_SOURCE,
                "peer": OUTER_DESTINATION, "interface": INTERFACE, "mac": SOURCE_MAC,
                "marker": marker, "lease_dir": str(directory)}
    if not isinstance(document, dict) or any(document.get(key) != value for key, value in expected.items()):
        raise ValueError("Local bench lease is missing, finished, or has mismatched ownership")
    identity = document.get("interface_identity")
    if not isinstance(identity, dict) or type(identity.get("ifindex")) is not int or identity["ifindex"] <= 0:
        raise ValueError("Local lease has no valid interface identity")
    links = ip_json("link", "show", "dev", INTERFACE)
    if (len(links) != 1 or links[0].get("ifindex") != identity["ifindex"]
            or links[0].get("ifname") != INTERFACE or identity.get("ifname") != INTERFACE
            or links[0].get("address", "").lower() != SOURCE_MAC
            or identity.get("address", "").lower() != SOURCE_MAC
            or "UP" not in links[0].get("flags", []) or links[0].get("operstate") != "UP"):
        raise ValueError("Local lease interface identity changed")
    addresses = ip_json("-4", "address", "show")
    local, peer = [], []
    for interface in addresses:
        for address in interface.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            targets = (address.get("local"), address.get("peer", "").split("/")[0])
            if OUTER_SOURCE in targets:
                local.append((interface.get("ifname"), address))
            if OUTER_DESTINATION in targets:
                peer.append(address)
    if (len(local) != 1 or peer or local[0][0] != INTERFACE
            or local[0][1].get("local") != OUTER_SOURCE or local[0][1].get("prefixlen") != 32
            or local[0][1].get("label") != INTERFACE + ":tlens" or "peer" in local[0][1]):
        raise ValueError("Local benchmark /32 address ownership changed")
    routes = ip_json("-4", "route", "show", "table", "all")
    candidates = []
    for route in routes:
        destination = route.get("dst", "default")
        if destination == "default":
            continue
        network = ipaddress.ip_network(destination, strict=False)
        if network.version == 4 and network.prefixlen and ipaddress.ip_address(OUTER_DESTINATION) in network:
            candidates.append((network, route))
    if len(candidates) != 1:
        raise ValueError("Peer benchmark route is absent or ambiguous")
    network, route = candidates[0]
    if (network != ipaddress.ip_network(OUTER_DESTINATION + "/32")
            or route.get("dev") != INTERFACE or route.get("prefsrc") != OUTER_SOURCE
            or route.get("metric") != 42796 or route.get("protocol") != "static"
            or route.get("table", "main") not in ("main", 254)
            or any(key in route for key in ("gateway", "via", "nexthops", "nhid"))):
        raise ValueError("Peer benchmark /32 route ownership changed")
    deadline = document.get("deadline_monotonic")
    estimated = (frame_count - 1) / pps
    if (type(deadline) not in (int, float) or not math.isfinite(deadline)
            or deadline - time.monotonic() < estimated + 5):
        raise ValueError("Local bench lease expires before estimated send plus five seconds")
    return {"path": str(path), "marker": marker, "deadline_monotonic": deadline,
            "estimated_send_seconds": estimated, "ifindex": identity["ifindex"],
            "verified_at_utc": utc(),
            "remote_readiness": "Coordinator must separately prove dev-79 ready through send completion"}


def emit(frames, interface=INTERFACE, pps=MAX_PPS, timeout=MAX_TIMEOUT, execute=False,
         preflight=None):
    if execute is not True:
        raise ValueError("Raw emit requires explicit --execute")
    validate_limits(1, pps, timeout)
    validate_frames(frames)
    if (len(frames) - 1) / pps >= timeout:
        raise ValueError("Rate/timeout cannot accommodate the bounded workload")
    index = check_interface(interface)
    lease = preflight() if preflight is not None else None
    if lease is not None and lease["ifindex"] != index:
        raise ValueError("Interface index changed during local lease inspection")
    result = {"kind": "tunnel-wire-emit", "interface": interface, "ifindex": index,
              "frame_count": len(frames), "sent_frames": 0, "complete": False,
              "backend_acceptance": None, "real_http_service": False,
              "started_at_utc": utc(), "errors": [], "pps": pps, "timeout_seconds": timeout}
    started = time.monotonic()
    deadline, previous = started + timeout, None
    if lease is not None:
        result["local_lease"] = lease
        deadline = min(deadline, lease["deadline_monotonic"] - 5)
        if deadline - started < (len(frames) - 1) / pps:
            raise ValueError("Local lease expired before AF_PACKET could be opened")
    try:
        with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)) as sender:
            sender.bind((interface, 0))
            for frame in frames:
                now = time.monotonic()
                delay = 0 if previous is None else max(0, 1 / pps - (now - previous))
                if now + delay >= deadline:
                    raise TimeoutError("Raw emit total deadline expired")
                if delay:
                    time.sleep(delay)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("Raw emit total deadline expired")
                sender.settimeout(min(1, remaining))
                if sender.send(frame) != len(frame):
                    raise OSError("Partial raw frame send; no retry is performed")
                result["sent_frames"] += 1
                previous = time.monotonic()
                if previous >= deadline:
                    raise TimeoutError("Raw send completed after the total deadline")
        result["complete"] = result["sent_frames"] == len(frames)
    except (OSError, TimeoutError) as error:
        result["errors"].append(str(error))
    result["finished_at_utc"] = utc()
    result["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return result


def save_json(path, document):
    path.write_text(json.dumps(document, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", nargs="?", choices=["plan", "emit"], default="plan")
    parser.add_argument("--marker", required=True)
    parser.add_argument("--flavors", default="basic", help="basic, all, or comma-separated known flavors")
    parser.add_argument("--count", type=int, default=1)
    parser.add_argument("--pps", type=float, default=MAX_PPS)
    parser.add_argument("--timeout", type=float, default=MAX_TIMEOUT)
    parser.add_argument("--interface", default=INTERFACE)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if (args.mode == "plan" and args.execute) or (args.mode == "emit" and not args.execute):
            raise ValueError("Only emit --execute may transmit; plan never opens a raw socket")
        if args.interface != INTERFACE:
            raise ValueError("Only the fixed enp2s0f0 interface is allowed")
        validate_limits(args.count, args.pps, args.timeout)
        frames, expected, manifest = generate(args.marker, select_flavors(args.flavors), args.count)
        validate_frames(frames)
        if (len(frames) - 1) / args.pps >= args.timeout:
            raise ValueError("Rate/timeout cannot accommodate the generated workload")
        # A fresh output directory prevents overwriting a previous run's evidence.
        args.output_dir.mkdir(parents=True, exist_ok=False)
        data = pcap_bytes(frames, args.pps)
        (args.output_dir / "traffic.pcap").write_bytes(data)
        manifest["pcap_sha256"] = hashlib.sha256(data).hexdigest()
        manifest["generator_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        manifest["pps"] = args.pps
        for protocol, document in expected.items():
            save_json(args.output_dir / ("expected-" + protocol + ".json"), document)
        save_json(args.output_dir / "manifest.json", manifest)
        result = (emit(frames, args.interface, args.pps, args.timeout, args.execute,
                       preflight=lambda: guard_local_lease(args.marker, len(frames), args.pps))
                  if args.mode == "emit" else {"kind": "tunnel-wire-plan", "executed": False,
                    "sent_frames": 0, "frame_count": len(frames), "request_count": len(manifest["requests"]),
                    "backend_acceptance": None, "real_http_service": False})
        save_json(args.output_dir / "result.json", result)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if args.mode == "plan" or result["complete"] else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(json.dumps({"error": str(error), "complete": False}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
