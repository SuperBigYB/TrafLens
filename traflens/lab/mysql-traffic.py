#!/usr/bin/env python3
"""Bounded MySQL wire fixture; it validates fixed SELECTs, never executes SQL.

Run serve on dev-240 and client on dev-79, with the same unique --marker and
--count (default 20), each host's link interface, and the server's link-local
IPv6 --address. Default TCP port: 18060. The ready event goes to stderr; the
final JSON goes to stdout and optionally --output. No password/TLS is used.

Protocol sources (Protocol10 greeting, Protocol41 login, classic packet framing,
COM_QUERY, ColumnDefinition41, text row and EOF without CLIENT_DEPRECATE_EOF):
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_response.html
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html

The pinned Agent ignores greeting logs and may also emit login/COM_QUIT logs.
Select COM_QUERY and the unique identifier in request_resource for acceptance.
Its successful response_code is null (no error), response_status is 0; EOF's
wire byte 0xfe is not an error code. SQL obfuscation preserves the implicit
column alias, whereas an explicit AS alias would be replaced by this Agent.
"""

import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import socket
import struct
import sys
import time


CAPABILITIES = 0x0008A205  # LONG_PASSWORD/LONG_FLAG/PROTOCOL_41/TRANSACTIONS/SECURE_CONNECTION/PLUGIN_AUTH
CHARSET = 45  # utf8mb4_general_ci
SERVER_STATUS = 2  # AUTOCOMMIT; no more results
PLUGIN = b"mysql_native_password"
USERNAME = b"traflens_fixture"
SCRAMBLE = b"12345678abcdefghijkl"  # protocol fixture, not a credential
MAX_PAYLOAD = 65536  # this fixture does not implement multi-packet large messages
OK = b"\x00\x00\x00\x02\x00\x00\x00"
EOF = b"\xfe\x00\x00\x02\x00"


class ProtocolError(ValueError):
    pass


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def packet(payload, sequence):
    if not 0 < len(payload) <= MAX_PAYLOAD or not 0 <= sequence <= 255:
        raise ProtocolError("packet size or sequence outside fixture limits")
    return len(payload).to_bytes(3, "little") + bytes([sequence]) + payload


class Wire:
    def __init__(self, connection, deadline):
        self.connection = connection
        self.deadline = deadline

    def remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("fixture total deadline expired")
        self.connection.settimeout(remaining)
        return remaining

    def exact(self, length):
        data = bytearray()
        while len(data) < length:
            self.remaining()
            part = self.connection.recv(length - len(data))
            if not part:
                raise ProtocolError("connection closed before a complete packet")
            data.extend(part)
        return bytes(data)

    def receive(self, sequence):
        header = self.exact(4)
        length = int.from_bytes(header[:3], "little")
        if not 0 < length <= MAX_PAYLOAD:
            raise ProtocolError("received packet size outside fixture limits")
        if header[3] != sequence:
            raise ProtocolError("unexpected packet sequence")
        return self.exact(length)

    def send(self, *frames):
        self.remaining()
        self.connection.sendall(b"".join(frames))

    def expect_close(self):
        self.remaining()
        if self.connection.recv(1):
            raise ProtocolError("unexpected data after COM_QUIT")


def length_string(value):
    if len(value) >= 251:
        raise ProtocolError("length-encoded string outside fixture limits")
    return bytes([len(value)]) + value


def nul_string(payload, position):
    end = payload.find(b"\0", position)
    if end < 0:
        raise ProtocolError("missing NUL string terminator")
    return payload[position:end], end + 1


def greeting():
    return (b"\x0a5.7.44\0" + struct.pack("<I", 1) + SCRAMBLE[:8] + b"\0"
            + struct.pack("<HBHHB", CAPABILITIES & 0xFFFF, CHARSET, SERVER_STATUS,
                          CAPABILITIES >> 16, len(SCRAMBLE) + 1)
            + bytes(10) + SCRAMBLE[8:] + b"\0" + PLUGIN + b"\0")


def verify_greeting(payload):
    # A numeric server version is also required by the pinned Agent's is_greeting.
    if not payload or payload[0] != 10:
        raise ProtocolError("expected protocol version 10 greeting")
    version, pos = nul_string(payload, 1)
    if version != b"5.7.44" or len(payload) < pos + 31:
        raise ProtocolError("unexpected or truncated fixture greeting")
    connection_id = struct.unpack_from("<I", payload, pos)[0]
    if connection_id != 1 or payload[pos + 4:pos + 12] != SCRAMBLE[:8] or payload[pos + 12] != 0:
        raise ProtocolError("invalid connection id or scramble prefix")
    lower, charset, status, upper, auth_length = struct.unpack_from("<HBHHB", payload, pos + 13)
    if (lower | (upper << 16), charset, status, auth_length) != (CAPABILITIES, CHARSET, SERVER_STATUS, 21):
        raise ProtocolError("unexpected greeting capabilities or status")
    if payload[pos + 21:pos + 31] != bytes(10):
        raise ProtocolError("nonzero greeting reserved bytes")
    if payload[pos + 31:] != SCRAMBLE[8:] + b"\0" + PLUGIN + b"\0":
        raise ProtocolError("unexpected greeting authentication method")
    return {"protocol_version": 10, "server_version": version.decode("ascii"),
            "connection_id": connection_id, "tls": False, "empty_password": True}


def login():
    return (struct.pack("<IIB", CAPABILITIES, MAX_PAYLOAD, CHARSET) + bytes(23)
            + USERNAME + b"\0\0" + PLUGIN + b"\0")


def verify_login(payload):
    if len(payload) < 33:
        raise ProtocolError("truncated protocol 4.1 login")
    flags, maximum, charset = struct.unpack_from("<IIB", payload)
    if (flags, maximum, charset) != (CAPABILITIES, MAX_PAYLOAD, CHARSET) or payload[9:32] != bytes(23):
        raise ProtocolError("unexpected login flags, limits or reserved bytes")
    username, pos = nul_string(payload, 32)
    if username != USERNAME or payload[pos:pos + 1] != b"\0":
        raise ProtocolError("fixture requires its fixed user and empty password")
    plugin, end = nul_string(payload, pos + 1)
    if plugin != PLUGIN or end != len(payload):
        raise ProtocolError("unexpected login authentication method or trailing bytes")


def query_record(marker, sequence):
    token = "traflens-mysql-%s-%04d" % (marker, sequence)
    column = "traflens_mysql_%s_%04d" % (marker.replace("-", "_"), sequence)
    return {"sequence": sequence, "request_type": "COM_QUERY",
            "request_resource": "SELECT '%s' %s" % (token, column),
            "column_name": column, "row_value": token,
            "expected_response_status": 0, "expected_response_code": None}


def column_definition(name):
    return (b"".join(length_string(value) for value in
                     (b"def", b"", b"", b"", name.encode("ascii"), b""))
            + b"\x0c" + struct.pack("<HIBHB", CHARSET, 1024, 0xFD, 0, 0) + b"\0\0")


def result_frames(record):
    # No CLIENT_DEPRECATE_EOF: metadata EOF and final-row EOF are both required.
    return (packet(b"\x01", 1), packet(column_definition(record["column_name"]), 2),
            packet(EOF, 3), packet(length_string(record["row_value"].encode("ascii")), 4),
            packet(EOF, 5))


def verify_result(wire, record):
    expected = (b"\x01", column_definition(record["column_name"]), EOF,
                length_string(record["row_value"].encode("ascii")), EOF)
    for sequence, payload in enumerate(expected, 1):
        if wire.receive(sequence) != payload:
            raise ProtocolError("result column, row, status or EOF verification failed")


def serve_connection(connection, marker, count, deadline, result):
    wire = Wire(connection, deadline)
    wire.send(packet(greeting(), 0))
    verify_login(wire.receive(1))
    result["handshake"] = verify_greeting(greeting())
    wire.send(packet(OK, 2))
    for sequence in range(count):
        record = query_record(marker, sequence)
        if wire.receive(0) != b"\x03" + record["request_resource"].encode("ascii"):
            raise ProtocolError("expected unique SELECT COM_QUERY in sequence")
        wire.send(*result_frames(record))
        result["records"].append(dict(record, time=utc(), verified=True))
    if wire.receive(0) != b"\x01":
        raise ProtocolError("expected COM_QUIT after the configured SELECT count")
    result["quit_verified"] = True


def client_connection(connection, marker, count, deadline, interval_ms, result):
    wire = Wire(connection, deadline)
    result["handshake"] = verify_greeting(wire.receive(0))
    wire.send(packet(login(), 1))
    if wire.receive(2) != OK:
        raise ProtocolError("login did not return the expected OK status")
    for sequence in range(count):
        record = query_record(marker, sequence)
        started = time.monotonic()
        wire.send(packet(b"\x03" + record["request_resource"].encode("ascii"), 0))
        verify_result(wire, record)
        result["records"].append(dict(record, time=utc(), verified=True,
                                      duration_ms=round((time.monotonic() - started) * 1000, 3)))
        if sequence + 1 < count and interval_ms:
            if wire.remaining() < interval_ms / 1000:
                raise TimeoutError("fixture total deadline insufficient for interval")
            time.sleep(interval_ms / 1000)
    wire.send(packet(b"\x01", 0))
    wire.expect_close()
    result["quit_verified"] = True


def run(args, result):
    deadline = time.monotonic() + args.timeout
    address = (args.address, args.port, 0, socket.if_nametoindex(args.interface))
    if args.mode == "serve":
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            listener.bind(address)
            listener.listen(1)
            listener.settimeout(max(0.001, deadline - time.monotonic()))
            print(json.dumps({"event": "ready", "address": args.address,
                              "interface": args.interface, "port": args.port}), file=sys.stderr, flush=True)
            connection, unused_peer = listener.accept()
            with connection:
                connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                serve_connection(connection, args.marker, args.count, deadline, result)
    else:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as connection:
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(address)
            client_connection(connection, args.marker, args.count, deadline, args.interval_ms, result)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("serve", "client"))
    parser.add_argument("--address", required=True, help="server link-local IPv6 literal, without %%zone")
    parser.add_argument("--interface", required=True, help="local interface used to scope the link")
    parser.add_argument("--marker", required=True)
    parser.add_argument("--port", type=int, default=18060)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=90, help="total wall-clock deadline in seconds")
    parser.add_argument("--interval-ms", type=int, default=100)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[a-z0-9-]{1,64}", args.marker):
        parser.error("marker must contain 1-64 lowercase letters, digits or hyphens")
    if not 1 <= args.count <= 1000 or not 0.1 <= args.timeout <= 300 or not 1 <= args.port <= 65535 or not 0 <= args.interval_ms <= 10000:
        parser.error("count, timeout, port or interval is out of range")
    try:
        if "%" in args.address or not ipaddress.IPv6Address(args.address).is_link_local:
            raise ValueError()
    except ValueError:
        parser.error("address must be an IPv6 link-local literal; specify scope with --interface")
    return args


def main(argv=None):
    args = parse_args(argv)
    started = time.monotonic()
    result = {"kind": "mysql-wire-fixture-" + args.mode, "marker": args.marker,
              "address": args.address, "interface": args.interface, "port": args.port,
              "expected_count": args.count, "database_execution": False, "records": [], "success": False}
    try:
        run(args, result)
        result["success"] = True
    except (OSError, ValueError) as error:
        result["error"] = {"type": type(error).__name__, "message": str(error)}
    result["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
    document = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(document, encoding="utf-8")
    print(document, end="", flush=True)
    return 0 if result["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
