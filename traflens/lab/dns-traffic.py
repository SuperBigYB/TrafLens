#!/usr/bin/env python3
"""Bounded DNS A-query workload over an explicitly scoped IPv6 direct link.

Run serve on dev-240 (enp2s0f0) and client on dev-79 (enp1s0f0).
Only this marker's exact question/ID pairs are answered. No retries are sent.
Both modes save the DNS datagrams as hex alongside validated fields and times.
"""

import argparse
import datetime
import ipaddress
import json
from pathlib import Path
import re
import socket
import struct
import time

LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)
HEADER = struct.Struct("!6H")
QUESTION = struct.Struct("!HH")
ANSWER = struct.Struct("!HHIH")
TTL = 60
MAX_PACKET = 512


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def encode_name(name):
    labels = name.rstrip(".").lower().split(".")
    if not all(LABEL.fullmatch(label) for label in labels):
        raise ValueError("Invalid DNS label")
    value = b"".join(bytes([len(label)]) + label.encode("ascii") for label in labels) + b"\0"
    if len(value) > 255:
        raise ValueError("DNS name exceeds 255 wire bytes")
    return value


def decode_name(payload, offset):
    labels, visited = [], set()
    resume = None
    expanded_size = 1
    while True:
        if not 0 <= offset < len(payload) or offset in visited:
            raise ValueError("Truncated or cyclic DNS name")
        visited.add(offset)
        size = payload[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(payload):
                raise ValueError("Truncated DNS compression pointer")
            target = ((size & 0x3F) << 8) | payload[offset + 1]
            if target >= offset:
                raise ValueError("DNS compression pointer must reference earlier data")
            if resume is None:
                resume = offset + 2
            offset = target
            continue
        if size & 0xC0:
            raise ValueError("Unsupported DNS label encoding")
        offset += 1
        if size == 0:
            return ".".join(labels), resume if resume is not None else offset
        if offset + size > len(payload):
            raise ValueError("Truncated DNS label")
        try:
            label = payload[offset:offset + size].decode("ascii").lower()
        except UnicodeDecodeError as error:
            raise ValueError("Non-ASCII DNS label") from error
        if not LABEL.fullmatch(label):
            raise ValueError("Invalid DNS label")
        expanded_size += size + 1
        if expanded_size > 255:
            raise ValueError("Expanded DNS name exceeds 255 wire bytes")
        labels.append(label)
        offset += size


def header(payload, response):
    if not HEADER.size <= len(payload) <= MAX_PACKET:
        raise ValueError("DNS datagram size is outside this workload's bounds")
    ident, flags, questions, answers, authorities, additional = HEADER.unpack_from(payload)
    if bool(flags & 0x8000) != response or flags & 0x7A70:
        raise ValueError("Unexpected DNS direction/opcode/truncation/reserved flags")
    if (questions, answers, authorities, additional) != (1, int(response), 0, 0):
        raise ValueError("Expected one A question and exactly one A answer for responses")
    return ident, flags


def question(payload):
    name, offset = decode_name(payload, HEADER.size)
    if not name or offset + QUESTION.size > len(payload):
        raise ValueError("Missing DNS question")
    if QUESTION.unpack_from(payload, offset) != (1, 1):
        raise ValueError("Only IN A questions are supported")
    return name, offset + QUESTION.size


def build_query(ident, name):
    if not 0 <= ident <= 65535:
        raise ValueError("DNS transaction ID is out of range")
    return HEADER.pack(ident, 0x0100, 1, 0, 0, 0) + encode_name(name) + QUESTION.pack(1, 1)


def parse_query(payload):
    ident, flags = header(payload, False)
    if flags != 0x0100:
        raise ValueError("Unexpected DNS query flags")
    name, end = question(payload)
    if end != len(payload):
        raise ValueError("Unexpected trailing query data")
    return {"id": ident, "name": name}


def build_response(query, address):
    value = parse_query(query)
    return (HEADER.pack(value["id"], 0x8180, 1, 1, 0, 0) + query[HEADER.size:]
            + b"\xc0\x0c" + ANSWER.pack(1, 1, TTL, 4)
            + ipaddress.IPv4Address(address).packed)


def parse_response(payload):
    ident, flags = header(payload, True)
    name, offset = question(payload)
    answer_name, offset = decode_name(payload, offset)
    if offset + ANSWER.size > len(payload):
        raise ValueError("Truncated DNS answer header")
    record_type, record_class, ttl, size = ANSWER.unpack_from(payload, offset)
    offset += ANSWER.size
    if (record_type, record_class, size) != (1, 1, 4) or offset + size != len(payload):
        raise ValueError("Expected exactly one complete IN A answer")
    return {"id": ident, "name": name, "answer_name": answer_name,
            "address": str(ipaddress.IPv4Address(bytes(payload[offset:offset + size]))),
            "rcode": flags & 0xF, "ttl": ttl}


def verify_response(payload, ident, name, address):
    value = parse_response(payload)
    expected_name = name.rstrip(".").lower()
    if (value["id"] != ident or value["name"] != expected_name
            or value["answer_name"] != expected_name or value["address"] != address
            or value["rcode"] != 0 or value["ttl"] != TTL):
        raise ValueError("DNS response ID/name/address/rcode/TTL verification failed")
    return value


def workload(marker, count):
    if not LABEL.fullmatch(marker) or not 1 <= count <= 1000:
        raise ValueError("Use a DNS-label marker and 1-1000 questions")
    return [{"sequence": sequence, "id": 0xA000 + sequence,
             "name": "q%d.%s.traflens.invalid" % (sequence, marker),
             "address": str(ipaddress.IPv4Address("198.18.0.1") + sequence)}
            for sequence in range(count)]


def scoped_endpoint(address, port, interface):
    if "%" in address or not ipaddress.IPv6Address(address).is_link_local:
        raise ValueError("Use a bare IPv6 link-local address and a separate interface")
    return address, port, 0, socket.if_nametoindex(interface)


def base_result(args):
    return {"kind": "marked-dns-" + args.mode, "marker": args.marker,
            "address": args.address, "interface": args.interface, "port": args.port,
            "expected_count": args.count, "started_at_utc": utc(),
            "records": [], "errors": [], "complete": False}


def serve(args):
    result = base_result(args)
    expected = {value["name"]: value for value in workload(args.marker, args.count)}
    seen = set()
    deadline = time.monotonic() + args.timeout
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as server:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            server.bind(scoped_endpoint(args.address, args.port, args.interface))
            print("ready " + json.dumps({"address": args.address, "interface": args.interface,
                                         "port": args.port, "marker": args.marker}), flush=True)
            received = 0
            while len(seen) < args.count and received < args.count * 4:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                server.settimeout(min(1, remaining))
                try:
                    query, peer = server.recvfrom(MAX_PACKET + 1)
                except socket.timeout:
                    continue
                received += 1
                received_at = utc()
                try:
                    parsed = parse_query(query)
                    value = expected.get(parsed["name"])
                    if value is None or parsed["id"] != value["id"] or parsed["name"] in seen:
                        raise ValueError("Unknown, duplicate, or mismatched workload question")
                    response = build_response(query, value["address"])
                    server.sendto(response, peer)
                    seen.add(value["name"])
                    result["records"].append(dict(value, rcode=0, ttl=TTL, verified=True,
                        received_at_utc=received_at, replied_at_utc=utc(),
                        peer_address=peer[0], peer_port=peer[1],
                        query_hex=query.hex(), response_hex=response.hex()))
                except ValueError as error:
                    result["errors"].append({"received_at_utc": received_at,
                                             "error": str(error), "query_hex": query.hex()})
    except OSError as error:
        result["errors"].append({"error": str(error)})
    result["complete"] = len(seen) == args.count and not result["errors"]
    result["finished_at_utc"] = utc()
    return result


def client(args):
    result = base_result(args)
    destination = scoped_endpoint(args.address, args.port, args.interface)
    deadline = time.monotonic() + args.timeout
    for value in workload(args.marker, args.count):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            result["errors"].append({"error": "Total client deadline expired"})
            break
        query = build_query(value["id"], value["name"])
        record = dict(value, sent_at_utc=utc(), query_hex=query.hex(), verified=False)
        started = time.monotonic()
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as connection:
                connection.settimeout(min(args.response_timeout, remaining))
                connection.connect(destination)
                connection.send(query)
                response = connection.recv(MAX_PACKET + 1)
                record["response_hex"] = response.hex()
                record.update(verify_response(response, value["id"], value["name"], value["address"]))
                record["verified"] = True
        except (OSError, ValueError) as error:
            record["error"] = str(error)
            result["errors"].append({"sequence": value["sequence"], "error": str(error)})
        record["finished_at_utc"] = utc()
        record["duration_ms"] = round((time.monotonic() - started) * 1000, 3)
        result["records"].append(record)
        time.sleep(min(args.interval_ms / 1000, max(0, deadline - time.monotonic())))
    result["complete"] = (len(result["records"]) == args.count
                           and all(record["verified"] for record in result["records"]))
    result["finished_at_utc"] = utc()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["serve", "client"])
    parser.add_argument("--address", required=True, help="Bare IPv6 link-local address")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--marker", required=True, help="One lowercase DNS label")
    parser.add_argument("--port", type=int, default=18053)
    parser.add_argument("--count", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=90, help="Total mode deadline in seconds")
    parser.add_argument("--response-timeout", type=float, default=3, help="Client per-query timeout; no retries")
    parser.add_argument("--interval-ms", type=int, default=50)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        workload(args.marker, args.count)
        scoped_endpoint(args.address, args.port, args.interface)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    if (not 1 <= args.port <= 65535 or not 0 < args.timeout <= 300
            or not 0 < args.response_timeout <= 10 or not 0 <= args.interval_ms <= 10000):
        parser.error("Port, timeout, response-timeout or interval is out of range")
    result = (serve if args.mode == "serve" else client)(args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    document = json.dumps(result, indent=2) + "\n"
    args.output.write_text(document, encoding="utf-8")
    print(document, end="", flush=True)
    if not result["complete"]:
        raise SystemExit("DNS workload did not complete all verified questions")


if __name__ == "__main__":
    main()
