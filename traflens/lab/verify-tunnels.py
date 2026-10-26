#!/usr/bin/env python3
"""Read-only exact application and persisted tunnel-metadata acceptance.

Consumes tunnel-traffic.py's manifest. L7 has tunnel_type but no outer ID/IPs;
those are checked in associated L4 rows using exact uint64 flow IDs. Periodic
L4 reports may be partial: every nonzero metadata value must agree, and every
flow must eventually have a complete bidirectional closing report. Trim policy
intentionally stores zero tunnel metadata, not the original ERSPAN/TEB ID.
"""

import argparse
from collections import Counter
import datetime
import hashlib
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import time
import urllib.parse
import urllib.request

import lab

INNER = ("ip_0", "ip_1", "client_port", "server_port", "protocol")
APPLICATION = ("request_resource", "request_domain", "request_type", "response_status", "response_code", "response_result")
L7_FIELDS = ("flow_id", "tunnel_type") + INNER + ("l7_protocol",) + APPLICATION
L7_COMPARE = L7_FIELDS[1:]
META_NUMBERS = ("tunnel_type", "tunnel_tier", "tunnel_tx_id", "tunnel_rx_id")
META_IPS = ("tunnel_tx_ip_0", "tunnel_tx_ip_1", "tunnel_rx_ip_0", "tunnel_rx_ip_1")
L4_FIELDS = ("flow_id",) + INNER + ("l7_protocol",) + META_NUMBERS + META_IPS + ("close_type", "total_packet_tx", "total_packet_rx")
CLOSING_TYPES = {1, 2, 3, 7, 8, 9, 10, 11, 13, 15, 17, 18, 19, 20}


def uint(value, bits=64, positive=False):
    # Never coerce a float: above 2**53, that can silently identify another flow.
    if isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,19}", value):
        value = int(value)
    if type(value) is not int or not (int(positive) <= value < 1 << bits):
        raise ValueError("Expected an exact unsigned integer")
    return value


def flow_id(value):
    return uint(value, 64, positive=True)


def ip(value):
    if not isinstance(value, str):
        raise ValueError("Expected an IP literal")
    return str(ipaddress.ip_address(value))


def normalize_manifest(document):
    marker = document["marker"]
    records = document["requests"]
    if not isinstance(marker, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", marker):
        raise ValueError("Invalid SQL-safe workload marker")
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ValueError("Expected 1-1000 marked requests")
    if document.get("request_count", len(records)) != len(records):
        raise ValueError("Manifest request_count mismatch")
    outer = document["outer"]
    outer_src, outer_dst = ip(outer["source_ip"]), ip(outer["destination_ip"])
    if (outer_src, outer_dst) != ("198.18.0.240", "198.18.0.79"):
        raise ValueError("Unexpected isolated-lab outer endpoints")
    normalized, resources, tuples = [], set(), set()
    for record in records:
        application = uint(record.get("l7_protocol", record["protocol"]), 8)
        if application not in (20, 120):
            raise ValueError("Only the HTTP/DNS tunnel fixture is supported")
        key = record["inner_5tuple"]
        inner = {"ip_0": ip(key["client_ip"]), "ip_1": ip(key["server_ip"]),
                 "client_port": uint(key["client_port"], 16, True),
                 "server_port": uint(key["server_port"], 16, True),
                 "protocol": uint(key["ip_protocol"], 8)}
        if (inner["protocol"], inner["server_port"]) != ((6, 18080) if application == 20 else (17, 18053)):
            raise ValueError("Unexpected fixture transport/port")
        if ipaddress.ip_address(inner["ip_0"]).version != ipaddress.ip_address(inner["ip_1"]).version:
            raise ValueError("Mixed inner IP families")
        if record.get("ip_version", ipaddress.ip_address(inner["ip_0"]).version) != ipaddress.ip_address(inner["ip_0"]).version:
            raise ValueError("Manifest IP version disagrees with the inner tuple")
        expected = dict(record["expected_l7"])
        if set(expected) != set(APPLICATION) or not all(isinstance(expected[name], str) for name in
                ("request_resource", "request_domain", "request_type", "response_result")):
            raise ValueError("Expected the complete application-field contract")
        resource = expected["request_resource"]
        if resource != record["request_resource"] or marker not in resource or resource in resources:
            raise ValueError("Missing marker, repeated resource, or manifest resource mismatch")
        if type(expected["response_status"]) is not int or expected["response_status"] != 0:
            raise ValueError("Expected a successful application response")
        if type(expected["response_code"]) is not int or expected["response_code"] != (200 if application == 20 else 0):
            raise ValueError("Unexpected HTTP/DNS success code")
        if expected["request_type"] != ("GET" if application == 20 else "A"):
            raise ValueError("Unexpected HTTP/DNS request type")
        if application == 120:
            dns = record["dns"]
            if (expected["request_domain"] != resource or dns["name"] != resource
                    or dns["type"] != "A" or ipaddress.ip_address(dns["address"]).version != 4
                    or uint(dns["rcode"], 4) != 0 or uint(dns["ttl"], 32) != 60
                    or expected["response_result"] != "A=%s TTL=60" % ip(dns["address"])):
                raise ValueError("DNS answer/name/TTL contract mismatch")
        transport_key = tuple(inner[name] for name in INNER)
        if transport_key in tuples:
            raise ValueError("Each tunnel fixture record must have a unique inner five-tuple")
        resources.add(resource)
        tuples.add(transport_key)
        tunnel = record["tunnel"]
        decoded_type, ident = uint(tunnel["decoded_type_id"], 8), uint(tunnel["id"], 32)
        if tunnel["policy"] == "trim" and decoded_type in (6, 7):
            tunnel_type, tier, ident, src, dst = 0, 0, 0, "::", "::"
        elif tunnel["policy"] == "retain" and decoded_type in (3, 5):
            if decoded_type == 5 and ident >= 1 << 24:
                raise ValueError("VNI exceeds 24 bits")
            tunnel_type, tier, src, dst = decoded_type, 1, outer_src, outer_dst
        else:
            raise ValueError("Unsupported tunnel storage policy")
        metadata = {"tunnel_type": tunnel_type, "tunnel_tier": tier,
                    "tunnel_tx_id": ident, "tunnel_rx_id": ident,
                    "tunnel_tx_ip_0": src, "tunnel_tx_ip_1": dst,
                    "tunnel_rx_ip_0": src, "tunnel_rx_ip_1": dst}
        normalized.append({"flavor": record["flavor"], "inner": inner, "metadata": metadata,
                           "l7": {**inner, **expected, "l7_protocol": application, "tunnel_type": tunnel_type}})
    return marker, normalized


def rows(response, fields, limit):
    if response.get("OPT_STATUS") != "SUCCESS":
        raise ValueError("Query API did not succeed")
    result = response["result"]
    columns, values = result["columns"], result["values"] or []
    if len(columns) != len(set(columns)) or not set(fields) <= set(columns) or len(values) >= limit:
        raise ValueError("Missing/repeated query columns or row limit reached")
    if any(len(value) != len(columns) for value in values):
        raise ValueError("Malformed query row")
    return [dict(zip(columns, value)) for value in values]


def compare_l7(expected, response):
    actual = rows(response, L7_FIELDS, 1001)
    wanted = Counter(tuple(record["l7"][name] for name in L7_COMPARE) for record in expected)
    by_resource = {record["l7"]["request_resource"]: record for record in expected}
    seen, flows = Counter(), {}
    for row in actual:
        ident = flow_id(row["flow_id"])
        for name in ("ip_0", "ip_1"):
            row[name] = ip(row[name])
        for name in ("tunnel_type", "client_port", "server_port", "protocol", "l7_protocol", "response_status"):
            row[name] = uint(row[name])
        if row["response_code"] is not None:
            row["response_code"] = uint(row["response_code"], 32)
        seen[tuple(row[name] for name in L7_COMPARE)] += 1
        record = by_resource.get(row["request_resource"])
        if record is not None:
            if ident in flows and flows[ident] != record:
                raise ValueError("A flow_id was associated with different fixture five-tuples")
            flows[ident] = record
    return {"exact_match": seen == wanted, "queried_rows": len(actual),
            "missing_rows": sum((wanted - seen).values()),
            "unexpected_or_duplicate_rows": sum((seen - wanted).values()),
            "flow_ids": [str(value) for value in sorted(flows)]}, flows


def compare_l4(flows, response):
    actual = rows(response, L4_FIELDS, 10001)
    complete, contradictions = set(), []
    seen = Counter()
    for row in actual:
        ident = flow_id(row["flow_id"])
        if ident not in flows:
            raise ValueError("L4 query returned an unrelated flow_id")
        record = flows[ident]
        seen[ident] += 1
        for name, value in record["inner"].items():
            observed = ip(row[name]) if name in ("ip_0", "ip_1") else uint(row[name])
            if observed != value:
                contradictions.append({"flow_id": str(ident), "field": name, "expected": value, "actual": observed})
        application = uint(row["l7_protocol"], 8)
        if application not in (0, record["l7"]["l7_protocol"]):
            contradictions.append({"flow_id": str(ident), "field": "l7_protocol", "actual": application})
        metadata = record["metadata"]
        all_metadata = True
        for name in META_NUMBERS + META_IPS:
            observed = uint(row[name]) if name in META_NUMBERS else ip(row[name])
            present = observed != 0 if name in META_NUMBERS else not ipaddress.ip_address(observed).is_unspecified
            if present and observed != metadata[name]:
                contradictions.append({"flow_id": str(ident), "field": name, "expected": metadata[name], "actual": observed})
            all_metadata = all_metadata and observed == metadata[name]
        if (all_metadata and application == record["l7"]["l7_protocol"]
                and uint(row["close_type"], 16) in CLOSING_TYPES
                and uint(row["total_packet_tx"]) > 0 and uint(row["total_packet_rx"]) > 0):
            complete.add(ident)
    return {"passed": not contradictions and complete == set(flows), "queried_rows": len(actual),
            "expected_flows": len(flows), "complete_bidirectional_closing_flows": len(complete),
            "missing_complete_flow_ids": [str(value) for value in sorted(set(flows) - complete)],
            "rows_per_flow": {str(key): value for key, value in seen.items()}, "contradictions": contradictions}


def owned_lab(root, timeout):
    deadline = time.monotonic() + timeout
    owner = json.loads((root / "owner.json").read_text())
    if owner != {"owner": lab.PREFIX, "root": str(root)}:
        raise RuntimeError("Lab ownership marker mismatch")
    for name in ("traflens-lab-server", "traflens-lab-clickhouse"):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Lab ownership check deadline expired")
        result = subprocess.run(["docker", "container", "inspect", name], capture_output=True,
                                text=True, check=True, timeout=remaining)
        info = json.loads(result.stdout)[0]
        lab.require_owned(info, root, "container")
        if not info["State"]["Running"]:
            raise RuntimeError("Owned lab container is not running")
        if name.endswith("server"):
            bindings = info["HostConfig"]["PortBindings"].get("20416/tcp", [])
            if bindings != [{"HostIp": "127.0.0.1", "HostPort": "20416"}]:
                raise RuntimeError("Query API is not the expected isolated loopback binding")


def query(sql, timeout):
    body = urllib.parse.urlencode({"db": "flow_log", "sql": sql}).encode()
    request = urllib.request.Request("http://127.0.0.1:20416/v1/query/", data=body)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.load(response)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/tmp/traflens-lab-20261026"))
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--consecutive", type=int, default=2)
    args = parser.parse_args()
    if not 5 <= args.timeout <= 300 or not 2 <= args.consecutive <= 5:
        parser.error("Use timeout 5-300 seconds and consecutive 2-5")
    deadline = time.monotonic() + args.timeout
    manifest_bytes = args.manifest.read_bytes()
    marker, expected = normalize_manifest(json.loads(manifest_bytes))
    owned_lab(args.root.resolve(), min(5, deadline - time.monotonic()))
    l7_sql = "SELECT " + ",".join(L7_FIELDS) + " FROM l7_flow_log WHERE request_resource LIKE '%" + marker + "%' LIMIT 1001"
    attempts, consecutive = [], 0
    observed_conflicts = set()
    final_l7, final_l4 = None, None
    while time.monotonic() < deadline and consecutive < args.consecutive:
        attempt = {"at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat()}
        try:
            final_l7 = query(l7_sql, min(5, deadline - time.monotonic()))
            l7, flows = compare_l7(expected, final_l7)
            attempt["l7"] = l7
            if flows:
                ids = ",".join(str(flow_id(value)) for value in sorted(flows))
                l4_sql = "SELECT " + ",".join(L4_FIELDS) + " FROM l4_flow_log WHERE flow_id IN(" + ids + ") LIMIT 10001"
                attempt["l4_sql"] = l4_sql
                final_l4 = query(l4_sql, min(5, deadline - time.monotonic()))
                attempt["l4"] = compare_l4(flows, final_l4)
                observed_conflicts.update(json.dumps(value, sort_keys=True) for value in attempt["l4"]["contradictions"])
            else:
                attempt["l4"] = {"passed": False, "reason": "No marked L7 flow IDs yet"}
            passed = l7["exact_match"] and attempt["l4"]["passed"] and not observed_conflicts
        except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
            passed = False
            attempt["error_type"] = type(error).__name__
            attempt["error"] = str(error)
        consecutive = consecutive + 1 if passed else 0
        attempt["passed"] = passed
        attempts.append(attempt)
        if consecutive < args.consecutive:
            time.sleep(min(2, max(0, deadline - time.monotonic())))
    manifest_changed = args.manifest.read_bytes() != manifest_bytes
    result = {"marker": marker, "passed": consecutive >= args.consecutive and not manifest_changed, "expected_requests": len(expected),
              "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(), "manifest_changed": manifest_changed,
              "observed_metadata_contradictions": [json.loads(value) for value in sorted(observed_conflicts)],
              "l7_sql": l7_sql, "attempts": attempts, "final_l7_query": final_l7, "final_l4_query": final_l4,
              "scope": "Exact marked L7 records plus associated persisted L4 tunnel metadata; trim intentionally discards ERSPAN/TEB metadata; no flags or performance-parity claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    lab.private_write(args.output, json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if not key.startswith("final_")}, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
