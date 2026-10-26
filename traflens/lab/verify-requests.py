#!/usr/bin/env python3
"""Verify an exact marked request multiset through the isolated lab's query API."""

import argparse
from collections import Counter
import datetime
import json
from pathlib import Path
import re
import time

import lab

FIELDS = ("request_resource", "request_type", "response_code", "response_status", "response_result")


def validate_expected(document):
    marker = document["marker"]
    protocol = document["protocol"]
    records = document["records"]
    if not isinstance(marker, str) or not re.fullmatch(r"[a-z0-9-]{1,64}", marker):
        raise ValueError("Invalid workload marker")
    if type(protocol) is not int or protocol not in (20, 60, 120):
        raise ValueError("Expected packet smoke protocol HTTP=20, MySQL=60 or DNS=120")
    if not isinstance(records, list) or not 1 <= len(records) <= 1000:
        raise ValueError("Expected 1-1000 unique requests")
    resources = []
    keys = set(records[0])
    if not {"request_resource", "request_type", "response_code", "response_status"} <= keys or not keys <= set(FIELDS):
        raise ValueError("Expected request resource/type and response code/status")
    if protocol == 120 and "response_result" not in keys:
        raise ValueError("DNS acceptance requires the exact answer address and TTL")
    for record in records:
        if set(record) != keys or marker not in record["request_resource"]:
            raise ValueError("Inconsistent request fields or marker missing from request resource")
        if not isinstance(record["request_type"], str) or record["response_status"] != 0:
            raise ValueError("This smoke acceptance requires successful responses")
        resources.append(record["request_resource"])
    if len(set(resources)) != len(resources):
        raise ValueError("Workload request resources must be unique")
    return tuple(field for field in FIELDS if field in keys)


def compare_records(expected, query, fields):
    if query.get("OPT_STATUS") != "SUCCESS":
        raise RuntimeError("Query API did not succeed: " + str(query.get("DESCRIPTION")))
    result = query["result"]
    columns = result["columns"]
    if len(columns) != len(set(columns)) or not set(fields) <= set(columns):
        raise ValueError("Query returned missing or repeated columns")
    values = result["values"] or []
    if any(len(row) != len(columns) for row in values):
        raise ValueError("Query returned malformed rows")
    offsets = [columns.index(field) for field in fields]
    actual = Counter(tuple(row[index] for index in offsets) for row in values)
    wanted = Counter(tuple(row[field] for field in fields) for row in expected)
    return {"exact_match": actual == wanted, "queried_rows": len(values),
            "missing_rows": sum((wanted - actual).values()),
            "unexpected_or_duplicate_rows": sum((actual - wanted).values())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=150)
    parser.add_argument("--consecutive", type=int, default=2)
    args = parser.parse_args()
    if not 1 <= args.timeout <= 300 or not 1 <= args.consecutive <= 5:
        parser.error("Timeout must be 1-300 seconds; consecutive reads 1-5")
    document = json.loads(args.expected.read_text())
    fields = validate_expected(document)
    sql = ("SELECT " + ",".join(fields) + " FROM l7_flow_log WHERE request_resource LIKE '%"
           + document["marker"] + "%' AND l7_protocol=" + str(document["protocol"]) + " LIMIT 1001")
    attempts = []
    deadline = time.monotonic() + args.timeout
    consecutive = 0
    query = None
    while time.monotonic() < deadline:
        started = time.monotonic()
        query = lab.query(sql)
        comparison = compare_records(document["records"], query, fields)
        attempts.append({"at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                         "elapsed_seconds": round(time.monotonic() - started, 6), **comparison})
        consecutive = consecutive + 1 if comparison["exact_match"] else 0
        if consecutive >= args.consecutive:
            break
        time.sleep(min(2, max(0, deadline - time.monotonic())))
    result = {"marker": document["marker"], "protocol": document["protocol"],
              "expected_rows": len(document["records"]), "sql": sql, "attempts": attempts,
              "passed": consecutive >= args.consecutive, "final_query": query,
              "scope": "Exact unique request/status acceptance; no performance-parity claim"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    lab.private_write(args.output, json.dumps(result, indent=2) + "\n")
    print(json.dumps({key: value for key, value in result.items() if key != "final_query"}, indent=2))
    if not result["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
