#!/usr/bin/env python3
"""Read-only whole-marker HTTP trace oracle for the owned lab; default plan only."""
import argparse
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

import lab


def expected_records(value):
    if not re.fullmatch('trace-[0-9a-f]{24}', value.get('marker', '')):
        raise ValueError('Fresh fixture marker required')
    for key in ['primary_trace', 'unrelated_trace']:
        trace = value.get(key, '')
        if not re.fullmatch('[0-9a-f]{32}', trace) or trace == '0' * 32:
            raise ValueError('Invalid expected Trace ID')
    if value['primary_trace'] == value['unrelated_trace']:
        raise ValueError('Unrelated trace must differ')
    rows = value['records']
    if not isinstance(rows, list) or len(rows) % 2 or not 4 <= len(rows) <= 42:
        raise ValueError('Expected two legs for1..20 primary requests plus one control')
    count = len(rows) // 2 - 1
    expected = {}
    for leg, port, offset in [('front', 18080, 0x1000), ('back', 18081, 0x2000)]:
        for sequence in range(count + 1):
            resource = '/traflens-trace/' + value['marker'] + '/' + leg + '/' + str(sequence)
            expected[resource] = {'request_resource': resource,
                'trace_id': value['primary_trace'] if sequence < count else value['unrelated_trace'],
                'span_id': format(offset + sequence + 1, '016x'), 'server_port': port}
    if len({r['request_resource'] for r in rows}) != len(rows) or any(expected.get(r['request_resource']) != r for r in rows):
        raise ValueError('Actual fixture receipts differ from independent context/sequence contract')
    return expected


def validate_rows(result, expected, agent):
    columns = result['columns']
    rows = [dict(zip(columns, row)) for row in result.get('values') or []]
    if len(rows) != len(expected):
        raise ValueError('Expected ' + str(len(expected)) + ' records, got ' + str(len(rows)))
    identities = set()
    seen = set()
    for row in rows:
        resource = row['request_resource']
        if resource in seen or resource not in expected:
            raise ValueError('Duplicate/unexpected request resource')
        seen.add(resource)
        if any(row.get(key) != value for key, value in expected[resource].items()):
            raise ValueError('Actual trace/span/endpoint differs from wire contract')
        identity = row.get('id')
        if not isinstance(identity, str) or not identity.isdecimal() or not 0 < int(identity) < 2**64 or identity in identities:
            raise ValueError('Invalid or duplicate exact record ID')
        identities.add(identity)
        for key, value in [('agent_id', agent), ('signal_source', 0), ('l7_protocol', 20),
                           ('type', 2), ('response_code', 200), ('response_status', 0)]:
            if type(row.get(key)) is not int or row[key] != value:
                raise ValueError('Unexpected stored metadata: ' + key)
    return identities


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--execute', action='store_true')
    for name in ['root', 'expected', 'output']:
        p.add_argument('--' + name, type=Path)
    p.add_argument('--agent-id', type=int)
    p.add_argument('--timeout', type=int, default=90)
    args = p.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'starts_capture': False, 'writes_controller': False,
                          'whole_marker_without_trace_source_filter': True, 'required_passing_reads': 2}))
        return
    if not all([args.root, args.expected, args.output, args.agent_id]) or not 1 <= args.timeout <= 180 or not 1 <= args.agent_id <= 65535:
        p.error('Explicit owned root, expected receipt, new output, Agent ID and bounded timeout required')
    lab.require_owned(lab.inspect('container', 'traflens-lab-server'), args.root, 'container')
    if (not args.output.is_absolute() or args.output != args.output.resolve() or not args.output.is_relative_to(args.root.resolve())
            or args.output.parent.stat().st_uid != os.geteuid() or args.output.parent.stat().st_mode & 0o077):
        raise ValueError('New private output inside the owned lab required')
    value = json.loads(args.expected.read_text())
    expected = expected_records(value)
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    fields = 'toString(_id) AS id,request_resource,trace_id,span_id,parent_span_id,server_port,agent_id,signal_source,l7_protocol,type,response_code,response_status,observation_point'
    sql = "SELECT " + fields + " FROM l7_flow_log WHERE request_resource LIKE '%" + value['marker'] + "%' ORDER BY _id ASC LIMIT 43"
    deadline = time.monotonic() + args.timeout
    previous = None
    attempts = []
    passed = False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    while time.monotonic() < deadline:
        req = urllib.request.Request('http://127.0.0.1:20416/v1/query/', data=urllib.parse.urlencode({'db': 'flow_log', 'sql': sql}).encode())
        with opener.open(req, timeout=10) as response:
            result = json.load(response)
        with (args.output / ('query-' + str(len(attempts)) + '.json')).open('x') as out:
            json.dump({'sql': sql, 'response': result}, out, indent=2)
        try:
            if result.get('OPT_STATUS') != 'SUCCESS':
                raise ValueError('Backend query rejected')
            identities = validate_rows(result.get('result') or {'columns': [], 'values': []}, expected, args.agent_id)
            attempts.append({'passed': True, 'rows': len(identities)})
            if previous == identities:
                passed = True
                break
            previous = identities
        except (ValueError, KeyError, TypeError) as error:
            attempts.append({'passed': False, 'error': str(error)})
            previous = None
        time.sleep(1)
    summary = {'passed': passed, 'expected_records': len(expected), 'consecutive_passing_reads': 2 if passed else 0,
               'expected_trace_counts': dict(Counter(r['trace_id'] for r in expected.values())), 'attempts': attempts}
    with (args.output / 'result.json').open('x') as output:
        json.dump(summary, output, indent=2)
    print(json.dumps({'passed': passed, 'records': len(expected), 'consecutive_passing_reads': summary['consecutive_passing_reads']}))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
