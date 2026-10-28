#!/usr/bin/env python3
"""Read-only whole-marker DNS/MySQL oracle for the owned lab; default plan only."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import time
import urllib.parse
import urllib.request

import lab


def expected_records(value):
    marker = value.get('marker', '')
    count = value.get('count')
    if not re.fullmatch('p6-[0-9a-f]{24}', marker) or type(count) is not int or not 1 <= count <= 20:
        raise ValueError('Fresh bounded protocol fixture contract required')
    expected = {}
    for sequence in range(count):
        dns = 'q%d.%s-dns.traflens.invalid' % (sequence, marker)
        expected[dns] = dict(request_resource=dns, request_type='A', response_code=0,
            response_status=0, response_result='A=198.18.0.%d TTL=60' % (sequence + 1),
            l7_protocol=120, server_port=18053, protocol=17)
        token = 'traflens-mysql-%s-mysql-%04d' % (marker, sequence)
        column = 'traflens_mysql_%s_mysql_%04d' % (marker.replace('-', '_'), sequence)
        sql = "SELECT '%s' %s" % (token, column)
        expected[sql] = dict(request_resource=sql, request_type='COM_QUERY', response_code=None,
            response_status=0, l7_protocol=60, server_port=18060, protocol=6)
    return expected


def validate_rows(result, expected, agent):
    columns = result['columns']
    if len(set(columns)) != len(columns) or any(len(row) != len(columns) for row in result.get('values') or []):
        raise ValueError('Malformed query rows')
    rows = [dict(zip(columns, row)) for row in result.get('values') or []]
    if len(rows) != len(expected):
        raise ValueError('Expected %d records, got %d' % (len(expected), len(rows)))
    identities, seen = set(), set()
    for row in rows:
        resource = row['request_resource']
        if resource in seen or resource not in expected:
            raise ValueError('Duplicate/unexpected resource or out-of-scope negative control')
        seen.add(resource)
        if any(row.get(key) != value for key, value in expected[resource].items()):
            raise ValueError('Actual protocol/resource/response differs from wire contract')
        identity = row.get('id')
        if not isinstance(identity, str) or not re.fullmatch('[0-9]+', identity) or not 0 < int(identity) < 2**64 or identity in identities:
            raise ValueError('Invalid or duplicate exact ID')
        identities.add(identity)
        for key, value in [('agent_id', agent), ('signal_source', 0), ('type', 2)]:
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
                          'whole_marker_without_protocol_source_status_filter': True, 'required_passing_reads': 2}))
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
    fields = 'toString(_id) AS id,request_resource,request_type,response_result,server_port,agent_id,signal_source,l7_protocol,protocol,type,response_code,response_status,observation_point,response_duration'
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
               'expected_protocol_counts': dict(Counter(r['l7_protocol'] for r in expected.values())), 'attempts': attempts}
    with (args.output / 'result.json').open('x') as output:
        json.dump(summary, output, indent=2)
    print(json.dumps({'passed': passed, 'records': len(expected), 'consecutive_passing_reads': summary['consecutive_passing_reads']}))
    raise SystemExit(0 if passed else 1)


if __name__ == '__main__':
    main()
