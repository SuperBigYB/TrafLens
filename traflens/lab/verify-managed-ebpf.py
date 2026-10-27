#!/usr/bin/env python3
"""Read-only strict 40-Session oracle for ebpf-netns-gate.c's dual-endpoint worker.

Run on the isolated lab host after both bounded traffic workers have finished.
This queries marked L7 rows only; it never starts capture, traffic or containers.
Two socket observation points intentionally produce two Sessions per request.
"""
import argparse
from collections import Counter
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

FIELDS = ('request_resource', 'request_domain', 'request_type', 'response_code',
          'response_status', 'type', 'signal_source', 'observation_point',
          'agent_id', 'flow_id', 'process_id_0', 'process_id_1', 'client_port',
          'server_port', 'l7_protocol', 'protocol', 'ip_0', 'ip_1')
COMPARE = tuple(x for x in FIELDS if x not in
                ('flow_id', 'client_port', 'process_id_0', 'process_id_1'))
INTEGER_FIELDS = ('response_code', 'response_status', 'type', 'signal_source',
                  'agent_id', 'process_id_0', 'process_id_1', 'client_port',
                  'server_port', 'l7_protocol', 'protocol')


def uint(value, bits=64, positive=True, strings=False):
    if strings and isinstance(value, str) and re.fullmatch(r'0|[1-9][0-9]{0,19}', value):
        value = int(value)
    if type(value) is not int or not int(positive) <= value < 1 << bits:
        raise ValueError('Expected an exact bounded integer; floats and booleans are rejected')
    return value


def marker(value):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,23}', value):
        raise ValueError('Expected the C worker SQL-safe marker (1-24 lowercase characters)')
    return value


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('Repeated JSON object key')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('Non-finite JSON constant')
    return json.loads(raw.decode('utf-8', errors='strict'), object_pairs_hook=pairs,
                      parse_constant=constant)


def resource(mark, role, index):
    return '/traflens-ebpf/{}/{}/{:02d}'.format(marker(mark), role, index)


def validate_receipt(doc, mark, role):
    count = 20 if role == 'positive' else 40
    if (not isinstance(doc, dict) or doc.get('pass') is not True or
            doc.get('marker') != marker(mark) or doc.get('role') != role or
            type(doc.get('roundtrips')) is not int or doc['roundtrips'] != count or
            not isinstance(doc.get('records'), list)):
        raise ValueError('Worker receipt identity/pass/count mismatch')
    actual = Counter()
    for row in doc['records']:
        if not isinstance(row, dict):
            raise ValueError('Invalid wire record')
        path = row.get('request_resource')
        if row.get('request_type') != 'GET' or type(row.get('response_code')) is not int or row['response_code'] != 200:
            raise ValueError('Wire method/status mismatch')
        for field in ('request_bytes', 'response_bytes'):
            uint(row.get(field), 16)
        actual[path] += 1
    if actual != Counter(resource(mark, role, i) for i in range(1, count + 1)):
        raise ValueError('Worker exact resource multiset differs')


def query_rows(doc):
    if not isinstance(doc, dict) or doc.get('OPT_STATUS') != 'SUCCESS':
        raise ValueError('Query API did not return SUCCESS')
    result = doc.get('result')
    if not isinstance(result, dict) or result.get('columns') != list(FIELDS):
        raise ValueError('Query returned missing, repeated, reordered or unsupported columns')
    if 'values' not in result:
        raise ValueError('Query result omitted the values field')
    values = result['values']
    if values is None:
        values = []
    if not isinstance(values, list) or any(not isinstance(row, list) or len(row) != len(FIELDS) for row in values):
        raise ValueError('Malformed query rows')
    return [dict(zip(FIELDS, row)) for row in values]


def expected_rows(mark, agent_id, server_port):
    uint(agent_id, 16); uint(server_port, 16)
    return [dict(request_resource=resource(mark, 'positive', i),
                 request_domain='traflens-ebpf.invalid', request_type='GET',
                 response_code=200, response_status=0, type=2, signal_source=3,
                 observation_point=point, agent_id=agent_id, server_port=server_port,
                 l7_protocol=20, protocol=6, ip_0='127.0.0.1', ip_1='127.0.0.1')
            for i in range(1, 21) for point in ('c-p', 's-p')]


def compare_positive(doc, mark, agent_id, host_pid, server_port):
    uint(host_pid, 31)
    rows = query_rows(doc)
    wanted = Counter(tuple(r[k] for k in COMPARE) for r in expected_rows(mark, agent_id, server_port))
    actual, by_point, ports, errors = Counter(), {}, set(), []
    for row in rows:
        for name in INTEGER_FIELDS:
            if type(row[name]) is not int:
                raise ValueError('Non-integer application/identity field: ' + name)
        ident = uint(row['flow_id'], 64, strings=True)
        port = uint(row['client_port'], 16)
        point = row['observation_point']
        if not isinstance(point, str):
            raise ValueError('Invalid observation point type')
        for name in ('request_resource', 'request_domain', 'request_type', 'ip_0', 'ip_1'):
            if not isinstance(row[name], str):
                raise ValueError('Invalid application/IP string field')
        actual[tuple(row[k] for k in COMPARE)] += 1
        by_point.setdefault(point, Counter())[ident] += 1
        ports.add(port)
        expected_pid = (host_pid, 0) if point == 'c-p' else (0, host_pid)
        if point not in ('c-p', 's-p') or (row['process_id_0'], row['process_id_1']) != expected_pid:
            errors.append('Local endpoint process identity mismatch')
    if len(ports) != 1 or server_port in ports:
        errors.append('Expected one shared ephemeral client port distinct from the server')
    if set(by_point) != {'c-p', 's-p'} or any(len(ids) != 1 or sum(ids.values()) != 20 for ids in by_point.values()):
        errors.append('Expected one socket flow_id and20 Sessions per observation point')
    identifiers = set().union(*(set(ids) for ids in by_point.values())) if by_point else set()
    if len(identifiers) != 2:
        errors.append('Expected two distinct full-precision socket flow_ids')
    missing, extra = wanted - actual, actual - wanted
    return {'passed': not missing and not extra and not errors, 'rows': len(rows),
            'missing_rows': sum(missing.values()), 'unexpected_or_duplicate_rows': sum(extra.values()),
            'observation_point_counts': {p: sum(v.values()) for p, v in by_point.items()},
            'flow_ids': {p: [str(i) for i in sorted(v)] for p, v in by_point.items()},
            'errors': sorted(set(errors))}


def sql_for(mark, negative=False):
    # The positive read deliberately includes the whole marker family. No source,
    # protocol, observation-point, Agent or status predicate can hide a leak/error.
    mark = marker(mark)
    pattern = '/traflens-ebpf/' + mark + '/negative/%' if negative else '%' + mark + '%'
    return 'SELECT ' + ','.join(FIELDS) + " FROM l7_flow_log WHERE request_resource LIKE '" + pattern + "' LIMIT 1001"


def owned_scope(root, timeout):
    if not root.is_absolute() or root.resolve() != root:
        raise ValueError('Use an absolute canonical owned lab root')
    if strict_json((root / 'owner.json').read_bytes()) != {'owner': 'traflens-lab', 'root': str(root)}:
        raise ValueError('Owned lab marker mismatch')
    snapshot = {}
    deadline = time.monotonic() + timeout
    for name in ('traflens-lab-server', 'traflens-lab-clickhouse', 'traflens-lab-mysql'):
        result = subprocess.run(['docker', 'container', 'inspect', name], check=True, text=True,
                                capture_output=True, timeout=max(.1, deadline - time.monotonic()))
        info = json.loads(result.stdout)[0]
        if info.get('Config', {}).get('Labels', {}).get('io.traflens.lab') != str(root) or not info['State']['Running']:
            raise ValueError('Owned running container mismatch')
        if name == 'traflens-lab-server' and info['HostConfig']['PortBindings'].get('20416/tcp') != [
                {'HostIp': '127.0.0.1', 'HostPort': '20416'}]:
            raise ValueError('Query API is not the owned loopback binding')
        snapshot[name] = {'id': info['Id'], 'image': info['Image'], 'started_at': info['State']['StartedAt']}
    return snapshot


def query(sql, timeout):
    req = urllib.request.Request('http://127.0.0.1:20416/v1/query/', data=urllib.parse.urlencode(
        {'db': 'flow_log', 'sql': sql}).encode())
    try:
        response = urllib.request.urlopen(req, timeout=timeout)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        raw = response.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError('Query response exceeded bounded evidence size')
        doc = strict_json(raw)
        return response.code, doc


def private_write(path, doc):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as output:
        json.dump(doc, output, indent=2)
        output.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--marker', required=True)
    parser.add_argument('--agent-id', type=int, required=True)
    parser.add_argument('--worker-host-pid', type=int, required=True)
    parser.add_argument('--server-port', type=int, required=True, help='Explicit port matching the controlled worker and managed profile')
    parser.add_argument('--positive-receipt', type=Path, required=True)
    parser.add_argument('--negative-receipt', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True, help='Absolute canonical root of the existing owned isolated lab')
    parser.add_argument('--output', type=Path, required=True, help='New private directory under the owned lab root')
    parser.add_argument('--timeout', type=int, default=150)
    args = parser.parse_args()
    marker(args.marker); uint(args.agent_id, 16); uint(args.worker_host_pid, 31); uint(args.server_port, 16)
    if not 10 <= args.timeout <= 300:
        parser.error('Timeout must be10-300 seconds')
    if not args.output.is_absolute() or args.output.resolve() != args.output or args.root not in args.output.parents:
        parser.error('Output must be a canonical new private directory strictly inside the owned lab root')
    for role in ('positive', 'negative'):
        validate_receipt(strict_json(getattr(args, role + '_receipt').read_bytes()), args.marker, role)
    deadline = time.monotonic() + args.timeout
    before = owned_scope(args.root, min(15, args.timeout))
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    attempts, consecutive, error = [], 0, None
    try:
        while time.monotonic() < deadline:
            number = len(attempts) + 1
            status, positive = query(sql_for(args.marker), max(.1, min(15, deadline - time.monotonic())))
            private_write(args.output / ('positive-{:03d}.json'.format(number)), {'http_status': status, 'response': positive})
            if status != 200:
                raise ValueError('Positive query returned non200 HTTP status')
            comparison = compare_positive(positive, args.marker, args.agent_id, args.worker_host_pid, args.server_port)
            if time.monotonic() >= deadline:
                raise TimeoutError('Overall query deadline expired')
            nstatus, negative = query(sql_for(args.marker, True), max(.1, min(15, deadline - time.monotonic())))
            private_write(args.output / ('negative-{:03d}.json'.format(number)), {'http_status': nstatus, 'response': negative})
            if nstatus != 200:
                raise ValueError('Negative query returned non200 HTTP status')
            negative_count = len(query_rows(negative))
            passed = comparison['passed'] and negative_count == 0
            attempts.append({'at_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                             **comparison, 'negative_rows': negative_count})
            consecutive = consecutive + 1 if passed else 0
            if consecutive == 2:
                break
            time.sleep(min(2, max(0, deadline - time.monotonic())))
    except (OSError, ValueError, TimeoutError) as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    after = owned_scope(args.root, min(15, args.timeout))
    result = {'passed': consecutive == 2 and error is None and before == after,
              'marker': args.marker, 'agent_id': args.agent_id, 'worker_host_pid': args.worker_host_pid,
              'expected_sessions': 40, 'expected_observation_points': {'c-p': 20, 's-p': 20},
              'consecutive_reads': consecutive, 'attempts': attempts, 'error': error,
              'containers_preserved': before == after, 'container_identity': after,
              'positive_sql': sql_for(args.marker), 'negative_sql': sql_for(args.marker, True),
              'helper_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              'receipt_sha256': {role: hashlib.sha256(getattr(args, role + '_receipt').read_bytes()).hexdigest()
                                for role in ('positive', 'negative')},
              'scope': 'Bounded marked HTTP dual-endpoint syscall case only; no general/performance/eBPF feature parity claim.'}
    private_write(args.output / 'result.json', result)
    print(json.dumps({k: result[k] for k in ('passed', 'expected_sessions', 'consecutive_reads', 'containers_preserved', 'error')}))
    if not result['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
