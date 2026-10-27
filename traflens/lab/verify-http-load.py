#!/usr/bin/env python3
"""Offline paired HTTP report verification; optional exact one-endpoint packet rows."""
import argparse
from collections import Counter
import ipaddress
import json
import math
from pathlib import Path
import re

FIELDS = ['request_resource', 'request_type', 'response_code', 'response_status',
          'l7_protocol', 'type', 'signal_source', 'tap_side', 'agent_id', 'protocol']


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'Invalid integer')
    return value


def finite(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0, 'Invalid nonnegative number')
    return value


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'Duplicate JSON key')
        result[key] = value
    return result


def load(path):
    def reject(value):
        raise ValueError('Nonfinite JSON value')
    return json.loads(Path(path).read_text(), object_pairs_hook=pairs, parse_constant=reject)


def report(document, mode):
    require(document['schema'] == 'traflens.http-load.v1' and document['mode'] == mode and document['pass'] is True,
            'Failed or unknown workload')
    marker = document['marker']
    require(type(marker) is str and re.fullmatch('[a-z0-9-]{1,48}', marker), 'Invalid marker')
    c = document['private_config']
    require(c['Mode'] == mode and c['Marker'] == marker and c['Execute'] is True, 'Configuration identity differs')
    integer(c['Rate'], 1, 10000); integer(c['Seconds'], 1, 30); integer(c['Concurrency'], 1, 128)
    integer(c['TimeoutMS'], 100, 5000); integer(c['Port'], 1024, 65535)
    count = integer(c['Rate'] * c['Seconds'], 1, 200000)
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', c['Interface']), 'Invalid interface')
    addresses = [ipaddress.IPv6Address(c[key]) for key in ('Bind', 'Peer')]
    require(all(v.is_link_local and '%' not in str(v) for v in addresses) and addresses[0] != addresses[1], 'Invalid endpoint')
    require(integer(document['scheduled'], 1, 200000) == count
            and integer(document['attempted'], 1, count) == count
            and integer(document['completed'], 1, count) == count
            and integer(document['failed'], 0, count) == 0
            and integer(document['skipped'], 0, count) == 0 and not document.get('error'), 'Incomplete workload counts')
    finite(document['process_cpu_user_seconds']); finite(document['process_cpu_system_seconds'])
    integer(document['process_peak_rss_kib'], 1, 1024 * 1024)
    require(0 < finite(document['elapsed_seconds']) <= c['Seconds'] + c['TimeoutMS'] / 1000 + 12, 'Invalid elapsed duration')
    return c, count


def verify(client, server, queries=(), agent_id=None):
    cc, count = report(client, 'client'); sc, other = report(server, 'server')
    require(not queries or count <= 1000, 'Packet query oracle is bounded to 1000 unique requests per run')
    require(count == other and client['marker'] == server['marker'], 'Different workload pair')
    require(all(cc[k] == sc[k] for k in ('Rate', 'Seconds', 'Concurrency', 'TimeoutMS', 'Port'))
            and ipaddress.IPv6Address(cc['Bind']) == ipaddress.IPv6Address(sc['Peer'])
            and ipaddress.IPv6Address(cc['Peer']) == ipaddress.IPv6Address(sc['Bind']), 'Paired endpoint/profile mismatch')
    records = client['records']
    require(type(records) is list and len(records) == count, 'Partial request record set')
    interval = 1_000_000_000 // cc['Rate']
    service, offered = [], []
    for seq, row in enumerate(records):
        require(type(row) is dict and row['state'] == 'completed' and integer(row['sequence'], 0, count - 1) == seq,
                'Missing, repeated or failed request')
        require(integer(row['scheduled_ns'], 0, 30_000_000_000) == seq * interval, 'Scheduled time mismatch')
        started = integer(row['started_ns'], row['scheduled_ns'], 40_000_000_000)
        duration = integer(row['service_ns'], 1, cc['TimeoutMS'] * 1_000_000 + 1_000_000_000)
        latency = integer(row['offered_latency_ns'], 1, 40_000_000_000)
        require(abs(latency - (started - row['scheduled_ns'] + duration)) <= 1_000_000,
                'Scheduled latency accounting differs')
        service.append(duration); offered.append(latency)
    def rank(values, p):
        return sorted(values)[math.ceil(len(values) * p) - 1]
    for key in ('service_p50_ns', 'service_p99_ns', 'offered_p99_ns'):
        integer(client[key], 1, 40_000_000_000)
    require(client['service_p50_ns'] == rank(service, .5) and client['service_p99_ns'] == rank(service, .99)
            and client['offered_p99_ns'] == rank(offered, .99), 'Percentile differs')
    require((agent_id is None and len(queries) == 0) or (agent_id is not None and len(queries) == 2),
            'Packet acceptance needs exactly two whole-marker reads and an expected Agent')
    if queries:
        integer(agent_id, 1, 65535)
        wanted = Counter(('/traflens-load/' + client['marker'] + '/' + str(i), 'GET', 200, 0, 20, 2, 0, 'c', agent_id, 6)
                         for i in range(count))
        for query in queries:
            require(query.get('OPT_STATUS') == 'SUCCESS' and type(query.get('result')) is dict, 'Query failed')
            result = query['result']
            require(result.get('columns') == FIELDS and type(result.get('values')) is list, 'Invalid query schema')
            values = result['values']
            require(len(values) == count and all(type(row) is list and len(row) == len(FIELDS) for row in values),
                    'Partial or extra query rows')
            require(all(type(row[i]) is int for row in values for i in (2, 3, 4, 5, 6, 8, 9)), 'Query numeric type differs')
            require(Counter(tuple(row) for row in values) == wanted, 'Missing, duplicate or unexpected packet Session')
    return {'kind': 'finite-http-load-acceptance', 'rate_rps': cc['Rate'], 'offered_seconds': cc['Seconds'],
            'scheduled': count, 'completed': count, 'failed': 0, 'skipped': 0,
            'service_p50_ms': client['service_p50_ns'] / 1e6, 'service_p99_ms': client['service_p99_ns'] / 1e6,
            'offered_p99_ms': client['offered_p99_ns'] / 1e6,
            'generator_cpu_seconds': client['process_cpu_user_seconds'] + client['process_cpu_system_seconds'],
            'generator_peak_rss_kib': client['process_peak_rss_kib'], 'packet_exact_query_reads': len(queries),
            'expected_captured_endpoints_per_request': 1 if queries else 0,
            'agent_performance_ceiling_measured': False, 'deepflow_performance_parity_proven': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--client', required=True, type=Path); parser.add_argument('--server', required=True, type=Path)
    parser.add_argument('--query', action='append', type=Path, default=[]); parser.add_argument('--agent-id', type=int)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = verify(load(args.client), load(args.server), [load(p) for p in args.query], args.agent_id)
    with args.output.open('x') as output:
        json.dump(result, output, indent=2, allow_nan=False); output.write('\n')
    print(json.dumps(result, allow_nan=False))


if __name__ == '__main__':
    main()
