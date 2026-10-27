#!/usr/bin/env python3
"""Offline, fail-closed qualification of paired iperf3.22 link-only evidence."""

import argparse
import ipaddress
import json
import math
from pathlib import Path
import re
import statistics

SHA = '7271e9c687e534e996b3c1b9854d80c7f70db6e6517d8cedacf130d8c7937a8e'
LAYER = 'sha256:6b7908e4c7473003628ddbd1d8ad378db659f0bf29a3019f7bb7150e9bfd109d'
IMAGES = {'sha256:8ea4cbcf3a26ffe08ba1fa548831bc318beb1a689e921b70c0c47cac329e96fd',
          'sha256:dffca0bf86c0527e623a044b6bdae90cf6ebb2d95fcfb5f1d9345e9140972fec'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, minimum=0, maximum=math.inf, integer=False):
    require(type(value) is int if integer else type(value) in (int, float), 'Numeric type differs')
    require(math.isfinite(value) and minimum <= value <= maximum, 'Numeric range differs')
    return value


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'Duplicate JSON key')
        value[key] = item
    return value


def load(path):
    def invalid(value):
        raise ValueError('Non-finite JSON value')
    return json.loads(Path(path).read_text(), object_pairs_hook=unique_object, parse_constant=invalid)


def worker(path, role, expected):
    data = {name: load(path / (name + '.json'))
            for name in ('result', 'before', 'after', 'created', 'exit-state', 'stdout')}
    result, receipt, state = (data[key] for key in ('result', 'created', 'exit-state'))
    for key in ('pass', 'process_passed', 'owned_container_removed', 'network_configuration_preserved',
                'preexisting_containers_preserved'):
        require(result[key] is True, 'Worker or cleanup failed: ' + key)
    require(result['capture_enabled'] is False and result['error'] is None and result['cleanup_errors'] == [],
            'Worker reported capture/error')
    require(type(result['exit_code']) is int and result['exit_code'] == 0 and result['oom_killed'] is False,
            'Worker exit differs')
    require(state['Running'] is False and state['ExitCode'] == 0 and state['OOMKilled'] is False,
            'Independent exit state differs')
    require(receipt['role'] == role and receipt['run_id'] == expected['run_id'], 'Worker identity differs')
    require(receipt['binary_sha256'] == SHA and receipt['image'] in IMAGES and receipt['rootfs_layer'] == LAYER,
            'Pinned software differs')
    config = data['before']['configuration']
    require(config == data['after']['configuration'] and config['mtu'] == 1500 and config['operstate'] == 'UP',
            'Link configuration changed or differs from qualified MTU')
    require(config['route_device'] == config['ifname'], 'Route interface differs')
    source = ipaddress.IPv6Address(config['route_source'])
    require(source.is_link_local, 'Non-link-local source')
    delta = {k: number(data['after']['counters'][k], integer=True) - number(v, integer=True)
             for k, v in data['before']['counters'].items()}
    require(delta == result['interface_counter_delta'], 'Counter delta differs')
    require(all(v >= 0 for v in delta.values()), 'Counter reset')
    require(all(delta[k] == 0 for k in ('rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped')),
            'Interface error/drop counters increased')
    command = receipt['command']
    require(command[:5] == ['--signal=TERM', '--kill-after=5s', '37', '/iperf3', '-6'], 'Deadline differs')
    require(command[command.index('-B') + 1] == str(source) + '%' + config['ifname'], 'Explicit bind differs')
    if role == 'client':
        for key, value in (('-t', '10'), ('-O', '2'), ('-P', str(expected['streams'])),
                           ('--extra-data', expected['run_id'])):
            require(command[command.index(key) + 1] == value, 'Client command differs')
        require(('-R' in command) is expected['reverse'], 'Client direction differs')
        require('--get-server-output' in command, 'Missing independent server output')
    else:
        ready = load(path / 'ready.json')
        require(ready['owned_listener'] is True and ready['id'] == receipt['id']
                and ready['run_id'] == expected['run_id'], 'Owned listener unproven')
        require('-1' in command and '-s' in command, 'Finite server differs')
    return data, delta


def transcript(data, expected, local, peer, role):
    require(type(data) is dict and 'error' not in data, 'iperf error or non-object')
    require(data['extra_data'] == expected['run_id'], 'Run token differs')
    start, end = data['start'], data['end']
    require(start['version'] == 'iperf 3.22', 'iperf version differs')
    test = start['test_start']
    require(test['protocol'] == 'TCP', 'Protocol differs')
    for key, value in (('num_streams', expected['streams']), ('duration', 10), ('omit', 2),
                       ('reverse', int(expected['reverse'])), ('bidir', 0), ('bytes', 0), ('blocks', 0)):
        require(type(test[key]) is int and test[key] == value, 'Test parameters differ: ' + key)
    connections = start['connected']
    require(type(connections) is list and len(connections) == expected['streams'], 'Partial connection set')
    sockets, tuples = set(), set()
    for conn in connections:
        socket = number(conn['socket'], minimum=0, integer=True)
        require(socket not in sockets, 'Duplicate socket')
        sockets.add(socket)
        require(conn['local_host'] == local and conn['remote_host'] == peer, 'Endpoint address differs')
        lp = number(conn['local_port'], 1024, 65535, integer=True)
        rp = number(conn['remote_port'], 1024, 65535, integer=True)
        require((rp if role == 'client' else lp) == 55201, 'Endpoint port differs')
        tuples.add((local, lp, peer, rp))
    require(len(tuples) == expected['streams'], 'Duplicate connection')
    require(len(end['streams']) == expected['streams'], 'Partial stream summary')
    for direction in ('sender', 'receiver'):
        require({v[direction]['socket'] for v in end['streams']} == sockets, 'Stream socket set differs')
    require(type(data['intervals']) is list and len(data['intervals']) >= 10, 'Missing interval evidence')
    measured_seconds, omitted_seconds, started = 0, 0, False
    for row in data['intervals']:
        require(len(row['streams']) == expected['streams'], 'Partial interval streams')
        require({v['socket'] for v in row['streams']} == sockets, 'Interval socket set differs')
        omitted = row['sum']['omitted']
        require(type(omitted) is bool, 'Interval omit flag differs')
        require(not (started and omitted), 'Warmup restarted after measurement')
        require(all(v['omitted'] is omitted for v in row['streams']), 'Stream omit flags differ')
        seconds = number(row['sum']['seconds'], 0, 2.1)
        require(number(row['sum']['bytes'], integer=True) == sum(
            number(v['bytes'], integer=True) for v in row['streams']), 'Interval byte sum differs')
        if omitted:
            omitted_seconds += seconds
        else:
            started = True
            measured_seconds += seconds
    # 3.22 sometimes merges the omit transition into its first non-omitted
    # interval (one omitted second + eleven flagged non-omitted seconds).
    # Check the whole 12-second timeline here; the end summary independently
    # must contain the actual 10-second measurement. Sub-millisecond tails occur.
    require(11.5 <= measured_seconds + omitted_seconds <= 12.5
            and 9.5 <= measured_seconds <= 11.5 and .5 <= omitted_seconds <= 2.5,
            'Incomplete interval timeline or warmup')
    cpu = number(end['cpu_utilization_percent']['host_total'], 0, 200)
    return tuples, cpu


def measured(summary):
    count = number(summary['bytes'], 1, integer=True)
    seconds = number(summary['seconds'], 9.5, 10.5)
    rate = number(summary['bits_per_second'], 1, 10_500_000_000)
    require(math.isclose(count * 8 / seconds, rate, rel_tol=1e-8), 'Rate/byte/duration inconsistency')
    return count, rate


def qualify(client_path, server_path, expected):
    require(expected['streams'] in (1, 4) and type(expected['streams']) is int
            and type(expected['reverse']) is bool and re.fullmatch('[0-9a-f]{32}', expected['run_id']),
            'Invalid expected case')
    client, cd = worker(Path(client_path), 'client', expected)
    server, sd = worker(Path(server_path), 'server', expected)
    ca, sa = (x['before']['configuration']['route_source'] for x in (client, server))
    require(ca != sa, 'Same-host peer')
    c, s = client['stdout'], server['stdout']
    ct, ccpu = transcript(c, expected, ca, sa, 'client')
    st, scpu = transcript(s, expected, sa, ca, 'server')
    require(ct == {(rh, rp, lh, lp) for lh, lp, rh, rp in st}, 'Paired connections differ')
    require(c['start']['cookie'] == s['start']['cookie'], 'Paired cookies differ')
    nested = c['server_output_json']
    require(nested['start'] == s['start'] and nested['end'] == s['end']
            and nested['intervals'] == s['intervals'], 'Independent server transcript differs')
    sender, receiver = (s, c) if expected['reverse'] else (c, s)
    sb, tx = measured(sender['end']['sum_sent'])
    rb, rx = measured(receiver['end']['sum_received'])
    require(c['end']['sum_received']['bytes'] == rb and c['end']['sum_sent']['bytes'] == sb,
            'Client exchanged byte summaries disagree')
    # iperf3.22's independent server output has only its local direction;
    # the other direction is a zero placeholder, not a second measurement.
    require(s['end']['sum_received' if expected['reverse'] else 'sum_sent']['bytes'] == 0,
            'Server remote-direction placeholder differs')
    require(sum(v['sender']['bytes'] for v in sender['end']['streams']) == sb
            and sum(v['receiver']['bytes'] for v in receiver['end']['streams']) == rb, 'Stream byte sum differs')
    retransmits = number(sender['end']['sum_sent']['retransmits'], integer=True)
    require(sum(number(v['sender']['retransmits'], integer=True) for v in sender['end']['streams']) == retransmits,
            'Retransmission sum differs')
    tx_delta, rx_delta = (sd, cd) if expected['reverse'] else (cd, sd)
    require(tx_delta['tx_bytes'] >= sb and rx_delta['rx_bytes'] >= rb, 'Selected NIC did not carry payload bytes')
    return {'link': number(expected['link'], 1, 2, integer=True), 'reverse': expected['reverse'],
            'streams': expected['streams'], 'receiver_gbps': rx / 1e9, 'sender_gbps': tx / 1e9,
            'sender_tcp_retransmits': retransmits, 'client_process_cpu_percent': ccpu,
            'server_process_cpu_percent': scpu, 'interface_error_drop_delta': 0,
            'both_workers_cleaned': True}


def aggregate(samples):
    groups = []
    for link in (1, 2):
        for reverse in (False, True):
            for streams in (1, 4):
                rows = [v for v in samples if (v['link'], v['reverse'], v['streams']) == (link, reverse, streams)]
                require(len(rows) == 3, 'Expected exactly three repeats per link/direction/stream count')
                rates = [v['receiver_gbps'] for v in rows]
                groups.append({'link': link, 'reverse': reverse, 'streams': streams, 'repeats': 3,
                               'receiver_gbps_min': min(rates), 'receiver_gbps_median': statistics.median(rates),
                               'receiver_gbps_max': max(rates),
                               'sender_tcp_retransmits_total': sum(v['sender_tcp_retransmits'] for v in rows)})
    require(len(samples) == 24, 'Unexpected extra cases')
    return {'schema_version': 1, 'kind': 'network-capacity-only', 'capture_enabled': False,
            'agent_ingestion_performance_measured': False, 'deepflow_performance_parity_proven': False,
            'transport': 'IPv6 link-local TCP', 'link_speed_gbps': 10, 'mtu': 1500,
            'measurement_seconds': 10, 'warmup_seconds': 2, 'endpoint_cpu_limit': 2,
            'endpoint_memory_mib': 256, 'endpoint_pids_limit': 64, 'endpoint_added_capabilities': [],
            'iperf_version': '3.22', 'iperf_binary_sha256': SHA, 'runtime_rootfs_layer': LAYER,
            'groups': groups, 'samples': samples}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', required=True, type=Path)
    parser.add_argument('--index', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    require(not args.output.exists(), 'Do not overwrite existing summary')
    cases = [json.loads(row, object_pairs_hook=unique_object) for row in args.index.read_text().splitlines()]
    require(len({v['run_id'] for v in cases}) == len(cases), 'Repeated run token')
    require(len({v['label'] for v in cases}) == len(cases), 'Repeated case directory')
    samples = []
    for case in cases:
        require(re.fullmatch('matrix-[12]-(forward|reverse)-p[14]-r[123]', case['label']), 'Unsafe case directory')
        parts = case['label'].split('-')
        require(int(parts[1]) == case['link'] and (parts[2] == 'reverse') is case['reverse']
                and int(parts[3][1:]) == case['streams'], 'Case label and parameters differ')
        samples.append(qualify(args.root / case['label'], args.root / (case['label'] + '-server'), case))
    summary = aggregate(samples)
    with args.output.open('x') as output:
        json.dump(summary, output, indent=2, allow_nan=False)
        output.write('\n')
    print(json.dumps({'qualified_samples': len(samples), 'groups': summary['groups']}))


if __name__ == '__main__':
    main()
