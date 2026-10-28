#!/usr/bin/env python3
"""Read-only finite acceptance of three real owned TCP socket outcomes."""
import argparse
import calendar
import datetime
import errno
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY, MAX_ROWS, MAX_REQUESTS = 4 << 20, 64, 32
REPORT_ALIGNMENT_SECONDS = 60
SOURCE = 'actual Python stdlib/Linux TCP sockets'
COLUMNS = ('id,flow_id,start_us,end_us,time_epoch,duration,agent_id,signal_source,tap_side,protocol,l3_epc_id_0,l3_epc_id_1,'
           'ip_0,ip_1,client_port,server_port,close_type,packet_tx,packet_rx,byte_tx,byte_rx,total_packet_tx,total_packet_rx,'
           'total_byte_tx,total_byte_rx,l3_byte_tx,l3_byte_rx,l4_byte_tx,l4_byte_rx,rtt,rtt_client,rtt_server,retrans_tx,retrans_rx,l7_protocol').split(',')
TEXT = {'id', 'flow_id', 'start_us', 'end_us', 'time_epoch', 'duration', 'packet_tx', 'packet_rx', 'byte_tx', 'byte_rx',
        'total_packet_tx', 'total_packet_rx', 'total_byte_tx', 'total_byte_rx', 'l3_byte_tx', 'l3_byte_rx',
        'l4_byte_tx', 'l4_byte_rx', 'rtt', 'rtt_client', 'rtt_server', 'retrans_tx', 'retrans_rx'}
KINDS = ('normal', 'reset', 'refused')
CLOSE = {'normal': 1, 'reset': 2, 'refused': 15}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, low=0, high=2**64-1):
    require(type(value) is int or isinstance(value, str) and re.fullmatch('[0-9]+', value), 'Exact integer required')
    number = int(value)
    require(low <= number <= high, 'Integer outside finite bounds')
    return number


def save(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def read(path, cap=MAX_BODY):
    require(path.is_absolute() and path == path.resolve() and path.is_file(), 'Canonical regular artifact required')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    require(len(raw) <= cap, 'Artifact exceeds finite byte limit')
    return raw


def document(raw):
    value = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))
    require(isinstance(value, dict), 'JSON object required')
    return value


def base_url(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'http' and parsed.username is None and parsed.password is None
            and parsed.path in ('', '/') and not parsed.query and not parsed.fragment,
            'Explicit credential-free loopback HTTP base required')
    try:
        require(ipaddress.ip_address(parsed.hostname).is_loopback and 1 <= parsed.port <= 65535,
                'Numeric loopback and explicit port required')
    except (TypeError, ValueError):
        raise ValueError('Numeric loopback and explicit port required') from None
    return value.rstrip('/')


def endpoint(value):
    require(isinstance(value, dict) and set(value) == {'ip', 'port'}, 'Actual socket endpoint required')
    address = ipaddress.ip_address(value['ip'])
    require(address.version == 4 and address.is_loopback, 'Owned IPv4 loopback endpoint required')
    return str(address), integer(value['port'], 1, 65535)


def wire(event):
    value = event.get('wire_ascii')
    require(isinstance(value, str), 'Actual socket bytes required')
    raw = value.encode('ascii')
    require(len(raw) <= 4096 and event.get('bytes') == len(raw)
            and event.get('sha256') == hashlib.sha256(raw).hexdigest(), 'Actual socket byte/SHA receipt differs')
    return raw


def fixture_oracle(folder):
    receipt = document(read(folder / 'receipt.json'))
    process = document(read(folder / 'process.json'))
    run = receipt.get('run', '')
    require(re.fullmatch('tcp-[0-9a-f]{24}', run) and receipt.get('source') == SOURCE and receipt.get('pass') is True
            and receipt.get('expected_connections') == 3 and receipt.get('thread_errors') == []
            and receipt.get('owned_sockets_closed') is True and receipt.get('owned_threads_exited') is True
            and receipt.get('collector_started') is False and receipt.get('synthetic_tcp_packets') is False
            and receipt.get('stored_l4_verified') is False, 'Actual socket workload did not complete its isolated contract')
    require(process.get('source') == SOURCE and process.get('run') == run and process.get('sdk') is False,
            'Original finite process identity is absent')
    for key in ('pid', 'tid', 'start_ticks', 'netns', 'pidns'):
        require(process.get(key) == receipt.get(key), 'Socket process identity differs')
    start, end = integer(receipt.get('started_unix_ns'), 1), integer(receipt.get('finished_unix_ns'), 1)
    require(0 <= end-start <= 95*10**9, 'Socket workload exceeded finite lifetime')
    require(set(receipt.get('completed', {})) == {'server_normal', 'server_reset', 'client_normal', 'client_reset', 'client_refused'}
            and all(v is True for v in receipt['completed'].values()), 'Three actual TCP outcomes are incomplete')
    raw = read(folder / 'events.jsonl')
    require(hashlib.sha256(raw).hexdigest() == receipt.get('events_sha256'), 'Original event artifact changed')
    lines = raw.splitlines()
    require(1 <= len(lines) <= 64 and receipt.get('events') == len(lines), 'Socket event count differs')
    events = [document(line) for line in lines]
    for index, event in enumerate(events, 1):
        require(event.get('sequence') == index and event.get('run') == run and event.get('scenario') in KINDS
                and type(event.get('tid')) is int and event['tid'] > 0, 'Actual event identity or sequence differs')
        for key in ('pid', 'start_ticks', 'netns', 'pidns'):
            require(event.get(key) == process[key], 'Event came from a different process lifetime/namespace')
        require(start <= integer(event.get('finished_unix_ns'), 1) <= end, 'Actual event timestamp outside workload')
    def select(kind, operation):
        return [e for e in events if e['scenario'] == kind and e.get('operation') == operation]
    cases = {}
    for kind in KINDS:
        connects, bounds = select(kind, 'connect'), select(kind, 'bound_endpoint')
        require(len(connects) == len(bounds) == 1, 'Exactly one real connect and owned endpoint per case required')
        connect, bound = connects[0], bounds[0]
        client, server = endpoint(connect.get('local')), endpoint(connect.get('requested_target'))
        require(client[0] == '127.77.0.1' and server[0] == '127.77.0.2'
                and endpoint(bound.get('local')) == server and bound.get('exclusive_bind') is True,
                'Actual TCP tuple differs from the owned endpoints')
        require(bound.get('accepting') is (kind != 'refused'), 'Actual SO_ACCEPTCONN endpoint purpose differs')
        if kind == 'refused':
            require(connect.get('connected') is False and connect.get('errno') == errno.ECONNREFUSED
                    and connect.get('peer') is None and connect.get('peer_is_actual') is False
                    and not select(kind, 'accept'), 'Refused connect is not actual ECONNREFUSED to a non-listener')
        else:
            accepts = select(kind, 'accept')
            require(connect.get('connected') is True and connect.get('errno') == 0 and connect.get('peer_is_actual') is True
                    and endpoint(connect.get('peer')) == server and len(accepts) == 1
                    and endpoint(accepts[0].get('local')) == server and endpoint(accepts[0].get('peer')) == client
                    and accepts[0].get('peer_is_actual') is True, 'Actual connect/accept tuples differ')
        cases[kind] = {'client': client, 'server': server}
    require(len({cases[k]['server'][1] for k in KINDS}) == 3, 'Scenarios reuse the same server port')
    normal = cases['normal']
    sends, receives = select('normal', 'send'), select('normal', 'recv')
    require(len(sends) == len(receives) == 2, 'Normal HTTP must retain both actual send/recv pairs')
    sent = {endpoint(e['local']): wire(e) for e in sends}
    got = {endpoint(e['local']): wire(e) for e in receives}
    require(set(sent) == set(got) == {normal['client'], normal['server']}
            and sent[normal['client']] == got[normal['server']] and sent[normal['server']] == got[normal['client']]
            and all(e.get('eof_observed') is True for e in receives), 'Actual HTTP bytes or EOF differ across peers')
    resource = '/traflens-tcp/' + run + '/normal'
    require(receipt.get('http_resource') == resource and sent[normal['client']].startswith(('GET '+resource+' HTTP/1.1\r\n').encode())
            and sent[normal['server']].startswith(b'HTTP/1.1 200 OK\r\n'), 'Actual normal exchange is not the marked HTTP200')
    body = document(sent[normal['server']].split(b'\r\n\r\n', 1)[1])
    server_identity = receipt.get('server_identities', {}).get('normal', {})
    require(body == {'run': run, 'scenario': 'normal', 'pid': process['pid'], 'tid': server_identity.get('tid')}
            and len(select('normal', 'shutdown_write')) == 2
            and all(e.get('errno') == 0 for e in select('normal', 'shutdown_write')), 'Normal real HTTP/half-close proof differs')
    resets = [e for e in select('reset', 'close_intent') if e.get('abortive') is True]
    errors = select('reset', 'recv_error')
    require(len(resets) == len(errors) == 1 and endpoint(resets[0].get('local')) == cases['reset']['server']
            and resets[0].get('linger_onoff') == 1 and resets[0].get('linger_seconds') == 0
            and errors[0].get('errno') == errno.ECONNRESET
            and endpoint(errors[0].get('local')) == cases['reset']['client'], 'Actual abortive-close/ECONNRESET evidence differs')
    reset_send, reset_recv = select('reset', 'send'), select('reset', 'recv')
    require(len(reset_send) == len(reset_recv) == 1 and wire(reset_send[0]) == wire(reset_recv[0])
            == ('traflens-tcp/'+run+'/reset/request\n').encode(), 'Reset does not retain actual matched request bytes')
    return {'run': run, 'resource': resource, 'cases': cases, 'from': start//10**9,
            'to': (end+10**9-1)//10**9, 'events_sha256': receipt['events_sha256'],
            'started_unix_ns': start, 'finished_unix_ns': end, 'process_identity': {k: process[k] for k in ('pid', 'tid', 'start_ticks', 'netns', 'pidns')},
            'last_event_unix_ns':max(integer(event['finished_unix_ns'],1) for event in events),
            'normal_request_bytes': len(sent[normal['client']]), 'normal_response_bytes': len(sent[normal['server']])}


def packet_runtime_module():
    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))
    spec = importlib.util.spec_from_file_location('tcp_acceptance_packet_runtime', here/'tcp-packet-agent.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def docker_finished_ns(value):
    require(isinstance(value, str), 'Actual Docker FinishedAt UTC string required')
    match = re.fullmatch(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z', value)
    require(match, 'Actual Docker FinishedAt must preserve its UTC timezone and nanoseconds')
    stamp = datetime.datetime.strptime(match[1], '%Y-%m-%dT%H:%M:%S')
    return integer(calendar.timegm(stamp.timetuple())*10**9+int((match[2] or '').ljust(9, '0')), 1)


def report_window_end(finished_ns):
    # Native FlowAggr can publish a Force Report with EndTime aligned forward
    # by60s, even when that report was emitted before the collector stopped.
    return (integer(finished_ns, 1)+10**9-1)//10**9 + REPORT_ALIGNMENT_SECONDS


def installed_ifindex_guard(words, lo):
    """Independently prove every accepting classic-BPF path requires IFINDEX=lo."""
    require(isinstance(words, list) and 5 <= len(words) <= 4096 and type(lo) is int and 0 < lo < 2**32,
            'Finite actual classic-BPF interface program required')
    for word in words:
        require(isinstance(word, list) and len(word) == 4 and all(type(value) is int for value in word)
                and 0 <= word[0] <= 65535 and 0 <= word[1] <= 255 and 0 <= word[2] <= 255 and 0 <= word[3] < 2**32,
                'Invalid actual classic-BPF instruction')
    load, branch = len(words)-5, len(words)-4
    require(words[load] == [0x20, 0, 0, 0xfffff008]
            and words[branch][0] == 0x15 and words[branch][1] in (1, 2) and words[branch][2:] == [0, lo]
            and words[-3] == [6, 0, 0, 0] and words[-2][:3] == [6, 0, 0] and 1 <= words[-2][3] <= 65535
            and words[-1] == [6, 0, 0, 65535], 'Missing exact native single-interface IFINDEX suffix')
    # Only the classic opcodes accepted by this finite proof are admitted. All
    # conditional branches are explored in both directions, without inferring
    # packet contents; a scope bypass therefore cannot hide behind a condition.
    linear = {0x00, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x60, 0x80,
              0x01, 0x61, 0x81, 0xb1, 0x02, 0x03, 0x07, 0x87, 0x84}
    linear |= {code+source for code in (0x04,0x14,0x24,0x34,0x44,0x54,0x64,0x74,0x94,0xa4) for source in (0,8)}
    conditional = {code+source for code in (0x15,0x25,0x35,0x45) for source in (0,8)}
    successors, predecessors = {}, {index:set() for index in range(len(words))}
    for pc, (code, jt, jf, value) in enumerate(words):
        if code in (6, 0x16):
            require(jt == jf == 0, 'Unexpected classic-BPF return encoding')
            targets = []
        elif code == 5:
            require(jt == jf == 0, 'Unexpected classic-BPF unconditional jump encoding')
            targets = [pc+1+value]
        elif code in conditional:
            targets = [pc+1+jt, pc+1+jf]
        elif code in linear:
            require(jt == jf == 0, 'Unexpected classic-BPF linear instruction encoding')
            targets = [pc+1]
        else:
            raise ValueError('Unknown/dynamic classic-BPF opcode cannot prove interface scope')
        require(all(pc < target < len(words) for target in targets), 'Non-forward/outside classic-BPF control flow')
        successors[pc] = targets
        for target in targets:
            predecessors[target].add(pc)
    require(predecessors[branch] == {load}, 'IFINDEX comparison is reachable without its exact preceding load')
    seen, todo = set(), [0]
    while todo:
        pc = todo.pop()
        if pc in seen:
            continue
        seen.add(pc)
        code, _, _, value = words[pc]
        require(code != 0x16 and not (code == 6 and value != 0), 'Non-lo branch can reach a positive/dynamic return')
        todo.extend([branch+1] if pc == branch else successors[pc])
    return {'kernel_accepts_only_lo':True, 'ifindex_load_instruction':load, 'ifindex_comparison_instruction':branch,
            'non_lo_reachable_instruction_count':len(seen), 'method':'exact native IFINDEX suffix plus complete forward classic-BPF CFG'}


def runtime_provenance(folder, agent, positive, negative, runtime=None):
    """Read receipts plus the present Docker/kernel state; never starts a resource."""
    require(folder.is_absolute() and folder == folder.resolve() and folder.is_dir()
            and folder.stat().st_uid == os.geteuid() and not folder.stat().st_mode & 0o077,
            'Canonical owned private packet Agent runtime required')
    current = document(read(folder/'current.json'))
    proof = document(read(folder/'packet-bpf-proof.json'))
    stopped = document(read(folder/'stopped.json'))
    exit_state = document(read(folder/'exit-state.json'))
    require(current.get('schema') == 'traflens.packet-tcp-agent.v1' and current.get('output') == str(folder)
            and current.get('agent_id') == agent and current.get('run') == positive['run']
            and re.fullmatch('[0-9a-f]{64}', current.get('id', ''))
            and re.fullmatch('[0-9a-f]{40}', current.get('source_commit', ''))
            and re.fullmatch('[0-9a-f]{64}', current.get('binary_sha256', ''))
            and re.fullmatch('[0-9a-f]{64}', current.get('artifact_manifest_sha256', ''))
            and current.get('requires_packet_bpf_ready_before_traffic') is True,
            'Packet Agent receipt lacks exact run/Agent/core identity')
    spec = current.get('spec', {})
    require(spec.get('network') == 'host' and spec.get('pid_mode') == '' and spec.get('readonly') is True
            and spec.get('privileged') is False and spec.get('cap_add') == ['NET_RAW'] and spec.get('cap_drop') == ['ALL']
            and spec.get('ports') == {} and spec.get('publish_all') is False
            and spec.get('labels', {}).get('io.traflens.purpose') == 'traflens.packet-tcp-agent'
            and spec.get('labels', {}).get('io.traflens.run') == positive['run']
            and spec.get('labels', {}).get('io.traflens.output') == str(folder), 'Packet Agent runtime exceeded its fixed envelope')
    binaries = [m for m in spec.get('mounts', []) if isinstance(m, list) and len(m) == 3 and m[1] == '/opt/traflens/deepflow-agent']
    require(len(binaries) == 1 and binaries[0][2] is False, 'Exact read-only native core mount required')
    binary = Path(binaries[0][0])
    require(binary.is_absolute() and binary == binary.resolve() and binary.is_file()
            and 0 < binary.stat().st_size <= 256<<20, 'Bounded original native core artifact required')
    digest = hashlib.sha256()
    with binary.open('rb') as stream:
        for block in iter(lambda: stream.read(1<<20), b''):
            digest.update(block)
    require(digest.hexdigest() == current['binary_sha256'], 'Original native core SHA differs from actual process proof')
    require(proof.get('schema') == 'traflens.packet-tcp-ready.v1' and proof.get('agent_id') == agent
            and proof.get('agent_container_id') == current['id'] and proof.get('binary_sha256') == current['binary_sha256']
            and all(proof.get(key) is True for key in ('native_dispatcher_started', 'fresh_three_listener_sync', 'safe_profile_verified',
                                                       'outside_custom_filter_returns_zero_before_default_policy'))
            and proof.get('on_cpu_enabled') is False, 'Actual native dispatcher/listener/custom-filter ready proof missing')
    actual = proof.get('actual_agent', {})
    require(integer(actual.get('pid'), 2) != integer(actual.get('container_pid'), 2)
            and integer(actual.get('start_ticks'), 1) > 0
            and all(re.fullmatch('(net|pid):\\[[0-9]+\\]', actual.get(key, '')) for key in ('netns', 'pidns')),
            'Actual native PID lifetime/namespace proof missing')
    require(all(actual['netns'] == original['process_identity']['netns']
                and actual['pidns'] != original['process_identity']['pidns'] for original in (positive, negative)),
            'Native Agent and actual socket workloads do not share only the intended hostNET')
    finished_ns = docker_finished_ns(exit_state.get('finished_at'))
    require(exit_state.get('schema') == 'traflens.packet-tcp-agent.exit.v1' and exit_state.get('container_id') == current['id']
            and exit_state.get('image_id') == spec.get('image') and type(exit_state.get('exit_code')) is int
            and 0 <= exit_state['exit_code'] <= 255 and exit_state.get('oom_killed') is False
            and integer(exit_state.get('observed_unix_ns'), 1) >= finished_ns and stopped.get('exit') == exit_state,
            'Actual immutable container exit identity differs from its public stop receipt')
    ready_time = proof.get('observed_at_unix')
    require(type(ready_time) in (int, float)
            and 0 < ready_time <= min(o['started_unix_ns'] for o in (positive, negative))/10**9
            and finished_ns >= max(o['finished_unix_ns'] for o in (positive, negative)),
            'Actual sockets did not run after readiness and before stop')
    runtime = runtime or packet_runtime_module()
    expected = runtime.tcp_packet_filter.compile_prefix(runtime.PACKET_TCP_FILTER)
    prefix = proof.get('custom_prefix')
    require(prefix == expected and proof.get('custom_prefix_sha256')
            == hashlib.sha256(json.dumps(expected, separators=(',', ':')).encode()).hexdigest(), 'Proof custom prefix differs from the fixed native compiled filter')
    sockets = proof.get('sockets')
    require(isinstance(sockets, list) and 1 <= len(sockets) <= 16 and proof.get('af_packet_socket_count') == len(sockets)
            and integer(proof.get('lo_ifindex'), 1) > 0, 'Actual lo AF_PACKET socket inventory missing')
    seen = set()
    for item in sockets:
        require(isinstance(item, dict) and integer(item.get('inode'), 1) not in seen and integer(item.get('fd')) >= 0
                and type(item.get('ifindex')) is int and item['ifindex'] in (0, proof['lo_ifindex'])
                and item.get('exact_custom_prefix') is True, 'Unexpected actual AF_PACKET binding')
        seen.add(integer(item['inode'], 1))
        words = item.get('instructions')
        require(isinstance(words, list) and len(expected) < len(words) <= 4096 and words[:len(expected)] == expected
                and item.get('instruction_count') == len(words)
                and all(isinstance(word, list) and len(word) == 4 and all(type(v) is int and v >= 0 for v in word) for word in words)
                and item.get('filter_sha256') == hashlib.sha256(json.dumps(words, separators=(',', ':')).encode()).hexdigest(),
                'Installed actual classic BPF instruction readback is inconsistent')
        installed_ifindex_guard(words, proof['lo_ifindex'])
    require(all(stopped.get(key) is True for key in ('agent_stopped', 'container_removed', 'bpf_inventory_restored',
                                                  'tracefs_restored', 'lo_identity_and_flags_restored')),
            'Public packet stop did not prove its original baseline restored')
    require(runtime.inspect('container', current['id']) is None and runtime.restored(current),
            'Present packet container/kernel/lo baseline does not confirm the stop receipt')
    return {'agent_runtime_provenance_verified': True, 'native_binary_sha256': current['binary_sha256'],
            'native_source_commit': current['source_commit'], 'actual_packet_socket_count': len(sockets),
            'dispatcher_and_three_listener_gate': True, 'installed_fixed_custom_bpf_verified': True,
            'kernel_accepts_only_lo': True, 'actual_all_interface_bound_socket_count':sum(item['ifindex'] == 0 for item in sockets),
            'actual_agent_finished_unix_ns':str(finished_ns),
            'current_container_absence_and_original_kernel_baseline_verified': True}


def rows(envelope, columns):
    require(envelope.get('OPT_STATUS') == 'SUCCESS' and isinstance(envelope.get('result'), dict), 'Native query not successful')
    value = envelope['result']
    names, values = value.get('columns'), value.get('values')
    if values is None:
        values = []
    require(isinstance(names, list) and all(isinstance(n, str) for n in names) and len(names) == len(set(names))
            and set(columns) <= set(names) and isinstance(values, list) and len(values) <= MAX_ROWS
            and all(isinstance(v, list) and len(v) == len(names) for v in values), 'Missing/duplicate/excessive result schema')
    return [dict(zip(names, value)) for value in values]


def tuple_key(row):
    return str(ipaddress.ip_address(row['ip_0'])), integer(row['client_port'], 1, 65535), str(ipaddress.ip_address(row['ip_1'])), integer(row['server_port'], 1, 65535)


def population(count, envelope, oracle, agent, start, end):
    aggregate, actual = rows(count, ['records']), rows(envelope, COLUMNS)
    require(len(aggregate) == 1 and integer(aggregate[0]['records']) == len(actual) and 3 <= len(actual) <= MAX_ROWS,
            'Incomplete/excessive whole TCP tuple population')
    grouped = {kind: [] for kind in KINDS}
    keys = {(*case['client'], *case['server']): kind for kind, case in oracle['cases'].items()}
    seen = set()
    for row in actual:
        # Python's JSON decoder preserves bare integer tokens at arbitrary
        # precision. Native flow_id may be that exact form despite toString;
        # never accept a float or mutate the original raw row/fingerprint.
        require(isinstance(row['id'], str) and (type(row['flow_id']) is int or isinstance(row['flow_id'], str)),
                'Native UInt64 identity must be a decimal string or exact JSON integer')
        identifier = integer(row['id'], 1)
        require(identifier not in seen, 'Duplicate native record ID')
        seen.add(identifier)
        key = tuple_key(row)
        require(key in keys and integer(row['agent_id']) == agent and integer(row['signal_source']) == 0
                and integer(row['protocol']) == 6, 'Unexpected Agent/source/protocol/endpoint observation')
        require(start <= integer(row['end_us'], 1)//10**6 <= end and integer(row['start_us'], 1) <= integer(row['end_us'], 1),
                'Stored TCP timestamps contradict explicit window')
        require(integer(row['time_epoch'], 1) == integer(row['end_us'], 1)//10**6,
                'Stored L4 time epoch is not the exact native EndTime second')
        if integer(row['close_type']) == 5:
            event_second = (integer(oracle['last_event_unix_ns'],1)+10**9-1)//10**9
            require(integer(row['end_us']) == (integer(row['start_us'])//10**6+REPORT_ALIGNMENT_SECONDS)*10**6
                    and integer(row['end_us']) <= (event_second+REPORT_ALIGNMENT_SECONDS)*10**6,
                    'Force Report does not match the native bounded60second report alignment')
        require(integer(row['flow_id'], 1) > 0 and isinstance(row['tap_side'], str), 'Missing flow/observation identity')
        for column in TEXT - {'id', 'flow_id'}:
            integer(row[column])
        for suffix in ('tx', 'rx'):
            require(integer(row['total_packet_'+suffix]) >= integer(row['packet_'+suffix])
                    and integer(row['total_byte_'+suffix]) >= integer(row['byte_'+suffix]), 'Lifetime count smaller than report count')
        grouped[keys[key]].append(row)
    finals = {}
    for kind, values in grouped.items():
        require(values and len({integer(r['flow_id'],1) for r in values}) == 1, 'Tuple does not identify one actual finite flow')
        terminal = [r for r in values if integer(r['close_type']) != 5]
        require(len(terminal) == 1 and integer(terminal[0]['close_type']) == CLOSE[kind], 'Actual socket scenario has unexpected/missing final close classification')
        final = terminal[0]
        require(integer(final['total_packet_tx']) > 0 and integer(final['total_packet_rx']) > 0
                and integer(final['total_byte_tx']) > 0 and integer(final['total_byte_rx']) > 0,
                'Actual bidirectional packet/byte evidence missing')
        for suffix in ('tx', 'rx'):
            for metric in ('packet', 'byte'):
                field, total = metric+'_'+suffix, 'total_'+metric+'_'+suffix
                require(all(integer(row[total]) <= integer(final[total]) for row in values)
                        and sum(integer(row[field]) for row in values) == integer(final[total]),
                        'Complete same-flow report counters differ from final lifetime totals')
        if kind == 'normal':
            require(integer(final['total_byte_tx']) >= oracle['normal_request_bytes']
                    and integer(final['total_byte_rx']) >= oracle['normal_response_bytes'], 'Observed packet bytes cannot contain actual HTTP payload')
        finals[kind] = final
    require(len({integer(r['flow_id'],1) for r in finals.values()}) == 3, 'Independent TCP scenarios share a flow identity')
    actual.sort(key=lambda r: integer(r['id']))
    return actual, finals, hashlib.sha256(json.dumps(actual, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def api_connections(value, expected, agent, start, end):
    actual = value.get('connections')
    require(value.get('from') == start and value.get('to') == end and value.get('agent_id') == agent
            and value.get('signal_source') == 0 and value.get('limit') == 64
            and isinstance(value.get('records'), str) and integer(value['records']) == len(expected)
            and isinstance(actual, list) and len(actual) == len(expected) and isinstance(value.get('semantics'), dict), 'Connection API scope/schema differs')
    by_id = {r['id']: r for r in expected}
    seen = set()
    for item in actual:
        require(isinstance(item, dict) and item.get('id') in by_id and item['id'] not in seen, 'Unexpected/duplicate API connection')
        seen.add(item['id'])
        row = by_id[item['id']]
        for column in COLUMNS:
            require(column in item, 'Missing API original field: '+column)
            if column in TEXT:
                require(type(item[column]) is str and integer(item[column]) == integer(row[column]), 'API changed exact counter/time/identity: '+column)
            else:
                require(type(item[column]) is type(row[column]) and item[column] == row[column], 'API changed raw metadata: '+column)
        require(isinstance(item.get('close_type_name'), str) and item['close_type_name'], 'Missing local close-code description')
        for field in ('rtt', 'rtt_client', 'rtt_server'):
            key = field + '_available'
            if key in item:
                require(item[key] is (integer(row[field]) > 0), 'RTT availability must mean only a positive recorded value')


class Client:
    def __init__(self, output, deadline):
        self.output, self.deadline, self.requests = output, deadline, 0
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, name, base, path, fields=None, get=False):
        self.requests += 1
        remaining = self.deadline-time.monotonic()
        require(self.requests <= MAX_REQUESTS and remaining > 0, 'Finite TCP acceptance request/deadline budget exhausted')
        body = urllib.parse.urlencode(fields).encode() if fields is not None and not get else None
        if get:
            path += '?' + urllib.parse.urlencode(fields or {})
        request = urllib.request.Request(base+path, data=body, headers={'Content-Type': 'application/x-www-form-urlencoded',
            'X-Org-Id': '1', 'X-User-Id': '1', 'X-User-Type': '1'})
        prefix = '%03d-%s' % (self.requests, name)
        save(self.output/(prefix+'.request.json'), {'path': path, 'fields': fields})
        try:
            response = self.opener.open(request, timeout=min(12, remaining))
        except urllib.error.HTTPError as error:
            response = error
        with response:
            raw, status = response.read(MAX_BODY+1), response.code
        (self.output/(prefix+'.body')).open('xb').write(raw)
        require(status == 200 and len(raw) <= MAX_BODY, 'Read-only TCP request failed/exceeded byte cap; no fallback')
        return document(raw)


def acceptance(client, args, oracle, report, negative):
    # The complete Agent/window population deliberately has no source, protocol,
    # close-code, address or known-port filter. Unexpected observations, including
    # the independent outside-filter sockets, must fail rather than disappear.
    where = 'agent_id=%d AND time>=%d AND time<=%d' % (args.agent, args.time_from, args.time_to)
    projection = ('toString(_id) AS id,toString(flow_id) AS flow_id,toUnixTimestamp64Micro(start_time) AS start_us,'
                  'toUnixTimestamp64Micro(end_time) AS end_us,toUnixTimestamp(time) AS time_epoch,' + ','.join(COLUMNS[5:]))
    def query(name, sql):
        return client.request(name, args.query_base, '/v1/query/', {'db': 'flow_log', 'sql': sql})
    def snapshot(label):
        return population(query(label+'-count', 'SELECT Count(row) AS records FROM l4_flow_log WHERE '+where),
            query(label+'-rows', 'SELECT '+projection+' FROM l4_flow_log WHERE '+where+' ORDER BY _id ASC LIMIT 65'),
            oracle, args.agent, args.time_from, args.time_to)
    actual, finals, fingerprint = snapshot('first')
    scope = {'from': args.time_from, 'to': args.time_to, 'agent': args.agent}
    api_connections(client.request('connections', args.console_base, '/api/connections', scope, True), actual, args.agent, args.time_from, args.time_to)
    for kind, row in finals.items():
        selected = dict(scope, id=row['id'])
        api_connections(client.request(kind+'-detail', args.console_base, '/api/connections', selected, True), [row], args.agent, args.time_from, args.time_to)
        linked = client.request(kind+'-requests', args.console_base, '/api/connection-requests', selected, True)
        require(linked.get('connection_found') is True and linked.get('connection_id') == row['id']
                and type(linked.get('flow_id')) is str and integer(linked['flow_id'],1) == integer(row['flow_id'],1)
                and linked.get('relation') == 'native_packet_same_flow_scope', 'L7 link does not identify the exact packet flow')
        l7columns = ['id', 'flow_id', 'start_us', 'end_us', 'agent_id', 'signal_source', 'type', 'protocol', 'l7_protocol', 'ip_0', 'ip_1',
                     'client_port', 'server_port', 'l3_epc_id_0', 'l3_epc_id_1', 'request_resource', 'response_code', 'response_status']
        l7projection = ('toString(_id) AS id,toString(flow_id) AS flow_id,toUnixTimestamp64Micro(start_time) AS start_us,'
                        'toUnixTimestamp64Micro(end_time) AS end_us,' + ','.join(l7columns[4:]))
        l7where = ("agent_id=%d AND signal_source=0 AND type=2 AND protocol=6 AND l7_protocol=20 AND flow_id=%d "
                   "AND time>=%d AND time<=%d AND ip_0='%s' AND client_port=%d AND ip_1='%s' AND server_port=%d "
                   "AND l3_epc_id_0=%d AND l3_epc_id_1=%d") % (args.agent, integer(row['flow_id']), args.time_from, args.time_to,
                    row['ip_0'], integer(row['client_port']), row['ip_1'], integer(row['server_port']), int(row['l3_epc_id_0']), int(row['l3_epc_id_1']))
        original_requests = rows(query(kind+'-native-http', 'SELECT '+l7projection+' FROM l7_flow_log WHERE '+l7where+' ORDER BY _id ASC LIMIT 65'), l7columns)
        requests = rows({'OPT_STATUS': 'SUCCESS', 'result': linked.get('requests')}, l7columns)
        require(len(requests) == (1 if kind == 'normal' else 0), 'Unexpected complete HTTP Session for the actual TCP outcome')
        require(len(original_requests) == len(requests), 'L7 API population differs from native same-flow query')
        originals = {request['id']: request for request in original_requests}
        for request in requests:
            require(type(request['id']) is str and integer(request['id'], 1) and integer(request['flow_id'], 1) == integer(row['flow_id'])
                    and tuple_key(request) == tuple_key(row) and integer(request['agent_id']) == args.agent
                    and integer(request['signal_source']) == 0 and integer(request['type']) == 2 and integer(request['protocol']) == 6
                    and integer(request['l7_protocol']) == 20 and request['l3_epc_id_0'] == row['l3_epc_id_0'] and request['l3_epc_id_1'] == row['l3_epc_id_1']
                    and request['request_resource'] == oracle['resource'] and integer(request['response_code']) == 200
                    and integer(request['response_status']) == 0, 'HTTP link differs from independent socket/native flow evidence')
            require(request['id'] in originals, 'L7 API invented a native observation ID')
            for field in l7columns:
                if field in ('id', 'ip_0', 'ip_1', 'request_resource'):
                    require(request[field] == originals[request['id']][field], 'L7 API changed native metadata: '+field)
                elif field.startswith('l3_epc_id'):
                    require(int(request[field]) == int(originals[request['id']][field]), 'L7 API changed native EPC')
                else:
                    require(integer(request[field]) == integer(originals[request['id']][field]), 'L7 API changed native integer: '+field)
            require(min(integer(r['start_us']) for r in actual if integer(r['flow_id'],1) == integer(row['flow_id'],1)) <= integer(request['start_us'])
                    <= integer(request['end_us']) <= max(integer(r['end_us']) for r in actual if integer(r['flow_id'],1) == integer(row['flow_id'],1)),
                    'HTTP observation does not lie inside the measured flow reports')
    unknown = str(next(n for n in range(1, 100) if str(n) not in {r['id'] for r in actual}))
    for name, changes in [('wrong-agent', {'agent': 65535 if args.agent != 65535 else 65534}),
                          ('wrong-time', {'from': args.time_to+1, 'to': args.time_to+1}), ('unknown-id', {'id': unknown})]:
        selected = dict(scope, id=finals['normal']['id'])
        selected.update(changes)
        api_connections(client.request(name, args.console_base, '/api/connections', selected, True), [], selected['agent'], selected['from'], selected['to'])
        unlinked = client.request(name+'-requests', args.console_base, '/api/connection-requests', selected, True)
        require(unlinked.get('connection_found') is False and unlinked.get('connection_id') == selected['id']
                and isinstance(unlinked.get('requests'), dict) and unlinked['requests'].get('values') in (None, []),
                'Absent exact connection acquired a request association')
    final, _, last_hash = snapshot('second')
    require(final == actual and last_hash == fingerprint, 'Complete native tuple population changed across non-atomic API reads')
    report.update(native_records=len(actual), whole_tuple_reads=2, row_fingerprint=fingerprint,
                  exact_detail_reads=3, actual_connections=3, final_close_types={kind: integer(row['close_type']) for kind, row in finals.items()},
                  normal_http_same_flow_linked=True, reset_and_refused_no_http_session=True, negative_scopes_passed=3,
                  socket_events_sha256=oracle['events_sha256'], request_count=client.requests,
                  outside_filter_actual_connections=3, outside_filter_stored_records=0,
                  negative_socket_events_sha256=negative['events_sha256'],
                  raw_population_scope='entire Agent/time window; no source/protocol/tuple/port/close filter',
                  native_time_epoch_equals_end_us_floor=True, periodic_reports=len(actual)-3,
                  query_time_semantics='native report EndTime seconds; may extend beyond capture exit by at most60s alignment',
                  rtt_unit='microseconds; zero means unavailable/not proven, not health',
                  count_scope='observed report counters; lifetime total counters are not summed across reports')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--fixture-dir', type=Path)
    parser.add_argument('--negative-fixture-dir', type=Path)
    parser.add_argument('--agent-runtime-dir', type=Path)
    parser.add_argument('--query-base')
    parser.add_argument('--console-base')
    parser.add_argument('--from', dest='time_from', type=int)
    parser.add_argument('--to', dest='time_to', type=int)
    parser.add_argument('--agent', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'execute': False, 'reads_files': False, 'starts_network': False, 'new_capture': False,
                          'max_rows': MAX_ROWS, 'max_requests': MAX_REQUESTS, 'total_seconds': 60}))
        return 0
    args.query_base, args.console_base = base_url(args.query_base), base_url(args.console_base)
    require(args.fixture_dir and args.fixture_dir.is_absolute() and args.fixture_dir == args.fixture_dir.resolve()
            and args.fixture_dir.is_dir(), 'Canonical fixture directory required')
    require(args.negative_fixture_dir and args.negative_fixture_dir.is_absolute()
            and args.negative_fixture_dir == args.negative_fixture_dir.resolve() and args.negative_fixture_dir.is_dir()
            and args.negative_fixture_dir != args.fixture_dir, 'Independent canonical outside-filter fixture directory required')
    require(args.agent_runtime_dir is not None, 'Original public packet Agent runtime directory required')
    require(type(args.agent) is int and 1 <= args.agent <= 65535 and type(args.time_from) is int and type(args.time_to) is int
            and 0 < args.time_from <= args.time_to and args.time_to-args.time_from < 300, 'Exact Agent and at most300 inclusive seconds required')
    output = args.output
    require(output and output.is_absolute() and output == output.resolve() and not output.exists()
            and output.parent.stat().st_uid == os.geteuid() and not output.parent.stat().st_mode & 0o077,
            'Fresh output below owned private parent required')
    os.umask(0o077)
    output.mkdir(mode=0o700)
    started = time.monotonic()
    report = {'passed': False, 'new_capture': False, 'new_traffic': False, 'source': 'native packet source0; three actual owned socket outcomes',
              'limitations': 'Finite report-level connection observations; not deduplicated business throughput, automatic causal tracing or RTT precision validation.'}
    def expired(*_):
        raise TimeoutError('Finite60second TCP acceptance deadline exceeded')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 60)
    try:
        oracle = fixture_oracle(args.fixture_dir)
        negative = fixture_oracle(args.negative_fixture_dir)
        require(args.time_from <= oracle['from'] <= oracle['to'] <= args.time_to, 'Query interval excludes original actual socket lifetime')
        require(args.time_from <= negative['from'] <= negative['to'] <= args.time_to,
                'Query interval excludes actual outside-filter socket lifetime')
        require(negative['run'] != oracle['run'] and negative['events_sha256'] != oracle['events_sha256'],
                'Outside-filter workload must be an independent actual run')
        require({case['server'][1] for case in oracle['cases'].values()} == {18081, 18082, 18083}
                and {case['server'][1] for case in negative['cases'].values()} == {18084, 18085, 18086},
                'Positive and outside-filter scenarios must use the declared disjoint port populations')
        save(output/'expected-socket-projection.json', oracle)
        save(output/'expected-outside-filter-socket-projection.json', negative)
        provenance = runtime_provenance(args.agent_runtime_dir, args.agent, oracle, negative)
        save(output/'packet-runtime-provenance.json', provenance)
        report.update(provenance)
        finish = integer(provenance['actual_agent_finished_unix_ns'], 1)
        require(args.time_to == report_window_end(finish),
                'Query upper second must be ceil(actual container FinishedAt)+60s report alignment, not restoration completion')
        acceptance(Client(output, started+60), args, oracle, report, negative)
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        report['elapsed_seconds'] = round(time.monotonic()-started, 3)
        save(output/'result.json', report)
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
