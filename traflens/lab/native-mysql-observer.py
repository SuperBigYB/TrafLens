#!/usr/bin/env python3
"""Plan stock native CLI calls or parse stdin metadata; never runs planned calls.

Scope/Agent/container identity must be proved by the owning runtime before any
planned command. Stock datadump prints owned payload to Agent stdout. This
parser retains only bounded metadata, hashes and counts, never payload or IPs.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import sys
import time

MAX_LOG = 8 << 20
MAX_RECORDS = 256
MAX_LINES = 32768
U64 = (1 << 64) - 1
CAPTURE_CONTRACTS = {
    'traflens.ebpf-mysql.capture.v1': {
        'worker_schema': 'traflens.ebpf-mysql.worker-runtime.v1',
        'worker_purpose': 'traflens.ebpf-mysql.worker',
        'scope_schema': 'traflens.ebpf-mysql.scope.v1',
    },
    'traflens.ebpf-mysql-diagnostic.capture.v1': {
        'worker_schema': 'traflens.ebpf-mysql-diagnostic.worker-runtime.v1',
        'worker_purpose': 'traflens.ebpf-mysql-diagnostic.worker',
        'scope_schema': 'traflens.ebpf-mysql-diagnostic.scope.v1',
    },
    'traflens.ebpf-mysql-fast.capture.v1': {
        'worker_schema': 'traflens.ebpf-mysql-fast.worker-runtime.v1',
        'worker_purpose': 'traflens.ebpf-mysql-fast.worker',
        'scope_schema': 'traflens.ebpf-mysql-fast.scope.v1',
    },
}
HEADER = re.compile(
    r'^.*?\[datadump\] SEQ (?P<seq>\d+) <(?P<proto>[^<>\s]{1,24})> '
    r'DIR (?P<direction>in|out) TYPE (?P<type>[a-z]+)\((?P<msg>\d+)\) '
    r'PID (?P<pid>\d+) THREAD_ID (?P<tid>\d+) COROUTINE_ID (?P<coroutine>\d+) '
    r'FD (?P<fd>\d+) ROLE (?P<role>client|server|unknown) '
    r'CONTAINER_ID (?P<container>\S{1,128}) SOURCE (?P<source>\d+) COMM (?P<comm>\S{1,16}) '
    r'(?P<transport>TCP|UDP|Unknow) (?P<left>[0-9.]+)\.(?P<leftport>\d+) > '
    r'(?P<right>[0-9.]+)\.(?P<rightport>\d+) LEN (?P<length>\d+) '
    r'SYSCALL_LEN (?P<syscall_len>\d+) SOCKET_ID (?P<socket>\d+) TRACE_ID (?P<trace>\d+) '
    r'TCP_SEQ (?P<tcp>\d+) DATA_SEQ (?P<cap>\d+) TLS (?P<tls>true|false) '
    r'SyscallTime .{1,64}? SyscallMonoTime (?P<syscall_us>\d+) us '
    r'CapTime .{1,64}? CapMonoTime (?P<capture_us>\d+) us$')
WORKER = re.compile(r'^worker (\d+) for queue, de (\d+) en (\d+) lost (\d+) '
                    r'alloc failed (\d+) burst (\d+) queue size (\d+) cap (\d+)$')
SUM = re.compile(r'^SUM dequeue (\d+) enqueue (\d+) lost (\d+) alloc failed (\d+) burst count (\d+)$')


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def integer(text, low=0, high=U64):
    require(isinstance(text, (str, int)) and not isinstance(text, bool), 'Invalid bounded integer')
    require(re.fullmatch(r'0|[1-9][0-9]*', str(text)) is not None, 'Invalid decimal integer')
    value = int(text)
    require(low <= value <= high, 'Integer exceeds metadata budget')
    return value


def command_plan(container_id=None, duration=30):
    require(1 <= duration <= 30, 'Observer duration must be1..30seconds')
    require(container_id is None or re.fullmatch(r'[0-9a-f]{64}', container_id), 'Exact immutable container ID required')
    prefix = ['docker', 'exec', container_id or '<verified-owned-agent-container-id>', '/usr/bin/deepflow-ebpfctl']
    return {
        'schema': 'traflens.native-mysql-observer.plan.v1', 'executes_commands': False,
        'requires_external_scope_and_owned_agent_proof': True,
        'control_socket': '/var/run/deepflow_bpf_ctrl',
        'pre': prefix + ['tracer', 'show'],
        'set': prefix + ['datadump', 'set', '--pid', '0', '--comm', '', '--l7-proto', '0', '--port', '0'],
        'start': prefix + ['datadump', 'on', '--only-stdout', '--timeout', str(duration)],
        'post': prefix + ['tracer', 'show'], 'stop': prefix + ['datadump', 'off'],
        'stock_cli_default_timeout_seconds': 60,
        'dump_destination': 'owned Agent stdout; not docker-exec stdout',
        'close_filter_note': 'CLOSE tuple/port may be zero and protocol may be0; rely on proved exclusive namespace and fixed MySQL profile',
        'deadline_note': 'stock auto-stop uses elapsed_seconds>timeout on maintenance ticks; always explicitly stop in finally',
        'order_semantics': 'C-worker serialized print order; not actual Rust queue acceptance or collector order',
        'execution_cpu_available': False, 'socket_id_high_bits_are_event_cpu': False,
    }


def process_identities(server, client):
    result = {}
    for role, value, comm in [('server', server, 'mysqld'), ('client', client, 'traflens-mysql')]:
        require(isinstance(value, dict) and value.get('role') == role and value.get('comm') == comm,
                'Actual fixture process role/comm required')
        pid = integer(value.get('pid'), 1, (1 << 31)-1)
        require(integer(value.get('tid'), 1) == pid and value.get('single_threaded') is True,
                'Actual single-threaded fixture PID/TID required')
        integer(value.get('start_ticks'), 1)
        require(re.fullmatch(r'my-[0-9a-f]{24}', value.get('run', '')), 'Actual positive fixture run required')
        require(re.fullmatch(r'net:\[[0-9]+\]', value.get('netns', '')) and
                re.fullmatch(r'pid:\[[0-9]+\]', value.get('pidns', '')), 'Actual fixture namespace identities required')
        require(value.get('wire_fixture') is True and value.get('sql_executed') is False,
                'Only actual no-SQL wire fixture is allowed')
        require(pid not in result, 'Distinct actual worker PIDs required')
        result[pid] = (role, comm)
    require(server['run'] == client['run'] and server['netns'] == client['netns'] and
            server['pidns'] == client['pidns'], 'Both workers must belong to one actual positive run/namespace')
    return result


def parse_datadump(text, identities, anonymous_sequences=()):
    lines = text.splitlines()
    require(len(lines) <= MAX_LINES, 'Agent log line budget exceeded')
    events = []
    require(len(set(anonymous_sequences)) == len(anonymous_sequences) and
            all(type(s) is int and 0 <= s < MAX_RECORDS for s in anonymous_sequences), 'Invalid anonymous CLOSE sequence accounting')
    for line in lines:
        if '[datadump] SEQ ' not in line:
            continue  # Full private Agent stdout is hashed separately; payload is not copied.
        require(len(line) <= 4096, 'Datadump header budget exceeded')
        match = HEADER.fullmatch(line)
        require(match is not None, 'Malformed datadump header; no partial-header success')
        require(len(events)+len(anonymous_sequences) < MAX_RECORDS, 'Datadump record budget exceeded')
        h = match.groupdict()
        numbers = {k: integer(h[k]) for k in ['seq', 'msg', 'pid', 'tid', 'fd', 'source', 'length',
                    'syscall_len', 'socket', 'trace', 'tcp', 'cap', 'coroutine', 'syscall_us', 'capture_us',
                    'leftport', 'rightport']}
        require(numbers['pid'] in identities, 'Datadump includes an unowned process')
        role, comm = identities[numbers['pid']]
        require(numbers['tid'] == numbers['pid'] and h['comm'] == comm, 'Datadump process identity contradicts fixture')
        require(not events or numbers['seq'] > events[-1]['print_sequence'], 'Datadump print sequence reset; coverage cannot be assumed')
        require(numbers['source'] == 0 and h['tls'] == 'false' and numbers['coroutine'] == 0,
                'Only actual syscall raw source0 is allowed; stored signal source is separately3')
        is_close = numbers['msg'] == 10
        if is_close:
            require(numbers['length'] == numbers['syscall_len'] == 0, 'CLOSE metadata must not claim payload')
            require(h['proto'].lower() in ('mysql', 'unknown', 'unknow', 'other'), 'Unexpected CLOSE protocol')
            require(h['left'] == h['right'] == '0.0.0.0' and numbers['leftport'] == numbers['rightport'] == 0,
                    'Expected original zero-tuple CLOSE metadata')
        else:
            require(h['proto'].lower() == 'mysql' and h['transport'] == 'TCP' and h['role'] == role,
                    'Unexpected non-MySQL owned-namespace data')
            endpoints = {(h['left'], numbers['leftport']), (h['right'], numbers['rightport'])}
            require(('127.0.0.2', 18080) in endpoints and
                    any(ip == '127.0.0.1' and 0 < port <= 65535 for ip, port in endpoints),
                    'Data is outside the exact owned MySQL endpoint')
            require(0 < numbers['length'] <= 2048 and numbers['syscall_len'] == numbers['length'] and
                    numbers['socket'] > 0, 'Incomplete or unexpected syscall metadata')
        key = f'{role}/{numbers["socket"]}'
        events.append({
            'print_sequence': numbers['seq'], 'process_role': role, 'fd': numbers['fd'],
            'socket_id': str(numbers['socket']), 'socket_key_sha256': digest(key.encode()),
            'cap_seq': str(numbers['cap']), 'msg_type': numbers['msg'], 'is_close': is_close,
            'raw_source': numbers['source'], 'direction': h['direction'], 'socket_role': h['role'],
            'capture_bytes': numbers['length'], 'syscall_bytes': numbers['syscall_len'],
            'syscall_mono_us': str(numbers['syscall_us']), 'capture_mono_us': str(numbers['capture_us']),
            'tcp_seq': str(numbers['tcp']), 'syscall_trace_id': str(numbers['trace']),
            'header_sha256': digest(line.encode()),
            'tuple_sha256': digest(f'{h["transport"]}/{h["left"]}/{h["leftport"]}/{h["right"]}/{h["rightport"]}'.encode()),
            'execution_cpu': None, 'actual_queue_id': None,
        })
    require(events or anonymous_sequences, 'No complete datadump headers; empty output does not prove zero traffic')
    observed_sequences = [e['print_sequence'] for e in events]+list(anonymous_sequences)
    require(sorted(observed_sequences) == list(range(len(observed_sequences))),
            'Datadump print sequence gap/reset; coverage cannot be assumed')
    owned_sockets = {(e['process_role'], e['fd'], e['socket_id']) for e in events if not e['is_close']}
    unknown_zero_close = len(anonymous_sequences)+sum(e['is_close'] and e['socket_id'] == '0' for e in events)
    unbound_close = sum(e['is_close'] and e['socket_id'] != '0' and
                       (e['process_role'], e['fd'], e['socket_id']) not in owned_sockets for e in events)
    # Unbound CLOSE records are anonymous counts only, never persisted as metadata.
    events = [e for e in events if not e['is_close'] or
              (e['process_role'], e['fd'], e['socket_id']) in owned_sockets]
    backtracks = 0
    time_backtracks = 0
    last = {}
    close_without_data = 0
    data_keys = set()
    for event in events:
        key = event['socket_key_sha256']
        seq, time = int(event['cap_seq']), int(event['syscall_mono_us'])
        if key in last:
            backtracks += int(seq < last[key][0])
            time_backtracks += int(time < last[key][1])
        last[key] = (seq, time)
        if event['is_close']:
            close_without_data += int(key not in data_keys)
        else:
            data_keys.add(key)
    return events, {
        'records': len(events), 'data_records': sum(not e['is_close'] for e in events),
        'close_records': sum(e['is_close'] for e in events), 'data_socket_count': len(data_keys),
        'close_without_prior_printed_data': close_without_data,
        'anonymous_unknown_uid0_close_count': unknown_zero_close,
        'anonymous_unbound_nonzero_close_count': unbound_close,
        'apparent_per_socket_cap_seq_backtracks': backtracks,
        'apparent_per_socket_syscall_time_backtracks': time_backtracks,
        'execution_cpu_available': False, 'actual_queue_order_available': False,
        'scope_or_storage_completeness_proved': False,
    }


def parse_tracer(text):
    require(len(text.splitlines()) <= 1024, 'Tracer-show line budget exceeded')
    require(len(re.findall(r'^Tracer\s+\S+$', text, re.M)) == 1, 'Exactly one owned native tracer snapshot required')
    lost = re.findall(r'^Events Lost\s+(\d+)$', text, re.M)
    workers = re.findall(r'^Workers\s+(\d+)$', text, re.M)
    require(len(lost) == len(workers) == 1, 'Missing tracer counters; no empty-as-zero fallback')
    rows = []
    summary = None
    fields = ['worker', 'dequeue', 'enqueue', 'lost', 'alloc_failed', 'burst', 'queue_size', 'capacity']
    for line in text.splitlines():
        match = WORKER.fullmatch(line.strip())
        if match:
            row = dict(zip(fields, (integer(x) for x in match.groups())))
            require(row['queue_size'] <= row['capacity'], 'Contradictory queue capacity')
            rows.append(row)
        match = SUM.fullmatch(line.strip())
        if match:
            require(summary is None, 'Duplicate tracer counter totals')
            summary = dict(zip(['dequeue', 'enqueue', 'lost', 'alloc_failed', 'burst'],
                               (integer(x) for x in match.groups())))
    require(rows and len(rows) == integer(workers[0], 1, 256) and
            [r['worker'] for r in rows] == list(range(len(rows))), 'Incomplete or duplicate tracer queues')
    require(summary is not None and all(summary[k] == sum(r[k] for r in rows) for k in summary),
            'Tracer totals contradict complete queue rows')
    return {'perf_lost_snapshot': integer(lost[0]), 'queues': rows, 'totals': summary,
            'semantics': 'snapshots of counters concurrently reset by Agent stats; not cumulative and not safe to subtract'}


def read_private(path, limit):
    p = Path(path)
    require(p.is_absolute() and p == p.resolve(), 'Canonical absolute private input required')
    flags = os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
    fd = os.open(p, flags)
    with os.fdopen(fd, 'rb') as stream:
        st = os.fstat(stream.fileno())
        require(stat.S_ISREG(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077 and
                0 <= st.st_size <= limit, 'Bounded owned private regular input required')
        raw = stream.read(limit+1)
        require(len(raw) == st.st_size and len(raw) <= limit, 'Input changed or exceeded budget')
        return raw


def save(output, name, value):
    fd = os.open(output/name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write('\n');stream.flush();os.fsync(stream.fileno())


def capture_binding(capture, container_id):
    require(re.fullmatch(r'[0-9a-f]{64}', container_id or ''), 'Exact owned Agent container ID required')
    require(capture.is_absolute() and capture == capture.resolve(), 'Canonical capture directory required')
    current_raw = read_private(capture/'agent/current.json', 65536)
    scope_raw = read_private(capture/'scope-runtime.json', 65536)
    state_raw = read_private(capture/'state.json', 65536)
    current, scope = json.loads(current_raw), json.loads(scope_raw)
    state = json.loads(state_raw);contract = capture_contract(state, capture)
    require(scope.get('schema') == contract['scope_schema'], 'Scope schema differs from explicit capture contract')
    require(current.get('id') == scope.get('agent_container_id') == container_id, 'Agent/container scope identity differs')
    runtime = Path(current.get('folder', ''))
    require(runtime.is_absolute() and runtime == runtime.resolve() and runtime.parent == capture/'agent', 'Exact private Agent runtime required')
    proof_raw = read_private(runtime/'coordinator-scope-proof.json', 65536)
    proof = json.loads(proof_raw)
    require(proof.get('agent_container_id') == container_id and proof.get('af_packet_socket_count') == 0 and
            proof.get('agent_binary_sha256') == current.get('binary_sha256') and
            proof.get('source_commit') == current.get('source') and
            all(proof.get(k) is True for k in ['scope_fd_pinned', 'safe_profile_verified',
                                            'native_collector_started', 'fresh_three_listener_sync']),
            'Original namespace/FD/map/readiness proof required before observation')
    require(integer(proof.get('agent_pid'), 1) > 0 and isinstance(proof.get('agent_scope_fds'), list) and
            1 <= len(proof['agent_scope_fds']) <= 32 and
            all(type(fd) is int and fd >= 0 for fd in proof['agent_scope_fds']) and isinstance(proof.get('scope_map'), dict),
            'Original owned Agent PID and scope map proof required')
    inode = integer(scope.get('positive', {}).get('inode'), 1, (1 << 32)-1)
    require(scope['positive'].get('netns') == f'net:[{inode}]', 'Original positive namespace identity differs')
    return scope, {'agent_current': digest(current_raw), 'scope_runtime': digest(scope_raw), 'capture_state': digest(state_raw),
                   'coordinator_scope_proof': digest(proof_raw)}


def capture_contract(state, capture):
    require(isinstance(state, dict) and state.get('schema') in CAPTURE_CONTRACTS,
            'Only explicit MySQL product or diagnostic capture schemas are allowed')
    require(state.get('output') == str(capture) and re.fullmatch(r'my-[0-9a-f]{24}', state.get('run', '')),
            'Capture state does not bind the exact output/run')
    return CAPTURE_CONTRACTS[state['schema']]


def roster(capture, container_id, scope):
    processes = {}
    hashes = {}
    state_raw = read_private(capture/'state.json', 65536)
    state = json.loads(state_raw);contract = capture_contract(state, capture)
    require(scope.get('schema') == contract['scope_schema'], 'Scope schema differs from actual capture state')
    hashes['capture_state_at_first_header'] = digest(state_raw)
    for role in ['server', 'client']:
        name = 'positive-'+role
        process_raw = read_private(capture/name/'process.json', 65536)
        runtime_raw = read_private(capture/(name+'-runtime.json'), 65536)
        process, runtime = json.loads(process_raw), json.loads(runtime_raw)
        actual = runtime.get('inspect', {})
        require(runtime.get('schema') == contract['worker_schema'] and
                runtime.get('role') == name and runtime.get('scope_role') == 'positive' and
                runtime.get('agent_container_id') == container_id and runtime.get('scope_receipt') == 'scope-runtime.json' and
                runtime.get('workload_run') == runtime.get('run') == process.get('run') == state['run'],
                'Actual positive worker runtime identity differs')
        normalized = runtime.get('create', {}).get('normalized', {})
        labels = {'io.traflens.purpose': contract['worker_purpose'], 'io.traflens.run': state['run'],
                  'io.traflens.role': name, 'io.traflens.output': str(capture)}
        require(normalized.get('labels') == actual.get('labels') == labels,
                'Actual worker purpose/ownership labels differ from explicit capture contract')
        mounts = normalized.get('mounts')
        require(isinstance(mounts, list) and len(mounts) == 2 and actual.get('mounts') == mounts,
                'Actual worker executable/output mount identity required')
        by_target = {m[1]: m for m in mounts if isinstance(m, list) and len(m) == 3}
        require(set(by_target) == {'/workload', '/output'} and by_target['/workload'][2] is False and
                by_target['/output'] == [str(capture/name), '/output', True], 'Worker mounts do not bind exact private output')
        binary_sha = digest(read_private(by_target['/workload'][0], 8 << 20))
        require(actual.get('running') is True and re.fullmatch(r'[0-9a-f]{64}', actual.get('id', '')) and
                all(actual.get(k) == process.get(k) for k in ['pid', 'netns', 'pidns', 'comm']) and
                str(actual.get('start_ticks')) == str(process.get('start_ticks')) and
                actual.get('netns') == scope['positive']['netns'] and actual.get('pid_mode') == 'host' and
                actual.get('network_mode') == 'container:'+scope['positive']['container_id'] and
                actual.get('executable_sha256') == binary_sha and
                re.fullmatch(r'[0-9a-f]{64}', actual.get('executable_sha256', '')),
                'Actual Docker/proc proof does not bind owned positive worker')
        processes[role] = process
        hashes[name+'_process'] = digest(process_raw);hashes[name+'_runtime'] = digest(runtime_raw)
    return process_identities(processes['server'], processes['client']), hashes


def stream_metadata(stream, capture, container_id, scope, duration):
    """Keep only validated header metadata in memory; no original log is saved."""
    selected = selectors.DefaultSelector();selected.register(stream, selectors.EVENT_READ)
    started = time.monotonic();pending = b'';size = 0;whole_hash = hashlib.sha256()
    headers = [];anonymous_sequences = [];header_count = 0
    identities = None;hashes = {};error = '';eof = False;stopped = [False]
    previous = {}
    def stop(_number, _frame):
        stopped[0] = True
    for number in [signal.SIGINT, signal.SIGTERM]:
        previous[number] = signal.signal(number, stop)
    try:
        while not stopped[0] and time.monotonic()-started <= duration+5:
            if not selected.select(0.1):
                continue
            raw = os.read(stream.fileno(), 65536)
            if not raw:
                eof = True;break
            size += len(raw);whole_hash.update(raw)
            require(size <= MAX_LOG, 'Agent stdout byte budget exceeded')
            pending += raw
            while b'\n' in pending:
                line, pending = pending.split(b'\n', 1)
                require(len(line) <= 32768, 'Agent stdout line budget exceeded')
                if b'[datadump] SEQ ' not in line:
                    continue
                text = line.decode('utf-8')
                raw_header = HEADER.fullmatch(text)
                require(raw_header is not None, 'Malformed datadump header; no partial-header success')
                h = raw_header.groupdict()
                sequence = integer(h['seq'])
                require(sequence == header_count and header_count < MAX_RECORDS,
                        'Datadump print sequence gap/reset or record budget exceeded')
                header_count += 1
                if integer(h['msg']) == 10 and integer(h['socket']) == 0:
                    require(integer(h['source']) == 0 and h['tls'] == 'false' and
                            integer(h['length']) == integer(h['syscall_len']) == 0 and
                            h['left'] == h['right'] == '0.0.0.0' and
                            integer(h['leftport']) == integer(h['rightport']) == 0,
                            'Invalid anonymous zero-UID CLOSE header')
                    # No process/runtime may exist yet. Keep only an anonymous count
                    # and sequence accounting; never retain this PID or header.
                    anonymous_sequences.append(sequence)
                    continue
                if identities is None:
                    identities, hashes = roster(capture, container_id, scope)
                # Validate before retaining even a header in the observation set.
                parse_datadump('\n'.join(headers+[text]), identities, anonymous_sequences)
                headers.append(text)
            require(len(pending) <= 32768, 'Agent stdout pending-line budget exceeded')
        require(eof and not stopped[0] and not pending, 'Observer stream ended by signal/deadline or incomplete line')
    except Exception as failure:
        error = str(failure) if type(failure) is ValueError else 'Streaming metadata parsing failed; no payload retained'
    finally:
        selected.close()
        for number, handler in previous.items():
            signal.signal(number, handler)
    events, summary = (parse_datadump('\n'.join(headers), identities or {}, anonymous_sequences)
                       if headers or anonymous_sequences else ([], {}))
    return events, summary, hashes, {'agent_stdout_sha256': whole_hash.hexdigest(), 'agent_stdout_bytes_observed': size,
                                    'original_stdout_or_payload_saved': False, 'stream_eof': eof,
                                    'observer_duration_seconds': time.monotonic()-started}, error


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--container-id')
    parser.add_argument('--duration', type=int, default=30)
    parser.add_argument('--execute', action='store_true', help='Parse stdin metadata only; never execute planned commands')
    parser.add_argument('--stream', action='store_true')
    for name in ['capture-dir', 'tracer-pre', 'tracer-post', 'output']:
        parser.add_argument('--'+name)
    args = parser.parse_args(argv)
    plan = command_plan(args.container_id, args.duration)
    if not args.execute:
        print(json.dumps(plan));return 0
    require(args.stream and all(getattr(args, k) for k in ['capture_dir', 'tracer_pre', 'tracer_post', 'output']),
            'Streaming mode, original runtime/counters and a fresh output are required')
    output = Path(args.output)
    require(output.is_absolute() and output.parent == output.parent.resolve() and not output.exists(), 'Fresh canonical output required')
    st = output.parent.stat()
    require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.geteuid() and not st.st_mode & 0o077, 'Owned private output parent required')
    output.mkdir(mode=0o700)
    result = {'schema': 'traflens.native-mysql-observer.result.v1', 'pass': False,
              'only_stdin_metadata_parsing': True, 'native_or_scope_or_storage_verified': False,
              'source_hashes': {}, 'limits': {'log_bytes': MAX_LOG, 'records': MAX_RECORDS},
              'order_semantics': plan['order_semantics'], 'error': ''}
    try:
        capture = Path(args.capture_dir)
        scope, binding_hashes = capture_binding(capture, args.container_id)
        result['source_hashes'].update(binding_hashes)
        pre_raw = read_private(args.tracer_pre, 65536)
        pre = parse_tracer(pre_raw.decode('utf-8'));result['source_hashes']['tracer_pre'] = digest(pre_raw)
        events, summary, hashes, stream_info, stream_error = stream_metadata(sys.stdin.buffer, capture, args.container_id, scope, args.duration)
        result['source_hashes'].update(hashes);result.update(stream_info)
        save(output, 'events.json', events)
        result['summary'] = summary
        require(not stream_error, stream_error)
        require(events, 'No bound original metadata; empty is not a zero-loss proof')
        post_raw = read_private(args.tracer_post, 65536)
        post = parse_tracer(post_raw.decode('utf-8'));result['source_hashes']['tracer_post'] = digest(post_raw)
        save(output, 'tracer-snapshots.json', {'pre': pre, 'post': post})
        result.update({'pass': True, 'summary': summary,
                       'snapshot_loss_or_alloc_nonzero': any(s['perf_lost_snapshot'] or s['totals']['lost'] or s['totals']['alloc_failed'] for s in [pre, post])})
    except Exception as error:
        result['error'] = str(error) if type(error) is ValueError else 'Private input/output parsing failed; no payload retained'
    save(output, 'result.json', result)
    print(json.dumps({k: v for k, v in result.items() if k not in ['source_hashes']}))
    return 0 if result['pass'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (ValueError, OSError):
        print(json.dumps({'pass': False, 'error': 'Invalid observer arguments or private paths'}));sys.exit(2)
