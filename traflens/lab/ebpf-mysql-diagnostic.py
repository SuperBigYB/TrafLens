#!/usr/bin/env python3
"""Explicit unqualified archived-MySQL diagnosis with bounded observer gates."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require

spec = importlib.util.spec_from_file_location('diagnostic_mysql_base', HERE / 'ebpf-mysql.py')
PACED = importlib.util.module_from_spec(spec)
spec.loader.exec_module(PACED)
RUNTIME, CORE = PACED.RUNTIME, PACED.CORE
ARCHIVED_ARTIFACT_SHA256 = '1c17c2cec2808c20c220e64e483a4ce5e213c1b2f37959b4dd6c42e0f7163136'
ARCHIVED_SOURCE_SHA256 = 'd097917c05cfb5de5e8a0f5fe91cfc4181ae7653e4b3c11b4488333dab17c06f'
STAGES = ('before-first-wire', 'after-final-wire')
MAX_MANIFEST = 64 << 10
MAX_ARTIFACT = 4 << 20


def validate_receipt(receipt, run, role):
    connections = receipt.get('connections')
    require(receipt.get('run') == run and receipt.get('role') == role and receipt.get('pass') is True
            and receipt.get('completed_requests') == 3 and receipt.get('expected_requests') == 3
            and receipt.get('wire_events') == 21 and receipt.get('classic_packets') == 26
            and receipt.get('owned_sockets_closed') is True and receipt.get('listener_closed') is True
            and receipt.get('single_threaded') is True and receipt.get('error') == ''
            and receipt.get('wire_fixture') is True and receipt.get('sql_executed') is False
            and receipt.get('comm') == ('mysqld' if role == 'server' else 'traflens-mysql')
            and isinstance(connections, list) and len(connections) == 3
            and all(isinstance(v, dict) and v.get('complete') is True and v.get('closed') is True for v in connections)
            and not any(key in receipt for key in ('pacing_only_qualification', 'pacing_ms', 'pacing_waits',
                                                  'pacing_duration_ns', 'waits_sha256')),
            'Archived unpaced wire receipt differs; no invented pacing is accepted')


def preflight(args):
    require(args.workload_sha256 == ARCHIVED_ARTIFACT_SHA256, 'Diagnostic entry only accepts the archived unpaced artifact')
    source = getattr(args, 'workload_source', None)
    require(isinstance(source, str) and Path(source).is_absolute(), 'Explicit archived --workload-source required')
    require(CORE.file_hash(source) == ARCHIVED_SOURCE_SHA256, 'Archived unpaced source SHA differs')
    timeout = getattr(args, 'observer_timeout_seconds', None)
    require(type(timeout) is int and 5 <= timeout <= 45, 'Observer timeout must be an integer5..45 seconds')


def private_json(path):
    require(path.is_absolute() and path == path.resolve(), 'Canonical private observer file required')
    meta = path.stat()
    require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and not meta.st_mode & 0o077
            and meta.st_size <= MAX_MANIFEST, 'Observer JSON ownership/type/budget differs')
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), 'Observer JSON must be an object')
    return value


def pinned_namespace_fd(pid, descriptors, inode):
    for fd in descriptors:
        require(type(fd) is int and fd >= 0, 'Invalid Agent scope FD receipt')
        path = Path('/proc', str(pid), 'fd', str(fd))
        try:
            if path.stat().st_ino != inode:
                continue
            handle = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
        except FileNotFoundError:
            continue  # Another receipt FD may be the persistent live pin.
        try:
            if os.fstat(handle).st_ino == inode and fcntl.ioctl(handle, 0xb703) == 0x40000000:
                return True
        finally:
            os.close(handle)
    return False


def live_agent_binding(work):
    current = CORE.read(work / 'agent/current.json')
    folder = Path(current['folder'])
    require(folder.is_relative_to(work / 'agent') and folder == folder.resolve(), 'Agent proof folder escaped run')
    agent = RUNTIME.module('diagnostic_live_agent', 'managed-http-agent.py')
    info = CORE.inspect('container', current['id'])
    require(info and agent.owned(info, current) and info['State']['Running'], 'Actual owned Agent is not live')
    proof_path = folder / 'coordinator-scope-proof.json'
    proof = CORE.read(proof_path)
    require(proof.get('agent_container_id') == current['id'] and proof.get('scope_fd_pinned') is True
            and proof.get('af_packet_socket_count') == 0 and proof.get('native_collector_started') is True
            and proof.get('fresh_three_listener_sync') is True
            and proof.get('agent_binary_sha256') == current['binary_sha256'], 'Qualified live scope proof differs')
    actual = CORE.proc_identity(proof['agent_pid'])
    require(Path('/proc', str(actual['pid']), 'comm').read_text().strip() == 'deepflow-agent', 'Actual Agent process comm differs')
    binaries = [source for source, target, rw in current['mounts'] if target == '/opt/traflens/deepflow-agent' and rw is False]
    require(len(binaries) == 1, 'Actual native binary mount differs')
    native, running = Path(binaries[0]).stat(), Path('/proc', str(actual['pid']), 'exe').stat()
    require((native.st_dev, native.st_ino) == (running.st_dev, running.st_ino), 'Live Agent executable inode differs from qualified bind')
    matched = pinned_namespace_fd(actual['pid'], proof['agent_scope_fds'], current['scope_inode'])
    require(matched and CORE.UTIL.process_start(actual['pid']) == actual['start_ticks'], 'Live Agent namespace FD or generation changed')
    binding = {'container_id': current['id'], 'pid': actual['pid'], 'start_ticks': actual['start_ticks'],
               'agent_id': current['agent_id'], 'hostname': current['hostname'], 'scope_inode': current['scope_inode'],
               'native_binary_sha256': current['binary_sha256'], 'native_source_commit': current['source'],
               'scope_proof_sha256': CORE.file_hash(proof_path)}
    return binding, current


def gate_request(work, stage):
    require(stage in STAGES, 'Unknown observer stage')
    value = private_json(work / 'observer' / stage / 'request.json')
    state = CORE.read(work / 'state.json')
    require(state.get('schema') == CONTRACT.schema and state.get('output') == str(work)
            and value.get('schema') == 'traflens.scoped-observer-request.v1'
            and value.get('stage') == stage and value.get('run') == state.get('run')
            and re.fullmatch('my-[0-9a-f]{24}', value.get('run', '')) is not None
            and re.fullmatch('[0-9a-f]{32}', value.get('nonce', '')) is not None,
            'Observer request does not belong to this diagnostic lifecycle')
    return value


def validate_manifest(folder, request):
    path = folder / 'manifest.json'
    manifest = private_json(path)
    require(manifest.get('schema') == 'traflens.scoped-observer-manifest.v1'
            and manifest.get('run') == request['run'] and manifest.get('stage') == request['stage']
            and manifest.get('nonce') == request['nonce'] and manifest.get('agent') == request['agent']
            and manifest.get('completed') is True and manifest.get('scope_profile_unchanged') is True
            and manifest.get('old_server_unchanged') is True
            and type(manifest.get('captured_at_unix_ns')) is int
            and request['requested_at_unix_ns'] <= manifest['captured_at_unix_ns'] <= time.time_ns(),
            'Observer manifest stage/run/Agent identity/completion differs')
    artifacts = manifest.get('artifacts')
    require(isinstance(artifacts, list) and 1 <= len(artifacts) <= 8, 'Observer requires1..8 explicit data artifacts')
    seen, total = set(), 0
    for item in artifacts:
        require(isinstance(item, dict) and isinstance(item.get('name'), str)
                and re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', item['name'])
                and item['name'] not in ('manifest.json', 'request.json', 'ack.json') and item['name'] not in seen,
                'Observer artifact name differs')
        seen.add(item['name'])
        target = folder / item['name']
        require(target == target.resolve(), 'Observer data cannot follow a symlink')
        meta = target.stat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_uid == os.geteuid() and not meta.st_mode & 0o077
                and 0 < meta.st_size <= MAX_ARTIFACT and type(item.get('bytes')) is int and item['bytes'] == meta.st_size
                and isinstance(item.get('sha256'), str)
                and re.fullmatch('[0-9a-f]{64}', item['sha256']) is not None,
                'Observer artifact ownership/type/length/hash contract differs')
        total += meta.st_size
        require(total <= 16 << 20, 'Observer aggregate artifact budget exceeded')
        require(hashlib.sha256(target.read_bytes()).hexdigest() == item['sha256'], 'Observer data artifact SHA differs')
    # This only establishes bound private evidence collection, never zero loss
    # or completeness of a periodically-reset native counter or raw event stream.
    return CORE.file_hash(path)


def validate_ack(folder, request):
    value = private_json(folder / 'ack.json')
    require(value.get('schema') == 'traflens.scoped-observer-ack.v1' and value.get('run') == request['run']
            and value.get('stage') == request['stage'] and value.get('nonce') == request['nonce']
            and value.get('agent') == request['agent'] and value.get('request_sha256') == CORE.file_hash(folder / 'request.json')
            and value.get('manifest_sha256') == validate_manifest(folder, request)
            and type(value.get('acknowledged_at_unix_ns')) is int
            and request['requested_at_unix_ns'] <= value['acknowledged_at_unix_ns'] <= request['deadline_unix_ns'],
            'Observer ack differs from this live gate')
    return value


def acknowledge(work, stage):
    work = private_dir(work)
    request = gate_request(work, stage)
    require(time.time_ns() <= request['deadline_unix_ns'], 'Observer gate deadline passed')
    binding, _ = live_agent_binding(work)
    require(binding == request['agent'], 'Observer Agent identity differs from current live process')
    folder = work / 'observer' / stage
    manifest_sha = validate_manifest(folder, request)
    require(time.time_ns() <= request['deadline_unix_ns'], 'Observer gate deadline passed during validation')
    if (folder / 'ack.json').exists():
        validate_ack(folder, request)
    else:
        CORE.write(folder / 'ack.json', {'schema': 'traflens.scoped-observer-ack.v1', 'run': request['run'],
                   'stage': stage, 'nonce': request['nonce'], 'agent': binding,
                   'request_sha256': CORE.file_hash(folder / 'request.json'), 'manifest_sha256': manifest_sha,
                   'acknowledged_at_unix_ns': time.time_ns()})
    print(json.dumps({'observer_acknowledged': True, 'stage': stage, 'counter_completeness_claimed': False}))
    return 0


def observer_gate(work, state, stage):
    require(stage in STAGES, 'Unknown observer stage')
    require(state.get('schema') == CONTRACT.schema, 'Observer gates require an unqualified diagnostic lifecycle')
    if stage == 'before-first-wire':
        require(not state['workers'], 'Before-first-wire gate must precede every workload container')
    else:
        require(set(state['workers']) == set(RUNTIME.ROLES), 'After-final-wire gate requires all four finite workers')
    binding, current = live_agent_binding(work)
    timeout = state['args']['observer_timeout_seconds']
    require(type(timeout) is int and 5 <= timeout <= 45, 'Observer timeout outside5..45 seconds')
    require(time.time() - current['started_at_unix'] + timeout + 10 < current['hard_timeout_seconds'],
            'Insufficient bounded Agent lifetime for observer gate')
    root = work / 'observer'
    if root.exists():
        private_dir(root)
    else:
        root.mkdir(mode=0o700)
    folder = root / stage
    folder.mkdir(mode=0o700)
    now = time.time_ns()
    request = {'schema': 'traflens.scoped-observer-request.v1', 'run': state['run'], 'stage': stage,
               'nonce': secrets.token_hex(16), 'agent': binding, 'requested_at_unix_ns': now,
               'deadline_unix_ns': now + timeout * 1_000_000_000, 'timeout_seconds': timeout,
               'diagnostic_only': True, 'counter_read_may_reset': True, 'counter_completeness_claimed': False,
               'coordinator_source_sha256': CORE.file_hash(Path(__file__).resolve())}
    CORE.write(folder / 'request.json', request)
    state.setdefault('observer_gates', {})[stage] = {'status': 'waiting', 'request': str(folder / 'request.json')}
    CORE.persist(work, state)
    CORE.event(work, 'observer-' + stage + '-waiting', {'timeout_seconds': timeout, 'diagnostic_only': True})
    deadline = time.monotonic() + timeout
    while True:
        require(time.monotonic() < deadline, 'Bounded observer gate timed out; cleanup required')
        if (folder / 'ack.json').exists():
            ack = validate_ack(folder, request)
            actual, _ = live_agent_binding(work)
            require(actual == binding, 'Agent changed before observer gate release')
            state['observer_gates'][stage].update(status='completed', manifest_sha256=ack['manifest_sha256'],
                                                 completed_at_unix_ns=time.time_ns())
            CORE.persist(work, state)
            CORE.event(work, 'observer-' + stage + '-completed', {'diagnostic_only': True, 'counter_completeness_claimed': False})
            return
        require(CORE.UTIL.process_start(binding['pid']) == binding['start_ticks'], 'Actual Agent exited during observer gate')
        time.sleep(.1)


CONTRACT = PACED.CONTRACT._replace(diagnostic=True, receipt_validator=validate_receipt,
                                   preflight_validator=preflight, observer_gate=observer_gate)
SCHEMA, PURPOSE, ROLES = CONTRACT.schema, CONTRACT.purpose, RUNTIME.ROLES
worker_info, cleanup, module = RUNTIME.worker_info, RUNTIME.cleanup, RUNTIME.module


def main(argv=None):
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == 'ack':
        parser = argparse.ArgumentParser(description='Acknowledge fixed observer evidence; no shell commands are accepted.')
        parser.add_argument('action', choices=('ack',))
        parser.add_argument('--execute', action='store_true')
        parser.add_argument('--work', type=Path)
        parser.add_argument('--stage', choices=STAGES, required=True)
        args = parser.parse_args(selected)
        if not args.execute:
            print(json.dumps({'observer_acknowledged': False, 'writes_files': False, 'diagnostic_only': True}))
            return 0
        os.umask(0o077)
        require(args.work is not None, 'Explicit private work required')
        return acknowledge(args.work, args.stage)
    return RUNTIME.main(selected, CONTRACT)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'diagnostic_only': True,
                          'integrity_qualified': False, 'private_receipts_retained': True}))
        raise SystemExit(1)
