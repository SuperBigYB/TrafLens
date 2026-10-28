#!/usr/bin/env python3
"""Finite packet-only lo TCP Agent. Default is an offline plan."""
import argparse
from datetime import datetime
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import socket
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require, validate_controller_url
from cpu_profile_controller import packet_tcp_profile, PACKET_TCP_FILTER
import tcp_packet_filter


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


UTIL = module('packet_cpu_utilities', 'cpu-profile.py')
MANAGED = module('packet_artifact_utilities', 'managed-http-agent.py')
SECURITY = module('packet_docker_security', 'ebpf-association.py')
call, inspect = UTIL.call, UTIL.inspect
PURPOSE = 'traflens.packet-tcp-agent'


def write(path, value, replace=False):
    if replace:
        temporary = path.with_name(str(time.time_ns()) + '-' + path.name)
        write(temporary, value)
        os.replace(temporary, path)
        return
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def read(path):
    return json.loads(MANAGED.canonical_private(path).read_text())


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def event(work, name, value):
    write(work / (str(time.time_ns()) + '-' + name + '.json'), value)


def readiness_logs(work, docker_text):
    """Bounded fresh owned log snapshots; return hashes/markers, never text."""
    limit = 4 << 20
    markers = {'native_dispatcher_started': False, 'fresh_three_listener_sync': False}
    sources = []
    consumed = 0
    def observe(source, data):
        nonlocal consumed
        require(len(data) <= limit - consumed, 'Ready log snapshots exceed4MiB')
        consumed += len(data)
        text = data.decode('utf-8', errors='replace')
        markers['native_dispatcher_started'] |= any(value in text for value in
            ('Start dispatcher ', 'Start local plus dispatcher ', 'Start local multi-namespace dispatcher'))
        markers['fresh_three_listener_sync'] |= 'on 3 listener' in text
        sources.append({'source': source, 'bytes_read': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
                        'hash_scope': 'bounded_fd_snapshot_bytes'})
    observe('docker_stdout', docker_text.encode('utf-8'))
    root = work / 'logs'
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        require(os.fstat(fd).st_uid == 0, 'Native log root is not root-owned')
        # dir_fd plus no-follow traversal prevents a symlink (including the
        # native latest-log symlink) from escaping the fresh bound directory.
        for relative, directories, files, directory_fd in os.fwalk('.', topdown=True, follow_symlinks=False, dir_fd=fd):
            safe = []
            for name in directories:
                info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode) and info.st_uid == 0:
                    safe.append(name)
            directories[:] = safe
            for name in sorted(files):
                if not re.fullmatch(r'deepflow-agent(?:[_.-].*)?', name):
                    continue
                try:
                    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    if not stat.S_ISREG(before.st_mode) or before.st_uid != 0:
                        continue
                    log_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
                    with os.fdopen(log_fd, 'rb') as stream:
                        actual = os.fstat(stream.fileno())
                        require(stat.S_ISREG(actual.st_mode) and actual.st_uid == 0
                                and (actual.st_dev, actual.st_ino) == (before.st_dev, before.st_ino),
                                'Native log identity changed while opening')
                        require(actual.st_size <= limit - consumed, 'Native log snapshots exceed4MiB')
                        data = stream.read(actual.st_size)
                    observe(str(Path('logs') / relative / name), data)
                except FileNotFoundError:
                    continue  # Rotation during the owned snapshot; next poll rechecks.
    finally:
        os.close(fd)
    return {'method': 'fresh_root_owned_regular_no_symlink_prefix_bounded_snapshots',
            'byte_limit': limit, 'bytes_read': consumed, 'sources': sources, **markers}


def envelope(info):
    config, host = info['Config'], info['HostConfig']
    security = host.get('SecurityOpt') or []
    canonical_security, _ = SECURITY.worker_security(security)
    require(all(m['Type'] == 'bind' for m in info['Mounts']), 'Unexpected packet Agent mount type')
    return {'name': info['Name'].removeprefix('/'), 'image': info['Image'], 'config_image': config['Image'],
            'hostname': config['Hostname'], 'user': config.get('User'), 'entrypoint': config['Entrypoint'], 'command': config['Cmd'],
            'network': host['NetworkMode'], 'pid_mode': host.get('PidMode', ''), 'readonly': host['ReadonlyRootfs'],
            'privileged': host['Privileged'], 'cap_add': sorted(c.removeprefix('CAP_') for c in host.get('CapAdd') or []),
            'cap_drop': sorted(c.removeprefix('CAP_') for c in host.get('CapDrop') or []),
            'nano_cpus': host['NanoCpus'], 'memory': host['Memory'], 'memory_swap': host['MemorySwap'], 'pids_limit': host['PidsLimit'],
            'ports': host.get('PortBindings') or {}, 'publish_all': host.get('PublishAllPorts', False),
            'restart': host['RestartPolicy']['Name'], 'security': canonical_security,
            'labels': {k: (config.get('Labels') or {}).get(k) for k in ('io.traflens.purpose', 'io.traflens.run', 'io.traflens.output')},
            'mounts': sorted([[m['Source'], m['Destination'], m['RW']] for m in info['Mounts']])}


def owned(info, receipt):
    if info is None:
        return False
    try:
        return (not receipt.get('id') or info['Id'] == receipt['id']) and envelope(info) == receipt['spec']
    except (KeyError, RuntimeError, TypeError):
        return False


def live_process(info, receipt):
    # PID1 is timeout in a private PID namespace; the actual native Agent is its
    # direct child. No hostPID or host /proc mount is granted to the container.
    root = info['State']['Pid']
    require(info['State']['Running'] and type(root) is int and root > 1, 'Owned packet Agent container is not running')
    children = Path('/proc', str(root), 'task', str(root), 'children').read_text().split()
    matches = []
    for child in children:
        pid = int(child)
        proc = Path('/proc', child)
        if (proc / 'comm').read_text().strip() == 'deepflow-agent' and sha(proc / 'exe') == receipt['binary_sha256']:
            ticks = UTIL.process_start(pid)
            require(os.readlink(proc / 'ns/net') == os.readlink('/proc/self/ns/net'), 'Packet Agent is not in hostNET')
            require(os.readlink(proc / 'ns/pid') != os.readlink('/proc/self/ns/pid'), 'Packet Agent unexpectedly uses hostPID')
            matches.append({'pid': pid, 'start_ticks': ticks, 'container_pid': root,
                            'netns': os.readlink(proc / 'ns/net'), 'pidns': os.readlink(proc / 'ns/pid')})
    require(len(matches) == 1, 'Expected exactly one actual SHA-qualified native Agent child')
    return matches[0]


def baseline():
    ids = MANAGED.ids()
    return {'bpf_ids': ids, 'bpf_types': {str(pid): program_type(pid) for pid in ids}, 'tracefs': MANAGED.tracefs(),
            'lo_ifindex': socket.if_nametoindex('lo'), 'lo_flags': Path('/sys/class/net/lo/flags').read_text()}


def program_type(program_id):
    try:
        return MANAGED.workload.program_type(program_id)
    except (OSError, RuntimeError):
        return None  # Type visibility never exempts an unmatched program ID.


def restoration_snapshot(receipt):
    expected = receipt['baseline']
    original, current = set(expected['bpf_ids']), set(MANAGED.ids())
    missing, added = sorted(original - current), sorted(current - original)
    tracefs_ok = MANAGED.tracefs() == expected['tracefs']
    lo_index_ok = socket.if_nametoindex('lo') == expected['lo_ifindex']
    lo_flags_ok = Path('/sys/class/net/lo/flags').read_text() == expected['lo_flags']
    return {'observed_at_unix': time.time(), 'bpf_missing': [
                {'id': pid, 'type': expected.get('bpf_types', {}).get(str(pid)),
                 'type_source': 'baseline' if str(pid) in expected.get('bpf_types', {}) else 'not_recorded'} for pid in missing],
            'bpf_new': [{'id': pid, 'type': program_type(pid)} for pid in added],
            'bpf_inventory_exact': not missing and not added, 'tracefs_restored': tracefs_ok,
            'lo_ifindex_restored': lo_index_ok, 'lo_flags_restored': lo_flags_ok,
            'restored': not missing and not added and tracefs_ok and lo_index_ok and lo_flags_ok}


def wait_restoration(work, receipt, timeout=90):
    started = time.monotonic()
    deadline = started + timeout
    path = work / ('restoration-polls-' + str(time.time_ns()) + '.jsonl')
    with path.open('x') as stream:
        path.chmod(0o600)
        while True:
            snapshot = restoration_snapshot(receipt)
            snapshot['elapsed_seconds'] = round(time.monotonic() - started, 6)
            json.dump(snapshot, stream)
            stream.write('\n')
            stream.flush()
            if snapshot['restored']:
                return {'journal': str(path), 'final': snapshot}
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'Original BPF/tracefs/lo inventory did not restore within bounded wait')
            time.sleep(min(.2, remaining))


def restored(receipt):
    value = receipt['baseline']
    return (set(MANAGED.ids()) == set(value['bpf_ids']) and MANAGED.tracefs() == value['tracefs']
            and socket.if_nametoindex('lo') == value['lo_ifindex']
            and Path('/sys/class/net/lo/flags').read_text() == value['lo_flags'])


def read_exit_state(work, receipt):
    path = work / 'exit-state.json'
    if not path.exists():
        return None  # Old absent-container runs cannot manufacture exit proof.
    value = read(path)
    require(value.get('schema') == 'traflens.packet-tcp-agent.exit.v1'
            and value.get('container_id') == receipt.get('id')
            and value.get('image_id') == receipt['spec']['image']
            and type(value.get('exit_code')) is int and type(value.get('oom_killed')) is bool
            and type(value.get('observed_unix_ns')) is int and value['observed_unix_ns'] > 0,
            'Immutable packet Agent exit proof differs from owned receipt')
    finished = value.get('finished_at')
    require(isinstance(finished, str)
            and re.fullmatch(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z', finished),
            'Actual packet Agent FinishedAt is missing')
    try:
        # Docker preserves nanoseconds; Python3.10 accepts at most6 fractional
        # digits. Validate calendar/time without changing the saved raw value.
        normalized = re.sub(r'(\.\d{6})\d+(?=Z$)', r'\1', finished)
        require(datetime.fromisoformat(normalized.replace('Z', '+00:00')).timestamp() > 0,
                'Actual packet Agent FinishedAt is invalid')
    except ValueError:
        raise RuntimeError('Actual packet Agent FinishedAt is invalid') from None
    return value


def record_exit_state(work, receipt, info):
    require(owned(info, receipt) and not info['State']['Running'], 'Actual owned stopped container required for exit proof')
    actual = {'schema': 'traflens.packet-tcp-agent.exit.v1', 'container_id': info['Id'], 'image_id': info['Image'],
              'exit_code': info['State']['ExitCode'], 'oom_killed': info['State']['OOMKilled'],
              'finished_at': info['State']['FinishedAt'], 'observed_unix_ns': time.time_ns()}
    previous = read_exit_state(work, receipt)
    if previous is None:
        write(work / 'exit-state.json', actual)
        return read_exit_state(work, receipt)
    require(all(previous[key] == actual[key] for key in actual if key != 'observed_unix_ns'),
            'Actual packet Agent exit state changed; immutable proof retained')
    return previous


def recover(work):
    current = work / 'current.json'
    receipt = read(current if current.exists() else work / 'intent.json')
    require(receipt.get('schema') == 'traflens.packet-tcp-agent.v1' and receipt['output'] == str(work), 'Invalid packet Agent receipt')
    info = inspect('container', receipt.get('id') or receipt['spec']['name'])
    if info is not None:
        require(owned(info, receipt), 'Refusing unknown or changed packet Agent')
        if not receipt.get('id'):
            receipt['id'] = info['Id']
            write(current, receipt)
            event(work, 'uncertain-create-recovered', {'id': info['Id']})
    return receipt, info


def stop(work):
    work = private_dir(work)
    with (work / 'launcher.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        receipt, info = recover(work)
        exit_state = read_exit_state(work, receipt)
        if info is not None:
            logs = call(['docker', 'logs', info['Id']], check=False)
            (work / (str(time.time_ns()) + '-native.log')).write_text(logs.stdout + logs.stderr)
            if info['State']['Running']:
                call(['docker', 'stop', '--time', '40', info['Id']], timeout=55)
            info = inspect('container', info['Id'])
            require(owned(info, receipt) and not info['State']['Running'], 'Owned packet Agent did not stop')
            exit_state = record_exit_state(work, receipt, info)
            event(work, 'exit', exit_state)
            call(['docker', 'rm', info['Id']])
        require(inspect('container', receipt.get('id') or receipt['spec']['name']) is None, 'Packet Agent absence is unproven')
        restoration = wait_restoration(work, receipt, 90)
        result = {'agent_stopped': True, 'container_removed': True, 'bpf_inventory_restored': True,
                  'tracefs_restored': True, 'lo_identity_and_flags_restored': True, 'exit': exit_state,
                  'restoration_journal': restoration['journal'],
                  'restoration_wait_seconds': restoration['final']['elapsed_seconds'],
                  'observed_at_unix': time.time()}
        event(work, 'stop', result)
        if not (work / 'stopped.json').exists():
            write(work / 'stopped.json', result)
        print(json.dumps(result))
        return result


def start(args):
    validate_controller_url(args.controller_api)  # No credential-bearing intent.
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Qualified Linux x86_64 root execution required')
    require(re.fullmatch('g-[A-Za-z0-9]{1,64}', args.group_id or '') and type(args.agent_id) is int and 1 <= args.agent_id <= 65535,
            'Exact new Controller group and Agent ID required')
    profile = packet_tcp_profile(args.controller_ip, args.controller_port, args.ingester_port)
    artifact, binary, libraries = MANAGED.verified_artifacts(args.artifacts)
    require(inspect('image', artifact['image_id'])['Id'] == artifact['image_id'], 'Qualified native image is not cached')
    boot = {'controller-ips': [args.controller_ip], 'controller-port': args.controller_port,
            'vtap-group-id-request': args.group_id, 'async-worker-thread-number': 2,
            'log-file': '/var/log/traflens/deepflow-agent.log', 'pid-file': '/run/traflens/deepflow-agent.pid',
            'cgroups-disabled': True, 'liveness-probe-enabled': True, 'liveness-probe-port': 39091}
    registration = MANAGED.controller_readback(args.controller_api, boot, profile, args.agent_id)
    run = registration['agent']['NAME'].removeprefix('traflens-')
    require(re.fullmatch('tcp-[0-9a-f]{24}', run) and registration['group']['NAME'] == 'traflens-' + run
            and sorted(registration['agent']['LICENSE_FUNCTIONS']) == [2, 4, 5], 'Only the fresh fixed-license packet group may be used')
    active = call(['docker', 'ps', '-aq', '--filter', 'label=io.traflens.purpose=' + PURPOSE])
    require(not active.stdout.strip(), 'Earlier packet Agent resource remains')
    for proc in Path('/proc').iterdir():
        if proc.name.isdigit():
            try:
                name = (proc / 'comm').read_text().strip()
            except OSError:
                continue
            require(name not in {'deepflow-agent', 'deepflow_agent', 'socket_tracer', 'tlens-ebpf-gate'}, 'Another native tracer process exists')
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 39091))
    work = private_dir(args.work, fresh=True)
    with (work / 'launcher.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        write(work / 'profile.json', profile)
        write(work / 'bootstrap.yaml', boot)
        logs, state = work / 'logs', work / 'native-state'
        logs.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        name = 'traflens-packet-tcp-' + secrets.token_hex(6)
        image = artifact['image_id']
        mounts = sorted([[str(binary), '/opt/traflens/deepflow-agent', False], [str(libraries), '/opt/traflens-libs', False],
                         [str(work / 'bootstrap.yaml'), '/etc/traflens/agent.yaml', False],
                         [str(logs), '/var/log/traflens', True], [str(state), '/run/traflens', True]])
        command = ['--signal=TERM', '--kill-after=40s', '180', '/opt/traflens/deepflow-agent', '--cgroups-disabled', '-f', '/etc/traflens/agent.yaml']
        spec = {'name': name, 'image': image, 'config_image': image, 'hostname': registration['agent']['NAME'], 'user': '0:0',
                'entrypoint': ['/usr/bin/timeout'], 'command': command, 'network': 'host', 'pid_mode': '', 'readonly': True,
                'privileged': False, 'cap_add': ['NET_RAW'], 'cap_drop': ['ALL'], 'nano_cpus': 2000000000,
                'memory': 1073741824, 'memory_swap': 1073741824, 'pids_limit': 384, 'ports': {}, 'publish_all': False,
                'restart': 'no', 'security': ['no-new-privileges'], 'mounts': mounts,
                'labels': {'io.traflens.purpose': PURPOSE, 'io.traflens.run': run, 'io.traflens.output': str(work)}}
        argv = ['docker', 'create', '--name', name, '--network', 'host', '--user', '0:0', '--hostname', registration['agent']['NAME'],
                '--cpus', '2', '--memory', '1073741824', '--memory-swap', '1073741824', '--pids-limit', '384',
                '--cap-drop', 'ALL', '--cap-add', 'NET_RAW', '--read-only', '--restart', 'no', '--security-opt', 'no-new-privileges',
                '--ulimit', 'memlock=-1:-1', '--ulimit', 'core=0:0', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=2',
                '--env', 'LD_LIBRARY_PATH=/opt/traflens-libs', '--env', 'IN_CONTAINER=yes']
        for key, value in spec['labels'].items():
            argv += ['--label', key + '=' + value]
        for source, target, writable in mounts:
            argv += ['--mount', 'type=bind,source=' + source + ',target=' + target + ('' if writable else ',readonly')]
        argv += ['--entrypoint', '/usr/bin/timeout', image, *command]
        receipt = {'schema': 'traflens.packet-tcp-agent.v1', 'output': str(work), 'spec': spec, 'argv': argv,
                   'agent_id': args.agent_id, 'run': run, 'controller_api': args.controller_api,
                   'binary_sha256': artifact['binary_sha256'], 'source_commit': artifact['source'],
                   'artifact_manifest_sha256': sha(args.artifacts), 'bootstrap_sha256': sha(work / 'bootstrap.yaml'),
                   'profile_sha256': sha(work / 'profile.json'), 'baseline': baseline(), 'requires_packet_bpf_ready_before_traffic': True}
        write(work / 'intent.json', receipt)
        created = call(argv, timeout=25).stdout.strip()
        info = inspect('container', created)
        require(owned(info, receipt), 'Actual packet Agent differs from restricted intent')
        receipt['id'] = info['Id']
        write(work / 'current.json', receipt)
        call(['docker', 'start', info['Id']], timeout=15)
        info = inspect('container', info['Id'])
        require(owned(info, receipt) and info['State']['Running'], 'Owned packet Agent did not remain running')
        print(json.dumps({'started': True, 'container_id': info['Id'], 'current': str(work / 'current.json'),
                          'ready': False, 'traffic_allowed': False, 'hard_timeout_seconds': 180, 'kill_grace_seconds': 40}))


class ReadyFailure(RuntimeError):
    def __init__(self, stage, error_class):
        super().__init__('Packet readiness failed; private structured diagnostics retained')
        self.stage = stage
        self.original_error_class = error_class


def _ready(args, diagnostics):
    work = private_dir(args.work)
    with (work / 'launcher.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        diagnostics['stage'] = 'receipt_and_preparation'
        receipt, info = recover(work)
        require(sha(work / 'bootstrap.yaml') == receipt['bootstrap_sha256'] and sha(work / 'profile.json') == receipt['profile_sha256'],
                'Packet Agent prepared files changed')
        boot, profile = read(work / 'bootstrap.yaml'), read(work / 'profile.json')
        require('ebpf-socket-netns-scope' not in boot and profile == packet_tcp_profile(boot['controller-ips'][0], boot['controller-port'],
                profile['global']['communication']['ingester_port']), 'Packet-only profile or bootstrap differs')
        diagnostics['stage'] = 'controller_readback'
        MANAGED.controller_readback(receipt['controller_api'], boot, profile, receipt['agent_id'])
        diagnostics['stage'] = 'dispatcher_and_policy'
        deadline = time.monotonic() + 65
        while time.monotonic() < deadline:
            info = inspect('container', receipt['id'])
            require(owned(info, receipt) and info['State']['Running'], 'Owned packet Agent exited before readiness')
            logs = call(['docker', 'logs', receipt['id']])
            snapshot = readiness_logs(work, logs.stdout + logs.stderr)
            diagnostics['readiness_log_sources'] = snapshot
            if snapshot['native_dispatcher_started'] and snapshot['fresh_three_listener_sync']:
                break
            time.sleep(1)
        else:
            raise RuntimeError('Actual packet dispatcher and fresh three-listener policy did not become ready')
        diagnostics.update(native_dispatcher_started=True, fresh_three_listener_sync=True)
        diagnostics['stage'] = 'actual_agent_process'
        actual = live_process(info, receipt)
        diagnostics['actual_agent'] = actual
        diagnostics['stage'] = 'actual_packet_filter'
        proof = tcp_packet_filter.prove(actual['pid'], PACKET_TCP_FILTER, diagnostics.setdefault('filter', {}))
        diagnostics['stage'] = 'stable_agent_process'
        require(UTIL.process_start(actual['pid']) == actual['start_ticks'], 'Agent process changed during BPF readback')
        proof.update(schema='traflens.packet-tcp-ready.v1', agent_container_id=receipt['id'], agent_id=receipt['agent_id'],
                     actual_agent=actual, binary_sha256=receipt['binary_sha256'], native_dispatcher_started=True,
                     fresh_three_listener_sync=True, safe_profile_verified=True, on_cpu_enabled=False, observed_at_unix=time.time(),
                     readiness_log_sources=diagnostics['readiness_log_sources'])
        write(work / 'packet-bpf-proof.json', proof)
        diagnostics.update(stage='complete', passed=True)
        print(json.dumps({'ready': True, 'proof': str(work / 'packet-bpf-proof.json'),
                          'effective_kernel_lo_only': True, 'actual_custom_bpf_prefix_verified': True, 'http_emitted': False}))


def ready(args):
    work = private_dir(args.work)
    diagnostics = {'schema': 'traflens.packet-tcp-ready-diagnostics.v1', 'passed': False,
                   'stage': 'initial', 'packet_payload_read': False}
    try:
        _ready(args, diagnostics)
    except Exception as error:
        stage = diagnostics.get('stage', 'initial')
        if stage == 'actual_packet_filter':
            stage += '.' + diagnostics.get('filter', {}).get('stage', 'initial')
        diagnostics.update(stage=stage, error_class=type(error).__name__,
            reason_code=getattr(error, 'reason_code', stage.replace('.', '_') + '_failed'),
            errno=getattr(error, 'errno', None), observed_at_unix=time.time())
        write(work / ('ready-failure-' + str(time.time_ns()) + '.json'), diagnostics)
        raise ReadyFailure(stage, type(error).__name__) from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('plan', 'start', 'ready', 'stop'), default='plan')
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--artifacts', type=Path)
    parser.add_argument('--controller-api')
    parser.add_argument('--controller-ip')
    parser.add_argument('--controller-port', type=int, default=20035)
    parser.add_argument('--ingester-port', type=int, default=20033)
    parser.add_argument('--group-id')
    parser.add_argument('--agent-id', type=int)
    args = parser.parse_args(argv)
    if not args.execute or args.action == 'plan':
        print(json.dumps({'execute': False, 'reads_artifacts': False, 'starts_network': False, 'creates_resources': False,
                          'interface': '^lo$', 'fixed_server_ports': [18081, 18082, 18083], 'cap_add': ['NET_RAW'],
                          'host_pid': False, 'ebpf_enabled': False, 'hard_timeout_seconds': 180, 'kill_grace_seconds': 40}))
        return 0
    os.umask(0o077)
    require(args.work is not None, 'Explicit private work required')
    if args.action == 'start':
        try:
            start(args)
        except BaseException:
            if (args.work / 'intent.json').exists():
                try:
                    stop(args.work)
                except Exception:
                    pass  # Preserve initial failure; explicit stop retains full guards.
            raise
    elif args.action == 'ready':
        ready(args)
    else:
        stop(args.work)
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': getattr(error, 'original_error_class', type(error).__name__),
                          'stage': getattr(error, 'stage', 'command'), 'private_receipts_retained': True}))
        raise SystemExit(1)
