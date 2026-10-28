#!/usr/bin/env python3
"""Finite scoped eBPF DNS/TCP capture. Default is an offline plan."""
import argparse
import fcntl
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import sys
import time
from typing import NamedTuple

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require, validate_controller_url
from cpu_profile_controller import kernel_dns_profile


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CORE = module('dns_scoped_common', 'ebpf-association.py')
PREPARE = module('dns_scoped_preparation', 'managed-dns.py')
SCHEMA = 'traflens.ebpf-dns.capture.v1'
ROLE_SCHEMA = 'traflens.ebpf-dns.worker-runtime.v1'
PURPOSE = 'traflens.ebpf-dns.worker'
ROLES = ('negative-client', 'negative-server', 'positive-client', 'positive-server')


class ProtocolContract(NamedTuple):
    name: str
    prefix: str
    integration_mode: str
    protocol_id: int
    profile_factory: object
    prepare_file: str
    expected_observations: object
    receipt_validator: object = None
    server_comm: object = None
    client_comm: object = None

    @property
    def label(self):
        return {'dns': 'DNS/TCP', 'mysql': 'MySQL/TCP'}[self.name]

    @property
    def schema(self):
        return 'traflens.ebpf-' + self.name + '.capture.v1'

    @property
    def role_schema(self):
        return 'traflens.ebpf-' + self.name + '.worker-runtime.v1'

    @property
    def purpose(self):
        return 'traflens.ebpf-' + self.name + '.worker'

    @property
    def script(self):
        return 'ebpf-' + self.name + '.py'


DNS_CONTRACT = ProtocolContract('dns', 'dns-', 'kernel_dns', 120, kernel_dns_profile, 'managed-dns.py', 6)


def validate_contract(contract):
    require(isinstance(contract, ProtocolContract)
            and (contract.name, contract.prefix, contract.integration_mode, contract.protocol_id, contract.prepare_file)
                in (('dns', 'dns-', 'kernel_dns', 120, 'managed-dns.py'),
                    ('mysql', 'my-', 'kernel_mysql', 60, 'managed-mysql.py')),
            'Unsupported fixed scoped protocol contract')


def worker_selection(state, role):
    scope_role, worker_role = role.split('-', 1)
    require(scope_role in ('positive', 'negative') and worker_role in ('server', 'client'), 'Unknown DNS worker role')
    return scope_role, worker_role, state['run'] if scope_role == 'positive' else state['negative_run']


def worker_spec(state, role, contract=DNS_CONTRACT):
    validate_contract(contract)
    scope_role, worker_role, run = worker_selection(state, role)
    a, work = state['args'], Path(state['output'])
    return {'name': 'traflens-' + state['run'] + '-' + role, 'image': a['image'],
            'pid_mode': 'host', 'network_mode': 'container:' + state['scope'][scope_role]['container_id'],
            'read_only': True, 'cap_drop': ['ALL'], 'cap_add': [], 'nano_cpus': 500000000,
            'memory_bytes': 67108864, 'memory_swap_bytes': 67108864, 'pids_limit': 16,
            'privileged': False, 'port_bindings': {}, 'publish_all_ports': False,
            'security_opt': ['no-new-privileges'], 'restart_policy': 'no',
            'labels': {'io.traflens.purpose': contract.purpose, 'io.traflens.run': state['run'],
                       'io.traflens.role': role, 'io.traflens.output': str(work)},
            'entrypoint': ['/workload'],
            'command': ['--execute', '--role', worker_role, '--run', run, '--output', '/output',
                        '--seconds', '90', '--port', '18080'],
            'mounts': sorted([[a['workload_bin'], '/workload', False], [str(work / role), '/output', True]])}


def worker_info(state, role):
    return CORE.worker_info(state, role)


def live_executable_sha(actual):
    """Hash only this named live PID's kernel exe handle, never an arbitrary path."""
    pid, ticks = actual.get('pid'), actual.get('start_ticks')
    require(type(pid) is int and pid > 1 and isinstance(ticks, str) and ticks.isdigit(),
            'Explicit live DNS process identity required')
    require(CORE.UTIL.process_start(pid) == ticks, 'DNS PID identity changed before executable proof')
    path = Path('/proc', str(pid), 'exe')
    # /proc/PID/exe is intentionally a kernel-owned symlink. Artifact paths
    # continue to use CORE.file_hash's canonical non-symlink contract.
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        opened = os.fstat(fd)
        require(stat.S_ISREG(opened.st_mode) and 0 < opened.st_size <= 64 << 20,
                'DNS live executable exceeds finite proof budget')
        digest = hashlib.sha256()
        read = 0
        while True:
            block = os.read(fd, 1 << 20)
            if not block:
                break
            read += len(block)
            require(read <= 64 << 20, 'DNS live executable exceeds finite proof budget')
            digest.update(block)
        current = path.stat()
        require(CORE.UTIL.process_start(pid) == ticks
                and (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
                    == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns)
                and read == opened.st_size, 'DNS process/executable changed during SHA proof')
        return digest.hexdigest()
    finally:
        os.close(fd)


def comm_direction_hint(actual, process, worker_role, contract=DNS_CONTRACT):
    expected = contract.server_comm if worker_role == 'server' else contract.client_comm
    if expected is None:
        return None
    actual_comm = Path('/proc', str(actual['pid']), 'comm').read_text().strip()
    require(actual_comm == expected and process.get('comm') == actual_comm,
            'Actual owned process comm direction hint differs')
    return actual_comm


def create_worker(work, state, role, contract=DNS_CONTRACT):
    scope_role, worker_role, run = worker_selection(state, role)
    (work / role).mkdir(mode=0o700)
    spec = worker_spec(state, role, contract)
    require(CORE.inspect('container', spec['name']) is None, 'Fresh DNS worker name already exists')
    argv = CORE.docker_argv(spec)
    intent = {'spec': spec, 'argv': argv, 'argv_sha256': CORE.digest(argv)}
    state['workers'][role] = intent
    CORE.persist(work, state)
    CORE.write(work / (role + '-intent.json'), intent)
    created = CORE.call(argv, timeout=20).stdout.strip()
    info = CORE.inspect('container', created)
    require(CORE.owned_worker(info, intent), 'DNS worker differs from restricted Docker intent')
    intent['id'] = info['Id']
    CORE.persist(work, state)
    CORE.write(work / (role + '-created.json'), {'id': info['Id'], 'name': spec['name'],
               'command': spec['command'], 'mounts': spec['mounts']})
    CORE.call(['docker', 'start', info['Id']], timeout=8)
    deadline = time.monotonic() + (3 if worker_role == 'client' else 10)
    while time.monotonic() < deadline:
        info = worker_info(state, role)
        require(info and info['State']['Running'], 'DNS worker exited before actual runtime proof')
        if (work / role / 'process.json').exists() and (worker_role == 'client' or (work / role / 'ready.json').exists()):
            break
        time.sleep(.02)
    else:
        raise RuntimeError('DNS actual process/ready receipt missing')
    actual = CORE.proc_identity(info['State']['Pid'])
    process = CORE.read(work / role / 'process.json')
    require(process.get('run') == run and process.get('role') == worker_role
            and all(process.get(key) == actual[key] for key in ('pid', 'start_ticks', 'netns', 'pidns')),
            'DNS Docker PID differs from actual workload receipt')
    require(actual['netns'] == state['scope'][scope_role]['netns']
            and actual['pidns'] == os.readlink('/proc/self/ns/pid'), 'DNS worker namespace differs from intent')
    require(live_executable_sha(actual) == state['args']['workload_sha256'],
            'DNS actual executable SHA differs')
    actual_comm = comm_direction_hint(actual, process, worker_role, contract)
    require(CORE.UTIL.process_start(actual['pid']) == actual['start_ticks']
            and worker_info(state, role)['State']['Pid'] == actual['pid'], 'DNS actual process changed during proof')
    observed = CORE.normalized_worker(info)
    _, security_context = CORE.worker_security(info['HostConfig'].get('SecurityOpt') or [])
    observed.update(actual, id=info['Id'], started_at=info['State']['StartedAt'], running=True,
                    executable_sha256=state['args']['workload_sha256'],
                    security_opt_raw=info['HostConfig'].get('SecurityOpt') or [], security_opt_normalization=security_context)
    if actual_comm is not None:
        observed['comm'] = actual_comm
        observed['comm_direction_hint_only'] = True
    CORE.write(work / (role + '-runtime.json'), {'schema': contract.role_schema, 'role': role, 'scope_role': scope_role,
               'run': state['run'], 'workload_run': run, 'scope_receipt': 'scope-runtime.json',
               'agent_container_id': state['scope']['agent_container_id'],
               'create': {'argv': argv, 'argv_sha256': intent['argv_sha256'], 'normalized': spec}, 'inspect': observed})


def pause_server(work, state, phase, paused):
    role = phase + '-server'
    info = worker_info(state, role)
    require(info and info['State']['Running'], 'Owned DNS server is absent before identity gate')
    if paused:
        CORE.event(work, phase + '-pause-intent', {'id': info['Id'], 'max_seconds': 5, 'performance_measurement': False})
    if bool(info['State'].get('Paused')) != paused:
        CORE.call(['docker', 'pause' if paused else 'unpause', info['Id']], timeout=4)
    info = worker_info(state, role)
    require(info and bool(info['State'].get('Paused')) == paused, 'DNS server pause state differs')


def validate_receipt(receipt, run, role):
    connections = receipt.get('connections')
    require(receipt.get('run') == run and receipt.get('role') == role and receipt.get('pass') is True
            and receipt.get('completed_requests') == 3 and receipt.get('expected_requests') == 3
            and receipt.get('wire_events') == 6 and receipt.get('owned_sockets_closed') is True
            and receipt.get('listener_closed') is True and receipt.get('single_threaded') is True
            and receipt.get('error') == '' and isinstance(connections, list) and len(connections) == 3
            and all(isinstance(v, dict) and v.get('complete') is True and v.get('closed') is True for v in connections),
            'Actual DNS socket/application receipt is incomplete')


def run_phase(work, state, phase, contract=DNS_CONTRACT):
    create_worker(work, state, phase + '-server', contract)
    started = time.monotonic()
    def expired(*_):
        raise TimeoutError('DNS client identity pause gate exceeded5 seconds')
    previous = signal.signal(signal.SIGALRM, expired)
    signal.setitimer(signal.ITIMER_REAL, 5)
    try:
        pause_server(work, state, phase, True)
        create_worker(work, state, phase + '-client', contract)
        require(time.monotonic() - started <= 5, 'DNS identity gate exceeded5 seconds')
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        pause_server(work, state, phase, False)
        CORE.event(work, phase + '-unpaused', {'duration_seconds': time.monotonic() - started, 'performance_measurement': False})
    for role in (phase + '-client', phase + '-server'):
        require(int(CORE.call(['docker', 'wait', state['workers'][role]['id']], timeout=30).stdout) == 0,
                'Finite DNS worker exit failed')
        receipt = CORE.read(work / role / 'receipt.json')
        _, worker_role, run = worker_selection(state, role)
        validator = contract.receipt_validator or validate_receipt
        validator(receipt, run, worker_role)
    CORE.event(work, phase + '-completed', {'queries': 3, 'transport': 'tcp', 'port': 18080, 'protocol': contract.label})


def cleanup(work, state):
    errors = []
    exits = dict(state.get('worker_exits', {}))
    for role in ROLES:
        if role not in state['workers']:
            continue
        try:
            info = worker_info(state, role)
            CORE.persist(work, state)
            if info is None:
                continue
            if info['State'].get('Paused'):
                CORE.call(['docker', 'unpause', info['Id']], timeout=5)
                info = worker_info(state, role)
                require(info and not info['State'].get('Paused'), 'DNS worker remains paused')
            if info['State']['Running']:
                CORE.call(['docker', 'stop', '--time', '5', info['Id']], timeout=15)
            info = worker_info(state, role)
            require(info and not info['State']['Running'], 'DNS worker did not stop')
            exits[role] = {'exit_code': info['State']['ExitCode'], 'oom': info['State']['OOMKilled']}
            state['worker_exits'] = exits
            CORE.persist(work, state)
            CORE.call(['docker', 'rm', info['Id']])
            require(worker_info(state, role) is None, 'DNS worker removal unproven')
        except Exception as error:
            errors.append(role + ': ' + type(error).__name__)
    if errors:
        result = {'cleaned': False, 'worker_exits': exits, 'collector_stopped': False, 'lease_restored': False,
                  'controller_cleaned': False, 'cleanup_errors': errors}
        state.update(result)
        CORE.persist(work, state)
        CORE.event(work, 'cleanup-retained', result)
        return result
    # Shared strict restoration checks all actual workers absent, then stops
    # Agent/BPF/tracefs, releases NS pins, restores Controller, stops own forward.
    return CORE.cleanup(work, state)


def execute(args, contract=DNS_CONTRACT):
    validate_controller_url(args.controller_url)
    validate_contract(contract)
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Qualified Linux x86_64 root required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', args.backend_host or ''), 'Explicit SSH alias required')
    for key in ('work', 'backend_root', 'backend_work', 'backend_code', 'artifacts', 'workload_bin'):
        value = getattr(args, key)
        require(value and Path(value).is_absolute() and not any(c in value for c in ',\r\n\0'), 'Safe absolute paths required')
    require(Path(args.backend_work) != Path(args.backend_root)
            and Path(args.backend_work).is_relative_to(Path(args.backend_root)), 'Backend work must be below owned lab root')
    require(re.fullmatch('sha256:[0-9a-f]{64}', args.image or '')
            and re.fullmatch('[0-9a-f]{64}', args.workload_sha256 or ''), 'Exact image/workload SHA required')
    require(1024 <= args.forward_port <= 65535, 'Explicit unprivileged forward port required')
    address = ipaddress.ip_address(args.ctrl_ip)
    require(address.version == 4 and address.is_private and not address.is_loopback and not address.is_link_local
            and not address.is_unspecified, 'Verified host Controller IPv4 required')
    require(re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', args.ctrl_mac or '')
            and not int(args.ctrl_mac[:2], 16) & 1 and args.ctrl_mac != '00:00:00:00:00:00', 'Verified unicast MAC required')
    profile = contract.profile_factory(args.controller_ip, args.controller_port, args.ingester_port)
    require(CORE.file_hash(args.workload_bin) == args.workload_sha256, 'Workload hash differs')
    require(CORE.inspect('image', args.image)['Id'] == args.image, 'Exact worker image not cached')
    agent = module('dns_preflight_agent', 'managed-http-agent.py')
    agent.verified_artifacts(Path(args.artifacts))
    hashes = CORE.helper_hashes(args)
    parent = private_dir(Path(args.work).parent)
    with (parent / ('.ebpf-' + contract.name + '.lock')).open('a') as run_lock:
        fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = private_dir(args.work, fresh=True)
        state = {'schema': contract.schema, 'run': contract.prefix + secrets.token_hex(12), 'negative_run': contract.prefix + secrets.token_hex(12),
                 'output': str(work), 'args': vars(args), 'workers': {}, 'controller_attempted': False,
                 'agent_attempted': False, 'lease_attempted': False}
        require(state['run'] != state['negative_run'], 'Positive/negative DNS nonces must differ')
        CORE.persist(work, state)
        CORE.write(work / 'helper-code-sha256.json', hashes)
        CORE.write(work / 'capture-source-sha256.json', {name: CORE.file_hash(HERE / name) for name in
                   dict.fromkeys((contract.script, contract.prepare_file, 'ebpf-dns.py', 'managed-http-agent.py', 'association-lease.py',
                    'ebpf-association.py', 'managed_http_scope.py', 'managed_http_scope_validation.py', 'managed-http-scope-abi.json'))})
        CORE.write(work / 'supervisor.json', dict(CORE.proc_identity(os.getpid()), argv=sys.argv))
        result = {'schema': contract.schema, 'run': state['run'], 'negative_run': state['negative_run'], 'pass': False,
                  'storage_verified': False, 'runtime_receipts_required': True, 'performance_measurement': False}
        def interrupted(*_):
            raise InterruptedError('Owned DNS capture interrupted; public stop can resume')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        with (work / 'lifecycle.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                metadata = {'schema': contract.schema, 'runtime_receipts_required': True, 'run': state['run'],
                            'negative_run': state['negative_run'], 'integration_mode': contract.integration_mode,
                            'controller_ip': args.controller_ip, 'controller_port': args.controller_port,
                            'ingester_port': args.ingester_port, 'ctrl_ip': args.ctrl_ip, 'ctrl_mac': args.ctrl_mac,
                            'profile': profile, 'signal_source': 3, 'l7_protocol': contract.protocol_id, 'transport': 'tcp', 'port': 18080}
                CORE.write(work / 'metadata.json', metadata)
                state['controller_attempted'] = True
                CORE.persist(work, state)
                context = CORE.backend(state, 'prepare', metadata)
                metadata['agent_id'] = context['agent_id']
                CORE.write(work / 'ingestion-metadata.json', metadata)
                preparation = PREPARE if contract.name == 'dns' else module('mysql_scoped_preparation', contract.prepare_file)
                preparation.prepare(work / 'prepared', controller_ip=args.controller_ip, group_id=context['group_short_uuid'],
                                controller_port=args.controller_port, ingester_port=args.ingester_port)
                require(CORE.read(work / 'prepared/group-profile.json') == profile, 'DNS preparation differs from Controller profile')
                state['lease_attempted'] = True
                CORE.persist(work, state)
                holder = CORE.spawn(work, 'lease', [sys.executable, str(HERE / 'association-lease.py'), 'prepare', '--execute',
                                    '--work', str(work / 'lease-work'), '--image', args.image, '--workload-bin', args.workload_bin])
                lease = CORE.locate_lease(work, state, 20)
                require(lease is not None and holder.poll() is None, 'Quiet DNS namespaces are not ready')
                state['scope'] = CORE.scope_identity(lease, state)
                state['scope']['schema'] = 'traflens.ebpf-' + contract.name + '.scope.v1'
                CORE.persist(work, state)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', args.forward_port))
                from urllib.parse import urlsplit
                remote_port = urlsplit(args.controller_url).port
                CORE.spawn(work, 'forward', ['ssh', '-N', '-E', str(work / 'controller-forward.log'), '-o', 'BatchMode=yes',
                           '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:%d:127.0.0.1:%d' % (args.forward_port, remote_port), args.backend_host])
                time.sleep(.3)
                require(CORE.find_process(work, 'forward') is not None, 'Owned Controller forward exited')
                state['agent_attempted'] = True
                CORE.persist(work, state)
                CORE.logged(work, 'agent-start', [sys.executable, str(HERE / 'managed-http-agent.py'), 'start', '--execute',
                            '--work', str(work), '--prepared', str(work / 'prepared'), '--artifacts', args.artifacts,
                            '--lease', str(lease), '--controller-api', 'http://127.0.0.1:%d' % args.forward_port,
                            '--agent-id', str(context['agent_id'])], 80)
                CORE.logged(work, 'agent-ready', [sys.executable, str(HERE / 'managed-http-agent.py'), 'ready', '--execute', '--work', str(work)], 90)
                current = CORE.read(work / 'agent/current.json')
                state['scope']['agent_container_id'] = current['id']
                CORE.persist(work, state)
                CORE.write(work / 'scope-runtime.json', state['scope'])
                run_phase(work, state, 'negative', contract)
                run_phase(work, state, 'positive', contract)
                result.update(pass_execution=True, positive_queries=3, negative_queries=3,
                              agent_id=context['agent_id'])
                if contract.expected_observations is not None:
                    result['expected_observations'] = contract.expected_observations
                if contract.name == 'mysql':
                    result.update(expected_query_observations=6, whole_population_requires_independent_oracle=True,
                                  wire_fixture=True, sql_executed=False)
                time.sleep(5)
                result['pass'] = True
            except Exception as error:
                result['error'] = type(error).__name__ + ': ' + str(error)
            finally:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                restoration = cleanup(work, state)
                result.update(restoration)
                qualified = ((work / 'scope-restoration.json').exists()
                             and CORE.read(work / 'scope-restoration.json').get('pass') is True)
                result['pass'] = bool(result['pass'] and qualified and restoration['cleaned']
                    and all(restoration['worker_exits'].get(role) == {'exit_code': 0, 'oom': False} for role in ROLES))
                CORE.write(work / 'result.json', result)
        print(json.dumps(result))
        return 0 if result['pass'] else 1


def stop(work, contract=DNS_CONTRACT):
    validate_contract(contract)
    work = private_dir(work)
    state = CORE.read(work / 'state.json')
    require(state.get('schema') == contract.schema and state.get('output') == str(work)
            and re.fullmatch(contract.prefix + '[0-9a-f]{24}', state.get('run', '')), 'Invalid scoped protocol lifecycle receipt')
    supervisor = CORE.read(work / 'supervisor.json')
    pid = supervisor['pid']
    if Path('/proc', str(pid)).exists():
        require(CORE.UTIL.process_start(pid) == supervisor['start_ticks'], 'DNS supervisor PID was reused')
        if Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z':
            command = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
            cwd = Path('/proc', str(pid), 'cwd').resolve()
            helpers = [(cwd / os.fsdecode(v)).resolve() for v in command if v and os.fsdecode(v).endswith(contract.script)]
            require((HERE / contract.script).resolve() in helpers and any(v in (str(work).encode(), ('--work=' + str(work)).encode()) for v in command),
                    'DNS supervisor command differs')
            os.kill(pid, signal.SIGTERM)
    with (work / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = cleanup(work, CORE.read(work / 'state.json'))
        CORE.event(work, 'public-stop', result)
    print(json.dumps(result))
    return 0 if result['cleaned'] else 1


def main(argv=None, contract=DNS_CONTRACT):
    validate_contract(contract)
    p = argparse.ArgumentParser(description='Finite scoped eBPF ' + contract.label + ' capture. Default is an offline plan.')
    p.add_argument('action', nargs='?', choices=('plan', 'run', 'stop'), default='plan')
    p.add_argument('--execute', action='store_true')
    for key in ('work', 'backend-host', 'backend-root', 'backend-work', 'backend-code', 'controller-ip',
                'ctrl-ip', 'ctrl-mac', 'artifacts', 'workload-bin', 'workload-sha256', 'image'):
        p.add_argument('--' + key)
    p.add_argument('--server-container', default='traflens-lab-server')
    p.add_argument('--controller-url', default='http://127.0.0.1:20417')
    p.add_argument('--controller-port', type=int, default=20035)
    p.add_argument('--ingester-port', type=int, default=20033)
    p.add_argument('--forward-port', type=int, default=24017)
    a = p.parse_args(argv)
    if not a.execute or a.action == 'plan':
        print(json.dumps({'execute': False, 'starts_network': False, 'creates_resources': False,
                          'protocol': contract.label, 'port': 18080, 'positive_queries': 3, 'negative_queries': 3,
                          'scope': 'exact positive namespace FD/inode/map', 'source': 3, 'storage_verified': False}))
        return 0
    os.umask(0o077)
    require(a.work, 'Explicit private work required')
    return stop(a.work, contract) if a.action == 'stop' else execute(a, contract)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'private_receipts_retained': True}))
        raise SystemExit(1)
