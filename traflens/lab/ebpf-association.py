#!/usr/bin/env python3
"""Finite owned no-header HTTP capture with recoverable public run/stop.

Default invocation is an offline plan. Configuration preparation is not runtime
qualification: the public managed Agent ready gate must pass before workers run.
"""
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
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require, validate_controller_url
from cpu_profile_controller import kernel_http_profile

SCHEMA = 'traflens.ebpf-association.capture.v1'
ROLE_SCHEMA = 'traflens.ebpf-association.worker-runtime.v1'
ROLES = ('backend', 'frontend', 'generate')
CODE = ('cpu-profile.py', 'cpu_profile_common.py', 'cpu_profile_controller.py', 'configure-agent.py',
        'lab.py', 'agent-smoke.json', 'managed-http-profile.json', 'managed-http.py')
PURPOSE = 'traflens.no-header-http'
_SELINUX_CONTEXT = None


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


UTIL = module('association_cpu_utilities', HERE / 'cpu-profile.py')
call, inspect = UTIL.call, UTIL.inspect


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def write(path, value, replace=False):
    if replace:
        temporary = path.with_name(str(time.time_ns()) + '-' + path.name)
        write(temporary, value)
        os.replace(temporary, path)
        return
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')
    path.chmod(0o600)


def read(path):
    require(path.is_absolute() and path == path.resolve() and path.is_file(), 'Canonical receipt required')
    with path.open('rb') as stream:
        data = stream.read((4 << 20) + 1)
    require(len(data) <= 4 << 20, 'Receipt exceeds finite byte budget')
    return json.loads(data)


def event(work, name, value):
    write(work / (str(time.time_ns()) + '-' + name + '.json'), value)


def persist(work, state):
    write(work / 'state.json', state, True)


def file_hash(path):
    path = Path(path)
    require(path.is_absolute() and path == path.resolve() and path.is_file(), 'Canonical runtime artifact required')
    return hashlib.sha256(path.read_bytes()).hexdigest()


def proc_identity(pid):
    require(type(pid) is int and pid > 1, 'Actual live PID required')
    proc = Path('/proc', str(pid))
    before = UTIL.process_start(pid)
    value = {'pid': pid, 'start_ticks': before,
             'netns': os.readlink(proc / 'ns/net'), 'pidns': os.readlink(proc / 'ns/pid')}
    require(UTIL.process_start(pid) == before, 'Process identity changed during inspection')
    return value


def process_matches(pid, intent):
    try:
        proc = Path('/proc', str(pid))
        argv = [os.fsdecode(part) for part in (proc / 'cmdline').read_bytes().split(b'\0') if part]
        return (argv == intent['argv'] and proc.stat().st_uid == os.geteuid()
                and hashlib.sha256((proc / 'exe').read_bytes()).hexdigest() == intent['executable_sha256'])
    except (OSError, KeyError):
        return False


def find_process(work, name):
    path = work / (name + '-process-intent.json')
    if not path.exists():
        return None
    intent = read(path)
    saved = work / (name + '-process.json')
    if saved.exists():
        receipt = read(saved)
        pid = receipt['pid']
        if Path('/proc', str(pid)).exists():
            require(UTIL.process_start(pid) == receipt['start_ticks'], 'Refusing reused helper PID')
            if Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] == 'Z':
                return None
            require(process_matches(pid, intent),
                    'Refusing changed helper process identity')
            return receipt
        return None
    # Popen may have succeeded before its PID receipt was saved. The complete
    # command contains the fresh private work path and is never matched by prefix.
    found = [int(p.name) for p in Path('/proc').iterdir() if p.name.isdigit() and process_matches(int(p.name), intent)]
    require(len(found) <= 1, 'Ambiguous helper process identity')
    if found:
        receipt = proc_identity(found[0])
        write(saved, receipt)
        return receipt
    return None


def spawn(work, name, argv):
    executable = Path(shutil.which(argv[0]) or argv[0]).resolve()
    write(work / (name + '-process-intent.json'), {'argv': argv, 'executable_sha256': file_hash(executable)})
    with (work / (name + '-stdout.log')).open('x') as log:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    receipt = proc_identity(process.pid)
    require(process_matches(process.pid, read(work / (name + '-process-intent.json'))), 'Spawned helper identity differs')
    write(work / (name + '-process.json'), receipt)
    return process


def stop_process(work, name):
    receipt = find_process(work, name)
    if receipt is None:
        return
    os.kill(receipt['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and Path('/proc', str(receipt['pid'])).exists():
        state = Path('/proc', str(receipt['pid']), 'stat').read_text().rsplit(')', 1)[1].split()[0]
        if state == 'Z':
            return
        require(UTIL.process_start(receipt['pid']) == receipt['start_ticks'], 'Helper PID identity changed')
        time.sleep(.05)
    require(not Path('/proc', str(receipt['pid'])).exists(), 'Owned helper did not exit; retained')


def logged(work, name, argv, timeout):
    path = work / (name + '.log')
    if path.exists():
        path = work / (str(time.time_ns()) + '-' + name + '.log')
    with path.open('x') as log:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
    require(result.returncode == 0, 'Public ' + name + ' command failed; private logs retained')


def backend(state, action, value):
    a = state['args']
    argv = ['python3', a['backend_code'] + '/cpu-profile.py', 'controller', action,
            '--work', a['backend_work'], '--backend-root', a['backend_root'],
            '--server-container', a['server_container'], '--controller-url', a['controller_url']]
    response = call(['ssh', '-o', 'BatchMode=yes', '--', a['backend_host'], shlex.join(argv)],
                    timeout=100, body=json.dumps(value))
    result = json.loads(response.stdout)
    require(result.get('prepared' if action == 'prepare' else 'cleaned') is True, 'Controller lifecycle did not complete')
    return result


def helper_hashes(args):
    local = {name: file_hash(HERE / name) for name in CODE}
    script = ('import hashlib,json,pathlib,sys;root=pathlib.Path(sys.argv[1]);'
              'print(json.dumps({n:hashlib.sha256((root/n).read_bytes()).hexdigest() for n in sys.argv[2:]}))')
    result = call(['ssh', '-o', 'BatchMode=yes', '--', args.backend_host,
                   shlex.join(['python3', '-c', script, args.backend_code, *CODE])], timeout=25)
    remote = json.loads(result.stdout)
    require(remote == local, 'Source and deployed Controller helper dependencies differ')
    return {'source': local, 'backend': remote, 'exact_match': True}


def worker_spec(state, role):
    work, a = Path(state['output']), state['args']
    return {'name': 'traflens-' + state['run'] + '-' + role,
            'image': a['image'], 'pid_mode': 'host', 'network_mode': 'container:' + state['anchor'],
            'read_only': True, 'cap_drop': ['ALL'], 'cap_add': [], 'nano_cpus': 500000000,
            'memory_bytes': 67108864, 'memory_swap_bytes': 67108864, 'pids_limit': 16,
            'privileged': False, 'port_bindings': {}, 'publish_all_ports': False,
            'security_opt': ['no-new-privileges'], 'restart_policy': 'no',
            'labels': {'io.traflens.purpose': PURPOSE, 'io.traflens.run': state['run'],
                       'io.traflens.role': role, 'io.traflens.output': str(work)},
            'entrypoint': ['/workload'],
            'command': ['--execute', '--role', role, '--run', state['run'], '--output', '/output', '--seconds', '90', '--requests', '2'],
            'mounts': sorted([[a['workload_bin'], '/workload', False], [str(work / role), '/output', True]])}


def docker_argv(spec):
    argv = ['docker', 'create', '--name', spec['name'], '--network', spec['network_mode'], '--pid', 'host',
            '--cpus', '0.5', '--memory', '67108864', '--memory-swap', '67108864', '--pids-limit', '16',
            '--cap-drop', 'ALL', '--read-only', '--restart', 'no', '--security-opt', 'no-new-privileges',
            '--ulimit', 'core=0:0', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1']
    for key, value in spec['labels'].items():
        argv += ['--label', key + '=' + value]
    for source, target, writable in spec['mounts']:
        argv += ['--mount', 'type=bind,source=' + source + ',target=' + target + ('' if writable else ',readonly')]
    return argv + ['--entrypoint', '/workload', spec['image'], *spec['command']]


def selinux_context():
    global _SELINUX_CONTEXT
    if _SELINUX_CONTEXT is None:
        response = call(['docker', 'info', '--format', '{{json .SecurityOptions}}'], timeout=10)
        options = json.loads(response.stdout)
        require(isinstance(options, list) and len(options) <= 64 and all(isinstance(v, str) for v in options),
                'Docker security context is unavailable')
        enabled = any('selinux' in option.lower() for option in options)
        fs_present = Path('/sys/fs/selinux').exists()
        enforce_present = Path('/sys/fs/selinux/enforce').exists()
        require(not enabled and not fs_present and not enforce_present,
                'Cannot normalize label disable while SELinux may be available')
        _SELINUX_CONTEXT = {'selinux_enabled': False, 'host_selinux_fs_present': False,
            'host_selinux_enforce_present': False, 'daemon_security_options': options,
            'ignored_daemon_options': ['label=disable'],
            'reason': 'SELinux unavailable; Docker hostPID label disable'}
    return dict(_SELINUX_CONTEXT)


def worker_security(raw):
    if raw in (['no-new-privileges'], ['no-new-privileges:true']):
        return ['no-new-privileges'], None
    require(isinstance(raw, list) and len(raw) == 2 and raw.count('label=disable') == 1
            and sum(option in ('no-new-privileges', 'no-new-privileges:true') for option in raw) == 1,
            'Worker security options differ')
    return ['no-new-privileges'], selinux_context()


def normalized_worker(info):
    host, config = info['HostConfig'], info['Config']
    security = host.get('SecurityOpt') or []
    canonical_security, _ = worker_security(security)
    require(all(m['Type'] == 'bind' for m in info['Mounts']), 'Worker has unexpected mounts')
    return {'name': info['Name'].removeprefix('/'), 'image': info['Image'], 'pid_mode': host['PidMode'],
            'network_mode': host['NetworkMode'], 'read_only': host['ReadonlyRootfs'],
            'cap_drop': host.get('CapDrop') or [], 'cap_add': host.get('CapAdd') or [],
            'nano_cpus': host['NanoCpus'], 'memory_bytes': host['Memory'], 'memory_swap_bytes': host['MemorySwap'],
            'pids_limit': host['PidsLimit'], 'privileged': host['Privileged'],
            'port_bindings': host.get('PortBindings') or {}, 'publish_all_ports': host.get('PublishAllPorts', False),
            'security_opt': canonical_security, 'restart_policy': host['RestartPolicy']['Name'],
            'labels': {key: (config.get('Labels') or {}).get(key) for key in ('io.traflens.purpose', 'io.traflens.run', 'io.traflens.role', 'io.traflens.output')},
            'entrypoint': config['Entrypoint'], 'command': config['Cmd'],
            'mounts': sorted([[m['Source'], m['Destination'], m['RW']] for m in info['Mounts']])}


def owned_worker(info, intent):
    if info is None:
        return False
    try:
        return (not intent.get('id') or info['Id'] == intent['id']) and info['Config']['Image'] == intent['spec']['image'] and normalized_worker(info) == intent['spec']
    except (KeyError, RuntimeError, TypeError):
        return False


def worker_info(state, role):
    intent = state['workers'][role]
    info = inspect('container', intent.get('id') or intent['spec']['name'])
    if info is not None:
        require(owned_worker(info, intent), 'Refusing changed or foreign worker')
        intent['id'] = info['Id']
    return info


def pause_worker(work, state, paused):
    info = worker_info(state, 'frontend')
    require(info and info['State']['Running'], 'Owned frontend is absent before pause gate')
    if paused:
        event(work, 'frontend-pause-intent', {'id': info['Id'], 'non_performance_gate': True, 'max_seconds': 5})
    if bool(info['State'].get('Paused')) != paused:
        call(['docker', 'pause' if paused else 'unpause', info['Id']], timeout=4)
    info = worker_info(state, 'frontend')
    require(info and bool(info['State'].get('Paused')) == paused, 'Actual owned frontend pause state differs')


def create_worker(work, state, role):
    (work / role).mkdir(mode=0o700)
    spec = worker_spec(state, role)
    require(inspect('container', spec['name']) is None, 'Fresh worker name already exists')
    argv = docker_argv(spec)
    intent = {'spec': spec, 'argv': argv, 'argv_sha256': digest(argv)}
    state['workers'][role] = intent
    persist(work, state)  # Written before docker create, including uncertain results.
    write(work / (role + '-intent.json'), intent)
    created = call(argv, timeout=20).stdout.strip()
    info = inspect('container', created)
    require(owned_worker(info, intent), 'Worker differs from restricted Docker create intent')
    intent['id'] = info['Id']
    persist(work, state)
    write(work / (role + '-created.json'), {'id': info['Id'], 'name': spec['name'], 'command': spec['command'], 'mounts': spec['mounts']})
    call(['docker', 'start', info['Id']], timeout=8)
    deadline = time.monotonic() + (3 if role == 'generate' else 10)
    while time.monotonic() < deadline:
        info = worker_info(state, role)
        require(info and info['State']['Running'], 'Owned worker exited before actual runtime proof')
        if (work / role / 'process.json').exists() and (role == 'generate' or (work / role / 'ready.json').exists()):
            break
        time.sleep(.02)
    else:
        raise RuntimeError('Actual worker process receipt was not ready')
    actual = proc_identity(info['State']['Pid'])
    process = read(work / role / 'process.json')
    require(process.get('run') == state['run'] and process.get('role') == role
            and all(process.get(key) == actual[key] for key in ('pid', 'start_ticks', 'netns', 'pidns')),
            'Actual Docker host PID differs from C process receipt')
    require(actual['netns'] == state['scope']['positive']['netns'] and actual['pidns'] == os.readlink('/proc/self/ns/pid'),
            'Actual worker namespace differs from qualified scope')
    require(hashlib.sha256(Path('/proc', str(actual['pid']), 'exe').read_bytes()).hexdigest() == state['args']['workload_sha256'],
            'Actual worker executable differs from supplied SHA256')
    require(UTIL.process_start(actual['pid']) == actual['start_ticks'] and worker_info(state, role)['State']['Pid'] == actual['pid'],
            'Actual worker identity changed while recording runtime proof')
    observed = normalized_worker(info)
    _, security_context = worker_security(info['HostConfig'].get('SecurityOpt') or [])
    observed.update(actual, id=info['Id'], started_at=info['State']['StartedAt'], running=True,
                    security_opt_raw=info['HostConfig'].get('SecurityOpt') or [],
                    security_opt_normalization=security_context)
    write(work / (role + '-runtime.json'), {'schema': ROLE_SCHEMA, 'role': role, 'run': state['run'],
        'scope_receipt': 'scope-runtime.json', 'agent_container_id': state['scope']['agent_container_id'],
        'create': {'argv': argv, 'argv_sha256': intent['argv_sha256'], 'normalized': spec}, 'inspect': observed})


def locate_lease(work, state, wait=0):
    deadline = time.monotonic() + wait
    while True:
        found = list((work / 'lease-work').glob('managed-*/lease.json'))
        require(len(found) <= 1, 'Ambiguous namespace lease receipts')
        if found:
            path = found[0].parent
            state['lease'] = str(path)
            persist(work, state)
            return path
        process = find_process(work, 'lease')
        if not process or time.monotonic() >= deadline:
            return None
        time.sleep(.05)


def scope_identity(lease, state):
    value = read(lease / 'lease.json')
    require(value.get('scope_only') is True and value.get('status') == 'ready_waiting_root_commands'
            and value.get('phase') == 0 and value.get('port') == 18080, 'Namespace lease is not ready')
    supervisor = proc_identity(value['supervisor_pid'])
    started = read(Path(state['output']) / 'lease-process.json')
    require(supervisor['pid'] == started['pid'] and supervisor['start_ticks'] == started['start_ticks'],
            'Namespace supervisor differs from the owned child process')
    result = {'schema': 'traflens.ebpf-association.scope.v1', 'lease_path': str(lease),
              'supervisor_pid': supervisor['pid'], 'supervisor_start_ticks': supervisor['start_ticks']}
    for role in ('positive', 'negative'):
        pin = value[role]
        info = inspect('container', pin['container_id'])
        require(info and info['Id'] == pin['container_id'] and info['State']['Running']
                and info['State']['Pid'] == pin['pid'] and info['HostConfig']['NetworkMode'] == 'none', 'Actual namespace holder differs')
        actual = proc_identity(pin['pid'])
        require(actual['start_ticks'] == pin['start_ticks'] and os.stat(pin['source']).st_ino == pin['inode']
                and actual['netns'] == 'net:[%d]' % pin['inode']
                and re.fullmatch('/proc/%d/fd/[0-9]+' % supervisor['pid'], pin['source']), 'Held namespace FD or process identity differs')
        result[role] = dict(pin, netns=actual['netns'], pidns=actual['pidns'])
    require(result['positive']['inode'] != result['negative']['inode']
            and result['positive']['netns'] != os.readlink('/proc/self/ns/net'), 'Target namespace is not separate')
    return result


def agent_restore(work, state):
    agent = module('association_managed_agent', HERE / 'managed-http-agent.py')
    agent.WORK = work
    current = work / 'agent/current.json'
    intents = list((work / 'agent').glob('*/intent.json'))
    require(len(intents) <= 1, 'Ambiguous managed Agent create intent')
    if not current.exists() and intents:
        receipt = read(intents[0])
        require(Path(receipt['folder']) == intents[0].parent and Path(receipt['folder']).is_relative_to(work / 'agent'), 'Agent intent escaped run')
        info = inspect('container', receipt['name'])
        if info is not None:
            receipt['id'] = info['Id']
            require(agent.owned(info, receipt), 'Uncertain Agent does not match complete saved intent')
            write(current, receipt)
            event(work, 'agent-create-recovered', {'id': info['Id']})
        else:
            require(agent.restored_programs(agent.ids(), receipt) and agent.tracefs() == receipt['baseline']['tracefs'],
                    'Absent uncertain Agent has not restored BPF/tracefs')
    if not current.exists():
        if state.get('agent_attempted') and (work / 'agent').exists() and not intents:
            # The public launcher writes its intent before Docker creation. If
            # interrupted earlier, require live inventory too, not absence of a
            # current.json alone, before allowing namespace/registration release.
            inventory = call(['docker', 'ps', '-aq', '--filter', 'label=io.traflens.purpose=' + agent.PURPOSE])
            require(not inventory.stdout.strip(), 'Unidentified managed Agent exists; retain namespace pins')
            lease = Path(state['lease'])
            before = read(lease / 'inventory-before.json')
            worker = read(lease / 'inventory-workers.json')
            original = set(before['bpf_ids'])
            require(original <= set(agent.ids()) <= original | set(worker['owned_worker_cgroup_device_ids'])
                    and agent.tracefs() == before['tracefs'], 'Pre-intent Agent attempt has not restored live inventory')
        return True
    receipt = read(current)
    info = inspect('container', receipt['id'])
    if info is not None:
        require(agent.owned(info, receipt), 'Refusing changed managed Agent')
        logged(work, 'agent-stop', [sys.executable, str(HERE / 'managed-http-agent.py'), 'stop', '--execute', '--work', str(work)], 80)
    require(inspect('container', receipt['id']) is None, 'Agent container absence is unproven')
    require(agent.restored_programs(agent.ids(), receipt) and agent.tracefs() == receipt['baseline']['tracefs'],
            'Actual Agent BPF/tracefs has not restored')
    proof_path = Path(receipt['folder']) / 'stopped.json'
    if not proof_path.exists():
        write(proof_path, {'agent_stopped': True, 'container_removed': True, 'bpf_inventory_restored': True,
                           'tracefs_restored': True, 'recovered_after_uncertain_stop': True})
    proof = read(proof_path)
    require(all(proof.get(key) is True for key in ('agent_stopped', 'container_removed', 'bpf_inventory_restored', 'tracefs_restored')),
            'Managed Agent stop proof is incomplete')
    return True


def cleanup(work, state):
    errors, exits = [], dict(state.get('worker_exits', {}))
    workers_gone = True
    for role in ('generate', 'frontend', 'backend'):
        if role not in state['workers']:
            continue
        try:
            info = worker_info(state, role)
            persist(work, state)
            if info is None:
                continue
            if info['State'].get('Paused'):
                call(['docker', 'unpause', info['Id']], timeout=5)
                info = worker_info(state, role)
                require(info and not info['State'].get('Paused'), 'Actual worker remains paused')
            if info['State']['Running']:
                call(['docker', 'stop', '--time', '5', info['Id']], timeout=15)
            info = worker_info(state, role)
            require(info and not info['State']['Running'], 'Owned worker did not stop')
            exits[role] = {'exit_code': info['State']['ExitCode'], 'oom': info['State']['OOMKilled']}
            state['worker_exits'] = exits
            persist(work, state)
            call(['docker', 'rm', info['Id']])
            require(worker_info(state, role) is None, 'Owned worker removal is unproven')
        except Exception as error:
            workers_gone = False
            errors.append(role + ': ' + type(error).__name__)
    if workers_gone:
        try:
            workers_gone = all(worker_info(state, role) is None for role in state['workers'])
        except Exception:
            workers_gone = False
            errors.append('worker absence unavailable')
    collector_stopped, lease_restored = False, False
    if workers_gone:
        try:
            collector_stopped = agent_restore(work, state)
        except Exception as error:
            errors.append('agent: ' + type(error).__name__)
    else:
        errors.append('Agent/lease/Controller retained: worker absence unproven')
    if collector_stopped:
        try:
            lease = locate_lease(work, state, 20 if state.get('lease_attempted') else 0)
            if lease is None:
                require(not find_process(work, 'lease') and not list((work / 'lease-work').glob('managed-*')),
                        'Namespace holder startup has no safe release receipt; retain resources')
                lease_restored = True
            else:
                result_path = lease / 'result.json'
                if not result_path.exists():
                    logged(work, 'scope-release', [sys.executable, str(HERE / 'association-lease.py'), 'release', '--execute', '--lease', str(lease)], 45)
                deadline = time.monotonic() + 25
                while time.monotonic() < deadline and not result_path.exists():
                    time.sleep(.1)
                proof = read(result_path)
                require(proof.get('namespace_pins_released') is True
                        and proof.get('external_agent_exit_and_inventory_restored') is True
                        and proof.get('original_host_bpf_inventory_restored') is True
                        and proof.get('original_tracefs_restored') is True
                        and proof.get('preexisting_containers_still_running') is True
                        and proof.get('cleanup_errors') == [], 'Actual namespace/host restoration is incomplete')
                # Failed/early-cancelled runs retain pass:false; concrete recovery
                # fields establish cleanup, not an invented successful workload.
                event(work, 'scope-restoration', proof)
                if not (work / 'scope-restoration.json').exists():
                    write(work / 'scope-restoration.json', proof)
                lease_restored = True
        except Exception as error:
            errors.append('lease: ' + type(error).__name__)
    controller_cleaned = not state.get('controller_attempted')
    if collector_stopped and lease_restored and state.get('controller_attempted'):
        try:
            backend(state, 'cleanup', {'run': state['run'], 'agent_stopped': True, 'owned_agent_removed': True,
                                       'collector_never_started': not state.get('agent_attempted')})
            controller_cleaned = True
            event(work, 'controller-restored', {'cleaned': True})
        except Exception as error:
            errors.append('controller: ' + type(error).__name__)
    if collector_stopped and lease_restored:
        try:
            stop_process(work, 'forward')
        except Exception as error:
            errors.append('forward: ' + type(error).__name__)
    state.update(worker_exits=exits, collector_stopped=collector_stopped, lease_restored=lease_restored,
                 controller_cleaned=controller_cleaned, cleaned=not errors and workers_gone and collector_stopped and lease_restored and controller_cleaned)
    persist(work, state)
    result = {key: state[key] for key in ('cleaned', 'worker_exits', 'collector_stopped', 'lease_restored', 'controller_cleaned')}
    result['cleanup_errors'] = errors
    event(work, 'cleanup', result)
    return result


def execute(args):
    validate_controller_url(args.controller_url)  # Before writing any argument or intent.
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Qualified Linux x86_64 root execution required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', args.backend_host or ''), 'Explicit SSH alias required')
    for key in ('work', 'backend_root', 'backend_work', 'backend_code', 'artifacts', 'workload_bin'):
        value = getattr(args, key)
        require(value and Path(value).is_absolute() and not any(c in value for c in ',\r\n\0'), 'Explicit safe absolute paths required')
    require(Path(args.backend_work) != Path(args.backend_root) and Path(args.backend_work).is_relative_to(Path(args.backend_root)), 'Backend work must be strictly below owned lab root')
    require(re.fullmatch('sha256:[0-9a-f]{64}', args.image or '') and re.fullmatch('[0-9a-f]{64}', args.workload_sha256 or ''), 'Exact cached image/artifact SHA256 required')
    require(1024 <= args.forward_port <= 65535, 'Explicit local forward port1024..65535 required')
    address = ipaddress.ip_address(args.ctrl_ip)
    require(address.version == 4 and address.is_private and not address.is_loopback and not address.is_link_local and not address.is_unspecified,
            'Explicit inspected host Controller identity IPv4 required')
    require(re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', args.ctrl_mac or '') and not int(args.ctrl_mac[:2], 16) & 1 and args.ctrl_mac != '00:00:00:00:00:00', 'Explicit inspected unicast Controller MAC required')
    profile = kernel_http_profile(args.controller_ip, args.controller_port, args.ingester_port)
    require(file_hash(args.workload_bin) == args.workload_sha256, 'Workload binary hash differs')
    require(inspect('image', args.image)['Id'] == args.image, 'Exact worker image is not cached')
    agent = module('association_preflight_agent', HERE / 'managed-http-agent.py')
    agent.verified_artifacts(Path(args.artifacts))
    hashes = helper_hashes(args)
    parent = private_dir(Path(args.work).parent)
    with (parent / '.ebpf-association.lock').open('a') as run_lock:
        fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = private_dir(args.work, fresh=True)
        state = {'schema': SCHEMA, 'run': 'nh-' + secrets.token_hex(12), 'output': str(work), 'args': vars(args),
                 'workers': {}, 'controller_attempted': False, 'agent_attempted': False, 'lease_attempted': False}
        persist(work, state)
        write(work / 'helper-code-sha256.json', hashes)
        write(work / 'supervisor.json', dict(proc_identity(os.getpid()), argv=sys.argv))
        result = {'schema': SCHEMA, 'run': state['run'], 'pass': False, 'storage_verified': False,
                  'runtime_receipts_required': True, 'cleanup_errors': [], 'performance_measurement': False}
        def interrupted(*_):
            raise InterruptedError('Owned capture interrupted; use public stop to resume cleanup')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        with (work / 'lifecycle.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                metadata = {'schema': SCHEMA, 'runtime_receipts_required': True, 'run': state['run'], 'integration_mode': 'kernel_http',
                            'controller_ip': args.controller_ip, 'controller_port': args.controller_port, 'ingester_port': args.ingester_port,
                            'ctrl_ip': args.ctrl_ip, 'ctrl_mac': args.ctrl_mac, 'profile': profile}
                write(work / 'metadata.json', metadata)
                state['controller_attempted'] = True
                persist(work, state)
                context = backend(state, 'prepare', metadata)
                metadata['agent_id'] = context['agent_id']
                write(work / 'ingestion-metadata.json', metadata)
                prepare = module('association_http_preparation', HERE / 'managed-http.py')
                prepare.prepare(work / 'prepared', controller_ip=args.controller_ip, group_id=context['group_short_uuid'],
                                controller_port=args.controller_port, ingester_ip=args.controller_ip, ingester_port=args.ingester_port, http_port=18080)
                require(read(work / 'prepared/group-profile.json') == profile, 'Prepared kernel HTTP profile differs')
                state['lease_attempted'] = True
                persist(work, state)
                holder = spawn(work, 'lease', [sys.executable, str(HERE / 'association-lease.py'), 'prepare', '--execute',
                               '--work', str(work / 'lease-work'), '--image', args.image, '--workload-bin', args.workload_bin])
                lease = locate_lease(work, state, 20)
                require(lease is not None and holder.poll() is None, 'Quiet namespace holder did not become ready')
                state['scope'] = scope_identity(lease, state)
                state['anchor'] = state['scope']['positive']['container_id']
                persist(work, state)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', args.forward_port))
                from urllib.parse import urlsplit
                remote_port = urlsplit(args.controller_url).port
                spawn(work, 'forward', ['ssh', '-N', '-E', str(work / 'controller-forward.log'), '-o', 'BatchMode=yes',
                      '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:%d:127.0.0.1:%d' % (args.forward_port, remote_port), args.backend_host])
                time.sleep(.3)
                require(find_process(work, 'forward') is not None, 'Owned Controller forward exited')
                state['agent_attempted'] = True
                persist(work, state)
                logged(work, 'agent-start', [sys.executable, str(HERE / 'managed-http-agent.py'), 'start', '--execute', '--work', str(work),
                       '--prepared', str(work / 'prepared'), '--artifacts', args.artifacts, '--lease', str(lease),
                       '--controller-api', 'http://127.0.0.1:%d' % args.forward_port, '--agent-id', str(context['agent_id'])], 80)
                logged(work, 'agent-ready', [sys.executable, str(HERE / 'managed-http-agent.py'), 'ready', '--execute', '--work', str(work)], 90)
                current = read(work / 'agent/current.json')
                state['scope']['agent_container_id'] = current['id']
                persist(work, state)
                write(work / 'scope-runtime.json', state['scope'])
                for role in ('backend', 'frontend'):
                    create_worker(work, state, role)
                pause_started = time.monotonic()
                def pause_expired(*_):
                    raise TimeoutError('Owned generator identity pause gate exceeded5 seconds')
                prior_alarm = signal.signal(signal.SIGALRM, pause_expired)
                signal.setitimer(signal.ITIMER_REAL, 5)
                try:
                    pause_worker(work, state, True)
                    create_worker(work, state, 'generate')
                    require(time.monotonic() - pause_started <= 5, 'Generator runtime pause gate exceeded5 seconds')
                finally:
                    signal.setitimer(signal.ITIMER_REAL, 0)
                    signal.signal(signal.SIGALRM, prior_alarm)
                    pause_worker(work, state, False)
                    event(work, 'frontend-unpaused', {'duration_seconds': time.monotonic() - pause_started, 'performance_measurement': False})
                rc = int(call(['docker', 'wait', state['workers']['generate']['id']], timeout=30).stdout)
                require(rc == 0, 'Finite actual HTTP generator failed')
                for role in ROLES:
                    receipt = read(work / role / 'receipt.json')
                    require(receipt.get('run') == state['run'] and receipt.get('pass') is True and receipt.get('completed_requests') == 2,
                            'Finite actual HTTP workload receipt did not pass')
                result.update(pass_execution=True, actual_root_requests=2, actual_http_exchanges=4, expected_observations=8, agent_id=context['agent_id'])
                time.sleep(3)
                result['pass'] = True
            except Exception as error:
                result['error'] = type(error).__name__ + ': ' + str(error)
            finally:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                restoration = cleanup(work, state)
                result.update(restoration)
                qualified = (work / 'scope-restoration.json').exists() and read(work / 'scope-restoration.json').get('pass') is True
                result['pass'] = bool(result['pass'] and qualified and restoration['cleaned'] and all(restoration['worker_exits'].get(role) == {'exit_code': 0, 'oom': False} for role in ROLES))
                write(work / 'result.json', result)
        print(json.dumps(result))
        return 0 if result['pass'] else 1


def stop(work):
    work = private_dir(work)
    state = read(work / 'state.json')
    require(state.get('schema') == SCHEMA and state.get('output') == str(work) and re.fullmatch('nh-[0-9a-f]{24}', state.get('run', '')), 'Invalid capture receipt')
    supervisor = read(work / 'supervisor.json')
    pid = supervisor['pid']
    if Path('/proc', str(pid)).exists():
        require(UTIL.process_start(pid) == supervisor['start_ticks'], 'Supervisor PID changed')
        if Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z':
            command = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
            cwd = Path('/proc', str(pid), 'cwd').resolve()
            helpers = [(cwd / os.fsdecode(arg)).resolve() for arg in command if arg and os.fsdecode(arg).endswith('ebpf-association.py')]
            require(Path(__file__).resolve() in helpers and any(arg in (str(work).encode(), ('--work=' + str(work)).encode()) for arg in command), 'Supervisor command identity differs')
            os.kill(pid, signal.SIGTERM)
    with (work / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = cleanup(work, read(work / 'state.json'))
        event(work, 'stop-result', result)
    print(json.dumps(result))
    return 0 if result['cleaned'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('plan', 'run', 'stop'), default='plan')
    parser.add_argument('--execute', action='store_true')
    for key in ('work', 'backend-host', 'backend-root', 'backend-work', 'backend-code', 'controller-ip', 'ctrl-ip', 'ctrl-mac', 'image', 'artifacts', 'workload-bin', 'workload-sha256'):
        parser.add_argument('--' + key)
    parser.add_argument('--server-container', default='traflens-lab-server')
    parser.add_argument('--controller-url', default='http://127.0.0.1:20417')
    parser.add_argument('--controller-port', type=int, default=20035)
    parser.add_argument('--ingester-port', type=int, default=20033)
    parser.add_argument('--forward-port', type=int, default=24017)
    args = parser.parse_args(argv)
    if not args.execute or args.action == 'plan':
        print(json.dumps({'execute': False, 'reads_artifacts': False, 'starts_network': False, 'creates_resources': False,
                          'requests': 2, 'worker_seconds': 90, 'agent_max_seconds': 180,
                          'source': 'native scoped eBPF HTTP; no SDK or tracing headers', 'storage_verified': False}))
        return 0
    os.umask(0o077)
    return stop(args.work) if args.action == 'stop' else execute(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'private_receipts_retained': True}))
        raise SystemExit(1)
