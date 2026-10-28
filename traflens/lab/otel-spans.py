#!/usr/bin/env python3
"""Finite owned SDK HTTP spans through isolated native trace integration."""
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import signal
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require, save, load, validate_controller_url
from cpu_profile_controller import trace_only_profile

SPEC = importlib.util.spec_from_file_location('owned_profile_utilities', HERE / 'cpu-profile.py')
util = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(util)
call, inspect = util.call, util.inspect
LIMITS = {'namespace': (100000000, 33554432, 16), 'agent': (1000000000, 1073741824, 384),
          'frontend': (1000000000, 134217728, 64), 'backend': (1000000000, 134217728, 64),
          'generate': (200000000, 134217728, 32)}


def state_save(work, state):
    temp = work / (str(time.time_ns()) + '-state.json')
    save(temp, state)
    os.replace(temp, work / 'state.json')


def journal(work, event, value):
    return save(work / (str(time.time_ns()) + '-' + event + '.json'), value)


def bind(source, target, writable=False):
    return ['--mount', 'type=bind,source=' + str(source) + ',target=' + target + ('' if writable else ',readonly')]


def owned(info, state, kind):
    if info is None:
        return False
    intent = state['resources'][kind]
    host, cfg = info['HostConfig'], info['Config']
    labels = cfg.get('Labels') or {}
    actual_mounts = sorted((m['Source'], m['Destination'], m['RW']) for m in info['Mounts'] if m['Type'] == 'bind')
    expected_mounts = sorted(tuple(m) for m in intent['mounts'])
    return (not intent.get('id') or info['Id'] == intent['id']) and (
        info['Image'] == state['image'] and labels.get('io.traflens.run') == state['run']
        and labels.get('io.traflens.output') == state['output']
        and labels.get('io.traflens.purpose') == 'traflens.otel-spans.' + kind
        and (host['NanoCpus'], host['Memory'], host['PidsLimit']) == LIMITS[kind]
        and host['NetworkMode'] == intent['network'] and host['PidMode'] != 'host'
        and host['CapDrop'] == ['ALL'] and not host['Privileged'] and host['ReadonlyRootfs']
        and host['RestartPolicy']['Name'] in ('', 'no') and host.get('PortBindings') in (None, {})
        and cfg['Entrypoint'] == [intent['entrypoint']] and cfg['Cmd'] == intent['command']
        and actual_mounts == expected_mounts)


def create(work, state, kind, network, command, mounts=(), entrypoint='/usr/bin/timeout', extra=()):
    cpu, memory, pids = LIMITS[kind]
    name = 'traflens-' + state['run'] + '-' + kind
    require(inspect('container', name) is None, 'Owned run container name already exists')
    state['resources'][kind] = {'name': name, 'network': network, 'entrypoint': entrypoint,
                                'command': command, 'mounts': [[str(source), target, writable] for source, target, writable in mounts]}
    state_save(work, state)
    argv = ['docker', 'create', '--name', name, '--network', network, '--cpus', str(cpu / 10**9),
            '--memory', str(memory), '--memory-swap', str(memory), '--pids-limit', str(pids),
            '--cap-drop', 'ALL', '--read-only', '--restart', 'no', '--security-opt', 'no-new-privileges',
            '--ulimit', 'core=0:0', '--label', 'io.traflens.run=' + state['run'],
            '--label', 'io.traflens.output=' + state['output'],
            '--label', 'io.traflens.purpose=traflens.otel-spans.' + kind,
            '--log-opt', 'max-size=2m', '--log-opt', 'max-file=1']
    for source, target, writable in mounts:
        argv += bind(source, target, writable)
    argv += list(extra) + ['--entrypoint', entrypoint, state['image']] + command
    cid = call(argv).stdout.strip()
    require(owned(inspect('container', cid), state, kind), 'New container differs from restricted intent')
    state['resources'][kind]['id'] = cid
    state_save(work, state)
    call(['docker', 'start', cid])
    return cid


def backend(state, action, body):
    args = state['args']
    argv = ['python3', args['backend_code'] + '/cpu-profile.py', 'controller', action,
            '--work', args['backend_output'], '--backend-root', args['backend_root'],
            '--server-container', args['server_container'], '--controller-url', args['controller_url']]
    raw = call(['ssh', '-o', 'BatchMode=yes', '--', args['backend_host'], shlex.join(argv)],
               timeout=100, body=json.dumps(body))
    result = json.loads(raw.stdout)
    require(result.get('prepared' if action == 'prepare' else 'cleaned') is True,
            'Controller lease did not complete')
    return result


def sockets_ready(anchor, ports):
    found = set()
    for proto in ['tcp', 'tcp6']:
        for line in Path('/proc', str(anchor['State']['Pid']), 'net', proto).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == '0A':
                found.add(int(fields[1].rsplit(':', 1)[1], 16))
    return set(ports) <= found


def cleanup(work, state):
    errors, exits = [], {}
    for kind in ['generate', 'frontend', 'backend', 'agent']:
        if kind not in state['resources']:
            continue
        try:
            intent = state['resources'][kind]
            info = inspect('container', intent.get('id') or intent['name'])
            if info is None:
                continue
            require(owned(info, state, kind), 'Refusing foreign or changed span container')
            if info['State']['Running']:
                call(['docker', 'stop', '--time', '40' if kind == 'agent' else '12', info['Id']], timeout=50)
            info = inspect('container', info['Id'])
            require(owned(info, state, kind) and not info['State']['Running'], 'Owned process did not stop')
            exits[kind] = {'exit_code': info['State']['ExitCode'], 'oom': info['State']['OOMKilled']}
            raw = call(['docker', 'logs', info['Id']])
            (work / (str(time.time_ns()) + '-' + kind + '.log')).write_text(raw.stdout + raw.stderr)
            call(['docker', 'rm', info['Id']])
        except Exception as error:
            errors.append(kind + ': ' + type(error).__name__)
    try:
        stopped = all(inspect('container', intent.get('id') or intent['name']) is None
                      for kind, intent in state['resources'].items() if kind != 'namespace')
    except Exception:
        stopped = False
        errors.append('cannot establish collector/workload absence')
    if stopped and state.get('controller_attempted'):
        try:
            backend(state, 'cleanup', {'run': state['run'], 'agent_stopped': True, 'owned_agent_removed': True})
            journal(work, 'controller-restored', {'cleaned': True})
        except Exception as error:
            errors.append('controller: ' + type(error).__name__)
    elif state.get('controller_attempted'):
        errors.append('controller retained: process absence not proven')
    if stopped:
        try:
            intent = state['resources'].get('namespace')
            info = inspect('container', intent.get('id') or intent['name']) if intent else None
            if info:
                require(owned(info, state, 'namespace'), 'Refusing changed namespace')
                if info['State']['Running']:
                    call(['docker', 'stop', '--time', '2', info['Id']])
                call(['docker', 'rm', info['Id']])
            net = inspect('network', state['network'])
            if net:
                labels = net.get('Labels') or {}
                require(labels.get('io.traflens.run') == state['run']
                        and labels.get('io.traflens.output') == state['output']
                        and labels.get('io.traflens.purpose') == 'traflens.otel-spans.network'
                        and net['Driver'] == 'bridge' and not net.get('Containers'), 'Refusing foreign/populated network')
                call(['docker', 'network', 'rm', net['Id']])
        except Exception as error:
            errors.append('namespace/network: ' + type(error).__name__)
    try:
        before = load(work / 'before.json')
        after = util.snapshot(state['args']['controller_ip'])
        if before:
            require(set(before['containers']) <= set(after['containers']) and set(before['networks']) <= set(after['networks'])
                    and before['route'] == after['route'] and before['bpf'] == [list(v) for v in after['bpf']],
                    'Original host baseline changed')
        journal(work, 'restoration', {'original_baseline_preserved': True, 'snapshot': after})
    except Exception as error:
        errors.append('baseline: ' + type(error).__name__)
    return {'cleaned': not errors, 'cleanup_errors': errors, 'process_exits': exits}


def stop(output):
    work = private_dir(output)
    state = load(work / 'state.json')
    require(state and state['output'] == str(work) and re.fullmatch(r'span-[0-9a-f]{24}', state['run']), 'Invalid span lease')
    supervisor = load(work / 'supervisor.json')
    if supervisor and Path('/proc', str(supervisor['pid'])).exists():
        proc = Path('/proc', str(supervisor['pid']))
        require(util.process_start(supervisor['pid']) == supervisor['start_ticks'], 'Supervisor PID identity changed')
        cmd = (proc / 'cmdline').read_bytes().split(b'\x00')
        require(str(Path(__file__).resolve()).encode() in cmd and str(work).encode() in cmd, 'Supervisor command differs')
        os.kill(supervisor['pid'], signal.SIGTERM)
    with (work / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = cleanup(work, load(work / 'state.json'))
        journal(work, 'stop', result)
    print(json.dumps(result))
    return 0 if result['cleaned'] else 1


def execute(args):
    validate_controller_url(args.controller_url)
    for key in ['backend_host', 'backend_root', 'backend_code', 'backend_output', 'controller_ip', 'image',
                'agent', 'agent_sha256', 'libs', 'workload', 'workload_sha256', 'output']:
        require(getattr(args, key), 'Execute requires --' + key.replace('_', '-'))
    require(re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', args.backend_host), 'Explicit SSH alias required')
    require(1 <= args.requests <= 4 and 30 <= args.seconds <= 120, 'Finite1..4 requests and30..120 seconds required')
    for key in ['backend_root', 'backend_code', 'backend_output', 'agent', 'libs', 'workload', 'output']:
        value = getattr(args, key)
        require(Path(value).is_absolute() and not any(c in value for c in ',\r\n\0'), 'Canonical explicit mount/backend paths required')
    require(Path(args.libs) == Path(args.libs).resolve() and Path(args.libs).is_dir(), 'Canonical Agent libraries required')
    for path, digest in [(args.agent, args.agent_sha256), (args.workload, args.workload_sha256)]:
        require(re.fullmatch('[0-9a-f]{64}', digest) and util.file_hash(path) == digest, 'Executable SHA256 differs')
    require(re.fullmatch('sha256:[0-9a-f]{64}', args.image), 'Preloaded immutable image ID required')
    require(inspect('image', args.image)['Id'] == args.image, 'Preloaded exact image required')
    profile = trace_only_profile(args.controller_ip, args.controller_port, args.ingester_port)
    work = private_dir(args.output, fresh=True)
    run = 'span-' + secrets.token_hex(12)
    state = {'run': run, 'output': str(work), 'args': vars(args), 'image': args.image,
             'network': 'traflens-' + run, 'resources': {}, 'controller_attempted': False}
    state_save(work, state)
    save(work / 'supervisor.json', {'pid': os.getpid(), 'start_ticks': util.process_start(os.getpid())})
    result = {'pass': False, 'run': run, 'storage_verified': False, 'source': 'actual OpenTelemetry SDK HTTP instrumentation; not eBPF'}
    def interrupted(*_):
        raise InterruptedError('Span lifecycle interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    with (work / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            save(work / 'before.json', util.snapshot(args.controller_ip))
            require(inspect('network', state['network']) is None, 'Fresh network name required')
            call(['docker', 'network', 'create', '--driver', 'bridge', '--label', 'io.traflens.run=' + run,
                  '--label', 'io.traflens.output=' + str(work), '--label', 'io.traflens.purpose=traflens.otel-spans.network', state['network']])
            anchor = create(work, state, 'namespace', state['network'], ['300'], entrypoint='/usr/bin/sleep')
            info = inspect('container', anchor)
            endpoint = info['NetworkSettings']['Networks'][state['network']]
            metadata = {'run': run, 'integration_mode': 'otel_trace', 'ctrl_ip': endpoint['IPAddress'],
                        'ctrl_mac': endpoint['MacAddress'], 'controller_ip': args.controller_ip,
                        'controller_port': args.controller_port, 'ingester_port': args.ingester_port, 'profile': profile}
            save(work / 'metadata.json', metadata)
            state['controller_attempted'] = True
            state_save(work, state)
            context = backend(state, 'prepare', metadata)
            metadata['agent_id'] = context['agent_id']
            save(work / 'ingestion-metadata.json', metadata)
            bootstrap = work / 'agent.yaml'
            bootstrap.write_text('controller-ips: [' + args.controller_ip + ']\ncontroller-port: ' + str(args.controller_port)
                + '\nvtap-group-id-request: ' + json.dumps(context['group_short_uuid'])
                + '\noverride-os-hostname: traflens-' + run + '\nasync-worker-thread-number: 2\nlog-file: /var/log/traflens/deepflow-agent.log\npid-file: /run/traflens/agent.pid\ncgroups-disabled: true\nliveness-probe-enabled: true\nliveness-probe-port: 39091\n')
            logs, native = work / 'native-logs', work / 'native-state'
            logs.mkdir(mode=0o700); native.mkdir(mode=0o700)
            agent = create(work, state, 'agent', 'container:' + anchor,
                ['--signal=TERM', '--kill-after=40s', '180', '/opt/agent', '--cgroups-disabled', '-f', '/etc/traflens/agent.yaml'],
                [(args.agent, '/opt/agent', False), (args.libs, '/opt/libs', False), (bootstrap, '/etc/traflens/agent.yaml', False),
                 (logs, '/var/log/traflens', True), (native, '/run/traflens', True)],
                extra=['--env', 'LD_LIBRARY_PATH=/opt/libs', '--env', 'IN_CONTAINER=yes', '--tmpfs', '/tmp:rw,noexec,nosuid,size=64m'])
            until = time.monotonic() + 65
            while time.monotonic() < until:
                require(owned(inspect('container', agent), state, 'agent') and inspect('container', agent)['State']['Running'], 'Owned Agent exited')
                if util.listener_ready(inspect('container', anchor), logs):
                    break
                time.sleep(.5)
            else:
                raise RuntimeError('Actual trace integration listener did not become ready')
            journal(work, 'integration-listener', {'actual_namespace_socket_and_owned_log': True})
            for role in ['backend', 'frontend']:
                out = work / role
                out.mkdir(mode=0o700)
                create(work, state, role, 'container:' + anchor,
                    ['--signal=TERM', '--kill-after=5s', str(args.seconds + 10), '/opt/workload', 'serve', '--execute',
                     '--role', role, '--run', run, '--output', '/output', '--seconds', str(args.seconds), '--requests', str(args.requests)],
                    [(args.workload, '/opt/workload', False), (out, '/output', True)])
            until = time.monotonic() + 20
            while time.monotonic() < until:
                for role in ['frontend', 'backend']:
                    current = inspect('container', state['resources'][role]['id'])
                    require(owned(current, state, role) and current['State']['Running'], 'Owned HTTP service exited')
                if sockets_ready(inspect('container', anchor), [18081, 18082]):
                    break
                time.sleep(.2)
            else:
                raise RuntimeError('Actual owned service LISTEN sockets not ready')
            out = work / 'generate'
            out.mkdir(mode=0o700)
            generator = create(work, state, 'generate', 'container:' + anchor,
                ['--signal=TERM', '--kill-after=3s', '30', '/opt/workload', 'generate', '--execute', '--run', run,
                 '--output', '/output', '--requests', str(args.requests), '--seconds', str(args.seconds)],
                [(args.workload, '/opt/workload', False), (out, '/output', True)])
            rc = int(call(['docker', 'wait', generator], timeout=35).stdout)
            require(rc == 0, 'Finite actual HTTP generator failed')
            result.update(pass_execution=True, actual_http_requests=args.requests, agent_id=context['agent_id'])
            time.sleep(2)
            result['pass'] = True
        except Exception as error:
            result.update(error_type=type(error).__name__, error=str(error))
        finally:
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            restoration = cleanup(work, state)
            result.update(restoration)
            result['pass'] = bool(result['pass'] and restoration['cleaned']
                and all(restoration['process_exits'].get(k, {}).get('exit_code') == 0
                        and not restoration['process_exits'].get(k, {}).get('oom')
                        for k in ['frontend', 'backend', 'generate', 'agent']))
            save(work / 'result.json', result)
    print(json.dumps(result))
    return 0 if result['pass'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['run', 'stop'], nargs='?', default='run')
    parser.add_argument('--execute', action='store_true')
    for key in ['backend-host', 'backend-root', 'backend-code', 'backend-output', 'controller-ip', 'image',
                'agent', 'agent-sha256', 'libs', 'workload', 'workload-sha256', 'output']:
        parser.add_argument('--' + key)
    parser.add_argument('--controller-url', default='http://127.0.0.1:20417')
    parser.add_argument('--server-container', default='traflens-lab-server')
    parser.add_argument('--controller-port', type=int, default=20035)
    parser.add_argument('--ingester-port', type=int, default=20033)
    parser.add_argument('--requests', type=int, default=2)
    parser.add_argument('--seconds', type=int, default=90)
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'execute': False, 'reads_files': False, 'starts_network': False, 'creates_resources': False,
                          'source': 'real SDK HTTP spans', 'normal_license_function': 6, 'max_requests': 4}))
        return 0
    os.umask(0o077)
    return stop(args.output) if args.action == 'stop' else execute(args)


if __name__ == '__main__':
    raise SystemExit(main())
