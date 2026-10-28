#!/usr/bin/env python3
"""Finite public TCP packet capture coordinator. Default is an offline plan."""
import argparse
import fcntl
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sys
import time

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import private_dir, require, validate_controller_url
from cpu_profile_controller import packet_tcp_profile


def module(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


CORE = module('tcp_capture_common', 'ebpf-association.py')
PACKET = module('tcp_capture_packet_agent', 'tcp-packet-agent.py')
SCHEMA = 'traflens.tcp-connections.capture.v1'
COMPLETED = {'server_normal', 'server_reset', 'client_normal', 'client_reset', 'client_refused'}
NATURAL_DRAIN_SECONDS = 50


def persist(work, state):
    CORE.write(work / 'state.json', state, True)


def fixture(work, state, phase):
    run = state['run'] if phase == 'positive' else state['negative_run']
    ports = (18081, 18082, 18083) if phase == 'positive' else (18084, 18085, 18086)
    state['fixtures'][phase] = {'run': run, 'output': str(work / phase), 'ports': list(ports), 'attempted': True}
    persist(work, state)
    argv = [sys.executable, str(HERE / 'tcp-traffic.py'), '--execute', '--run', run, '--output', str(work / phase),
            '--seconds', '15', '--normal-port', str(ports[0]), '--reset-port', str(ports[1]), '--refused-port', str(ports[2])]
    process = CORE.spawn(work, 'fixture-' + phase, argv)
    require(process.wait(timeout=20) == 0, 'Finite ' + phase + ' TCP fixture failed')
    receipt = CORE.read(work / phase / 'receipt.json')
    require(receipt.get('run') == run and receipt.get('pass') is True and receipt.get('expected_connections') == 3
            and receipt.get('source') == 'actual Python stdlib/Linux TCP sockets'
            and receipt.get('synthetic_tcp_packets') is False and receipt.get('thread_errors') == []
            and receipt.get('owned_sockets_closed') is True and receipt.get('owned_threads_exited') is True
            and set(receipt.get('completed', {})) == COMPLETED and all(v is True for v in receipt['completed'].values()),
            'Actual ' + phase + ' socket/application receipt is incomplete')
    state['fixtures'][phase]['completed'] = True
    persist(work, state)
    CORE.event(work, 'fixture-' + phase + '-completed', {'run': run, 'connections': 3, 'ports': list(ports)})


def natural_drain(work, state):
    # Keep native closing-RST (35s), packet-delay/ticker and 4s sender buckets
    # intact. This is a bounded output wait, not a traffic/performance window.
    state['natural_drain'] = {'seconds': NATURAL_DRAIN_SECONDS, 'started_unix_ns': time.time_ns()}
    persist(work, state)
    CORE.event(work, 'natural-drain-started', dict(state['natural_drain']))
    time.sleep(NATURAL_DRAIN_SECONDS)
    state['natural_drain']['completed_unix_ns'] = time.time_ns()
    persist(work, state)
    CORE.event(work, 'natural-drain-completed', dict(state['natural_drain']))


def cleanup(work, state):
    errors, fixtures_gone = [], True
    for phase in ('positive', 'negative'):
        try:
            CORE.stop_process(work, 'fixture-' + phase)
            require(CORE.find_process(work, 'fixture-' + phase) is None, 'Actual owned TCP fixture remains')
        except Exception as error:
            fixtures_gone = False
            errors.append('fixture-' + phase + ': ' + type(error).__name__)
    collector_stopped = False
    packet_work = work / 'packet-agent'
    if fixtures_gone:
        try:
            if (packet_work / 'intent.json').exists():
                CORE.logged(work, 'packet-agent-stop', [sys.executable, str(HERE / 'tcp-packet-agent.py'),
                            'stop', '--execute', '--work', str(packet_work)], 160)
                proof = CORE.read(packet_work / 'stopped.json')
                require(all(proof.get(key) is True for key in ('agent_stopped', 'container_removed',
                        'bpf_inventory_restored', 'tracefs_restored', 'lo_identity_and_flags_restored')),
                        'Public packet Agent restoration proof is incomplete')
                CORE.event(work, 'packet-restored', proof)
            else:
                # The public launcher writes complete intent before create. A
                # missing current.json alone is never accepted as absence.
                active = CORE.call(['docker', 'ps', '-aq', '--filter', 'label=io.traflens.purpose=' + PACKET.PURPOSE])
                require(not active.stdout.strip(), 'Unidentified packet Agent exists; retain Controller registration')
            collector_stopped = True
        except Exception as error:
            errors.append('packet-agent: ' + type(error).__name__)
    else:
        errors.append('Agent/Controller retained: actual fixture absence unproven')
    controller_cleaned = not state.get('controller_attempted')
    if collector_stopped and state.get('controller_attempted'):
        try:
            CORE.backend(state, 'cleanup', {'run': state['run'], 'agent_stopped': True, 'owned_agent_removed': True,
                        'collector_never_started': not (packet_work / 'intent.json').exists()})
            controller_cleaned = True
            CORE.event(work, 'controller-restored', {'cleaned': True})
        except Exception as error:
            errors.append('controller: ' + type(error).__name__)
    if collector_stopped:
        try:
            CORE.stop_process(work, 'forward')
        except Exception as error:
            errors.append('forward: ' + type(error).__name__)
    result = {'cleaned': fixtures_gone and collector_stopped and controller_cleaned and not errors,
              'collector_stopped': collector_stopped, 'controller_cleaned': controller_cleaned,
              'fixtures_stopped': fixtures_gone, 'cleanup_errors': errors}
    state.update(result)
    persist(work, state)
    CORE.event(work, 'cleanup', result)
    return result


def execute(args):
    validate_controller_url(args.controller_url)  # Before receipts, SSH or Docker.
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Qualified Linux x86_64 root execution required')
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}', args.backend_host or ''), 'Explicit SSH alias required')
    for key in ('work', 'backend_root', 'backend_work', 'backend_code', 'artifacts'):
        value = getattr(args, key)
        require(value and Path(value).is_absolute() and not any(c in value for c in ',\r\n\0'), 'Explicit safe absolute paths required')
    require(Path(args.backend_work) != Path(args.backend_root) and Path(args.backend_work).is_relative_to(Path(args.backend_root)),
            'Fresh backend work must be strictly below owned lab root')
    address = ipaddress.ip_address(args.ctrl_ip)
    require(address.version == 4 and address.is_private and not address.is_loopback and not address.is_link_local and not address.is_unspecified,
            'Explicit verified host control IPv4 required')
    require(re.fullmatch('(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', args.ctrl_mac or '') and not int(args.ctrl_mac[:2], 16) & 1
            and args.ctrl_mac != '00:00:00:00:00:00', 'Explicit verified unicast control MAC required')
    require(1024 <= args.forward_port <= 65535, 'Explicit owned local forward port required')
    profile = packet_tcp_profile(args.controller_ip, args.controller_port, args.ingester_port)
    artifact, _, _ = PACKET.MANAGED.verified_artifacts(Path(args.artifacts))
    require(CORE.inspect('image', artifact['image_id'])['Id'] == artifact['image_id'], 'Qualified native image is not cached')
    hashes = CORE.helper_hashes(args)
    parent = private_dir(Path(args.work).parent)
    with (parent / '.tcp-connections.lock').open('a') as global_lock:
        fcntl.flock(global_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        work = private_dir(args.work, fresh=True)
        state = {'schema': SCHEMA, 'run': 'tcp-' + secrets.token_hex(12), 'negative_run': 'tcp-' + secrets.token_hex(12),
                 'output': str(work), 'args': vars(args), 'fixtures': {}, 'controller_attempted': False, 'agent_attempted': False}
        require(state['run'] != state['negative_run'], 'Fresh positive and negative identities must differ')
        persist(work, state)
        CORE.write(work / 'helper-code-sha256.json', hashes)
        CORE.write(work / 'capture-source-sha256.json', {name: CORE.file_hash(HERE / name) for name in
                   ('tcp-connections.py', 'tcp-packet-agent.py', 'tcp_packet_filter.py', 'tcp-traffic.py', 'ebpf-association.py')})
        CORE.write(work / 'supervisor.json', CORE.proc_identity(os.getpid()))
        result = {'schema': SCHEMA, 'run': state['run'], 'negative_run': state['negative_run'], 'pass': False,
                  'stored_l4_verified': False, 'performance_measurement': False, 'capture_source': 'packet-only lo',
                  'image_id': artifact['image_id'], 'artifact_manifest_sha256': CORE.file_hash(args.artifacts)}
        def interrupted(*_):
            raise InterruptedError('Owned TCP capture interrupted; public stop can resume cleanup')
        signal.signal(signal.SIGTERM, interrupted)
        signal.signal(signal.SIGINT, interrupted)
        with (work / 'lifecycle.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                metadata = {'schema': SCHEMA, 'run': state['run'], 'negative_run': state['negative_run'], 'integration_mode': 'packet_tcp',
                    'controller_ip': args.controller_ip, 'controller_port': args.controller_port, 'ingester_port': args.ingester_port,
                    'ctrl_ip': args.ctrl_ip, 'ctrl_mac': args.ctrl_mac, 'profile': profile,
                    'positive_ports': [18081, 18082, 18083], 'negative_ports': [18084, 18085, 18086],
                    'source': 'packet', 'signal_source': 0}
                CORE.write(work / 'metadata.json', metadata)
                state['controller_attempted'] = True
                persist(work, state)
                context = CORE.backend(state, 'prepare', metadata)
                metadata['agent_id'] = context['agent_id']
                CORE.write(work / 'ingestion-metadata.json', metadata)
                with socket.socket() as probe:
                    probe.bind(('127.0.0.1', args.forward_port))
                from urllib.parse import urlsplit
                remote_port = urlsplit(args.controller_url).port
                CORE.spawn(work, 'forward', ['ssh', '-N', '-E', str(work / 'controller-forward.log'), '-o', 'BatchMode=yes',
                           '-o', 'ExitOnForwardFailure=yes', '-L', '127.0.0.1:%d:127.0.0.1:%d' % (args.forward_port, remote_port), args.backend_host])
                time.sleep(.3)
                require(CORE.find_process(work, 'forward') is not None, 'Owned Controller forward exited')
                state['agent_attempted'] = True
                persist(work, state)
                CORE.logged(work, 'packet-agent-start', [sys.executable, str(HERE / 'tcp-packet-agent.py'), 'start', '--execute',
                    '--work', str(work / 'packet-agent'), '--artifacts', args.artifacts,
                    '--controller-api', 'http://127.0.0.1:%d' % args.forward_port,
                    '--controller-ip', args.controller_ip, '--controller-port', str(args.controller_port),
                    '--ingester-port', str(args.ingester_port), '--group-id', context['group_short_uuid'], '--agent-id', str(context['agent_id'])], 65)
                CORE.logged(work, 'packet-agent-ready', [sys.executable, str(HERE / 'tcp-packet-agent.py'), 'ready', '--execute',
                    '--work', str(work / 'packet-agent')], 85)
                proof = CORE.read(work / 'packet-agent/packet-bpf-proof.json')
                require(proof.get('native_dispatcher_started') is True and proof.get('fresh_three_listener_sync') is True
                        and proof.get('outside_custom_filter_returns_zero_before_default_policy') is True,
                        'Actual dispatcher/lo/custom BPF proof is incomplete')
                fixture(work, state, 'negative')
                fixture(work, state, 'positive')
                result.update(pass_execution=True, actual_positive_connections=3, actual_negative_connections=3,
                              agent_id=context['agent_id'], expected_positive_ports=[18081, 18082, 18083])
                natural_drain(work, state)
                result['natural_drain'] = dict(state['natural_drain'])
                result['pass'] = True
            except Exception as error:
                result['error'] = type(error).__name__ + ': ' + str(error)
            finally:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
                signal.signal(signal.SIGINT, signal.SIG_IGN)
                restoration = cleanup(work, state)
                result.update(restoration)
                result['pass'] = bool(result['pass'] and restoration['cleaned'])
                CORE.write(work / 'result.json', result)
        print(json.dumps(result))
        return 0 if result['pass'] else 1


def stop(work):
    work = private_dir(work)
    state = CORE.read(work / 'state.json')
    require(state.get('schema') == SCHEMA and state.get('output') == str(work)
            and re.fullmatch('tcp-[0-9a-f]{24}', state.get('run', '')), 'Invalid public TCP capture receipt')
    supervisor = CORE.read(work / 'supervisor.json')
    pid = supervisor['pid']
    if Path('/proc', str(pid)).exists():
        require(CORE.UTIL.process_start(pid) == supervisor['start_ticks'], 'Supervisor PID identity changed')
        if Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[0] != 'Z':
            command = Path('/proc', str(pid), 'cmdline').read_bytes().split(b'\0')
            cwd = Path('/proc', str(pid), 'cwd').resolve()
            helpers = [(cwd / os.fsdecode(v)).resolve() for v in command if v and os.fsdecode(v).endswith('tcp-connections.py')]
            require(Path(__file__).resolve() in helpers and any(v in (str(work).encode(), ('--work=' + str(work)).encode()) for v in command),
                    'Supervisor command identity differs')
            os.kill(pid, signal.SIGTERM)
    with (work / 'lifecycle.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        result = cleanup(work, CORE.read(work / 'state.json'))
        CORE.event(work, 'public-stop', result)
    print(json.dumps(result))
    return 0 if result['cleaned'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=('plan', 'run', 'stop'), default='plan')
    parser.add_argument('--execute', action='store_true')
    for key in ('work', 'backend-host', 'backend-root', 'backend-work', 'backend-code', 'controller-ip', 'ctrl-ip', 'ctrl-mac', 'artifacts'):
        parser.add_argument('--' + key)
    parser.add_argument('--server-container', default='traflens-lab-server')
    parser.add_argument('--controller-url', default='http://127.0.0.1:20417')
    parser.add_argument('--controller-port', type=int, default=20035)
    parser.add_argument('--ingester-port', type=int, default=20033)
    parser.add_argument('--forward-port', type=int, default=24017)
    args = parser.parse_args(argv)
    if not args.execute or args.action == 'plan':
        print(json.dumps({'execute': False, 'reads_artifacts': False, 'starts_network': False, 'creates_resources': False,
                          'positive_ports': [18081, 18082, 18083], 'negative_ports': [18084, 18085, 18086],
                          'connections_per_phase': 3, 'agent_max_seconds': 180,
                          'natural_drain_seconds': NATURAL_DRAIN_SECONDS, 'stored_l4_verified': False}))
        return 0
    os.umask(0o077)
    require(args.work, 'Explicit private work required')
    return stop(args.work) if args.action == 'stop' else execute(args)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'private_receipts_retained': True}))
        raise SystemExit(1)
