#!/usr/bin/env python3
"""Finite, owned IPv6-link-local iperf endpoint. Default is an offline plan."""
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

PURPOSE = 'traflens.link-baseline'
IMAGE = 'sha256:8ea4cbcf3a26ffe08ba1fa548831bc318beb1a689e921b70c0c47cac329e96fd'
OCI_IMAGE = 'sha256:dffca0bf86c0527e623a044b6bdae90cf6ebb2d95fcfb5f1d9345e9140972fec'
LAYER = 'sha256:6b7908e4c7473003628ddbd1d8ad378db659f0bf29a3019f7bb7150e9bfd109d'


def call(argv, timeout=15, check=True):
    return subprocess.run([str(v) for v in argv], text=True, capture_output=True,
                          timeout=timeout, check=check)


def write(path, value):
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
    path.chmod(0o600)


def validate_input(args):
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', args.interface or ''):
        raise ValueError('Expected an explicit Linux interface')
    for value in (args.bind, args.peer):
        if '%' in (value or '') or not ipaddress.IPv6Address(value).is_link_local:
            raise ValueError('Use numeric link-local IPv6 literals without a zone')
    if ipaddress.IPv6Address(args.bind) == ipaddress.IPv6Address(args.peer):
        raise ValueError('Peer must differ from local address')
    if not 1024 <= args.port <= 65535 or args.streams not in (1, 4):
        raise ValueError('Expected unprivileged port and 1 or 4 streams')
    if not 5 <= args.seconds <= 30 or not 0 <= args.omit <= 5:
        raise ValueError('Bounded measurement duration required')
    if not re.fullmatch('[0-9a-f]{32}', args.run_id or ''):
        raise ValueError('Expected a fresh exact run token')
    if not re.fullmatch('[0-9a-f]{64}', args.sha256 or ''):
        raise ValueError('Expected explicit binary SHA256')


def interface_snapshot(interface, bind, peer):
    links = json.loads(call(['ip', '-j', '-d', 'link', 'show', 'dev', interface]).stdout)
    addresses = json.loads(call(['ip', '-j', 'address', 'show']).stdout)
    route = json.loads(call(['ip', '-6', '-j', 'route', 'get', peer, 'oif', interface]).stdout)
    root = Path('/sys/class/net') / interface
    if len(links) != 1 or links[0].get('master') or not (root / 'device').exists():
        raise ValueError('Expected one standalone physical interface')
    if (root / 'speed').read_text().strip() != '10000' or links[0]['operstate'] != 'UP':
        raise ValueError('Physical link is not up at 10G')
    local = [row for row in addresses if row['ifname'] == interface]
    if len(local) != 1 or not any(ipaddress.IPv6Address(row['local']) == ipaddress.IPv6Address(bind)
                                and row['family'] == 'inet6' and row.get('scope') == 'link'
                                and not row.get('tentative', False)
                                for row in local[0]['addr_info'] if row['family'] == 'inet6'):
        raise ValueError('Bind address is not assigned on the selected interface')
    if any(row['local'] == peer for item in addresses for row in item.get('addr_info', [])):
        raise ValueError('Peer resolves to this host')
    if len(route) != 1 or route[0].get('dev') != interface or route[0].get('prefsrc') != bind:
        raise ValueError('Peer route does not use the selected interface/source')
    projection = {'ifindex': links[0]['ifindex'], 'ifname': interface, 'mtu': links[0]['mtu'],
                  'operstate': links[0]['operstate'], 'address': links[0]['address'],
                  'addresses': sorted((v['family'], v['local'], v['prefixlen'], v['scope'])
                                      for v in local[0]['addr_info']),
                  'route_device': route[0]['dev'], 'route_source': route[0]['prefsrc']}
    counters = {name: int((root / 'statistics' / name).read_text())
                for name in ('rx_bytes', 'tx_bytes', 'rx_errors', 'tx_errors', 'rx_dropped', 'tx_dropped')}
    return {'configuration': projection, 'counters': counters}


def process_baseline():
    names = {'deepflow-agent', 'deepflow_agent', 'socket_tracer', 'tlens-ebpf-gate'}
    for item in Path('/proc').iterdir():
        if not item.name.isdigit():
            continue
        try:
            comm = (item / 'comm').read_text().strip()
        except OSError:
            continue
        if comm in names:
            raise ValueError('Capture process active; this is a link-only baseline')
    active = call(['docker', 'ps', '-aq', '--filter', 'label=io.traflens.purpose=' + PURPOSE]).stdout.strip()
    if active:
        raise ValueError('Another owned link endpoint already exists')
    return set(call(['docker', 'ps', '-q', '--no-trunc']).stdout.split())


def inspect(cid):
    p = call(['docker', 'inspect', cid], check=False)
    if p.returncode:
        if 'no such' in p.stderr.lower():
            return None
        raise RuntimeError('Container identity unavailable')
    values = json.loads(p.stdout)
    if len(values) != 1:
        raise RuntimeError('Ambiguous container identity')
    return values[0]


def owned(info, receipt):
    if not info:
        return False
    conf, host = info['Config'], info['HostConfig']
    labels = conf.get('Labels') or {}
    mounts = [(v['Source'], v['Destination'], v['RW']) for v in info['Mounts'] if v['Type'] == 'bind']
    return (info['Id'] == receipt['id'] and info['Name'] == '/' + receipt['name']
            and conf['Image'] == receipt['image'] and conf['Entrypoint'] == ['/usr/bin/timeout']
            and conf['Cmd'] == receipt['command'] and labels.get('io.traflens.purpose') == PURPOSE
            and labels.get('io.traflens.run') == receipt['run_id']
            and host['NetworkMode'] == 'host' and host['PidMode'] != 'host'
            and not host['Privileged'] and host['ReadonlyRootfs']
            and host['Memory'] == 268435456 and host['MemorySwap'] == 268435456
            and host['NanoCpus'] == 2000000000 and host['PidsLimit'] == 64
            and not host.get('CapAdd') and host.get('CapDrop') == ['ALL']
            and 'no-new-privileges' in (host.get('SecurityOpt') or [])
            and mounts == [(receipt['binary'], '/iperf3', False)])


def listener(cid, args):
    rows = [line.split() for line in call(['docker', 'top', cid, '-eo', 'pid,comm']).stdout.splitlines()[1:]]
    pids = {int(row[0]) for row in rows if len(row) == 2 and row[0].isdigit() and row[1] == 'iperf3'}
    output = call(['ss', '-H', '-lntp6', 'sport = :' + str(args.port)]).stdout
    (args.work / 'socket-observation.txt').write_text(output)
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        address = fields[3]
        if address.startswith('[') and ']:' in address:
            host, port = address[1:].rsplit(']:', 1)
        elif ':' in address:
            host, port = address.rsplit(':', 1)
        else:
            continue
        local, _, zone = host.partition('%')
        local = local.strip('[]')
        actual = set(map(int, re.findall(r'pid=(\d+)', line)))
        if (int(port) == args.port and ipaddress.IPv6Address(local) == ipaddress.IPv6Address(args.bind)
                and zone == args.interface and actual & pids):
            return {'owned_listener': True, 'iperf_host_pids': sorted(pids), 'socket_line': line}
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--role', choices=('server', 'client'), default='client')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--binary', type=Path)
    parser.add_argument('--sha256')
    parser.add_argument('--image', choices=(IMAGE, OCI_IMAGE), default=IMAGE)
    parser.add_argument('--interface'); parser.add_argument('--bind'); parser.add_argument('--peer')
    parser.add_argument('--port', type=int, default=55201)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--omit', type=int, default=2)
    parser.add_argument('--streams', type=int, default=1)
    parser.add_argument('--reverse', action='store_true'); parser.add_argument('--run-id')
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({'executes': False, 'capture': False, 'network_configuration_changes': False,
                          'transport': 'IPv6 link-local TCP', 'cpus': 2, 'memory_mib': 256})); return
    validate_input(args)
    if os.geteuid() != 0:
        raise ValueError('Root required for identity and socket checks')
    os.umask(0o077)
    work = args.work
    if (not work or not work.is_absolute() or work.resolve() != work or work.exists()
            or work.parent.stat().st_uid != 0 or work.parent.stat().st_mode & 0o077):
        raise ValueError('Use a new canonical work directory under a private owned parent')
    binary = args.binary
    if not binary or binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError('Use a verified regular executable')
    if hashlib.sha256(binary.read_bytes()).hexdigest() != args.sha256:
        raise ValueError('Binary fingerprint differs')
    version = call([binary, '--version']).stdout
    if not version.startswith('iperf 3.22 '):
        raise ValueError('This endpoint contract is qualified for iperf3.22')
    before = interface_snapshot(args.interface, args.bind, args.peer)
    existing = process_baseline()
    image = json.loads(call(['docker', 'image', 'inspect', args.image]).stdout)[0]
    if image['RootFS']['Layers'] != [LAYER] or image['Architecture'] != 'amd64' or image['Os'] != 'linux':
        raise ValueError('Runtime root filesystem differs')
    work.mkdir(mode=0o700)
    write(work / 'before.json', before)
    ttl = args.seconds + args.omit + 25
    command = ['--signal=TERM', '--kill-after=5s', str(ttl), '/iperf3', '-6', '-J',
               '-B', args.bind + '%' + args.interface, '-p', str(args.port)]
    if args.role == 'server':
        command += ['-s', '-1', '--idle-timeout', '15', '--server-max-duration', str(args.seconds + args.omit + 5)]
    else:
        command += ['-c', args.peer + '%' + args.interface, '--connect-timeout', '5000',
                    '-t', str(args.seconds), '-O', str(args.omit), '-P', str(args.streams),
                    '--get-server-output', '--extra-data', args.run_id]
        if args.reverse:
            command += ['-R']
    name = 'traflens-link-' + args.role + '-' + uuid.uuid4().hex[:12]
    argv = ['docker', 'create', '--name', name, '--network', 'host', '--cpus', '2',
            '--memory', '256m', '--memory-swap', '256m', '--pids-limit', '64', '--cap-drop', 'ALL',
            '--read-only', '--security-opt', 'no-new-privileges', '--label', 'io.traflens.purpose=' + PURPOSE,
            '--label', 'io.traflens.run=' + args.run_id, '--log-opt', 'max-size=2m', '--log-opt', 'max-file=2',
            '--mount', 'type=bind,source=' + str(binary) + ',target=/iperf3,readonly',
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--entrypoint', '/usr/bin/timeout', args.image] + command
    receipt = {'name': name, 'run_id': args.run_id, 'role': args.role, 'binary': str(binary),
               'binary_sha256': args.sha256, 'image': args.image, 'rootfs_layer': LAYER,
               'command': command, 'create_command': argv}
    result = {'process_passed': False, 'capture_enabled': False, 'error': None, 'cleanup_errors': []}
    cid = None
    try:
        cid = call(argv).stdout.strip(); receipt['id'] = cid
        write(work / 'created.json', receipt)
        if not owned(inspect(cid), receipt):
            raise RuntimeError('Created identity differs')
        call(['docker', 'start', cid])
        if args.role == 'server':
            until = time.monotonic() + 8
            while time.monotonic() < until:
                state = inspect(cid)
                if not owned(state, receipt) or not state['State']['Running']:
                    raise RuntimeError('Server exited before bound listener readiness')
                proof = listener(cid, args)
                if proof:
                    write(work / 'ready.json', {**receipt, **proof}); break
                time.sleep(.1)
            else:
                raise RuntimeError('Owned explicit listener not proven')
        waited = call(['docker', 'wait', cid], timeout=ttl + 8)
        state = inspect(cid)
        if not owned(state, receipt):
            raise RuntimeError('Exited identity differs')
        result.update(exit_code=state['State']['ExitCode'], oom_killed=state['State']['OOMKilled'])
        result['process_passed'] = result['exit_code'] == 0 and not result['oom_killed']
    except BaseException as exc:
        result['error'] = repr(exc)
    finally:
        if cid:
            try:
                info = inspect(cid)
                if not owned(info, receipt): raise RuntimeError('Refuse unknown cleanup')
                if info['State']['Running']: call(['docker', 'stop', '--time', '5', cid])
                logs = call(['docker', 'logs', cid], check=False)
                (work / 'stdout.json').write_text(logs.stdout)
                (work / 'stderr.log').write_text(logs.stderr)
                write(work / 'exit-state.json', inspect(cid)['State'])
                call(['docker', 'rm', cid]); result['owned_container_removed'] = inspect(cid) is None
            except BaseException as exc:result['cleanup_errors'].append(repr(exc))
        after = interface_snapshot(args.interface, args.bind, args.peer)
        write(work / 'after.json', after)
        result['network_configuration_preserved'] = before['configuration'] == after['configuration']
        result['interface_counter_delta'] = {k: after['counters'][k] - v for k, v in before['counters'].items()}
        remaining = set(call(['docker', 'ps', '-q', '--no-trunc']).stdout.split())
        result['preexisting_containers_preserved'] = existing <= remaining
        result['pass'] = bool(result['process_passed'] and result.get('owned_container_removed')
                              and result['network_configuration_preserved'] and result['preexisting_containers_preserved']
                              and not result['error'] and not result['cleanup_errors'])
        write(work / 'result.json', result)
    print(json.dumps({'pass': result['pass'], 'role': args.role, 'capture_enabled': False,
                      'error': result['error'], 'cleanup_errors': result['cleanup_errors']}))
    raise SystemExit(0 if result['pass'] else 1)


if __name__ == '__main__':
    main()
