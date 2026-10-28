#!/usr/bin/env python3
"""Finite independent profile Querier/console. Default prints an offline plan."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

PURPOSE = 'traflens.profile-query-runtime'
LAB_LABEL = 'io.traflens.lab'
MAX_BODY = 4 * 1024 * 1024
APP = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
STOP_REQUESTED = False


def require(condition, message):
    if not condition:
        raise ValueError(message)


def call(argv, timeout=20, check=True):
    p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(argv[:3]) + '; ' + p.stderr[-1200:])
    return p


def inspect(kind, name):
    p = call(['docker', kind, 'inspect', name], check=False)
    if p.returncode:
        if 'no such' in p.stderr.lower():
            return None
        raise RuntimeError('Docker identity inspection failed')
    values = json.loads(p.stdout)
    require(len(values) == 1, 'Ambiguous Docker identity')
    return values[0]


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def save(path, value, replace=False):
    if replace:
        temp = path.with_name(path.name + '.next-' + uuid.uuid4().hex)
        save(temp, value)
        os.replace(temp, path)
        return
    with path.open('x') as output:
        json.dump(value, output, indent=2)
        output.write('\n')
    path.chmod(0o600)


def canonical(path, directory=False):
    require(path is not None and path.is_absolute() and path == path.resolve(), 'Explicit canonical absolute path required')
    require(not any(c in str(path) for c in ',\r\n\0'), 'Path cannot contain Docker mount delimiters')
    info = path.stat()
    require(info.st_uid == os.geteuid(), 'Runtime paths must belong to the executing user')
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode), 'Unexpected runtime path type')
    if directory:
        require(info.st_mode & 0o077 == 0, 'Private directory permissions required')
    return path


def verify_artifact(path, expected):
    canonical(path)
    require(re.fullmatch('[0-9a-f]{64}', expected or '') is not None and sha(path) == expected, 'Explicit matching artifact SHA256 required')
    require(os.access(path, os.X_OK), 'Runtime artifact must be executable')


def server_identity(info):
    require(info is not None and info['State']['Running'], 'Existing owned Server must remain running')
    return {'id': info['Id'], 'image': info['Image'], 'name': info['Name'],
            'labels': info['Config'].get('Labels') or {}, 'entrypoint': info['Config'].get('Entrypoint'),
            'command': info['Config'].get('Cmd'), 'readonly_root': info['HostConfig']['ReadonlyRootfs'],
            'mounts': sorted([m['Source'], m['Destination'], m['RW']] for m in info['Mounts'] if m['Type'] == 'bind'),
            'network_mode': info['HostConfig']['NetworkMode']}


def network_identity(info):
    require(info is not None, 'Existing owned lab network required')
    return {'id': info['Id'], 'name': info['Name'], 'labels': info.get('Labels') or {}, 'driver': info['Driver']}


def baseline(args):
    server = inspect('container', args.server_name)
    network = inspect('network', args.network)
    require(server is not None and server['Config'].get('Labels', {}).get(LAB_LABEL) == str(args.lab_root), 'Server is not owned by this lab')
    require(network is not None and network.get('Labels', {}).get(LAB_LABEL) == str(args.lab_root), 'Network is not owned by this lab')
    require(server['Image'] == args.image and inspect('image', args.image)['Id'] == args.image, 'Use the explicit existing owned Server image ID')
    joined = server['NetworkSettings']['Networks'].get(network['Name'])
    require(joined is not None and joined['NetworkID'] == network['Id'], 'Server and query runtime must share the verified lab network')
    return {'server': server_identity(server), 'network': network_identity(network)}


def unchanged(state):
    return (server_identity(inspect('container', state['server_name'])) == state['baseline']['server']
            and network_identity(inspect('network', state['network_name'])) == state['baseline']['network'])


def config(args):
    require(re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}', args.clickhouse_host or '') is not None, 'Explicit safe ClickHouse host required')
    require(re.fullmatch('[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', args.clickhouse_user or '') is not None, 'Safe password-free ClickHouse user required')
    require(1 <= args.clickhouse_port <= 65535, 'ClickHouse port is invalid')
    # Never reads/copies the old Server YAML. Password-bearing configurations
    # are intentionally unsupported in this first password-free lab slice.
    return ('querier:\n  clickhouse:\n    host: ' + args.clickhouse_host + '\n    port: ' + str(args.clickhouse_port)
            + '\n    timeout: 10\n    user-name: ' + args.clickhouse_user
            + "\n  language: en\n  listen-port: 20416\n  log-file: /tmp/querier.log\n  otel-endpoint: ''\n")


def scope(args):
    provided = any(v is not None for v in [args.app, args.time_from, args.time_to, args.agent])
    if not provided:
        return None
    require(args.app is not None and APP.fullmatch(args.app) is not None and args.time_from is not None and args.time_to is not None, 'Actual readiness scope needs app/from/to together')
    require(0 < args.time_from <= args.time_to <= int(time.time()) + 300 and args.time_to - args.time_from <= 31*86400, 'Finite inclusive profile time scope required')
    require(args.agent is None or 1 <= args.agent <= 65535, 'Agent scope must be1..65535')
    return {'app': args.app, 'from': args.time_from, 'to': args.time_to, 'agent': args.agent}


def port_free(port):
    with socket.socket() as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind(('127.0.0.1', port))


def spec(state, component):
    w = Path(state['work'])
    query = component == 'querier'
    memory = (1024 if query else 256) * 1024 * 1024
    command = ['--signal=TERM', '--kill-after=10s', str(state['seconds']),
               '/opt/querier-candidate' if query else '/opt/traflens-console']
    if not query:
        command += ['-listen', '127.0.0.1:' + str(state['console_port']), '-query', 'http://127.0.0.1:' + str(state['query_port']), '-controller', 'http://127.0.0.1:20417']
    mounts = [(str(w / ('querier-candidate' if query else 'traflens-console')),
               '/opt/querier-candidate' if query else '/opt/traflens-console', False)]
    if query:
        # The qualified standalone Querier does not call flag.Parse: it uses
        # the default config path. Reuse db_descriptions already in the image.
        mounts.append((str(w / 'querier.yaml'), '/etc/server.yaml', False))
    return {'component': component, 'name': 'traflens-profile-' + component + '-' + state['run'],
            'image': state['image'], 'entrypoint': ['/usr/bin/timeout'], 'command': command,
            'network': state['network_name'] if query else 'host', 'memory': memory,
            'cpus': 2 if query else 1, 'pids': 128 if query else 64, 'mounts': mounts,
            'ports': {'20416/tcp': [{'HostIp': '127.0.0.1', 'HostPort': str(state['query_port'])}]} if query else {},
            'labels': {LAB_LABEL: state['lab_root'], 'io.traflens.purpose': PURPOSE,
                       'io.traflens.run': state['run'], 'io.traflens.component': component}}


def create_command(value):
    argv = ['docker', 'create', '--name', value['name'], '--network', value['network'], '--restart', 'no',
            '--cpus', str(value['cpus']), '--memory', str(value['memory']), '--memory-swap', str(value['memory']),
            '--pids-limit', str(value['pids']), '--cap-drop', 'ALL', '--read-only', '--security-opt', 'no-new-privileges',
            '--ulimit', 'core=0:0', '--log-opt', 'max-size=10m', '--log-opt', 'max-file=1',
            '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m', '--entrypoint', '/usr/bin/timeout']
    for key, item in value['labels'].items():
        argv += ['--label', key + '=' + item]
    for source, target, _ in value['mounts']:
        argv += ['--mount', 'type=bind,src=' + source + ',dst=' + target + ',readonly']
    for port, bindings in value['ports'].items():
        argv += ['--publish', '127.0.0.1:' + bindings[0]['HostPort'] + ':' + port]
    return argv + [value['image']] + value['command']


def fingerprint(info):
    c, h = info['Config'], info['HostConfig']
    value = {'id': info['Id'], 'image': info['Image'], 'image_argument': c['Image'], 'name': info['Name'],
             'entrypoint': c['Entrypoint'], 'command': c['Cmd'], 'labels': c.get('Labels') or {},
             'network': h['NetworkMode'], 'pid': h['PidMode'], 'privileged': h['Privileged'],
             'readonly': h['ReadonlyRootfs'], 'cpu': h['NanoCpus'], 'memory': h['Memory'],
             'memory_swap': h['MemorySwap'], 'pids': h['PidsLimit'], 'caps_add': h.get('CapAdd') or [],
             'caps_drop': h.get('CapDrop') or [], 'security': h.get('SecurityOpt') or [], 'ports': h.get('PortBindings') or {},
             'binds': sorted((m['Source'], m['Destination'], m['RW']) for m in info['Mounts'] if m['Type'] == 'bind')}
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def expected(info, value):
    if info is None:
        return False
    c, h = info['Config'], info['HostConfig']
    normalize = lambda values: sorted(x.removeprefix('CAP_') for x in values or [])
    return (info['Name'] == '/' + value['name'] and info['Image'] == value['image'] and c['Image'] == value['image']
            and c['Entrypoint'] == value['entrypoint'] and c['Cmd'] == value['command']
            and all(c.get('Labels', {}).get(k) == v for k, v in value['labels'].items())
            and h['NetworkMode'] == value['network'] and h['PidMode'] != 'host' and not h['Privileged']
            and h['ReadonlyRootfs'] and h['NanoCpus'] == value['cpus'] * 1000000000
            and h['Memory'] == value['memory'] and h['MemorySwap'] == value['memory'] and h['PidsLimit'] == value['pids']
            and normalize(h.get('CapDrop')) == ['ALL'] and normalize(h.get('CapAdd')) == []
            and 'no-new-privileges' in (h.get('SecurityOpt') or []) and (h.get('PortBindings') or {}) == value['ports']
            and sorted((m['Source'], m['Destination'], m['RW']) for m in info['Mounts'] if m['Type'] == 'bind') == sorted(tuple(v) for v in value['mounts']))


@contextmanager
def locked(work):
    with (work / 'runtime.lock').open('a') as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(port, path, payload=None):
    body = None if payload is None else json.dumps(payload).encode()
    headers = {'X-Org-Id': '1', 'X-User-Id': '1', 'X-User-Type': '1'}
    if body is not None:
        headers['Content-Type'] = 'application/json'
    req = urllib.request.Request('http://127.0.0.1:' + str(port) + path, data=body, headers=headers)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        response = opener.open(req, timeout=4)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BODY + 1)
        require(len(data) <= MAX_BODY, 'Readiness response exceeded4MiB')
        return response.status, json.loads(data)


def native_payload(selected, maximum):
    filters = "profile_value_unit='samples'"
    if selected.get('agent') is not None:
        filters = 'agent_id=' + str(selected['agent']) + ' AND ' + filters
    return {'app_service': selected['app'], 'profile_event_type': 'cpu', 'profile_language_type': 'Golang',
            'time_start': selected['from'], 'time_end': selected['to'], 'tag_filter': filters, 'max_rows': maximum}


def native_ready(status, document, maximum):
    require(status == 200 and document.get('OPT_STATUS') == 'SUCCESS', 'Bounded native profile endpoint is not ready; no legacy fallback')
    tree = document.get('result')
    require(isinstance(tree, dict) and tree.get('bounds_applied') is True and tree.get('max_rows') == maximum,
            'Native response did not establish bounded input semantics')
    n = tree.get('input_rows')
    require(type(n) is int and 0 <= n <= maximum, 'Invalid bounded native input row count')
    budgets = tree.get('budgets') or {}
    for key, cap in [('compressed_bytes', 4194304), ('decoded_stack_bytes', 1048576), ('total_decoded_stack_bytes', 8388608), ('nodes', 8192), ('stack_depth', 512)]:
        require(type(budgets.get(key)) is int and 0 < budgets[key] <= cap, 'Native decode budget not confirmed: ' + key)
    return tree


def readiness(state):
    selected = state['scope']
    if selected is None:
        now = int(time.time())
        selected = {'app': 'traflens-missing-' + state['run'], 'from': now-60, 'to': now, 'agent': None}
    status, document = request(state['query_port'], '/v1/profile/ProfileTracingBounded', native_payload(selected, 256))
    tree = native_ready(status, document, 256)
    if state['scope'] is not None:
        require(tree['input_rows'] > 0, 'Explicit actual readiness scope has no stored profile rows')
    else:
        require(tree['input_rows'] == 0, 'Offline-readiness marker unexpectedly exists')
    gate = False
    if tree['input_rows'] > 1:
        status, document = request(state['query_port'], '/v1/profile/ProfileTracingBounded', native_payload(selected, tree['input_rows']-1))
        require(status == 400 and document.get('OPT_STATUS') == 'RESOURCE_NUM_EXCEEDED', 'Native actual max_rows rejection gate failed')
        gate = True
    params = {k: v for k, v in selected.items() if v is not None}
    status, detail = request(state['console_port'], '/api/profile?' + urllib.parse.urlencode(params))
    require(status == 200 and detail.get('bounds_applied') is True and detail.get('max_rows') == 256
            and detail.get('input_rows') == tree['input_rows'] and detail.get('app') == selected['app']
            and detail.get('agent_id') == selected.get('agent') and detail.get('language') == 'Golang'
            and detail.get('event') == 'cpu' and detail.get('unit') == 'samples', 'Console did not preserve actual bounded profile scope')
    require(isinstance(detail.get('total_samples'), str) and detail['total_samples'].isdigit(), 'Console sample weights must remain exact strings')
    return {'ready': True, 'actual_scope_checked': state['scope'] is not None, 'input_rows': tree['input_rows'],
            'total_samples': detail['total_samples'], 'actual_max_rows_rejection_checked': gate,
            'empty_readiness_only': state['scope'] is None, 'legacy_fallback': False}


def cleanup(work, state):
    for component in ['console', 'querier']:
        entry = state['resources'].get(component)
        if entry is None:
            continue
        value = entry['spec']
        info = inspect('container', entry.get('id') or value['name'])
        if info is None:
            continue
        require(expected(info, value), 'Refusing to stop a runtime with different ownership/resources')
        if entry.get('id'):
            require(info['Id'] == entry['id'], 'Runtime container ID changed')
        if entry.get('fingerprint'):
            require(fingerprint(info) == entry['fingerprint'], 'Runtime container fingerprint changed')
        if info['State']['Running']:
            call(['docker', 'stop', '--time', '10', info['Id']], timeout=15)
        logs = call(['docker', 'logs', info['Id']], check=False)
        logpath = work / (component + '-final.log')
        if not logpath.exists():
            logpath.write_text(logs.stdout + logs.stderr)
            logpath.chmod(0o600)
        call(['docker', 'rm', info['Id']])
        require(inspect('container', info['Id']) is None, 'Owned runtime was not removed')
    require(unchanged(state), 'Old Server/network identity changed during the independent runtime')
    port_free(state['query_port'])
    port_free(state['console_port'])
    state['status'] = 'stopped'
    state['stopped_at'] = time.time()
    state['restoration'] = {'owned_containers_removed': True, 'old_server_network_unchanged': True,
                            'owned_loopback_ports_released': True, 'server_configuration_read_or_copied': False}
    save(work / 'runtime.json', state, replace=True)
    if not (work / 'restoration.json').exists():
        save(work / 'restoration.json', state['restoration'])
    return state['restoration']


def run(args):
    global STOP_REQUESTED
    require(os.name == 'posix' and os.geteuid() == 0, 'Qualified Linux root Docker lab execution required')
    canonical(args.lab_root, directory=True)
    require(args.work is not None and args.work.is_absolute() and args.work == args.work.resolve() and not args.work.exists()
            and args.work.is_relative_to(args.lab_root), 'Fresh canonical work directory inside the owned lab required')
    canonical(args.work.parent, directory=True)
    require(30 <= args.seconds <= 600 and 1024 <= args.query_port <= 65535 and 1024 <= args.console_port <= 65535
            and args.query_port != args.console_port, 'Finite TTL30..600 and distinct unprivileged loopback ports required')
    require(re.fullmatch('sha256:[0-9a-f]{64}', args.image or '') is not None, 'Explicit immutable image ID required')
    verify_artifact(args.querier_binary, args.querier_sha256)
    verify_artifact(args.console_binary, args.console_sha256)
    yaml = config(args)
    selected = scope(args)
    old = baseline(args)
    port_free(args.query_port)
    port_free(args.console_port)
    os.umask(0o077)
    args.work.mkdir(mode=0o700)
    state = {'schema': PURPOSE + '.v1', 'run': uuid.uuid4().hex[:20], 'status': 'creating', 'work': str(args.work),
             'lab_root': str(args.lab_root), 'server_name': args.server_name, 'network_name': old['network']['name'],
             'image': args.image, 'seconds': args.seconds, 'query_port': args.query_port, 'console_port': args.console_port,
             'scope': selected, 'baseline': old, 'resources': {}, 'started_at': time.time()}
    for source, name, digest in [(args.querier_binary, 'querier-candidate', args.querier_sha256),
                                 (args.console_binary, 'traflens-console', args.console_sha256)]:
        shutil.copyfile(source, args.work / name)
        (args.work / name).chmod(0o500)
        require(sha(args.work / name) == digest, 'Staged runtime artifact hash changed')
    (args.work / 'querier.yaml').write_text(yaml)
    (args.work / 'querier.yaml').chmod(0o400)
    state['artifact_sha256'] = {'querier': args.querier_sha256, 'console': args.console_sha256,
                                'query_config': sha(args.work / 'querier.yaml')}
    save(args.work / 'runtime.json', state)
    def interrupted(signum, frame):
        global STOP_REQUESTED
        STOP_REQUESTED = True
    previous = {sig: signal.signal(sig, interrupted) for sig in [signal.SIGINT, signal.SIGTERM, signal.SIGHUP]}
    result = {'passed': False}
    started = time.monotonic()
    try:
        with locked(args.work):
            for component in ['querier', 'console']:
                value = spec(state, component)
                require(inspect('container', value['name']) is None, 'Runtime name already exists')
                state['resources'][component] = {'spec': value}
                save(args.work / 'runtime.json', state, replace=True)
                created = call(create_command(value))
                identity = created.stdout.strip()
                info = inspect('container', identity)
                require(expected(info, value), 'New runtime differs from its restricted intent')
                state['resources'][component].update(id=identity, fingerprint=fingerprint(info))
                save(args.work / 'runtime.json', state, replace=True)
                call(['docker', 'start', identity])
            state['status'] = 'running'
            save(args.work / 'runtime.json', state, replace=True)
        ready = None
        deadline = time.monotonic() + min(30, args.seconds-5)
        last_error = None
        while time.monotonic() < deadline and not STOP_REQUESTED:
            try:
                ready = readiness(state)
                break
            except (OSError, ValueError) as error:
                last_error = str(error)
                time.sleep(.3)
        require(ready is not None, 'Bounded profile readiness failed: ' + str(last_error))
        save(args.work / 'ready.json', ready)
        print(json.dumps(dict(ready, work=str(args.work), console='http://127.0.0.1:' + str(args.console_port))), flush=True)
        result['passed'] = True
        while time.monotonic()-started < args.seconds and not STOP_REQUESTED:
            with locked(args.work):
                current = json.loads((args.work / 'runtime.json').read_text())
                if current['status'] == 'stopped':
                    break
                for entry in state['resources'].values():
                    info = inspect('container', entry['id'])
                    require(info is not None and expected(info, entry['spec']) and fingerprint(info) == entry['fingerprint'], 'Owned runtime disappeared or changed')
                    require(info['State']['Running'], 'Owned runtime exited before its finite supervisor deadline')
            time.sleep(.5)
    except BaseException as error:
        result.update(passed=False, error=str(error))
    finally:
        try:
            with locked(args.work):
                current = json.loads((args.work / 'runtime.json').read_text())
                result['restoration'] = cleanup(args.work, current) if current['status'] != 'stopped' else current['restoration']
        except BaseException as error:
            result.update(passed=False, cleanup_error=str(error))
        for sig, handler in previous.items():
            signal.signal(sig, handler)
        save(args.work / 'result.json', result)
    print(json.dumps(result), flush=True)
    return 0 if result['passed'] else 1


def stop(args):
    canonical(args.work, directory=True)
    with locked(args.work):
        state = json.loads((args.work / 'runtime.json').read_text())
        require(state.get('schema') == PURPOSE + '.v1' and state.get('work') == str(args.work), 'Runtime receipt differs')
        canonical(Path(state['lab_root']), directory=True)
        result = cleanup(args.work, state)
    print(json.dumps({'stopped': True, 'restoration': result}))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', nargs='?', choices=['run', 'stop'], default='run')
    p.add_argument('--execute', action='store_true')
    p.add_argument('--work', type=Path)
    p.add_argument('--lab-root', type=Path)
    p.add_argument('--server-name', default='traflens-lab-server')
    p.add_argument('--network', default='traflens-lab')
    p.add_argument('--image')
    for name in ['querier', 'console']:
        p.add_argument('--' + name + '-binary', type=Path)
        p.add_argument('--' + name + '-sha256')
    p.add_argument('--clickhouse-host', default='clickhouse')
    p.add_argument('--clickhouse-port', type=int, default=9000)
    p.add_argument('--clickhouse-user', default='default')
    p.add_argument('--seconds', type=int, default=300)
    p.add_argument('--query-port', type=int, default=20818)
    p.add_argument('--console-port', type=int, default=20880)
    p.add_argument('--app')
    p.add_argument('--from', dest='time_from', type=int)
    p.add_argument('--to', dest='time_to', type=int)
    p.add_argument('--agent', type=int)
    a = p.parse_args(argv)
    if not a.execute:
        print(json.dumps({'execute': False, 'starts_runtime': False, 'action': a.action,
                          'independent_querier_and_console': True, 'old_server_modified': False,
                          'password_supported': False, 'functional_readiness_requires_explicit_actual_scope': True,
                          'query_listen': '127.0.0.1:' + str(a.query_port), 'console_listen': '127.0.0.1:' + str(a.console_port)}))
        return 0
    return run(a) if a.action == 'run' else stop(a)


if __name__ == '__main__':
    raise SystemExit(main())
