#!/usr/bin/env python3
"""Prepare a restricted managed eBPF HTTP profile and bootstrap; never start capture."""
import argparse
from copy import deepcopy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
SCOPE_TARGET = '/run/traflens/target.netns'


def port(value):
    if type(value) is not int or not 1 <= value <= 65535:
        raise ValueError('Port must be an integer in 1..65535')
    return value


def documents(controller_ip, group_id, controller_port=30035, ingester_ip=None,
              ingester_port=30033, http_port=18080):
    if not isinstance(controller_ip, str) or (ingester_ip is not None and not isinstance(ingester_ip, str)):
        raise ValueError('Controller/ingester addresses must be IP strings')
    controller_ip = str(ipaddress.ip_address(controller_ip))
    ingester_ip = str(ipaddress.ip_address(ingester_ip or controller_ip))
    if not isinstance(group_id, str) or not re.fullmatch(r'g-[a-z0-9]{1,64}', group_id):
        raise ValueError('Expected a Controller group SHORT_UUID (g-...)')
    controller_port, ingester_port, http_port = map(port, (controller_port, ingester_port, http_port))
    profile = deepcopy(json.loads((HERE / 'managed-http-profile.json').read_text()))
    communication = profile['global']['communication']
    communication.update(proxy_controller_ip=controller_ip, proxy_controller_port=controller_port,
                         ingester_ip=ingester_ip, ingester_port=ingester_port)
    profile['inputs']['cbpf']['af_packet']['extra_bpf_filter'] = 'tcp port ' + str(http_port)
    profile['processors']['request_log']['filters']['port_number_prefilters'] = {'HTTP': str(http_port)}
    bootstrap = {
        'controller-ips': [controller_ip], 'controller-port': controller_port,
        'vtap-group-id-request': group_id, 'async-worker-thread-number': 2,
        'log-file': '/var/log/traflens/deepflow-agent.log',
        'pid-file': '/run/traflens/deepflow-agent.pid',
        'liveness-probe-enabled': False, 'cgroups-disabled': True,
        'ebpf-socket-netns-scope': SCOPE_TARGET,
    }
    return profile, bootstrap


def private_json(path, value):
    raw = (json.dumps(value, indent=2, ensure_ascii=False) + '\n').encode('utf-8')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as output:
        output.write(raw)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'bytes': len(raw)}


def prepare(output, **options):
    profile, bootstrap = documents(**options)
    output = Path(output)
    if os.name != 'posix':
        raise ValueError('Preparation requires POSIX private-file permissions')
    if not output.is_absolute() or output != output.resolve():
        raise ValueError('New canonical absolute output directory required')
    parent = output.parent
    info = parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError('Output parent must be owned and private (mode0700)')
    output.mkdir(mode=0o700)
    files = {
        'group-profile.json': private_json(output / 'group-profile.json', profile),
        # JSON is valid YAML and avoids interpolation/quoting errors in bootstrap.
        'bootstrap.yaml': private_json(output / 'bootstrap.yaml', bootstrap),
    }
    manifest = {
        'schema': 'traflens.managed-http-preparation.v1', 'files': files,
        'namespace_target': SCOPE_TARGET, 'http_port': options.get('http_port', 18080),
        'starts_agent': False, 'changes_controller': False, 'creates_namespace': False,
        'attaches_bpf': False, 'runtime_qualified': False,
        'requires': [
            'Explicit owned target network-namespace lease pinned until Agent exit',
            'Apply profile only to the owned stopped Agent group and verify exact readback',
            'Bounded scoped launcher and actual collector/scope-FD/map proof before traffic',
            'Stop owned Agent before releasing lease; verify BPF/tracefs and restore configuration',
        ],
    }
    private_json(output / 'manifest.json', manifest)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', choices=['plan', 'prepare'], default='plan')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--controller-ip')
    parser.add_argument('--controller-port', type=int, default=30035)
    parser.add_argument('--ingester-ip')
    parser.add_argument('--ingester-port', type=int, default=30033)
    parser.add_argument('--http-port', type=int, default=18080)
    parser.add_argument('--group-id')
    args = parser.parse_args()
    if args.action == 'plan':
        print(json.dumps({'writes_files': False, 'starts_agent': False, 'changes_controller': False,
                          'attaches_bpf': False, 'prepare_outputs': ['group-profile.json', 'bootstrap.yaml', 'manifest.json']}))
        return
    if args.output is None or not args.controller_ip or not args.group_id:
        parser.error('prepare requires --output, --controller-ip and --group-id')
    try:
        result = prepare(args.output, controller_ip=args.controller_ip, group_id=args.group_id,
                         controller_port=args.controller_port, ingester_ip=args.ingester_ip,
                         ingester_port=args.ingester_port, http_port=args.http_port)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    print(json.dumps({'prepared': True, 'output': str(args.output), 'files': list(result['files']),
                      'starts_agent': False, 'changes_controller': False, 'attaches_bpf': False,
                      'runtime_qualified': False}))


if __name__ == '__main__':
    main()
