#!/usr/bin/env python3
"""Prepare fixed scoped eBPF MySQL/TCP documents; default has no side effects."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_controller import kernel_mysql_profile

spec = importlib.util.spec_from_file_location('managed_mysql_http_documents', HERE / 'managed-http.py')
HTTP = importlib.util.module_from_spec(spec)
spec.loader.exec_module(HTTP)
SCOPE_TARGET = HTTP.SCOPE_TARGET
SCHEMA = 'traflens.managed-mysql-preparation.v1'
MYSQL_PORT = 18080


def documents(controller_ip, group_id, controller_port=30035, ingester_ip=None,
              ingester_port=30033, mysql_port=MYSQL_PORT):
    if type(mysql_port) is not int or mysql_port != MYSQL_PORT:
        raise ValueError('MySQL/TCP preparation uses only port18080')
    _, bootstrap = HTTP.documents(controller_ip, group_id, controller_port, ingester_ip, ingester_port, MYSQL_PORT)
    if ingester_ip is not None and ingester_ip != controller_ip:
        raise ValueError('MySQL lab Controller and ingester must use the same explicit IPv4')
    profile = kernel_mysql_profile(controller_ip, controller_port, ingester_port)
    return profile, bootstrap


def prepare(output, **options):
    profile, bootstrap = documents(**options)
    output = Path(output)
    if os.name != 'posix' or not output.is_absolute() or output != output.resolve():
        raise ValueError('New canonical absolute POSIX output required')
    parent = output.parent.stat()
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.geteuid() or parent.st_mode & 0o077:
        raise ValueError('Output parent must be owned and private')
    output.mkdir(mode=0o700)
    files = {'group-profile.json': HTTP.private_json(output / 'group-profile.json', profile),
             'bootstrap.yaml': HTTP.private_json(output / 'bootstrap.yaml', bootstrap)}
    manifest = {'schema': SCHEMA, 'files': files, 'namespace_target': SCOPE_TARGET,
                'mysql_port': MYSQL_PORT, 'protocol': 'MySQL/TCP', 'starts_agent': False,
                'changes_controller': False, 'creates_namespace': False, 'attaches_bpf': False,
                'runtime_qualified': False}
    HTTP.private_json(output / 'manifest.json', manifest)
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', nargs='?', choices=('plan', 'prepare'), default='plan')
    p.add_argument('--output', type=Path)
    p.add_argument('--controller-ip')
    p.add_argument('--group-id')
    p.add_argument('--controller-port', type=int, default=30035)
    p.add_argument('--ingester-port', type=int, default=30033)
    a = p.parse_args(argv)
    if a.action == 'plan':
        print(json.dumps({'writes_files': False, 'starts_agent': False, 'attaches_bpf': False,
                          'protocol': 'MySQL/TCP', 'port': MYSQL_PORT, 'runtime_qualified': False}))
        return 0
    if not a.output or not a.controller_ip or not a.group_id:
        p.error('prepare requires --output, --controller-ip and --group-id')
    prepare(a.output, controller_ip=a.controller_ip, group_id=a.group_id,
            controller_port=a.controller_port, ingester_port=a.ingester_port)
    print(json.dumps({'prepared': True, 'starts_agent': False, 'runtime_qualified': False, 'protocol': 'MySQL/TCP'}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
