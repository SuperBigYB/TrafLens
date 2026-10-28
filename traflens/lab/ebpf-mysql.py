#!/usr/bin/env python3
"""Finite scoped MySQL wire fixture; default is an offline plan, no SQL executes."""
import importlib.util
import json
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from cpu_profile_common import require
from cpu_profile_controller import kernel_mysql_profile

spec = importlib.util.spec_from_file_location('mysql_explicit_scoped_runtime', HERE / 'ebpf-dns.py')
RUNTIME = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNTIME)


def validate_receipt(receipt, run, role):
    connections = receipt.get('connections')
    require(receipt.get('run') == run and receipt.get('role') == role and receipt.get('pass') is True
            and receipt.get('completed_requests') == 3 and receipt.get('expected_requests') == 3
            and receipt.get('wire_events') == 21 and receipt.get('classic_packets') == 26
            and receipt.get('owned_sockets_closed') is True and receipt.get('listener_closed') is True
            and receipt.get('single_threaded') is True and receipt.get('error') == ''
            and receipt.get('wire_fixture') is True and receipt.get('sql_executed') is False
            and receipt.get('pacing_only_qualification') is True
            and type(receipt.get('pacing_ms')) is int and receipt['pacing_ms'] == 100
            and type(receipt.get('pacing_waits')) is int and receipt['pacing_waits'] == 21
            and type(receipt.get('pacing_duration_ns')) is int
            and 21 * 100_000_000 <= receipt['pacing_duration_ns'] <= 90_000_000_000
            and isinstance(receipt.get('waits_sha256'), str)
            and re.fullmatch('[0-9a-f]{64}', receipt['waits_sha256']) is not None
            and receipt.get('comm') == ('mysqld' if role == 'server' else 'traflens-mysql')
            and isinstance(connections, list) and len(connections) == 3
            and all(isinstance(v, dict) and v.get('complete') is True and v.get('closed') is True for v in connections),
            'Actual MySQL socket/wire receipt is incomplete')


CONTRACT = RUNTIME.ProtocolContract('mysql', 'my-', 'kernel_mysql', 60, kernel_mysql_profile,
                                    'managed-mysql.py', None, validate_receipt, 'mysqld', 'traflens-mysql')
SCHEMA = CONTRACT.schema
PURPOSE = CONTRACT.purpose
ROLES = RUNTIME.ROLES
CORE = RUNTIME.CORE
module = RUNTIME.module
worker_info = RUNTIME.worker_info
cleanup = RUNTIME.cleanup


def worker_spec(state, role):
    return RUNTIME.worker_spec(state, role, CONTRACT)


def create_worker(work, state, role):
    return RUNTIME.create_worker(work, state, role, CONTRACT)


def execute(args):
    return RUNTIME.execute(args, CONTRACT)


def stop(work):
    return RUNTIME.stop(work, CONTRACT)


def main(argv=None):
    return RUNTIME.main(argv, CONTRACT)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'private_receipts_retained': True}))
        raise SystemExit(1)
