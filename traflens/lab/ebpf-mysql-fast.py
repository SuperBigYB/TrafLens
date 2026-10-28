#!/usr/bin/env python3
"""Explicit archived unpaced MySQL candidate; offline by default, no performance claim."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('fast_mysql_observer_contract', HERE / 'ebpf-mysql-diagnostic.py')
DIAGNOSTIC = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DIAGNOSTIC)
RUNTIME, CORE = DIAGNOSTIC.RUNTIME, DIAGNOSTIC.CORE
ARCHIVED_SOURCE_SHA256 = DIAGNOSTIC.ARCHIVED_SOURCE_SHA256
ARCHIVED_ARTIFACT_SHA256 = DIAGNOSTIC.ARCHIVED_ARTIFACT_SHA256
OLD_NATIVE_SOURCE = '3dec20af5ce6ff25c696d136b5477f5310b4962c'
OLD_NATIVE_SHA256 = '8dd5ec668a09dcdac10068727fb47f282cf8091a93a11fb71cbbc33db3853763'


def validate_receipt(receipt, run, role):
    # This is the explicitly unpaced validator. It never calls the paced one.
    DIAGNOSTIC.validate_receipt(receipt, run, role)
    DIAGNOSTIC.require(receipt.get('wire_data_events') == 18 and receipt.get('tcp_eof_events') == 3,
                       'Actual18 data IO and3 TCP EOF events are required')


def preflight(args):
    DIAGNOSTIC.preflight(args)
    agent = RUNTIME.module('fast_mysql_artifact_guard', 'managed-http-agent.py')
    artifact, _, _ = agent.verified_artifacts(Path(args.artifacts))
    DIAGNOSTIC.require(artifact['source'] != OLD_NATIVE_SOURCE and artifact['binary_sha256'] != OLD_NATIVE_SHA256,
                       'Fast candidate requires the independently qualified newly committed native artifact')


def observer_gate(work, state, stage):
    return DIAGNOSTIC.observer_gate(work, state, stage, CONTRACT)


CONTRACT = DIAGNOSTIC.CONTRACT._replace(fast=True, receipt_validator=validate_receipt,
                                      preflight_validator=preflight, observer_gate=observer_gate)
SCHEMA, PURPOSE, ROLES = CONTRACT.schema, CONTRACT.purpose, RUNTIME.ROLES
module, cleanup, worker_info = RUNTIME.module, RUNTIME.cleanup, RUNTIME.worker_info


def main(argv=None):
    selected = list(sys.argv[1:] if argv is None else argv)
    if selected and selected[0] == 'ack':
        parser = argparse.ArgumentParser(description='Acknowledge exact bounded observer evidence; no shell hooks.')
        parser.add_argument('action', choices=('ack',))
        parser.add_argument('--execute', action='store_true')
        parser.add_argument('--work', type=Path)
        parser.add_argument('--stage', choices=DIAGNOSTIC.STAGES, required=True)
        args = parser.parse_args(selected)
        if not args.execute:
            print(json.dumps({'observer_acknowledged': False, 'writes_files': False, 'unpaced_fast_candidate': True}))
            return 0
        os.umask(0o077)
        DIAGNOSTIC.require(args.work is not None, 'Explicit private work required')
        return DIAGNOSTIC.acknowledge(args.work, args.stage, CONTRACT)
    return RUNTIME.main(selected, CONTRACT)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'unpaced_fast_candidate': True,
                          'unpaced_completeness_proven': False, 'private_receipts_retained': True}))
        raise SystemExit(1)
