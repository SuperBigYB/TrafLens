#!/usr/bin/env python3
"""Bounded single-peer UDP DNS capture; default is an offline plan."""
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('dns_udp_scoped_runtime', HERE / 'ebpf-dns.py')
RUNTIME = importlib.util.module_from_spec(spec)
spec.loader.exec_module(RUNTIME)


def validate_receipt(receipt, run, role):
    require = RUNTIME.require
    transactions = receipt.get('transactions')
    require(receipt.get('run') == run and receipt.get('role') == role and receipt.get('pass') is True
            and receipt.get('protocol') == 'real UDP DNS' and receipt.get('transport') == 'udp'
            and receipt.get('completed_requests') == receipt.get('expected_requests') == 3
            and receipt.get('wire_events') == 6 and receipt.get('owned_socket_count') == 1
            and receipt.get('udp_datagrams_sent') == receipt.get('udp_datagrams_received') == receipt.get('datagram_exchanges') == 3
            and receipt.get('bound_udp_sockets') == 1 and receipt.get('connected_udp_sockets') == (1 if role == 'client' else 0)
            and receipt.get('socket_type') == 'SOCK_DGRAM' and receipt.get('framing') == 'udp-datagram'
            and receipt.get('single_peer_only_qualification') is True and receipt.get('single_peer_per_socket') is True
            and receipt.get('separate_client_udp_sockets') is False
            and receipt.get('owned_sockets_closed') is True and receipt.get('listener_closed') is True
            and receipt.get('single_threaded') is True and receipt.get('error') == ''
            and isinstance(transactions, list) and len(transactions) == 3
            and all(isinstance(item, dict) and item.get('complete') is True for item in transactions),
            'Actual complete single-peer UDP DNS application receipt required')
    require(not any(key in receipt for key in ('tcp_frames', 'tcp_eof_events', 'pacing_ms', 'pacing_waits')),
            'UDP cannot carry a TCP/paced qualification receipt')


CONTRACT = RUNTIME.DNS_CONTRACT._replace(udp=True, prepare_file='managed-dns-udp.py',
                                      receipt_validator=validate_receipt)
SCHEMA, PURPOSE, ROLES = CONTRACT.schema, CONTRACT.purpose, RUNTIME.ROLES


def main(argv=None):
    return RUNTIME.main(argv, CONTRACT)


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({'pass': False, 'error_type': type(error).__name__, 'private_receipts_retained': True,
                          'udp_storage_verified': False, 'single_peer_only_qualification': True}))
        raise SystemExit(1)
