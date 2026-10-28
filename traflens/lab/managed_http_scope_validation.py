#!/usr/bin/env python3
"""Pure validation of a minimum socket-scope proof; never opens BPF objects."""
import argparse
import hashlib
import json
import pathlib
import re

FIELDS = {'netns_id', 'validated', 'task_nsproxy_offset', 'nsproxy_net_offset',
          'net_ns_offset', 'ns_inum_offset'}


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def validate_scope_proof(raw, expected_inode, abi, abi_sha256):
    if not isinstance(raw, dict) or not integer(expected_inode, 1, 0xffffffff):
        raise RuntimeError('Invalid proof or expected namespace')
    for key, value in [('schema_version', 1), ('new_socket_program_count', 81), ('map_lookup_count', 1)]:
        if type(raw.get(key)) is not int or raw[key] != value:
            raise RuntimeError('Invalid proof counter: ' + key)
    for key in ('pass', 'read_only', 'target_is_not_host_netns'):
        if raw.get(key) is not True:
            raise RuntimeError('Missing positive proof: ' + key)
    if raw.get('payload_or_cache_maps_read') is not False:
        raise RuntimeError('Payload/cache map exclusion was not proven')
    if type(raw.get('target_inode')) is not int or raw['target_inode'] != expected_inode:
        raise RuntimeError('Proof target namespace differs')
    if (not integer(raw.get('baseline_program_count'), 1, 0xffffffff)
            or not integer(raw.get('associated_map_metadata_count'), 1, 0xffffffff)):
        raise RuntimeError('Missing metadata inventory count')
    if (not re.fullmatch('[0-9a-f]{64}', abi_sha256 or '')
            or raw.get('scope_abi_sha256') != abi_sha256
            or abi.get('scope', {}).get('size') != 24 or abi.get('offset_max') != 65535):
        raise RuntimeError('Scope ABI provenance mismatch')
    info = raw.get('scope_map')
    if not isinstance(info, dict):
        raise RuntimeError('Scope map metadata is absent')
    for key, value in [('type', 2), ('key_size', 4), ('value_size', 24), ('max_entries', 1)]:
        if type(info.get(key)) is not int or info[key] != value:
            raise RuntimeError('Scope map shape differs: ' + key)
    if info.get('name') != '__socket_scope_' or not integer(info.get('id'), 1, 0xffffffff):
        raise RuntimeError('Scope map identity differs')
    config = raw.get('scope_config')
    if not isinstance(config, dict) or set(config) != FIELDS:
        raise RuntimeError('Expected the exact scope_config record')
    records = []
    def visit(value):
        if isinstance(value, dict):
            if 'netns_id' in value or 'validated' in value:
                records.append(value)
            for child in value.values():
                visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)
    visit(raw)
    if len(records) != 1 or records[0] is not config:
        raise RuntimeError('Missing, duplicate or misplaced namespace configuration')
    if (not integer(config['netns_id'], 1, 0xffffffff) or config['netns_id'] != expected_inode
            or type(config['validated']) is not int or config['validated'] != 1):
        raise RuntimeError('Scope config is unvalidated or targets another namespace')
    for key in FIELDS - {'netns_id', 'validated'}:
        if not integer(config[key], 0, abi['offset_max']):
            raise RuntimeError('Invalid namespace offset: ' + key)
    if config['net_ns_offset'] > abi['offset_max'] - config['ns_inum_offset']:
        raise RuntimeError('Combined namespace offset overflows')
    ids = raw.get('scope_program_ids')
    if (not isinstance(ids, list) or not 1 <= len(ids) <= 81
            or any(not integer(value, 1, 0xffffffff) for value in ids)
            or len(set(ids)) != len(ids)):
        raise RuntimeError('Invalid scope-associated program IDs')
    return config.copy()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proof', type=pathlib.Path, required=True)
    parser.add_argument('--expected-inode', type=int, required=True)
    parser.add_argument('--abi', type=pathlib.Path, default=pathlib.Path(__file__).with_name('managed-http-scope-abi.json'))
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    raw = json.loads(args.proof.read_text())
    abi_bytes = args.abi.read_bytes()
    validate_scope_proof(raw, args.expected_inode, json.loads(abi_bytes), hashlib.sha256(abi_bytes).hexdigest())
    result = {'pass': True, 'read_only': True, 'strict_scope_config_verified': True,
              'proof_sha256': hashlib.sha256(args.proof.read_bytes()).hexdigest(),
              'payload_or_cache_maps_read': False}
    if args.output:
        with args.output.open('x') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
        args.output.chmod(0o600)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
