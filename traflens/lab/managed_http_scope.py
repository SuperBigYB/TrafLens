#!/usr/bin/env python3
"""Read only the namespace configuration ARRAY of a new owned socket-tracer set."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
import pathlib
import platform
import struct
import subprocess

SCOPE_NAME = '__socket_scope_'
SCOPE_FIELDS = ('netns_id', 'validated', 'task_nsproxy_offset', 'nsproxy_net_offset', 'net_ns_offset', 'ns_inum_offset')


def field(layout, name, bound, width=None):
    value = layout[name]
    offset, size = value['offset'], value['size']
    if (type(offset) is not int or type(size) is not int or offset < 0 or size <= 0
            or offset > bound or size > bound - offset or (width is not None and size != width)):
        raise RuntimeError('Invalid ABI field bounds: ' + name)
    return offset, size


def validate_abi(abi):
    if platform.machine() != 'x86_64' or abi['syscall'] != 321:
        raise RuntimeError('Only the verified x86_64 syscall ABI is supported')
    if (abi['cmd_lookup'], abi['cmd_fd'], abi['cmd_info'], abi['readonly']) != (1, 14, 15, 8):
        raise RuntimeError('Unexpected read-only BPF command selectors')
    if abi['scope']['size'] != 24 or abi['array'] != 2:
        raise RuntimeError('Unexpected scope configuration ABI')
    seen = set()
    for name in SCOPE_FIELDS:
        offset, size = field(abi['scope'], name, 24, 4)
        if any(i in seen for i in range(offset, offset + size)):
            raise RuntimeError('Overlapping scope ABI')
        seen.update(range(offset, offset + size))
    if len(seen) != 24:
        raise RuntimeError('Incomplete scope ABI')
    for name, size in [('map_id', 4), ('open_flags', 4), ('map_fd', 4), ('key', 8), ('value', 8),
                       ('info.bpf_fd', 4), ('info.info_len', 4), ('info.info', 8)]:
        field(abi['attr'], name, abi['attr']['size'], size)
    for name in ('type', 'id', 'key_size', 'value_size', 'max_entries'):
        field(abi['map_info'], name, abi['map_info']['size'], 4)
    field(abi['map_info'], 'name', abi['map_info']['size'], 16)


def new_programs(baseline, current):
    def indexed(values):
        if not isinstance(values, list) or any(type(p.get('id')) is not int for p in values):
            raise RuntimeError('Expected raw bpftool JSON program arrays')
        result = {p['id']: p for p in values}
        if len(result) != len(values):
            raise RuntimeError('Duplicate program IDs')
        return result
    before, after = indexed(baseline), indexed(current)
    if not before or not set(before) <= set(after):
        raise RuntimeError('The complete pre-Agent baseline was not preserved')
    for identity, old in before.items():
        for key in ('name', 'tag', 'type', 'map_ids'):
            if old.get(key) != after[identity].get(key):
                raise RuntimeError('Preexisting program identity changed')
    delta = [after[p] for p in sorted(set(after) - set(before))]
    added = [p for p in delta if p.get('type') in ('kprobe', 'tracepoint', 'tracing', 'raw_tracepoint')]
    if any(p not in added and p.get('type') != 'cgroup_device' for p in delta):
        raise RuntimeError('Unexpected new non-socket program type')
    if len(added) != 81:
        raise RuntimeError('Expected exactly 81 new socket programs')
    for prog in added:
        if ((prog.get('name') and not prog['name'].startswith('df_'))
                or not isinstance(prog.get('map_ids'), list)
                or not prog['map_ids'] or any(type(v) is not int or v <= 0 for v in prog['map_ids'])):
            raise RuntimeError('Unexpected new program metadata')
    return added


def select_scope(infos):
    matches = [m for m in infos if m['name'] == SCOPE_NAME and m['type'] == 2
               and m['key_size'] == 4 and m['value_size'] == 24 and m['max_entries'] == 1]
    if len(matches) != 1:
        raise RuntimeError('Missing or ambiguous scope ARRAY configuration')
    return matches[0]


def decode_scope(data, abi, target):
    if len(data) != 24:
        raise RuntimeError('Truncated scope configuration')
    result = {name: struct.unpack_from('=I', data, field(abi['scope'], name, 24, 4)[0])[0]
              for name in SCOPE_FIELDS}
    if result['netns_id'] != target or result['validated'] != 1:
        raise RuntimeError('Namespace mismatch or unvalidated scope')
    for name in SCOPE_FIELDS[2:]:
        if result[name] > abi['offset_max']:
            raise RuntimeError('Scope BTF offset is out of bounds')
    if result['net_ns_offset'] > abi['offset_max'] - result['ns_inum_offset']:
        raise RuntimeError('Combined namespace offset is out of bounds')
    return result


class Reader:
    def __init__(self, abi):
        validate_abi(abi)
        self.abi = abi
        self.libc = ctypes.CDLL(None, use_errno=True)
        self.libc.syscall.restype = ctypes.c_long

    def attr(self):
        return ctypes.create_string_buffer(self.abi['attr']['size'])

    def put(self, attr, name, value):
        offset, size = field(self.abi['attr'], name, len(attr))
        struct.pack_into('=I' if size == 4 else '=Q', attr, offset, value)

    def call(self, command, attr):
        if command not in (1, 14, 15):
            raise RuntimeError('Only metadata and configuration lookup commands are permitted')
        result = self.libc.syscall(ctypes.c_long(self.abi['syscall']), ctypes.c_int(command),
                                   ctypes.byref(attr), ctypes.c_uint(len(attr)))
        if result < 0:
            error = ctypes.get_errno()
            raise OSError(error, os.strerror(error))
        return result

    def fd(self, identity):
        attr = self.attr()
        self.put(attr, 'map_id', identity)
        self.put(attr, 'open_flags', self.abi['readonly'])
        return self.call(self.abi['cmd_fd'], attr)

    def info(self, fd):
        data = ctypes.create_string_buffer(self.abi['map_info']['size'])
        attr = self.attr()
        self.put(attr, 'info.bpf_fd', fd)
        self.put(attr, 'info.info_len', len(data))
        self.put(attr, 'info.info', ctypes.addressof(data))
        self.call(self.abi['cmd_info'], attr)
        length = min(len(data), struct.unpack_from('=I', attr, self.abi['attr']['info.info_len']['offset'])[0])
        result = {}
        for name in ('type', 'id', 'key_size', 'value_size', 'max_entries', 'name'):
            offset, size = field(self.abi['map_info'], name, length)
            result[name] = (bytes(data[offset:offset + size]).split(b'\0', 1)[0].decode('ascii', errors='strict')
                            if name == 'name' else struct.unpack_from('=I', data, offset)[0])
        return result

    def scope(self, fd, expected_info):
        # Hard allowlist immediately precedes the only map lookup in this tool.
        actual = self.info(fd)
        selected = select_scope([actual])
        if selected != expected_info:
            raise RuntimeError('Configuration map identity changed')
        key = ctypes.c_uint32(0)
        value = ctypes.create_string_buffer(24)
        attr = self.attr()
        self.put(attr, 'map_fd', fd)
        self.put(attr, 'key', ctypes.addressof(key))
        self.put(attr, 'value', ctypes.addressof(value))
        self.call(self.abi['cmd_lookup'], attr)
        return value.raw


def programs():
    return json.loads(subprocess.check_output(['bpftool', '-j', 'prog', 'show'], text=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', type=pathlib.Path, required=True)
    parser.add_argument('--target-netns', type=pathlib.Path, required=True)
    parser.add_argument('--expected-inode', type=int, required=True)
    parser.add_argument('--abi', type=pathlib.Path, default=pathlib.Path(__file__).with_name('managed-http-scope-abi.json'))
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    abi = json.loads(args.abi.read_text())
    validate_abi(abi)
    if not 0 < args.expected_inode <= 0xffffffff:
        parser.error('expected inode must be nonzero u32')
    nsfd = os.open(args.target_netns, os.O_RDONLY | os.O_CLOEXEC)
    fd = None
    try:
        if fcntl.ioctl(nsfd, abi['ns_get_nstype']) != abi['clone_newnet']:
            raise RuntimeError('Pinned FD is not a network namespace')
        target = os.fstat(nsfd).st_ino
        if target != args.expected_inode or target == os.stat('/proc/self/ns/net').st_ino:
            raise RuntimeError('Target differs from expected inode or equals loader host netns')
        baseline = json.loads(args.baseline.read_text())
        current = programs()
        added = new_programs(baseline, current)
        ids = sorted({v for p in added for v in p['map_ids']})
        reader = Reader(abi)
        infos = []
        for identity in ids:
            candidate_fd = reader.fd(identity)
            try:
                info = reader.info(candidate_fd)
                if info['id'] != identity:
                    raise RuntimeError('Map ID mismatch')
                infos.append(info)
            finally:
                os.close(candidate_fd)
        selected = select_scope(infos)
        fd = reader.fd(selected['id'])
        config = decode_scope(reader.scope(fd, selected), abi, target)
        if {p['id'] for p in new_programs(baseline, programs())} != {p['id'] for p in added}:
            raise RuntimeError('Program set changed during proof')
        result = {'schema_version': 1, 'pass': True, 'read_only': True,
            'new_socket_program_count': len(added), 'baseline_program_count': len(baseline),
            'target_inode': target, 'target_is_not_host_netns': True, 'scope_map': selected,
            'scope_config': config, 'map_lookup_count': 1, 'payload_or_cache_maps_read': False,
            'associated_map_metadata_count': len(infos),
            'new_container_cgroup_metadata': [{k: p.get(k) for k in ('id', 'name', 'type')}
                for p in current if p['id'] not in {v['id'] for v in baseline + added}],
            'scope_program_ids': [p['id'] for p in added if selected['id'] in p['map_ids']],
            'scope_abi_sha256': hashlib.sha256(args.abi.read_bytes()).hexdigest(),
            'qualification': 'Scope configuration proof only; protocol/port/IO/profile maps are not read. Additional cgroup_device program ownership remains the container supervisor responsibility.'}
        with args.output.open('x') as output:
            json.dump(result, output, indent=2)
            output.write('\n')
        args.output.chmod(0o600)
        print(json.dumps({'pass': True, 'new_programs': 81, 'scope_configuration_valid': True,
                          'map_lookup_count': 1, 'payload_or_cache_maps_read': False}))
    finally:
        if fd is not None:
            os.close(fd)
        os.close(nsfd)


if __name__ == '__main__':
    main()
