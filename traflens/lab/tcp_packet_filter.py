"""Read-only actual AF_PACKET filter proof for the fixed loopback TCP slice."""
import ctypes
import ctypes.util
import hashlib
import json
import os
from pathlib import Path
import re
import socket


class FilterProofError(RuntimeError):
    def __init__(self, message):
        super().__init__(message)
        self.reason_code = re.sub('[^a-z0-9]+', '_', message.lower()).strip('_')


def require(condition, message):
    if not condition:
        raise FilterProofError(message)


class Instruction(ctypes.Structure):
    _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte), ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]


class Program(ctypes.Structure):
    _fields_ = [('length', ctypes.c_uint), ('instructions', ctypes.POINTER(Instruction))]


def native_custom_prefix(instructions):
    """Exactly mirror dispatcher/mod.rs get_bpf_instructions custom prefix."""
    code = [list(row) for row in instructions]
    require(2 <= len(code) <= 4096 and all(len(row) == 4 for row in code), 'Invalid compiled BPF program')
    require(code[-1][0] & 7 == 6, 'Compiled custom BPF must terminate in RET')
    if code[-1][3] != 0:
        return code[:-1]
    require(code[-2][0] & 7 == 6 and code[-2][3] != 0, 'Unsupported custom BPF return layout')
    code[-2] = [0x15, 1, 1, 0]
    return code


def compile_prefix(expression):
    library = ctypes.util.find_library('pcap')
    require(library, 'Local libpcap required for independent exact BPF-prefix proof')
    pcap = ctypes.CDLL(library)
    pcap.pcap_compile_nopcap.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(Program), ctypes.c_char_p, ctypes.c_int, ctypes.c_uint32]
    pcap.pcap_compile_nopcap.restype = ctypes.c_int
    pcap.pcap_freecode.argtypes = [ctypes.POINTER(Program)]
    program = Program()
    require(pcap.pcap_compile_nopcap(65535, 1, ctypes.byref(program), expression.encode(), 1, 0xffffffff) == 0,
            'Fixed capture BPF did not compile')
    try:
        require(2 <= program.length <= 4096, 'Compiled BPF exceeds finite instruction budget')
        words = [[v.code, v.jt, v.jf, v.k] for v in program.instructions[:program.length]]
        return native_custom_prefix(words)
    finally:
        pcap.pcap_freecode(ctypes.byref(program))


def read_filter(fd):
    libc = ctypes.CDLL(None, use_errno=True)
    length = ctypes.c_uint(0)
    require(libc.getsockopt(fd, socket.SOL_SOCKET, 26, None, ctypes.byref(length)) == 0,
            'Actual socket SO_GET_FILTER size is unavailable')
    require(1 <= length.value <= 4096, 'Actual socket has no bounded classic BPF filter')
    array = (Instruction * length.value)()
    capacity = length.value
    require(libc.getsockopt(fd, socket.SOL_SOCKET, 26, ctypes.byref(array), ctypes.byref(length)) == 0
            and length.value <= capacity, 'Actual socket classic BPF readback failed')
    return [[v.code, v.jt, v.jf, v.k] for v in array[:length.value]]


def packet_sockets(pid):
    owned = {}
    for entry in Path('/proc', str(pid), 'fd').iterdir():
        try:
            link = os.readlink(entry)
        except FileNotFoundError:
            continue
        match = re.fullmatch(r'socket:\[(\d+)\]', link)
        if match:
            owned[int(match[1])] = int(entry.name)
    lines = Path('/proc', str(pid), 'net/packet').read_text().splitlines()
    result = []
    for line in lines[1:]:
        fields = line.split()
        require(len(fields) >= 9, 'Malformed live AF_PACKET inventory')
        inode = int(fields[-1])
        if inode in owned:
            result.append({'inode': inode, 'fd': owned[inode], 'ifindex': int(fields[4])})
    return result


def prove_lo_guard(words, lo):
    """Prove every accepting path passes the native one-interface lo test.

    Local AF_PACKET normally binds ifindex0. The installed program must still
    reject every other interface; checking the textual profile or tail alone is
    insufficient because an earlier jump/return could bypass the guard.
    """
    require(5 <= len(words) <= 4096 and type(lo) is int and lo > 0, 'Invalid interface proof bounds')
    require(all(isinstance(row, list) and len(row) == 4 and all(type(v) is int for v in row)
                and 0 <= row[0] <= 65535 and 0 <= row[1] <= 255 and 0 <= row[2] <= 255
                and 0 <= row[3] <= 0xffffffff for row in words), 'Invalid classic BPF instruction encoding')
    start = len(words) - 5
    load, check = start, start + 1
    require(words[load] == [0x20, 0, 0, 0xfffff008]
            and words[check][0] == 0x15 and words[check][1] in (1, 2)
            and words[check][2] == 0 and words[check][3] == lo
            and words[start + 2] == [0x06, 0, 0, 0]
            and words[start + 3][0:3] == [0x06, 0, 0] and 0 < words[start + 3][3] <= 65535
            and words[start + 4] == [0x06, 0, 0, 65535], 'Actual installed native lo guard tail differs')
    allowed = {0x00, 0x20, 0x28, 0x30, 0x40, 0x48, 0x50, 0x60, 0x80,
               0x01, 0x61, 0x81, 0xb1, 0x02, 0x03, 0x07, 0x87,
               0x04, 0x0c, 0x14, 0x1c, 0x24, 0x2c, 0x34, 0x3c,
               0x44, 0x4c, 0x54, 0x5c, 0x64, 0x6c, 0x74, 0x7c,
               0x84, 0x94, 0x9c, 0xa4, 0xac, 0x05, 0x15, 0x1d,
               0x25, 0x2d, 0x35, 0x3d, 0x45, 0x4d, 0x06, 0x16}
    edges, incoming, accepting = {}, {i: set() for i in range(len(words))}, set()
    for i, (code, jt, jf, k) in enumerate(words):
        require(code in allowed, 'Unsupported classic BPF opcode in interface proof')
        if code in (0x06, 0x16):
            if code == 0x16 or k != 0:
                require(i in (start + 3, start + 4) and code == 0x06,
                        'Positive or dynamic return can bypass native lo guard')
                accepting.add(i)
            targets = []
        elif code == 0x05:
            require(jt == jf == 0, 'Malformed unconditional classic BPF jump')
            targets = [i + 1 + k]
        elif code & 7 == 5:
            targets = [i + 1 + jt, i + 1 + jf]
        else:
            targets = [i + 1]
        require(all(i < target < len(words) for target in targets), 'Classic BPF jump target is outside forward program')
        edges[i] = targets
        for target in targets:
            incoming[target].add(i)
    require(incoming[check] == {load}, 'Lo comparison can bypass IFINDEX load')
    def reaches_accept(blocked=None, non_lo=False):
        pending, seen = [0], set()
        while pending:
            i = pending.pop()
            if i in seen or i == blocked:
                continue
            seen.add(i)
            if i in accepting:
                return True
            pending.extend([check + 1] if non_lo and i == check else edges[i])
        return False
    require(reaches_accept(), 'Installed filter has no structurally reachable accept')
    require(not reaches_accept(load) and not reaches_accept(check) and not reaches_accept(non_lo=True),
            'Installed accepting path bypasses actual lo interface guard')
    return {'method': 'native_ifindex_tail_full_forward_cfg', 'guard_offset': start, 'lo_ifindex': lo,
            'load_ifindex_dominates_accept': True, 'lo_test_dominates_accept': True,
            'non_lo_accept_reachable': False, 'effective_kernel_lo_only': True}


def prove(pid, expression, diagnostics=None):
    diagnostics = diagnostics if diagnostics is not None else {}
    diagnostics['stage'] = 'packet_socket_inventory'
    require(os.uname().machine == 'x86_64', 'Qualified x86_64 pidfd syscall ABI required')
    sockets = packet_sockets(pid)
    lo = socket.if_nametoindex('lo')
    diagnostics.update(sockets=sockets, lo_ifindex=lo, socket_count=len(sockets))
    require(1 <= len(sockets) <= 16 and all(item['ifindex'] in (0, lo) for item in sockets),
            'Actual Agent AF_PACKET socket binds an unsupported interface')
    diagnostics['stage'] = 'compile_custom_prefix'
    prefix = compile_prefix(expression)
    diagnostics.update(custom_prefix=prefix, custom_prefix_sha256=hashlib.sha256(json.dumps(prefix, separators=(',', ':')).encode()).hexdigest())
    libc = ctypes.CDLL(None, use_errno=True)
    diagnostics['stage'] = 'pidfd_open'
    pidfd = libc.syscall(434, pid, 0)
    if pidfd < 0:
        raise OSError(ctypes.get_errno(), 'Actual Agent pidfd_open failed')
    try:
        for item in sockets:
            diagnostics['stage'] = 'pidfd_getfd'
            duplicate = libc.syscall(438, pidfd, item['fd'], 0)
            if duplicate < 0:
                raise OSError(ctypes.get_errno(), 'Read-only Agent pidfd_getfd requires host ptrace permission')
            with socket.socket(fileno=duplicate) as packet:
                diagnostics['stage'] = 'actual_socket_binding'
                name = packet.getsockname()[0]
                observed_index = socket.if_nametoindex(name) if name else 0
                require(packet.family == socket.AF_PACKET and observed_index == item['ifindex'] and observed_index in (0, lo),
                        'Duplicated actual socket binding differs from packet inventory')
                item['socket_bound_ifindex'] = observed_index
                diagnostics['stage'] = 'actual_filter_readback'
                words = read_filter(packet.fileno())
                item.update(instructions=words, instruction_count=len(words),
                            filter_sha256=hashlib.sha256(json.dumps(words, separators=(',', ':')).encode()).hexdigest())
                diagnostics['stage'] = 'verify_custom_prefix'
                require(len(words) > len(prefix) and words[:len(prefix)] == prefix,
                        'Actual classic BPF does not start with the exact fixed custom filter')
                item['exact_custom_prefix'] = True
                diagnostics['stage'] = 'verify_effective_lo_scope'
                item['interface_scope'] = prove_lo_guard(words, lo)
    finally:
        os.close(pidfd)
    diagnostics['stage'] = 'complete'
    return {'af_packet_socket_count': len(sockets), 'lo_ifindex': lo, 'sockets': sockets,
            'custom_prefix': prefix, 'custom_prefix_sha256': hashlib.sha256(json.dumps(prefix, separators=(',', ':')).encode()).hexdigest(),
            'method': 'Actual SO_GET_FILTER readback; exact native libpcap custom-prefix transformation',
            'outside_custom_filter_returns_zero_before_default_policy': True,
            'effective_kernel_lo_only': True, 'physical_socket_binding_may_be_all_interfaces': any(s['ifindex'] == 0 for s in sockets)}
