#!/usr/bin/env python3
"""Hold owned quiet namespace FDs for a separate bounded association workload."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import time

import managed_http_workload as W

M = W.M
PURPOSE = 'traflens.association-namespace-lease'
CANCELLED = False


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def private(path, fresh=False):
    require(path and path.is_absolute() and path == path.resolve(), 'Canonical absolute private path required')
    parent = path.parent if fresh else path
    info = parent.stat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            'Owned private directory required')
    if fresh:
        path.mkdir(mode=0o700)
    return path


def start_ticks(pid):
    return Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[19]


class HolderSpec(W.WorkerSpec):
    def create(self):
        argv = super().create()
        argv[2:2] = ['--read-only', '--restart', 'no']
        return argv

    def matches(self, value):
        if not super().matches(value):
            return False
        host = value['HostConfig']
        return (host.get('ReadonlyRootfs') is True and host.get('RestartPolicy', {}).get('Name') in ('', 'no')
                and host.get('PortBindings') in (None, {}) and host.get('NanoCpus') == 250000000
                and host.get('MemorySwap') == 67108864 and 'no-new-privileges' in (host.get('SecurityOpt') or []))


class AssociationLease(W.Lease):
    def __init__(self, work, workload=None):
        # The inherited Lease/Case supply exact owned create/state/cleanup and
        # normal Agent registration + scope proof protocols. No traffic is run.
        super().__init__(work, workload or Path('/usr/bin/sleep'))
        self.name = self.name.replace('traflens-managed-ebpf-', 'traflens-association-')
        self.workload = workload
        self.workload_sha256 = W.sha(workload) if workload else None
        self.result = {'schema': 'traflens.association-namespace-lease.v1', 'pass': False,
                       'scope_only': True, 'port': 18080, 'phase': 0, 'http_emitted': False,
                       'workload_executed_by_lease': False, 'error': None, 'cleanup_errors': [],
                       'agent_control_owned_by_coordinator': True}

    def metadata(self, status):
        value = super().metadata(status)
        for role in ('positive', 'negative'):
            if value.get(role) is not None:
                value[role]['container_id'] = self.ids.get(role)
        value.update(traffic_sha256=None, workload_sha256=self.workload_sha256,
                     workload_bin=str(self.workload) if self.workload else None,
                     scope_only=True, workload_executed_by_lease=False,
                     http_requires_explicit_root_phase=False, phase_matrix_supported=False,
                     scope_success_is_not_http_acceptance=True)
        return value

    def pin(self, role):
        # Same nsfs pin/ioctl/immutable Case.state checks as Case.pin, replacing
        # its old gate-traffic SHA/ready-file dependency with the sleep intent.
        state = self.state(role)
        pid = state['Pid']
        require(state['Running'] and pid > 1, 'Owned holder must be running')
        ticks = start_ticks(pid)
        proc = Path('/proc', str(pid))
        require((proc / 'cmdline').read_bytes().rstrip(b'\0').split(b'\0') == [b'/usr/bin/sleep', b'240'],
                'Owned namespace holder command differs')
        executable = (proc / 'exe').readlink()
        require(executable.name == 'sleep', 'Owned namespace holder executable differs')
        fd = os.open(proc / 'ns/net', os.O_RDONLY | os.O_CLOEXEC)
        self.fds.append(fd)
        inode = os.fstat(fd).st_ino
        require(fcntl.ioctl(fd, W.NS_GET_NSTYPE) == W.CLONE_NEWNET and 0 < inode <= 0xffffffff,
                'Holder FD is not a representable network namespace')
        require(inode != os.stat('/proc/self/ns/net').st_ino, 'Holder cannot be the host namespace')
        require(self.state(role)['Pid'] == pid and start_ticks(pid) == ticks, 'Holder process changed while pinning')
        return {'pid': pid, 'inode': inode, 'fd': fd, 'source': '/proc/%d/fd/%d' % (os.getpid(), fd),
                'start_ticks': ticks, 'holder_executable_sha256': W.sha(proc / 'exe'),
                'holder_kind': 'quiet sleep240; no traffic executable'}

    def prepare(self):
        for role in ('positive', 'negative'):
            self.create(HolderSpec(self, role, '/usr/bin/sleep', ['240'], []))
            added = set(M.bpf_ids()) - set(self.baseline_bpf)
            require(all(W.program_type(program) == 15 for program in added),
                    'Unexpected non-cgroup-device BPF program appeared during holder creation')
            self.worker_metadata_ids = added
        W.atomic_json(self.root / 'inventory-workers.json', {
            'original_bpf_ids': self.baseline_bpf,
            'owned_worker_cgroup_device_ids': sorted(self.worker_metadata_ids)})
        self.positive, self.negative = self.pin('positive'), self.pin('negative')
        require(self.positive['inode'] != self.negative['inode'], 'Holder namespaces must be distinct')
        W.atomic_json(self.root / 'inventory-before.json', {
            'bpf_ids': self.baseline_bpf, 'tracefs': self.baseline_tracefs,
            'running_containers': sorted(self.baseline_containers)})
        self.publish_status('ready_waiting_root_commands')

    def external_users_absent(self):
        # The coordinator owns the actual frontend/backend/generator containers.
        # It must remove those before release; this lease never stops them.
        inventory = M.run(['docker', 'ps', '-aq', '--no-trunc'])
        require(inventory.returncode == 0, 'Cannot verify external namespace users')
        own = set(self.ids.values())
        target_ids = own | {spec.name for spec in self.specs}
        inodes = {pin['inode'] for pin in (self.positive, self.negative) if pin}
        for cid in inventory.stdout.split():
            if cid in own:
                continue
            value = M.inspect(cid)
            if value is None:
                continue
            network = value['HostConfig'].get('NetworkMode', '')
            if network.startswith('container:') and network.partition(':')[2] in target_ids:
                return False
            state = value['State']
            if state.get('Running') and state.get('Pid', 0) > 1:
                try:
                    inode = os.stat('/proc/%d/ns/net' % state['Pid']).st_ino
                except FileNotFoundError:
                    # A changed live object must be inspected again, not guessed absent.
                    current = M.inspect(cid)
                    if current is not None and current['State'].get('Running'):
                        return False
                    continue
                if inode in inodes:
                    return False
        return True

    def cleanup_ready(self):
        return super().cleanup_ready() and self.external_users_absent()

    def handle(self, request):
        action = request.get('action')
        require(action != 'phase', 'Association lease does not emit or accept legacy HTTP phases')
        if action == 'release':
            require(self.cleanup_ready(), 'Agent, external namespace users or BPF/tracefs have not restored')
            return True
        require(action in ('register-agent', 'approve-agent'), 'Unsupported association coordinator action')
        return super().handle(request)

    def receive(self):
        path = self.control / 'coordinator-request.json'
        if not path.exists():
            return False
        request = W.read_private(path)
        nonce = request.get('nonce')
        require(re.fullmatch('[0-9a-f]{32}', nonce or ''), 'Invalid coordinator nonce')
        path.unlink()
        try:
            released = self.handle(request)
            response = {'accepted': True, 'nonce': nonce, 'phase': 0}
        except (ValueError, RuntimeError) as error:
            released = False
            response = {'accepted': False, 'nonce': nonce, 'error': str(error)}
        W.atomic_json(self.control / ('response-' + nonce + '.json'), response)
        return released

    def supervise(self):
        released, safe = False, False
        try:
            self.prepare()
            print(json.dumps({'ready': True, 'lease': str(self.root), 'scope_only': True,
                              'http_emitted': False, 'phase_matrix_supported': False}), flush=True)
            while time.monotonic() < self.lease_deadline and not CANCELLED:
                if self.receive():
                    released = True
                    break
                time.sleep(.05)
            if not released:
                self.result['error'] = 'lease_expired_or_cancelled'
        except BaseException as error:
            self.result['error'] = type(error).__name__ + ': ' + str(error)
        finally:
            self.publish_status('waiting_for_agent_exit_and_inventory_restore')
            timed_out = False
            while True:
                try:
                    safe = self.cleanup_ready()
                    if safe:
                        break
                    self.receive()
                except Exception as error:
                    self.result['last_cleanup_guard_error'] = type(error).__name__
                timed_out = timed_out or time.monotonic() >= self.cleanup_deadline
                W.atomic_json(self.root / 'cleanup-required.json', {
                    'agent_exit_required': True, 'namespace_fds_still_held': True,
                    'coordinator_owns_agent_and_external_workload_stop': True,
                    'cleanup_deadline_exceeded': timed_out,
                    'do_not_kill_holder_before_restoration': True})
                if timed_out:
                    self.result['error'] = self.result['error'] or 'restoration_deadline_exceeded_pins_retained'
                    W.atomic_json(self.root / 'failure-pins-retained.json', self.result)
                time.sleep(.5)
            self.result['external_agent_exit_and_inventory_restored'] = safe
            # Invoke Case.cleanup directly: Lease.supervise would require the
            # historical three-phase HTTP matrix, which is not this contract.
            errors = M.Case.cleanup(self)
            until = time.monotonic() + 5
            while time.monotonic() < until and set(M.bpf_ids()) != set(self.baseline_bpf):
                time.sleep(.1)
            self.result['original_host_bpf_inventory_restored'] = set(M.bpf_ids()) == set(self.baseline_bpf)
            self.result['original_tracefs_restored'] = M.tracefs() == self.baseline_tracefs
            if not self.result['original_host_bpf_inventory_restored'] or not self.result['original_tracefs_restored']:
                errors.append('Original BPF/tracefs did not restore after holder removal')
            current = M.run(['docker', 'ps', '-q', '--no-trunc'])
            self.result['preexisting_containers_still_running'] = (current.returncode == 0
                and self.baseline_containers <= set(current.stdout.split()))
            self.result.update(cleanup_errors=errors, released_by_coordinator=released,
                scope_proof_approved=self.approved, workload_complete=False)
            self.result['pass'] = bool(released and self.approved and not self.result['error'] and safe and not errors
                                       and self.result['preexisting_containers_still_running'])
            self.publish_status('complete' if self.result['pass'] else 'failed')
            W.atomic_json(self.root / 'result.json', self.result)
            print(json.dumps(self.result), flush=True)
        return 0 if self.result['pass'] else 1


def interrupted(*_):
    global CANCELLED
    CANCELLED = True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', nargs='?', default='plan', choices=('plan', 'prepare', 'register-agent', 'approve-agent', 'release'))
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--work', type=Path)
    parser.add_argument('--lease', type=Path)
    parser.add_argument('--workload-bin', type=Path)
    parser.add_argument('--image')
    parser.add_argument('--agent-id')
    parser.add_argument('--proof', type=Path)
    args = parser.parse_args(argv)
    if not args.execute or args.action == 'plan':
        print(json.dumps({'execute': False, 'starts_network': False, 'creates_resources': False,
            'scope_only': True, 'http_emitted': False, 'phase_matrix_supported': False,
            'holders': 2, 'holder_seconds': 240, 'port_for_agent_contract': 18080,
            'release_requires_agent_exit_bpf_tracefs_restore_and_external_users_removed': True}))
        return 0
    require(os.geteuid() == 0 and os.uname().machine == 'x86_64', 'Qualified Linux x86_64 root execution required')
    os.umask(0o077)
    if args.action == 'prepare':
        require(re.fullmatch('sha256:[0-9a-f]{64}', args.image or ''), 'Explicit cached immutable image required')
        W.IMAGE = M.IMAGE = args.image
        M.PURPOSE = PURPOSE
        image = M.run(['docker', 'image', 'inspect', args.image])
        require(image.returncode == 0 and json.loads(image.stdout)[0]['Id'] == args.image, 'Exact image is not cached')
        workload = None
        if args.workload_bin:
            require(args.workload_bin.is_absolute() and args.workload_bin == args.workload_bin.resolve()
                    and not any(c in str(args.workload_bin) for c in ',\r\n\0'), 'Canonical workload artifact required')
            workload = M.regular_executable(args.workload_bin)
        work = private(args.work, fresh=True)
        lock = (work / 'prepare.lock').open('a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        prior = M.run(['docker', 'ps', '-aq', '--filter', 'label=io.traflens.purpose=' + PURPOSE])
        require(prior.returncode == 0 and not prior.stdout.strip(), 'Earlier association holder resource remains')
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, interrupted)
        return AssociationLease(work, workload).supervise()
    require(args.lease is not None, 'Explicit --lease required')
    lease = private(args.lease)
    require(W.read_private(lease / 'lease.json').get('scope_only') is True, 'Not an association-only lease')
    request = {'action': args.action}
    if args.action == 'register-agent':
        request['agent_container_id'] = args.agent_id
    elif args.action == 'approve-agent':
        require(args.proof is not None, 'Explicit --proof required')
        request['proof'] = W.read_private(args.proof)
    return W.control(lease, request)


if __name__ == '__main__':
    raise SystemExit(main())
