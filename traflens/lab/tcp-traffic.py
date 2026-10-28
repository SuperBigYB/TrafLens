#!/usr/bin/env python3
"""Three bounded real owned TCP connections; the default only prints a plan.

Explicit execution uses only 127.77.0.1 -> 127.77.0.2: a normal real HTTP/FIN
exchange, an actual abortive server close, and an actual refused connect to an
exclusively bound non-listening socket. No collector, route or interface changes.
Socket outcomes are application evidence, not assertions about stored L4 rows.
"""
import argparse
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import struct
import sys
import threading
import time

CLIENT = '127.77.0.1'
SERVER = '127.77.0.2'
MAX_BYTES = 4096


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def save(path, document):
    with path.open('x', encoding='utf-8') as stream:
        os.chmod(path, 0o600)
        json.dump(document, stream, sort_keys=True)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def identity():
    return {'pid': os.getpid(), 'tid': threading.get_native_id(),
            'start_ticks': Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19],
            'netns': os.readlink('/proc/self/ns/net'), 'pidns': os.readlink('/proc/self/ns/pid')}


def endpoint(value):
    return {'ip': value[0], 'port': value[1]}


def normal_messages(run, port, server_identity):
    resource = '/traflens-tcp/'+run+'/normal'
    request = ('GET '+resource+' HTTP/1.1\r\nHost: '+SERVER+':'+str(port)
               +'\r\nConnection: close\r\n\r\n').encode('ascii')
    body = json.dumps({'run': run, 'scenario': 'normal', 'pid': server_identity['pid'],
                       'tid': server_identity['tid']}, sort_keys=True, separators=(',', ':')).encode('ascii')
    response = (b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: '
                +str(len(body)).encode()+b'\r\nConnection: close\r\n\r\n'+body)
    require(len(request) <= MAX_BYTES and len(response) <= MAX_BYTES, 'Finite HTTP wire budget exceeded')
    return request, response


def validate(args):
    require(re.fullmatch(r'tcp-[0-9a-f]{24}', args.run or ''), 'Explicit tcp-24lowerhex run required')
    require(5 <= args.seconds <= 90, 'Finite seconds must be5..90')
    ports = [args.normal_port, args.reset_port, args.refused_port]
    require(all(1024 <= p <= 65535 for p in ports) and len(set(ports)) == 3, 'Three distinct unprivileged owned ports required')
    output = args.output
    require(output and output.is_absolute() and output == output.resolve() and not output.exists()
            and output.parent.is_dir() and output.parent.stat().st_uid == os.geteuid()
            and not output.parent.stat().st_mode & 0o077, 'Fresh canonical output under owned private parent required')


class Workload:
    def __init__(self, args):
        self.args = args
        self.deadline = time.monotonic()+args.seconds-2  # Reserve bounded cleanup inside the requested lifetime.
        self.cancelled = threading.Event()
        self.lock = threading.Lock()
        self.sockets = []
        self.threads = []
        self.events = []
        self.errors = []
        self.completed = {}
        self.server_identities = {}
        self.listeners = {}
        self.log = (args.output/'events.jsonl').open('x', encoding='utf-8')

    def remaining(self):
        require(not self.cancelled.is_set(), 'Owned TCP workload cancelled')
        remaining = self.deadline-time.monotonic()
        require(remaining > 0, 'Finite TCP workload deadline expired')
        return remaining

    def record(self, scenario, operation, sock=None, data=None, started=None, **fields):
        event = {'scenario': scenario, 'operation': operation, 'run': self.args.run, **identity(),
                 'finished_unix_ns': time.time_ns(), 'finished_monotonic_ns': time.monotonic_ns()}
        if started:
            event.update(started_unix_ns=started[0], started_monotonic_ns=started[1])
        if sock:
            event.update(fd=sock.fileno(), local=endpoint(sock.getsockname()))
            try:
                event.update(peer=endpoint(sock.getpeername()), peer_is_actual=True)
            except OSError:
                event.update(peer=None, peer_is_actual=False)
        if data is not None:
            require(len(data) <= MAX_BYTES, 'Actual wire evidence exceeds byte budget')
            event.update(bytes=len(data), sha256=sha(data), wire_ascii=data.decode('ascii'))
        event.update(fields)
        with self.lock:
            require(len(self.events) < 64, 'Finite event budget exceeded')
            event['sequence'] = len(self.events)+1
            self.events.append(event)
            self.log.write(json.dumps(event, sort_keys=True)+'\n')
            self.log.flush()
        return event

    def own(self, sock):
        sock.settimeout(min(.5, self.remaining()))
        with self.lock:
            self.sockets.append(sock)
        return sock

    def send(self, sock, scenario, data):
        require(0 < len(data) <= MAX_BYTES, 'Finite actual send bytes required')
        started = time.time_ns(), time.monotonic_ns()
        sent, calls = 0, 0
        while sent < len(data):
            sock.settimeout(min(.5, self.remaining()))
            try:
                count = sock.send(data[sent:])
            except socket.timeout:
                continue
            require(count > 0, 'Actual socket send returned zero')
            sent += count
            calls += 1
        self.record(scenario, 'send', sock, data, started, syscalls=calls)

    def receive(self, sock, scenario, expected=None, eof=False):
        started = time.time_ns(), time.monotonic_ns()
        data, calls = bytearray(), 0
        while True:
            sock.settimeout(min(.5, self.remaining()))
            try:
                value = sock.recv(min(1024, MAX_BYTES+1-len(data)))
            except socket.timeout:
                continue
            calls += 1
            if not value:
                require(eof, 'Unexpected socket EOF before expected bytes')
                break
            data.extend(value)
            require(len(data) <= MAX_BYTES, 'Actual received bytes exceed finite budget')
            if expected is not None and not eof and len(data) >= len(expected):
                break
        if expected is not None:
            require(bytes(data) == expected, 'Actual received bytes differ from peer wire expectation')
        self.record(scenario, 'recv', sock, bytes(data), started, syscalls=calls, eof_observed=eof)
        return bytes(data)

    def close(self, sock, scenario, abortive=False):
        fields = {'actual_closed_fd': sock.fileno()}
        if abortive:
            linger = struct.pack('ii', 1, 0)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
            actual = struct.unpack('ii', sock.getsockopt(socket.SOL_SOCKET, socket.SO_LINGER, len(linger)))
            require(actual == (1, 0), 'Actual SO_LINGER is not the requested abortive close')
            fields.update(linger_onoff=actual[0], linger_seconds=actual[1])
        self.record(scenario, 'close_intent', sock, abortive=abortive, **fields)
        started = time.time_ns(), time.monotonic_ns()
        sock.close()
        self.record(scenario, 'close_return', started=started, abortive=abortive, errno=0, **fields)

    def shutdown_write(self, sock, scenario):
        started = time.time_ns(), time.monotonic_ns()
        sock.shutdown(socket.SHUT_WR)
        self.record(scenario, 'shutdown_write', sock, started=started, errno=0)

    def listener(self, scenario, port, listening):
        sock = self.own(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        # No reuse flags: an occupied port must fail rather than joining it.
        sock.bind((SERVER, port))
        if listening:
            sock.listen(1)
        accepting = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)
        require(accepting == int(listening), 'Actual SO_ACCEPTCONN differs from owned endpoint purpose')
        self.record(scenario, 'bound_endpoint', sock, accepting=bool(accepting), exclusive_bind=True,
                    requested_target={'ip': SERVER, 'port': port})
        self.listeners[scenario] = sock
        return sock

    def server(self, scenario):
        try:
            self.server_identities[scenario] = identity()
            listener = self.listeners[scenario]
            while True:
                self.remaining()
                try:
                    accepted, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            accepted = self.own(accepted)
            self.record(scenario, 'accept', accepted)
            if scenario == 'normal':
                request, response = normal_messages(self.args.run, self.args.normal_port, self.server_identities[scenario])
                self.receive(accepted, scenario, request, eof=True)
                self.send(accepted, scenario, response)
                self.shutdown_write(accepted, scenario)
                self.close(accepted, scenario)
            else:
                request = ('traflens-tcp/'+self.args.run+'/reset/request\n').encode('ascii')
                self.receive(accepted, scenario, request)
                self.close(accepted, scenario, abortive=True)
            self.completed['server_'+scenario] = True
        except Exception as error:
            with self.lock:
                self.errors.append({'scenario': scenario, 'error': type(error).__name__+': '+str(error)})
            self.cancelled.set()

    def connection(self, scenario, port):
        sock = self.own(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        sock.bind((CLIENT, 0))
        started = time.time_ns(), time.monotonic_ns()
        try:
            sock.settimeout(min(2, self.remaining()))
            sock.connect((SERVER, port))
        except OSError as error:
            self.record(scenario, 'connect', sock, started=started, errno=error.errno,
                        errno_name=errno.errorcode.get(error.errno, 'UNKNOWN'),
                        requested_target={'ip': SERVER, 'port': port}, connected=False)
            require(scenario == 'refused' and error.errno == errno.ECONNREFUSED, 'Expected real closed-port ECONNREFUSED')
            self.completed['client_refused'] = True
            self.close(sock, scenario)
            return None
        self.record(scenario, 'connect', sock, started=started, errno=0, connected=True,
                    requested_target={'ip': SERVER, 'port': port})
        require(scenario != 'refused', 'Refused-port guard unexpectedly accepted a connection')
        return sock

    def run(self):
        self.listener('normal', self.args.normal_port, True)
        self.listener('reset', self.args.reset_port, True)
        self.listener('refused', self.args.refused_port, False)
        for scenario in ('normal', 'reset'):
            thread = threading.Thread(target=self.server, args=(scenario,), name='traflens-tcp-'+scenario)
            self.threads.append(thread)
            thread.start()
        save(self.args.output/'ready.json', {'run': self.args.run, 'endpoints_prebound': True,
            'normal_listening': True, 'reset_listening': True, 'refused_bound_not_listening': True,
            'server_ip': SERVER, 'client_ip': CLIENT, **identity()})
        normal = self.connection('normal', self.args.normal_port)
        request, _ = normal_messages(self.args.run, self.args.normal_port, identity())
        self.send(normal, 'normal', request)
        self.shutdown_write(normal, 'normal')
        response = self.receive(normal, 'normal', eof=True)
        _, expected_response = normal_messages(self.args.run, self.args.normal_port, self.server_identities['normal'])
        require(response == expected_response, 'Actual HTTP200 headers/body differ from actual server bytes')
        self.close(normal, 'normal')
        self.completed['client_normal'] = True
        reset = self.connection('reset', self.args.reset_port)
        self.send(reset, 'reset', ('traflens-tcp/'+self.args.run+'/reset/request\n').encode('ascii'))
        started = time.time_ns(), time.monotonic_ns()
        while True:
            reset.settimeout(min(.5, self.remaining()))
            try:
                unexpected = reset.recv(1024)
            except socket.timeout:
                continue
            except OSError as error:
                self.record('reset', 'recv_error', reset, started=started, errno=error.errno,
                            errno_name=errno.errorcode.get(error.errno, 'UNKNOWN'))
                require(error.errno == errno.ECONNRESET, 'Expected actual abortive-close ECONNRESET')
                break
            raise ValueError('Reset scenario returned data/EOF instead of actual ECONNRESET: '+str(len(unexpected)))
        self.close(reset, 'reset')
        self.completed['client_reset'] = True
        self.connection('refused', self.args.refused_port)
        for thread in self.threads:
            thread.join(timeout=self.remaining())
            require(not thread.is_alive(), 'Owned server did not complete within finite deadline')
        require(not self.errors and all(self.completed.get(key) is True for key in
                ('server_normal', 'server_reset', 'client_normal', 'client_reset', 'client_refused')),
                'Incomplete actual TCP outcomes')

    def cleanup(self):
        self.cancelled.set()
        for sock in self.sockets:
            try:
                sock.close()
            except OSError:
                pass
        for thread in self.threads:
            thread.join(timeout=1)
        require(not any(thread.is_alive() for thread in self.threads), 'Owned socket thread failed to stop')
        self.log.flush()
        os.fsync(self.log.fileno())
        self.log.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--run')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--seconds', type=int, default=15)
    parser.add_argument('--normal-port', type=int, default=18081)
    parser.add_argument('--reset-port', type=int, default=18082)
    parser.add_argument('--refused-port', type=int, default=18083)
    args = parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'execute': False, 'starts_network': False, 'creates_files': False, 'reads_files': False,
            'client': CLIENT, 'server': SERVER, 'actual_connections': 3, 'max_seconds': 90,
            'scenarios': ['normal_http_fin', 'actual_server_rst', 'actual_connection_refused'],
            'changes_interfaces_routes_or_collector': False}))
        return 0
    try:
        validate(args)
    except (ValueError, OSError) as error:
        parser.error(str(error))
    os.umask(0o077)
    args.output.mkdir(mode=0o700)
    started = time.time_ns(), time.monotonic_ns()
    process = identity()
    save(args.output/'process.json', dict(process, run=args.run, source='actual Python stdlib/Linux TCP sockets', sdk=False))
    workload = Workload(args)
    receipt = {'run': args.run, 'pass': False, 'source': 'actual Python stdlib/Linux TCP sockets',
        'started_unix_ns': started[0], 'started_monotonic_ns': started[1], 'expected_connections': 3,
        'collector_started': False, 'stored_l4_verified': False, 'synthetic_tcp_packets': False, **process}
    def interrupted(*_):
        workload.cancelled.set()
        raise InterruptedError('Finite owned TCP workload interrupted')
    previous = {kind: signal.signal(kind, interrupted) for kind in (signal.SIGINT, signal.SIGTERM)}
    try:
        workload.run()
        receipt['pass'] = True
    except Exception as error:
        receipt['error'] = type(error).__name__+': '+str(error)
    finally:
        for kind, handler in previous.items():
            signal.signal(kind, handler)
        try:
            workload.cleanup()
        except Exception as error:
            receipt['pass'] = False
            receipt['cleanup_error'] = type(error).__name__+': '+str(error)
        receipt.update(finished_unix_ns=time.time_ns(), finished_monotonic_ns=time.monotonic_ns(),
            completed=workload.completed, server_identities=workload.server_identities, thread_errors=workload.errors,
            events=len(workload.events), events_sha256=sha((args.output/'events.jsonl').read_bytes()),
            http_resource='/traflens-tcp/'+args.run+'/normal', owned_sockets_closed=all(s.fileno() == -1 for s in workload.sockets),
            owned_threads_exited=not any(t.is_alive() for t in workload.threads))
        save(args.output/'receipt.json', receipt)
    print(json.dumps({'pass': receipt['pass'], 'run': args.run, 'events': receipt['events'],
                      'actual_outcomes': workload.completed, 'stored_l4_verified': False,
                      'error': receipt.get('error'), 'cleanup_error': receipt.get('cleanup_error')}))
    return 0 if receipt['pass'] else 1


if __name__ == '__main__':
    sys.exit(main())
