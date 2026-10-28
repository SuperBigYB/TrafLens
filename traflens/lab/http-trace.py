#!/usr/bin/env python3
"""Finite real HTTP client -> frontend -> backend trace-context fixture; default plan only."""
import argparse
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import TCPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import socket
import time

TRACE = re.compile(r'^[0-9a-f]{32}$')


def trace_id(value):
    if not TRACE.fullmatch(value or '') or value == '0' * 32:
        raise ValueError('Nonzero lowercase32-hex Trace ID required')
    return value


def context(c, sequence, leg):
    trace = c.trace_id if sequence < c.count else c.other_trace_id
    span = format((0x1000 if leg == 'front' else 0x2000) + sequence + 1, '016x')
    return trace, span, '00-' + trace + '-' + span + '-01'


def resource(c, sequence, leg):
    return '/traflens-trace/' + c.marker + '/' + leg + '/' + str(sequence)


def validate(c):
    trace_id(c.trace_id)
    trace_id(c.other_trace_id)
    if c.trace_id == c.other_trace_id:
        raise ValueError('Unrelated Trace ID must differ')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,14}', c.interface or ''):
        raise ValueError('Explicit interface required')
    addresses = [ipaddress.IPv6Address(v) for v in (c.bind, c.peer)]
    if any(not v.is_link_local or v.scope_id for v in addresses) or addresses[0] == addresses[1]:
        raise ValueError('Distinct numeric link-local IPv6 addresses without zones required')
    if (not re.fullmatch(r'[a-z0-9-]{1,48}', c.marker or '') or not 1 <= c.count <= 20
            or not 5 <= c.seconds <= 90 or c.front_port == c.back_port
            or any(not 1024 <= p <= 65535 for p in (c.front_port, c.back_port))):
        raise ValueError('Fixture exceeds finite marker/count/port/time contract')
    path = c.output
    if (os.name != 'posix' or not path.is_absolute() or path != path.resolve() or path.exists()
            or path.parent.stat().st_uid != os.geteuid() or path.parent.stat().st_mode & 0o077):
        raise ValueError('New canonical output under an owned private POSIX directory required')


def outcome(c, sequence):
    if getattr(c, 'red_pattern', False) and sequence < c.count:
        kind = sequence % 3
        return (404, 0) if kind == 1 else (503, .25) if kind == 2 else (200, 0)
    return 200, 0


def exchange(c, sequence, leg):
    _, _, header = context(c, sequence, leg)
    port = c.front_port if leg == 'front' else c.back_port
    index = socket.if_nametoindex(c.interface)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    conn = http.client.HTTPConnection('traflens-trace.invalid', timeout=3)
    try:
        sock.settimeout(3)
        sock.bind((c.bind, 0, 0, index))
        sock.connect((c.peer, port, 0, index))
        conn.sock = sock
        conn.request('GET', resource(c, sequence, leg), headers={'traceparent': header, 'Connection': 'close'})
        response = conn.getresponse()
        raw = response.read(4097)
        if response.status != outcome(c, sequence)[0] or len(raw) > 4096:
            raise RuntimeError('HTTP response rejected or oversized')
        body = json.loads(raw)
        trace, span, _ = context(c, sequence, 'back')
        if body != {'trace_id': trace, 'span_id': span, 'sequence': sequence, 'backend': True}:
            raise RuntimeError('Actual backend context acknowledgement differs')
        return body
    finally:
        conn.close()
        sock.close()


def request_context(c, path, header, relay=exchange):
    prefix = '/traflens-trace/' + c.marker + '/' + c.mode + '/'
    raw = path.removeprefix(prefix)
    if not path.startswith(prefix) or not raw.isdecimal() or str(int(raw)) != raw:
        raise ValueError('Unexpected fixture path')
    sequence = int(raw)
    if not 0 <= sequence <= c.count:
        raise ValueError('Unexpected sequence')
    trace, span, expected = context(c, sequence, c.mode)
    if header != expected:
        raise ValueError('Received traceparent differs from expected wire context')
    if c.mode == 'front':
        # Independently send the same Trace ID with a distinct downstream wire
        # span. This is real HTTP propagation, never a synthetic database row.
        body = relay(c, sequence, 'back')
    else:
        body = {'trace_id': trace, 'span_id': span, 'sequence': sequence, 'backend': True}
    return {'sequence': sequence, 'trace_id': trace, 'span_id': span,
            'request_resource': path, 'traceparent': header}, body


def serve(c, report):
    class Server(HTTPServer):
        address_family = socket.AF_INET6
        allow_reuse_address = False

        def server_bind(self):
            TCPServer.server_bind(self)
            self.server_name='traflens-trace.invalid'
            self.server_port=self.server_address[1]

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(3)
            return connection, address

    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def log_message(self, *_args):
            pass

        def do_GET(self):
            try:
                if self.headers.get('Host') != 'traflens-trace.invalid' or self.headers.get('Content-Length', '0') != '0':
                    raise ValueError('Unexpected request headers')
                record, body = request_context(c, self.path, self.headers.get('traceparent'))
                if any(row['sequence'] == record['sequence'] for row in report['records']):
                    raise ValueError('Duplicate counted exchange')
                raw = json.dumps(body).encode()
                status, delay = outcome(c, record['sequence'])
                if delay:
                    time.sleep(delay)
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(raw)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(raw)
                self.wfile.flush()
                self.close_connection = True
                if getattr(c, 'red_pattern', False):
                    record['response_code'] = status
                report['records'].append(record)
            except Exception:
                report['rejected'] += 1
                self.close_connection = True
                raise

    port = c.front_port if c.mode == 'front' else c.back_port
    index = socket.if_nametoindex(c.interface)
    with Server((c.bind, port, 0, index), Handler) as server:
        server.timeout = .2
        print(json.dumps({'ready': True, 'role': c.mode}), flush=True)
        deadline = time.monotonic() + c.seconds
        while len(report['records']) < c.count + 1 and time.monotonic() < deadline:
            server.handle_request()
        if len(report['records']) != c.count + 1:
            raise RuntimeError('Finite fixture deadline exceeded')


def interrupted(_signal, _frame):
    raise RuntimeError('Fixture interrupted')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute', action='store_true')
    parser.add_argument('--red-pattern', action='store_true', help='Explicit deterministic 200/404/503 plus delayed503 scenario')
    parser.add_argument('--mode', choices=['front', 'back', 'client'], default='client')
    for key in ('interface', 'bind', 'peer', 'marker', 'trace-id', 'other-trace-id'):
        parser.add_argument('--' + key)
    parser.add_argument('--front-port', type=int, default=18080)
    parser.add_argument('--back-port', type=int, default=18081)
    parser.add_argument('--count', type=int, default=5)
    parser.add_argument('--seconds', type=int, default=60)
    parser.add_argument('--output', type=Path)
    c = parser.parse_args()
    if not c.execute:
        print(json.dumps({'execute': False, 'starts_network': False, 'maximum_primary_requests': 20,
                          'unrelated_trace_requests': 1, 'legs_per_request': 2}))
        return
    if not all([c.output, c.bind, c.peer]):
        parser.error('Explicit addresses and private output required')
    validate(c)
    os.umask(0o077)
    report = {'schema': 'traflens.http-trace-fixture.v1', 'mode': c.mode, 'pass': False,
              'records': [], 'rejected': 0, 'error': None}
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        if c.mode == 'client':
            for sequence in range(c.count + 1):
                body = exchange(c, sequence, 'front')
                report['records'].append(body)
        else:
            serve(c, report)
        report['pass'] = len(report['records']) == c.count + 1 and report['rejected'] == 0
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    finally:
        fd = os.open(c.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as output:
            json.dump(report, output, indent=2)
            output.write('\n')
    print(json.dumps({'pass': report['pass'], 'mode': c.mode, 'completed': len(report['records'])}))
    raise SystemExit(0 if report['pass'] else 1)


if __name__ == '__main__':
    main()
