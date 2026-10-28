"""Offline TCP workload contract tests; never open a real socket or execute it."""
from contextlib import redirect_stderr, redirect_stdout
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1]/'tcp-traffic.py'
if not SCRIPT.is_file():
    SCRIPT = Path(__file__).with_name('tcp-traffic.py')
spec = importlib.util.spec_from_file_location('finite_tcp_traffic', SCRIPT)
t = importlib.util.module_from_spec(spec)
spec.loader.exec_module(t)
RUN = 'tcp-'+'a'*24


def args(output_dir, **changes):
    value = SimpleNamespace(run=RUN, output=Path(output_dir), seconds=15,
        normal_port=18081, reset_port=18082, refused_port=18083)
    for key, item in changes.items():
        setattr(value,key,item)
    return value


class FakeSocket:
    """No system sockets: only drives error/receipt code under explicit mocks."""
    def __init__(self, error=None, received=()):
        self.error,self.received = error,list(received)
        self.fd=10
        self.bound=None
        self.timeout=None

    def settimeout(self,value):
        self.timeout=value

    def bind(self,value):
        self.bound=value

    def connect(self,value):
        if self.error is not None:
            raise OSError(self.error,errno.errorcode[self.error])

    def getsockname(self):
        return t.CLIENT,34567

    def getpeername(self):
        if self.error is not None:
            raise OSError(errno.ENOTCONN,'not connected')
        return t.SERVER,18081

    def fileno(self):
        return self.fd

    def close(self):
        self.fd=-1

    def recv(self,_cap):
        return self.received.pop(0)


class TCPFixtureTests(unittest.TestCase):
    def test_default_plan_never_reads_process_files_opens_network_or_creates_output(self):
        output=io.StringIO()
        with mock.patch.object(t.socket,'socket',side_effect=AssertionError('network')), \
             mock.patch.object(t,'identity',side_effect=AssertionError('process read')), \
             mock.patch.object(t,'save',side_effect=AssertionError('file write')), redirect_stdout(output):
            self.assertEqual(t.main(['--output','/missing/unused']),0)
        plan=json.loads(output.getvalue())
        self.assertFalse(plan['starts_network'])
        self.assertFalse(plan['reads_files'])
        self.assertFalse(plan['creates_files'])
        self.assertEqual(plan['actual_connections'],3)

    def test_input_scope_and_private_fresh_output_are_required_before_network(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory)
            os.chmod(parent,0o700)
            valid=args(parent/'fresh')
            t.validate(valid)
            for changes in [dict(run='wrong'),dict(seconds=4),dict(seconds=91),dict(normal_port=80),
                            dict(reset_port=18081),dict(output=parent),dict(output=Path('relative'))]:
                with self.subTest(changes=changes),self.assertRaises(ValueError):
                    t.validate(args(parent/'fresh',**changes))
            os.chmod(parent,0o755)
            with self.assertRaises(ValueError):
                t.validate(valid)

    def test_normal_exchange_is_complete_http_with_exact_content_length(self):
        request,response=t.normal_messages(RUN,18081,{'pid':123,'tid':456})
        self.assertTrue(request.startswith(('GET /traflens-tcp/'+RUN+'/normal HTTP/1.1\r\n').encode()))
        self.assertIn(b'Host: 127.77.0.2:18081\r\n',request)
        header,body=response.split(b'\r\n\r\n',1)
        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertIn(('Content-Length: '+str(len(body))).encode(),header.split(b'\r\n'))
        self.assertEqual(json.loads(body),{'run':RUN,'scenario':'normal','pid':123,'tid':456})
        self.assertNotIn(b'traceparent',request.lower())

    def test_all_three_ports_are_prebound_before_any_thread_or_connect(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=t.Workload(args(directory))
            try:
                with mock.patch.object(worker,'listener',side_effect=[None,None,OSError(errno.EADDRINUSE,'occupied')]), \
                     mock.patch.object(worker,'connection',side_effect=AssertionError('connect before preflight')) as connect, \
                     mock.patch.object(t.threading,'Thread',side_effect=AssertionError('thread before preflight')):
                    with self.assertRaises(OSError):
                        worker.run()
                    connect.assert_not_called()
            finally:
                worker.cleanup()

    def test_refused_connect_records_real_error_contract_without_inventing_peer(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=t.Workload(args(directory))
            try:
                with mock.patch.object(t.socket,'socket',return_value=FakeSocket(errno.ECONNREFUSED)):
                    self.assertIsNone(worker.connection('refused',18083))
                event=worker.events[0]
                self.assertEqual(event['errno'],errno.ECONNREFUSED)
                self.assertFalse(event['peer_is_actual'])
                self.assertIsNone(event['peer'])
                self.assertEqual(event['requested_target'],{'ip':t.SERVER,'port':18083})
                self.assertTrue(worker.completed['client_refused'])
            finally:
                worker.cleanup()

    def test_wrong_connect_error_is_failure_and_does_not_become_refused_success(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=t.Workload(args(directory))
            try:
                with mock.patch.object(t.socket,'socket',return_value=FakeSocket(errno.ETIMEDOUT)):
                    with self.assertRaises(ValueError):
                        worker.connection('refused',18083)
                self.assertNotIn('client_refused',worker.completed)
                self.assertEqual(worker.events[0]['errno'],errno.ETIMEDOUT)
            finally:
                worker.cleanup()

    def test_peer_bytes_must_match_and_eof_is_explicit_not_empty_data_fabrication(self):
        with tempfile.TemporaryDirectory() as directory:
            worker=t.Workload(args(directory))
            try:
                fake=worker.own(FakeSocket(received=[b'ab',b'cd',b'']))
                self.assertEqual(worker.receive(fake,'normal',b'abcd',eof=True),b'abcd')
                event=worker.events[0]
                self.assertTrue(event['eof_observed'])
                self.assertEqual(event['bytes'],4)
                self.assertEqual(event['sha256'],hashlib.sha256(b'abcd').hexdigest())
                mismatch=worker.own(FakeSocket(received=[b'wrong',b'']))
                with self.assertRaises(ValueError):
                    worker.receive(mismatch,'normal',b'expected',eof=True)
            finally:
                worker.cleanup()


if __name__=='__main__':
    unittest.main()
