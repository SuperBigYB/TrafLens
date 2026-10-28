"""Offline compilation/parser/hash gates; never execute the HTTP workload."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'no-header-http.c'


class NoHeaderHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('Linux gcc is required for this finite C fixture')
        cls.root = tempfile.TemporaryDirectory()
        root = Path(cls.root.name)
        cls.binary = root / 'no-header-http'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(SOURCE), '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)
        wrapper = root / 'offline-check.c'
        wrapper.write_text('''#define main original_no_header_main
#include "no-header-http.c"
#undef main
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"output")) {
        if(argc!=3)return 2;
        int fd=output_directory(argv[2]);if(fd<0)return 1;close(fd);return 0;
    }
    unsigned char bytes[MESSAGE_CAP+1];size_t n=fread(bytes,1,MESSAGE_CAP+1,stdin);
    if(n>MESSAGE_CAP)return 2;
    char hash[65];sha256_hex(bytes,n,hash);
    if(!strcmp(argv[1],"sha")){printf("%s\\n",hash);return 0;}
    struct header h;int rc=parse_http(bytes,n,!strcmp(argv[1],"response"),&h);
    printf("{\\"status\\":%d,\\"header_bytes\\":%zu,\\"body_bytes\\":%zu}\\n",rc,h.length,h.body_length);
    return 0;
}
''', encoding='utf-8')
        cls.check = root / 'offline-check'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(SOURCE.parent),
                        str(wrapper), '-o', str(cls.check)], check=True, capture_output=True, timeout=30)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'root'):
            cls.root.cleanup()

    def test_default_plan_writes_nothing_and_does_not_start_network(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run([str(self.binary), '--output', str(Path(root) / 'unused')], cwd=root,
                                    check=True, text=True, capture_output=True, timeout=3)
            plan = json.loads(result.stdout)
            self.assertFalse(plan['execute'])
            self.assertFalse(plan['starts_network'])
            self.assertFalse(plan['creates_files'])
            self.assertFalse(plan['sdk'])
            self.assertFalse(plan['tracing_headers'])
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_invalid_execution_rejected_before_network_or_files(self):
        with tempfile.TemporaryDirectory() as root:
            token = 'nh-' + 'a' * 24
            for args in [[], ['--role', 'frontend'], ['--role', 'other', '--run', token],
                         ['--role', 'generate', '--run', 'bad'],
                         ['--role', 'generate', '--run', token, '--seconds', '91'],
                         ['--role', 'generate', '--run', token, '--requests', '5']]:
                result = subprocess.run([str(self.binary), '--execute', '--output', root, *args],
                                        text=True, capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0, args)
                self.assertEqual(list(Path(root).iterdir()), [])

    def test_sha256_matches_independent_standard_vectors(self):
        for data in [b'', b'abc', b'a' * 55, b'a' * 56, b'a' * 64, b'a' * 10000]:
            result = subprocess.run([str(self.check), 'sha'], input=data, check=True, capture_output=True, timeout=3)
            self.assertEqual(result.stdout.decode().strip(), hashlib.sha256(data).hexdigest())

    def parse(self, data, mode='request'):
        result = subprocess.run([str(self.check), mode], input=data, check=True, capture_output=True, timeout=3)
        return json.loads(result.stdout)

    def test_actual_whitelist_forbids_trace_and_all_custom_headers(self):
        request = b'GET /unit HTTP/1.1\r\nHost: 127.0.0.2:18080\r\nConnection: close\r\n\r\n'
        self.assertEqual(self.parse(request)['status'], 0)
        for header in [b'traceparent', b'TRACESTATE', b'baggage', b'b3', b'X-B3-TraceId',
                       b'X-Request-ID', b'x-requestid', b'X-Custom-Correlation', b'User-Agent']:
            modified = request[:-2] + header + b': forbidden\r\n\r\n'
            self.assertLess(self.parse(modified)['status'], 0, header)
        duplicate = request[:-2] + b'Host: 127.0.0.3:18080\r\n\r\n'
        self.assertLess(self.parse(duplicate)['status'], 0)

    def test_partial_body_extra_bytes_and_response_headers_are_checked(self):
        header = b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n'
        complete = self.parse(header + b'{}', 'response')
        self.assertEqual(complete['status'], 0)
        self.assertEqual(complete['header_bytes'], len(header))
        self.assertEqual(complete['body_bytes'], 2)
        self.assertEqual(self.parse(header + b'{', 'response')['status'], 1)
        self.assertLess(self.parse(header + b'{}x', 'response')['status'], 0)
        self.assertLess(self.parse(header[:-2] + b'traceparent: disallowed\r\n\r\n{}', 'response')['status'], 0)

    def test_existing_output_must_be_private_owned_and_canonical(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'private'
            path.mkdir(mode=0o700)
            result = subprocess.run([str(self.check), 'output', str(path)], capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 0)
            path.chmod(0o755)
            self.assertNotEqual(subprocess.run([str(self.check), 'output', str(path)], capture_output=True, timeout=3).returncode, 0)
            path.chmod(0o700)
            alias = Path(root) / 'alias'
            os.symlink(path, alias)
            self.assertNotEqual(subprocess.run([str(self.check), 'output', str(alias)], capture_output=True, timeout=3).returncode, 0)


if __name__ == '__main__':
    unittest.main()
