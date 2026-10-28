"""Offline UDP DNS C compilation, independent wire decoding and safe-entry checks."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'ebpf-dns-udp.c'
DNS = Path(__file__).resolve().parents[1] / 'dns-traffic.py'
RUN = 'dns-' + 'a' * 24


class UDPDNSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('Linux gcc is required for the finite C fixture')
        cls.root = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.root.name) / 'ebpf-dns-udp'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', str(SOURCE), '-o', str(cls.binary)],
                       check=True, capture_output=True, timeout=30)
        wrapper = Path(cls.root.name) / 'offline.c'
        wrapper.write_text(r'''#define main original_udp_dns_main
#include "ebpf-dns-udp.c"
#undef main
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"output")||!strcmp(argv[1],"fresh")) {
        if(argc!=3)return 2;
        int fd=output_directory(argv[2]);if(fd<0)return 1;
        if(!strcmp(argv[1],"fresh")) {
            FILE *f=fresh_file(fd,"offline.json");if(!f){close(fd);return 1;}
            fputs("{\"actual_offline_test\":true}\n",f);if(finish_file(f)){close(fd);return 1;}
        }
        close(fd);return 0;
    }
    if(!strcmp(argv[1],"identity")) {
        struct config c={"client","dns-aaaaaaaaaaaaaaaaaaaaaaaa",NULL,90,18080,false};
        if(identity())return 1;
        fputc('{',stdout);emit_identity(stdout,&c);puts("}");return 0;
    }
    unsigned char data[FRAME_CAP+1];
    if(!strcmp(argv[1],"sha")) {
        size_t n=fread(data,1,sizeof(data),stdin);char hash[65];sha256_hex(data,n,hash);puts(hash);return 0;
    }
    if(argc!=5)return 2;
    int index=atoi(argv[2]),response=atoi(argv[3]);
    struct config c={"client",argv[4],NULL,90,18080,false};
    if(!valid_run(c.run)||index<0||index>=3||(response!=0&&response!=1))return 2;
    if(!strcmp(argv[1],"message")) {
        int n=frame_message(&c,index,response!=0,data);if(n<0)return 1;
        return fwrite(data,1,(size_t)n,stdout)==(size_t)n?0:1;
    }
    size_t n=fread(data,1,sizeof(data),stdin);
    return validate_frame(&c,index,response!=0,data,n)?1:0;
}
''', encoding='utf-8')
        cls.check = Path(cls.root.name) / 'offline-check'
        subprocess.run(['gcc', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-I', str(SOURCE.parent),
                        str(wrapper), '-o', str(cls.check)], check=True, capture_output=True, timeout=30)
        spec = importlib.util.spec_from_file_location('independent_udp_fixture_dns', DNS)
        cls.dns = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.dns)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'root'):
            cls.root.cleanup()

    def message(self, index, response):
        return subprocess.run([str(self.check), 'message', str(index), str(int(response)), RUN],
                              check=True, capture_output=True, timeout=3).stdout

    def test_default_plan_does_not_open_endpoints_or_create_files(self):
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([str(self.binary), '--output', str(Path(directory) / 'unused')], cwd=directory,
                                    check=True, capture_output=True, text=True, timeout=3)
            plan = json.loads(result.stdout)
            self.assertFalse(plan['starts_network'])
            self.assertFalse(plan['reads_files'])
            self.assertFalse(plan['creates_files'])
            self.assertEqual(plan['max_queries'], 3)
            self.assertEqual((plan['client_udp_sockets'], plan['server_udp_sockets']), (1, 1))
            self.assertEqual((plan['client_bound_udp_sockets'], plan['server_bound_udp_sockets']), (1, 1))
            self.assertEqual((plan['client_connected_udp_sockets'], plan['server_connected_udp_sockets']), (1, 0))
            self.assertTrue(plan['single_peer_only'])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_invalid_execution_fails_before_identity_output_or_socket_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            for extra in [[], ['--role', 'client'], ['--role', 'other', '--run', RUN],
                          ['--role', 'server', '--run', 'dns-short'],
                          ['--role', 'client', '--run', RUN, '--port', '53'],
                          ['--role', 'client', '--run', RUN, '--seconds', '91'],
                          ['--role', 'client', '--run', RUN, '--seconds', '4']]:
                result = subprocess.run([str(self.binary), '--execute', '--output', directory, *extra],
                                        capture_output=True, timeout=3)
                self.assertNotEqual(result.returncode, 0, extra)
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_three_standard_A_queries_have_unique_TXID_and_no_TCP_prefix(self):
        values = []
        for index, scenario in enumerate(('main', 'nxdomain', 'control')):
            message = self.message(index, False)
            self.assertLessEqual(len(message), 512)
            parsed = self.dns.parse_query(message)
            self.assertEqual(parsed, {'id': 0xb101 + index, 'name': scenario + '.' + RUN + '.traflens.invalid'})
            self.assertNotEqual(struct.unpack_from('!H', message)[0], len(message) - 2)
            values.append(parsed['id'])
        self.assertEqual(len(set(values)), 3)

    def test_success_answers_independently_decode_exact_record_and_TTL(self):
        for index, address in [(0, '198.18.0.41'), (2, '198.18.0.42')]:
            value = self.dns.parse_response(self.message(index, True))
            self.assertEqual(value['address'], address)
            self.assertEqual(value['id'], 0xb101 + index)
            self.assertEqual(value['name'], value['answer_name'])
            self.assertEqual((value['ttl'], value['rcode']), (60, 0))

    def test_NXDOMAIN_retains_actual_rcode3_and_no_synthetic_answer(self):
        message = self.message(1, True)
        self.assertEqual(struct.unpack_from('!6H', message), (0xb102, 0x8183, 1, 0, 0, 0))
        name, end = self.dns.question(message)
        self.assertEqual(name, 'nxdomain.' + RUN + '.traflens.invalid')
        self.assertEqual(end, len(message))

    def test_partial_oversized_framed_or_mutated_messages_are_rejected(self):
        message = self.message(1, True)
        mutations = [message[:-1], struct.pack('!H', len(message)) + message,
                     b'\0\0' + message[2:], message[:2] + b'\x81\x80' + message[4:],
                     message + b'\0', b'x' * 513]
        for data in mutations:
            result = subprocess.run([str(self.check), 'validate', '1', '1', RUN], input=data,
                                    capture_output=True, timeout=3)
            self.assertNotEqual(result.returncode, 0)

    def test_actual_self_executable_hash_and_namespace_identity_are_recorded(self):
        result = subprocess.run([str(self.check), 'identity'], check=True, capture_output=True, text=True, timeout=3)
        identity = json.loads(result.stdout)
        self.assertEqual(identity['pid'], identity['tid'])
        self.assertGreater(int(identity['start_ticks']), 0)
        self.assertRegex(identity['netns'], r'^net:\[[1-9][0-9]*\]$')
        self.assertRegex(identity['pidns'], r'^pid:\[[1-9][0-9]*\]$')
        self.assertTrue(identity['comm'])
        self.assertEqual(identity['executable'], str(self.check))
        self.assertEqual(identity['executable_sha256'], hashlib.sha256(self.check.read_bytes()).hexdigest())

    def test_sha256_matches_independent_standard_vectors(self):
        for data in [b'', b'abc', b'a' * 55, b'a' * 56, b'a' * 64, self.message(0, True)]:
            result = subprocess.run([str(self.check), 'sha'], input=data, check=True, capture_output=True, timeout=3)
            self.assertEqual(result.stdout.decode().strip(), hashlib.sha256(data).hexdigest())

    def test_private_canonical_output_and_evidence_are_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            os.chmod(parent, 0o700)
            subprocess.run([str(self.check), 'fresh', directory], check=True, capture_output=True, timeout=3)
            path = parent / 'offline.json'
            initial = path.read_bytes()
            again = subprocess.run([str(self.check), 'fresh', directory], capture_output=True, timeout=3)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(path.read_bytes(), initial)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            alias = parent / 'alias'
            alias.symlink_to(parent, target_is_directory=True)
            symbolic = subprocess.run([str(self.check), 'output', str(alias)], capture_output=True, timeout=3)
            self.assertNotEqual(symbolic.returncode, 0)
            os.chmod(parent, 0o755)
            public = subprocess.run([str(self.check), 'output', directory], capture_output=True, timeout=3)
            self.assertNotEqual(public.returncode, 0)


if __name__ == '__main__':
    unittest.main()
