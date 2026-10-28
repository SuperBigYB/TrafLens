"""Offline C compilation/wire/identity-boundary checks; never run DNS endpoints."""
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

SOURCE=Path(__file__).resolve().parents[1]/'ebpf-dns.c'
DNS=Path(__file__).resolve().parents[1]/'dns-traffic.py'
RUN='dns-'+'a'*24


class DNSFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('Linux gcc is required for the finite C fixture')
        cls.root=tempfile.TemporaryDirectory()
        cls.binary=Path(cls.root.name)/'ebpf-dns'
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(SOURCE),'-o',str(cls.binary)],
            check=True,capture_output=True,timeout=30)
        wrapper=Path(cls.root.name)/'offline.c'
        wrapper.write_text('''#define main original_dns_main
#include "ebpf-dns.c"
#undef main
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"output")||!strcmp(argv[1],"fresh")) {
        if(argc!=3)return 2;
        int fd=output_directory(argv[2]);if(fd<0)return 1;
        if(!strcmp(argv[1],"fresh")) {
            FILE *f=fresh_file(fd,"offline.json");if(!f){close(fd);return 1;}
            fputs("{\\"actual_offline_test\\":true}\\n",f);if(finish_file(f)){close(fd);return 1;}
        }
        close(fd);return 0;
    }
    unsigned char data[FRAME_CAP+1];
    if(!strcmp(argv[1],"sha")) {
        size_t n=fread(data,1,sizeof(data),stdin);char hash[65];sha256_hex(data,n,hash);puts(hash);return 0;
    }
    if(argc!=5)return 2;
    int index=atoi(argv[2]),response=atoi(argv[3]);
    struct config c={"client",argv[4],NULL,90,18080,false};
    if(!valid_run(c.run)||index<0||index>=3||(response!=0&&response!=1))return 2;
    if(!strcmp(argv[1],"frame")) {
        int n=frame_message(&c,index,response!=0,data);if(n<0)return 1;
        return fwrite(data,1,(size_t)n,stdout)==(size_t)n?0:1;
    }
    size_t n=fread(data,1,sizeof(data),stdin);
    return validate_frame(&c,index,response!=0,data,n)?1:0;
}
''',encoding='utf-8')
        cls.check=Path(cls.root.name)/'offline-check'
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror','-I',str(SOURCE.parent),str(wrapper),'-o',str(cls.check)],
            check=True,capture_output=True,timeout=30)
        spec=importlib.util.spec_from_file_location('independent_existing_dns',DNS)
        cls.dns=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.dns)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'root'):
            cls.root.cleanup()

    def frame(self,index,response):
        return subprocess.run([str(self.check),'frame',str(index),str(int(response)),RUN],
            check=True,capture_output=True,timeout=3).stdout

    def test_default_plan_has_no_files_or_network_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            result=subprocess.run([str(self.binary),'--output',str(Path(directory)/'unused')],cwd=directory,
                check=True,capture_output=True,text=True,timeout=3)
            plan=json.loads(result.stdout)
            self.assertFalse(plan['starts_network'])
            self.assertFalse(plan['reads_files'])
            self.assertFalse(plan['creates_files'])
            self.assertEqual(plan['max_connections'],3)
            self.assertEqual(plan['default_port'],18080)
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_invalid_execution_is_rejected_before_output_or_socket_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            for extra in [[],['--role','client'],['--role','other','--run',RUN],['--role','server','--run','dns-short'],
                ['--role','client','--run',RUN,'--port','18053'],['--role','client','--run',RUN,'--seconds','91']]:
                result=subprocess.run([str(self.binary),'--execute','--output',directory,*extra],
                    capture_output=True,timeout=3)
                self.assertNotEqual(result.returncode,0,extra)
                self.assertEqual(list(Path(directory).iterdir()),[])

    def test_three_queries_are_real_standard_small_tcp_framed_A_messages(self):
        for index,scenario in enumerate(('main','nxdomain','control')):
            frame=self.frame(index,False)
            self.assertLess(len(frame),512)
            self.assertEqual(struct.unpack_from('!H',frame)[0],len(frame)-2)
            parsed=self.dns.parse_query(frame[2:])
            self.assertEqual(parsed,{'id':0xb101+index,'name':scenario+'.'+RUN+'.traflens.invalid'})

    def test_positive_answers_independently_decode_name_address_ttl_and_flags(self):
        for index,address in [(0,'198.18.0.41'),(2,'198.18.0.42')]:
            frame=self.frame(index,True)
            self.assertEqual(struct.unpack_from('!H',frame)[0],len(frame)-2)
            value=self.dns.parse_response(frame[2:])
            self.assertEqual(value['address'],address)
            self.assertEqual(value['id'],0xb101+index)
            self.assertEqual(value['name'],value['answer_name'])
            self.assertEqual(value['ttl'],60)
            self.assertEqual(value['rcode'],0)

    def test_nxdomain_is_real_rcode3_without_fake_answer_or_extra_records(self):
        frame=self.frame(1,True)
        ident,flags,questions,answers,authorities,additional=struct.unpack_from('!6H',frame,2)
        self.assertEqual((ident,flags,questions,answers,authorities,additional),(0xb102,0x8183,1,0,0,0))
        name,end=self.dns.question(frame[2:])
        self.assertEqual(name,'nxdomain.'+RUN+'.traflens.invalid')
        self.assertEqual(end,len(frame)-2)

    def test_partial_frame_length_id_and_rcode_are_not_silently_accepted(self):
        frame=self.frame(1,True)
        mutations=[frame[:-1],b'\0\x01'+frame[2:],frame[:2]+b'\0\0'+frame[4:],frame[:4]+b'\x81\x80'+frame[6:],frame+b'\0']
        for data in mutations:
            result=subprocess.run([str(self.check),'validate','1','1',RUN],input=data,capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)

    def test_wire_sha256_matches_independent_standard_vectors(self):
        for data in [b'',b'abc',b'a'*55,b'a'*56,b'a'*64,self.frame(0,True)]:
            result=subprocess.run([str(self.check),'sha'],input=data,check=True,capture_output=True,timeout=3)
            self.assertEqual(result.stdout.decode().strip(),hashlib.sha256(data).hexdigest())

    def test_private_canonical_output_and_exclusive_evidence_files(self):
        with tempfile.TemporaryDirectory() as directory:
            parent=Path(directory)
            os.chmod(parent,0o700)
            subprocess.run([str(self.check),'output',directory],check=True,capture_output=True,timeout=3)
            subprocess.run([str(self.check),'fresh',directory],check=True,capture_output=True,timeout=3)
            evidence=parent/'offline.json'
            original=evidence.read_bytes()
            again=subprocess.run([str(self.check),'fresh',directory],capture_output=True,timeout=3)
            self.assertNotEqual(again.returncode,0)
            self.assertEqual(evidence.read_bytes(),original)
            self.assertEqual(evidence.stat().st_mode&0o777,0o600)
            os.chmod(parent,0o755)
            public=subprocess.run([str(self.check),'output',directory],capture_output=True,timeout=3)
            self.assertNotEqual(public.returncode,0)


if __name__=='__main__':
    unittest.main()
