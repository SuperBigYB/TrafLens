"""Offline classic MySQL codec/hash/boundary checks; never execute endpoints."""
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

SOURCE=Path(__file__).resolve().parents[1]/'ebpf-mysql.c'
PREVIOUS=Path(__file__).resolve().parents[1]/'mysql-traffic.py'
RUN='my-'+'a'*24


def packets(data):
    result=[]
    while data:
        if len(data)<4:
            raise ValueError('incomplete classic packet header')
        n=int.from_bytes(data[:3],'little')
        if not 0<n<10000 or len(data)<4+n:
            raise ValueError('incomplete/excessive classic packet payload')
        result.append((data[3],data[4:4+n]))
        data=data[4+n:]
    return result


class MySQLFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('gcc'):
            raise unittest.SkipTest('Linux gcc required')
        cls.root=tempfile.TemporaryDirectory()
        cls.binary=Path(cls.root.name)/'ebpf-mysql'
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',str(SOURCE),'-o',str(cls.binary)],
            check=True,capture_output=True,timeout=30)
        wrapper=Path(cls.root.name)/'offline.c'
        wrapper.write_text('''#define main original_mysql_main
#include "ebpf-mysql.c"
#undef main
int main(int argc,char **argv) {
    if(argc<2)return 2;
    if(!strcmp(argv[1],"output")||!strcmp(argv[1],"fresh")) {
        if(argc!=3)return 2;
        int fd=output_directory(argv[2]);if(fd<0)return 1;
        if(!strcmp(argv[1],"fresh")){FILE *f=fresh_file(fd,"offline.json");if(!f){close(fd);return 1;}fputs("{}\\n",f);if(finish_file(f)){close(fd);return 1;}}
        close(fd);return 0;
    }
    if(!strcmp(argv[1],"paced")||!strcmp(argv[1],"paced-deadline")) {
        if(argc!=4)return 2;
        /* Actual clock-only helper check: no endpoint or capture is executed. */
        int directory=output_directory(argv[3]);if(directory<0)return 1;
        struct config c={"client",argv[2],NULL,90,18080,false};
        deadline_ns=now_ns(CLOCK_MONOTONIC)+(!strcmp(argv[1],"paced")?1000000000ULL:50000000ULL);
        int outcome=paced_wait(1,4,12,false);
        FILE *f=fresh_file(directory,"waits.jsonl");if(!f){close(directory);return 1;}
        int written=0;if(write_waits(f,&c,&written)||finish_file(f)){close(directory);return 1;}
        char hash[65];if(wait_file_hash(directory,hash)){close(directory);return 1;}
        printf("{\\\"outcome\\\":%d,\\\"waits_sha256\\\":\\\"%s\\\"}\\n",outcome,hash);close(directory);return 0;
    }
    unsigned char data[WIRE_CAP+1];
    if(!strcmp(argv[1],"eof-shape")){
        if(argc!=3)return 2;
        struct config c={"client",argv[2],NULL,90,18080,false};
        /* Offline serializer input only: this is never a real capture receipt. */
        events[0]=(struct event){.phase=6,.eof=true,.complete=true,.calls=1};event_count=1;
        FILE *f=tmpfile();if(!f)return 1;int written=0;if(write_events(f,&c,&written)){fclose(f);return 1;}
        rewind(f);size_t n;while((n=fread(data,1,sizeof(data),f))>0)fwrite(data,1,n,stdout);fclose(f);return 0;
    }
    if(!strcmp(argv[1],"sha")){size_t n=fread(data,1,sizeof(data),stdin);char hash[65];sha256_hex(data,n,hash);puts(hash);return 0;}
    if(!strcmp(argv[1],"metadata")){struct event e={0};e.bytes=fread(e.data,1,WIRE_CAP,stdin);emit_packets(stdout,&e);return packet_count(e.data,e.bytes)<0?1:0;}
    if(argc!=5)return 2;
    int index=atoi(argv[2]),phase=atoi(argv[3]);
    struct config c={"client",argv[4],NULL,90,18080,false};
    if(!valid_run(c.run)||index<0||index>=3||phase<0||phase>=6)return 2;
    if(!strcmp(argv[1],"message")){int n=build_message(&c,index,phase,data);if(n<0)return 1;return fwrite(data,1,(size_t)n,stdout)==(size_t)n?0:1;}
    size_t n=fread(data,1,sizeof(data),stdin);return validate_message(&c,index,phase,data,n)?1:0;
}
''',encoding='utf-8')
        cls.check=Path(cls.root.name)/'offline-check'
        subprocess.run(['gcc','-std=c11','-O2','-Wall','-Wextra','-Werror',
            '-I',str(SOURCE.parent),str(wrapper),'-o',str(cls.check)],check=True,capture_output=True,timeout=30)
        spec=importlib.util.spec_from_file_location('independent_old_mysql',PREVIOUS)
        cls.old=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.old)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls,'root'):
            cls.root.cleanup()

    def message(self,index,phase):
        return subprocess.run([str(self.check),'message',str(index),str(phase),RUN],
            check=True,capture_output=True,timeout=3).stdout

    def test_default_offline_plan_has_no_output_or_network(self):
        with tempfile.TemporaryDirectory() as directory:
            completed=subprocess.run([str(self.binary),'--output',str(Path(directory)/'unused')],cwd=directory,
                check=True,capture_output=True,text=True,timeout=3)
            plan=json.loads(completed.stdout)
            self.assertFalse(plan['starts_network'])
            self.assertFalse(plan['reads_files'])
            self.assertFalse(plan['creates_files'])
            self.assertFalse(plan['sql_executed'])
            self.assertTrue(plan['pacing_only_qualification'])
            self.assertEqual(plan['pacing_ms'],100)
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_invalid_execute_is_rejected_before_files_or_socket(self):
        with tempfile.TemporaryDirectory() as directory:
            for flags in [[],['--role','client'],['--role','invalid','--run',RUN],['--role','server','--run','wrong'],
                ['--role','client','--run',RUN,'--port','3306'],['--role','server','--run',RUN,'--seconds','91']]:
                value=subprocess.run([str(self.binary),'--execute','--output',directory,*flags],capture_output=True,timeout=3)
                self.assertNotEqual(value.returncode,0)
                self.assertEqual(list(Path(directory).iterdir()),[])

    def test_real_protocol10_greeting_and_protocol41_empty_password_login(self):
        greeting=packets(self.message(0,0))
        self.assertEqual(len(greeting),1)
        self.assertEqual(greeting[0][0],0)
        self.old.verify_greeting(greeting[0][1])
        sequence,login=packets(self.message(0,1))[0]
        self.assertEqual(sequence,1)
        caps,maximum,charset=struct.unpack_from('<IIB',login)
        self.assertEqual((caps,maximum,charset),(0x0008a205,65536,45))
        self.assertEqual(login[9:32],bytes(23))
        username,rest=login[32:].split(b'\0',1)
        self.assertEqual(username,('u_'+RUN).encode())
        self.assertLessEqual(len(username),32)
        self.assertEqual(rest,b'\0mysql_native_password\0')
        self.assertFalse(caps&0x800)  # CLIENT_SSL is deliberately absent.
        self.assertEqual(packets(self.message(0,2)),[(2,b'\0\0\0\x02\0\0\0')])

    def test_queries_are_marked_com_query_and_sequence_resets_each_connection(self):
        for index,scenario in enumerate(('main','error1064','control')):
            self.assertEqual(packets(self.message(index,3)),[(0,b'\x03'+("SELECT '%s.%s'"%(scenario,RUN)).encode())])
            self.assertEqual(packets(self.message(index,5)),[(0,b'\x01')])

    def test_normal_resultsets_have_all_five_real_classic_frames_and_both_eofs(self):
        for index,scenario in ((0,'main'),(2,'control')):
            framed=packets(self.message(index,4))
            self.assertEqual([seq for seq,_ in framed],[1,2,3,4,5])
            class Wire:
                def __init__(self,frames):
                    self.frames=list(frames)
                def receive(self,sequence):
                    actual,payload=self.frames.pop(0)
                    if actual!=sequence:
                        raise ValueError('sequence mismatch')
                    return payload
            wire=Wire(framed)
            self.old.verify_result(wire,{'column_name':scenario+'.'+RUN,'row_value':scenario+'.'+RUN})
            self.assertEqual(wire.frames,[])
            self.assertEqual(framed[2][1],b'\xfe\0\0\x02\0')
            self.assertEqual(framed[4][1],framed[2][1])

    def test_error1064_is_err_packet_not_a_success_or_eof_code(self):
        framed=packets(self.message(1,4))
        self.assertEqual(len(framed),1)
        sequence,payload=framed[0]
        self.assertEqual(sequence,1)
        self.assertEqual(payload[0],0xff)
        self.assertEqual(struct.unpack_from('<H',payload,1)[0],1064)
        self.assertEqual(payload[3:9],b'#42000')
        self.assertEqual(payload[9:],('fixture error1064 error1064.'+RUN).encode())

    def test_all_protocol_frames_are_retained_and_packet_metadata_hashes_are_real(self):
        count=0
        for index in range(3):
            for phase in range(6):
                raw=self.message(index,phase)
                self.assertLess(len(raw),10000)
                decoded=packets(raw)
                count+=len(decoded)
                metadata=json.loads(subprocess.run([str(self.check),'metadata'],input=raw,check=True,capture_output=True,timeout=3).stdout)
                self.assertEqual(len(metadata),len(decoded))
                for item,(sequence,payload) in zip(metadata,decoded):
                    self.assertEqual(item['sequence'],sequence)
                    self.assertEqual(item['payload_hex'],payload.hex())
                    self.assertEqual(item['payload_sha256'],hashlib.sha256(payload).hexdigest())
                    self.assertEqual(item['wire_sha256'],hashlib.sha256(raw[item['offset']:item['offset']+4+len(payload)]).hexdigest())
        self.assertEqual(count,26)

    def test_tcp_eof_is_a_zero_byte_actual_syscall_event_and_never_a_classic_packet(self):
        # This checks serialization only; actual recv(0) requires the future real run.
        value=json.loads(subprocess.run([str(self.check),'eof-shape',RUN],check=True,capture_output=True,timeout=3).stdout)
        self.assertEqual(value['stage'],'tcp-eof')
        self.assertEqual(value['bytes'],0)
        self.assertEqual(value['syscalls'],1)
        self.assertEqual(value['errno'],0)
        self.assertTrue(value['eof_observed'])
        self.assertTrue(value['complete_wire_event'])
        self.assertFalse(value['complete_mysql_message'])
        self.assertEqual(value['classic_packets'],0)
        self.assertEqual(value['packets'],[])
        self.assertEqual(value['wire_hex'],'')
        self.assertEqual(value['wire_sha256'],hashlib.sha256(b'').hexdigest())

    def test_partial_bad_length_wrong_auth_or_sequence_is_not_accepted(self):
        raw=self.message(0,4)
        for wrong in [raw[:-1],b'\xff\xff\xff'+raw[3:],raw[:3]+b'\x09'+raw[4:],raw+b'\0']:
            result=subprocess.run([str(self.check),'validate','0','4',RUN],input=wrong,capture_output=True,timeout=3)
            self.assertNotEqual(result.returncode,0)
        auth=bytearray(self.message(0,2));auth[4]=0xff
        result=subprocess.run([str(self.check),'validate','0','2',RUN],input=auth,capture_output=True,timeout=3)
        self.assertNotEqual(result.returncode,0)

    def test_sha256_and_private_exclusive_evidence_are_independent(self):
        for raw in [b'',b'abc',b'a'*56,self.message(0,4)]:
            actual=subprocess.run([str(self.check),'sha'],input=raw,check=True,capture_output=True,timeout=3).stdout.decode().strip()
            self.assertEqual(actual,hashlib.sha256(raw).hexdigest())
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            subprocess.run([str(self.check),'fresh',directory],check=True,capture_output=True,timeout=3)
            path=Path(directory)/'offline.json';original=path.read_bytes()
            self.assertEqual(path.stat().st_mode&0o777,0o600)
            self.assertNotEqual(subprocess.run([str(self.check),'fresh',directory],capture_output=True,timeout=3).returncode,0)
            self.assertEqual(path.read_bytes(),original)
            os.chmod(directory,0o755)
            self.assertNotEqual(subprocess.run([str(self.check),'output',directory],capture_output=True,timeout=3).returncode,0)

    def test_paced_wait_is_actual_monotonic_100ms_and_hashes_real_receipt_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            result=json.loads(subprocess.run([str(self.check),'paced',RUN,directory],check=True,capture_output=True,timeout=3).stdout)
            raw=(Path(directory)/'waits.jsonl').read_bytes()
            wait=json.loads(raw)
            self.assertEqual(result['outcome'],0)
            self.assertEqual(result['waits_sha256'],hashlib.sha256(raw).hexdigest())
            self.assertEqual((Path(directory)/'waits.jsonl').stat().st_mode&0o777,0o600)
            self.assertEqual((wait['sequence'],wait['connection_index'],wait['scenario']),(1,2,'error1064'))
            self.assertEqual((wait['type'],wait['stage'],wait['wire_sequence']),('after-data','result',12))
            self.assertEqual(wait['pacing_ms'],100)
            self.assertTrue(wait['complete'])
            self.assertEqual(wait['clock_errno'],0)
            self.assertEqual(wait['actual_duration_ns'],wait['finished_monotonic_ns']-wait['started_monotonic_ns'])
            self.assertGreaterEqual(wait['actual_duration_ns'],100_000_000)
            self.assertLess(wait['actual_duration_ns'],1_000_000_000)

    def test_paced_wait_cannot_overrun_remaining_deadline_and_retains_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory,0o700)
            result=json.loads(subprocess.run([str(self.check),'paced-deadline',RUN,directory],check=True,capture_output=True,timeout=3).stdout)
            wait=json.loads((Path(directory)/'waits.jsonl').read_bytes())
            self.assertEqual(result['outcome'],-1)
            self.assertFalse(wait['complete'])
            self.assertNotEqual(wait['clock_errno'],0)
            self.assertLess(wait['actual_duration_ns'],100_000_000)


if __name__=='__main__':
    unittest.main()
