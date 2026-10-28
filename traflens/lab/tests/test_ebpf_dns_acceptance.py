"""Independent finite DNS wire/runtime/query acceptance checks; never uses a socket."""
import contextlib
import copy
import errno
import importlib.util
import io
import json
import os
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('dns_acceptance',HERE/'verify-ebpf-dns.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
RUN='dns-'+'a'*24


def frame(scenario,response=False):
    index=V.SCENARIOS.index(scenario)
    name=scenario+'.'+RUN+'.traflens.invalid'
    question=b''.join(bytes([len(label)])+label.encode() for label in name.split('.'))+b'\0'+struct.pack('!HH',1,1)
    answers=1 if response and scenario!='nxdomain' else 0
    flags=(0x8183 if scenario=='nxdomain' else 0x8180) if response else 0x0100
    packet=struct.pack('!6H',0xb101+index,flags,1,answers,0,0)+question
    if answers:
        packet+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes((198,18,0,41 if scenario=='main' else 42))
    return struct.pack('!H',len(packet))+packet


def workload(folder,role='client'):
    folder.mkdir(mode=0o700)
    process={'role':role,'run':RUN,'pid':12345 if role=='client' else 12346,'tid':12345 if role=='client' else 12346,
             'start_ticks':'97','netns':'net:[9001]','pidns':'pid:[9002]',
             'single_threaded':True,'sdk':False,'protocol':'real TCP DNS','native_source3_verified':False}
    events=[];connections=[];begin=1700000000000000000
    for index,scenario in enumerate(V.SCENARIOS):
        client={'ip':'127.0.0.1','port':30001+index};server={'ip':'127.0.0.2','port':18080}
        local,peer=(client,server) if role=='client' else (server,client)
        connections.append({'scenario':scenario,'operation':'connect' if role=='client' else 'accept','syscalls':1,
                            'initial_errno':errno.EINPROGRESS if role=='client' else 0,'complete':True,'closed':True,'fd':7,
                            'local':local,'peer':peer})
        for response in (False,True):
            raw=frame(scenario,response);seq=len(events)+1
            event={k:process[k] for k in V.IDENTITY}
            event.update(sequence=seq,scenario=scenario,operation='recv' if (role=='client' and response) or (role=='server' and not response) else 'send',
                         response=response,fd=7,local=local,peer=peer,started_unix_ns=begin+seq*1000000,
                         finished_unix_ns=begin+seq*1000000+10000,started_monotonic_ns=seq*1000000,
                         finished_monotonic_ns=seq*1000000+10000,bytes=len(raw),syscalls=1,errno=0,
                         wire_sha256=V.digest(raw),complete_dns_frame=True,wire_hex=raw.hex(),
                         query_name=scenario+'.'+RUN+'.traflens.invalid',transaction_id=0xb101+index,
                         framing='tcp-u16-length-prefix',dns_message_bytes=len(raw)-2,query_type='A',
                         rcode=3 if response and scenario=='nxdomain' else 0,
                         answers=1 if response and scenario!='nxdomain' else 0,metadata_decoded_from_complete_wire=True)
            events.append(event)
    receipt={k:process[k] for k in V.IDENTITY}
    receipt.update({'pass':True,'completed_requests':3,'expected_requests':3,'wire_events':6,'separate_tcp_connections':True,
                    'port':18080,'owned_sockets_closed':True,'listener_closed':True,'single_threaded':True,'sdk':False,
                    'native_source3_verified':False,'error':'','connections':connections,
                    'started_unix_ns':begin,'finished_unix_ns':begin+10000000})
    (folder/'process.json').write_text(json.dumps(process));(folder/'receipt.json').write_text(json.dumps(receipt))
    (folder/'wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    return process,receipt,events


def expected_observations():
    result=[]
    for index,scenario in enumerate(V.SCENARIOS):
        for side,pid in (('c-p',12345),('s-p',12346)):
            result.append({'scenario':scenario,'side':side,'pid':pid,'tid':pid,
                           'tuple':('127.0.0.1',30001+index,'127.0.0.2',18080),
                           'parsed':V.parse_frame(frame(scenario,True),RUN,scenario,True),'call_us':1000})
    return result


def native_rows(expected):
    rows=[]
    for i,item in enumerate(expected):
        row=dict.fromkeys(V.COLUMNS,0)
        row.update(id=str(2**64-1-i),flow_id=2**64-101-i,start_us=1700000000000001,end_us=1700000000000101,
                   time_epoch=1700000000,agent_id=14,signal_source=3,type=2,protocol=6,l7_protocol=120,
                   tap_side=item['side'],l3_epc_id_0=0,l3_epc_id_1=-2,ip_0=item['tuple'][0],client_port=item['tuple'][1],
                   ip_1=item['tuple'][2],server_port=item['tuple'][3],response_duration=100,
                   process_id_0=item['pid'] if item['side']=='c-p' else 0,process_id_1=item['pid'] if item['side']=='s-p' else 0,
                   syscall_thread_0=item['tid'],syscall_thread_1=item['tid'],syscall_trace_id_request=0,syscall_trace_id_response=101)
        row.update({k:v for k,v in item['parsed'].items() if k in V.COLUMNS})
        rows.append(row)
    return rows


def table(rows,columns=None):
    columns=columns or V.COLUMNS
    return {'columns':columns,'values':[[r[c] for c in columns] for r in rows]}


class DNSAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.folder.chmod(0o700)
        self.expected=expected_observations()
    def tearDown(self):self.temp.cleanup()

    def snapshot(self,rows):
        return V.native_snapshot(table([{'records':len(rows)}],['records']),table(rows),self.expected,14,1700000000,1700000002)

    def test_default_offline_plan_never_reads_or_starts_network(self):
        output=io.StringIO()
        with patch.object(V,'application_oracle',side_effect=AssertionError('No file reads')),patch.object(V,'Client',side_effect=AssertionError('No network')),contextlib.redirect_stdout(output):
            self.assertEqual(V.main([]),0)
        self.assertFalse(json.loads(output.getvalue())['execute'])

    def test_independent_wire_parser_checks_question_rcode_and_compressed_answer(self):
        for scenario in V.SCENARIOS:
            for response in (False,True):
                parsed=V.parse_frame(frame(scenario,response),RUN,scenario,response)
                self.assertEqual(parsed['request_type'],'A')
                self.assertEqual(parsed['response_status'],4 if scenario=='nxdomain' else 0)
        self.assertEqual(V.parse_frame(frame('main',True),RUN,'main',True)['response_result'],'A=198.18.0.41 TTL=60')

    def test_wire_prefix_partial_rcode_qid_and_trailing_bytes_are_not_accepted(self):
        original=frame('main',True)
        mutations=[original[:-1],b'\0\1'+original[2:],original+b'junk',original[:2]+b'\xb1\x02'+original[4:],
                   original[:4]+b'\x81\x83'+original[6:],original[:-1]+b'\x63']
        for raw in mutations:
            with self.assertRaises(ValueError):V.parse_frame(raw,RUN,'main',True)

    def test_actual_c_calls_preserve_nonblocking_connect_and_both_socket_tuples(self):
        p,r,e=workload(self.folder/'positive-client')
        process,receipt,pairs,_=V.workload_oracle(self.folder/'positive-client','positive-client',RUN)
        self.assertEqual(process,p);self.assertEqual(len(pairs),3)
        self.assertEqual(pairs['main']['tuple'],('127.0.0.1',30001,'127.0.0.2',18080))
        e[0]['wire_sha256']='0'*64
        (self.folder/'positive-client/wire.jsonl').write_text(''.join(json.dumps(v)+'\n' for v in e))
        with self.assertRaises(ValueError):V.workload_oracle(self.folder/'positive-client','positive-client',RUN)

    def test_native_all_marker_population_maps_exact_pid_side_and_preserves_raw_uint64(self):
        values=native_rows(self.expected);before=copy.deepcopy(values)
        actual,fingerprint=self.snapshot(values)
        self.assertEqual(values,before);self.assertEqual(len(actual),6)
        self.assertIs(type(actual[0]['flow_id']),int);self.assertEqual(fingerprint,V.digest(V.canonical(actual)))
        self.assertEqual(sum(v['syscall_trace_id_request']==0 for v in actual),6)

    def test_wrong_source_pid_txid_rcode_answer_or_float_cannot_hide_in_marker(self):
        for field,value in [('signal_source',0),('type',0),('process_id_0',777),('request_id',1),('response_code',3),
                            ('response_status',4),('response_result','forged'),('flow_id',float(2**64-101)),('time_epoch',1700000001)]:
            rows=native_rows(self.expected);rows[0][field]=value
            with self.assertRaises(ValueError,msg=field):self.snapshot(rows)

    def test_rrt_uses_native_us_floor_and_actual_call_bound_not_application_sleep(self):
        rows=native_rows(self.expected);rows[0]['response_duration']=101
        self.snapshot(rows)
        rows[0]['response_duration']=102
        with self.assertRaisesRegex(ValueError,'RRT'):self.snapshot(rows)
        too_short=copy.deepcopy(self.expected);too_short[0]['call_us']=50
        rows=native_rows(self.expected)
        with self.assertRaisesRegex(ValueError,'RRT'):
            V.native_snapshot(table([{'records':6}],['records']),table(rows),too_short,14,1700000000,1700000002)

    def test_api_exact_ids_and_numbers_match_native_records(self):
        rows=native_rows(self.expected)
        V.api_rows(table(rows,V.API_COLUMNS),rows)
        response=table(rows,V.API_COLUMNS)
        response['values'][0][V.API_COLUMNS.index('id')]=int(rows[0]['id'])
        with self.assertRaises(ValueError):V.api_rows(response,rows)

    def test_malformed_schema_excess_rows_and_credential_url_are_rejected(self):
        for value in (None,{}, {'columns':V.COLUMNS,'values':False},{'columns':['id','id'],'values':[]}):
            with self.assertRaises(ValueError):V.table(value,V.COLUMNS)
        with self.assertRaises(ValueError):self.snapshot(native_rows(self.expected)*11)
        for url in ('http://u:secret@127.0.0.1:80','http://127.0.0.1:80?token=x','http://example.com:80'):
            with self.assertRaises(ValueError):V.loopback(url)

    def test_whole_marker_sql_has_no_hidden_source_agent_protocol_or_time_filters(self):
        calls=[]
        class Client:
            def query(inner,name,base,sql):
                calls.append((name,sql))
                raise RuntimeError('Stop before any actual query')
        args=SimpleNamespace(query_base='http://127.0.0.1:20416',console_base='http://127.0.0.1:22880',time_from=1700000000,time_to=1700000002)
        with self.assertRaises(RuntimeError):V.acceptance(Client(),args,RUN,'dns-'+'b'*24,14,self.expected,{})
        self.assertEqual(calls[0][1],"SELECT Count(row) AS records FROM l7_flow_log WHERE request_resource LIKE '%"+RUN+"%'")


if __name__=='__main__':unittest.main()
