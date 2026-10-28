import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('udp_dns_acceptance_tested',HERE/'verify-ebpf-dns-udp.py')
M=importlib.util.module_from_spec(spec)
import sys
sys.modules[spec.name]=M
spec.loader.exec_module(M)
RUN='dns-'+'a'*24


def message(scenario='main',response=False):
    index=M.SCENARIOS.index(scenario)
    name=scenario+'.'+RUN+'.traflens.invalid'
    qname=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'
    code=3 if scenario=='nxdomain' else 0
    answer=bool(response and not code)
    raw=struct.pack('!6H',0xb101+index,0x8180|code if response else 0x0100,1,int(answer),0,0)
    raw+=qname+struct.pack('!HH',1,1)
    if answer:
        raw+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+bytes([198,18,0,41 if scenario=='main' else 42])
    return raw


def actual_event(process,index,scenario,response,role):
    raw=message(scenario,response)
    decoded=M.parse_message(raw,RUN,scenario,response)
    op='recv' if (role=='client' and response) or (role=='server' and not response) else 'send'
    syscall=op if role=='client' else 'recvfrom' if op=='recv' else 'sendto'
    local={'ip':'127.0.0.1' if role=='client' else '127.0.0.2','port':22000 if role=='client' else 18080}
    peer={'ip':'127.0.0.2' if role=='client' else '127.0.0.1','port':18080 if role=='client' else 22000}
    ns=10_000_000_000+index*1_000_000
    return dict(process,schema='traflens.ebpf-dns-udp.wire.v1',sequence=index+1,scenario=scenario,response=response,
        operation=op,syscall=syscall,fd=9,local=local,peer=peer,started_unix_ns=ns,finished_unix_ns=ns+100_000,
        started_monotonic_ns=ns,finished_monotonic_ns=ns+100_000,bytes=len(raw),syscall_result=len(raw),
        actual_datagram_bytes=len(raw),wire_hex=raw.hex(),wire_sha256=M.digest(raw),syscalls=1,errno=0,flags=0,
        complete_dns_message=True,complete_datagram=True,transport='udp',oversize_sentinel_reached=False,framing='udp-datagram',metadata_decoded_from_complete_wire=True,
        dns_message_bytes=len(raw),query_name=decoded['request_resource'],transaction_id=decoded['request_id'],
        query_type='A',rcode=decoded['response_code'],answers=decoded['answers'])


def workload(role):
    process={'schema':'traflens.ebpf-dns-udp.process.v1','role':role,'run':RUN,'pid':101,'tid':101,
        'start_ticks':'900','netns':'net:[44]','pidns':'pid:[55]','single_threaded':True,'sdk':False,
        'native_source3_verified':False,'protocol':'real UDP DNS','transport':'udp','framing':'udp-datagram',
        'socket_type':'SOCK_DGRAM','executable_sha256':'a'*64}
    events=[actual_event(process,index*2+int(response),scenario,response,role)
        for index,scenario in enumerate(M.SCENARIOS) for response in (False,True)]
    transactions=[]
    for index,scenario in enumerate(M.SCENARIOS):
        first=events[index*2]
        transactions.append({'scenario':scenario,'operation':'send-request' if role=='client' else 'recvfrom-request',
            'kind':'datagram-transaction','complete':True,'closed':True,'local':first['local'],'peer':first['peer'],
            'fd':9,'initial_errno':0,'syscalls':1,**{k:first[k] for k in ['started_unix_ns','finished_unix_ns','started_monotonic_ns','finished_monotonic_ns']}})
    receipt=dict(process,schema='traflens.ebpf-dns-udp.receipt.v1',pass_=True,completed_requests=3,expected_requests=3,
        wire_events=6,port=18080,udp_datagrams_sent=3,udp_datagrams_received=3,datagram_exchanges=3,
        owned_socket_count=1,connected_udp_sockets=int(role=='client'),bound_udp_sockets=1,
        single_peer_only_qualification=True,single_peer_per_socket=True,single_connected_client_udp_socket=role=='client',
        separate_client_udp_sockets=False,owned_sockets_closed=True,listener_closed=True,error='',
        started_unix_ns=10_000_000_000,finished_unix_ns=10_007_000_000,transactions=transactions)
    receipt['pass']=receipt.pop('pass_')
    receipt['started_monotonic_ns']=receipt['started_unix_ns'];receipt['finished_monotonic_ns']=receipt['finished_unix_ns']
    receipt['socket_setup']={'operation':'udp-connect' if role=='client' else 'bind','fd':9,'syscalls':1,'initial_errno':0,
        'local':events[0]['local'],'peer':events[0]['peer'] if role=='client' else None,'complete':True,'closed':True,
        'started_unix_ns':receipt['started_unix_ns'],'finished_unix_ns':receipt['started_unix_ns'],
        'started_monotonic_ns':receipt['started_monotonic_ns'],'finished_monotonic_ns':receipt['started_monotonic_ns']}
    return process,receipt,events


def expected_rows():
    rows=[];expected=[]
    for index,scenario in enumerate(M.SCENARIOS):
        parsed=M.parse_message(message(scenario,True),RUN,scenario,True)
        for side,pid in [('c-p',101),('s-p',102)]:
            ident=2**63+len(rows)+7
            item={'scenario':scenario,'side':side,'tuple':('127.0.0.1',22000,'127.0.0.2',18080),
                'pid':pid,'tid':pid,'parsed':parsed,'call_us':500}
            expected.append(item)
            row={k:'' if k in M.TEXT else 0 for k in M.COLUMNS}
            row.update(parsed)
            row.update(id=str(ident),flow_id=2**63+5,agent_id=19,signal_source=3,type=2,protocol=17,l7_protocol=120,
                tap_side=side,start_us=10_000_100,end_us=10_000_200,time_epoch=10,response_duration=100,
                ip_0='127.0.0.1',ip_1='127.0.0.2',client_port=22000,server_port=18080,
                process_id_0=pid if side=='c-p' else 0,process_id_1=pid if side=='s-p' else 0,
                syscall_thread_0=pid,syscall_thread_1=pid,syscall_trace_id_request=1,syscall_trace_id_response=2)
            rows.append(row)
    return rows,expected


def document(rows):
    return {'columns':M.COLUMNS,'values':[[r[k] for k in M.COLUMNS] for r in rows]}


class UDPAcceptanceTests(unittest.TestCase):
    def test_default_plan_has_no_file_reads_or_network(self):
        with patch.object(M,'read_json',side_effect=AssertionError),patch.object(M,'Client',side_effect=AssertionError):
            with contextlib.redirect_stdout(io.StringIO()) as out:self.assertEqual(M.main([]),0)
        value=json.loads(out.getvalue())
        self.assertFalse(value['reads_files']);self.assertFalse(value['starts_network'])

    def test_unprefixed_wire_A_and_NXDOMAIN(self):
        for scenario in M.SCENARIOS:
            q=M.parse_message(message(scenario),RUN,scenario,False)
            a=M.parse_message(message(scenario,True),RUN,scenario,True)
            self.assertEqual(q['request_id'],a['request_id'])
            self.assertEqual(a['response_code'],3 if scenario=='nxdomain' else 0)
            self.assertEqual(a['response_status'],4 if scenario=='nxdomain' else 0)
            self.assertEqual(a['answers'],int(scenario!='nxdomain'))

    def test_TCP_length_prefix_is_rejected(self):
        raw=message()
        with self.assertRaises(ValueError):M.parse_message(struct.pack('!H',len(raw))+raw,RUN,'main',False)

    def test_partial_trailing_wrong_question_and_flags_rejected(self):
        raw=message()
        mutations=[raw[:-1],raw+b'\0',raw[:2]+b'\x80\x00'+raw[4:],raw[:-4]+b'\0\x1c\0\x01']
        for invalid in mutations:
            with self.subTest(invalid=invalid.hex()),self.assertRaises(ValueError):
                M.parse_message(invalid,RUN,'main',False)

    def test_compression_cycle_is_rejected(self):
        with self.assertRaises(ValueError):M.dns_name(b'\xc0\x00',0)

    def test_actual_datagram_result_flags_and_schema_enforced(self):
        process,_,events=workload('client')
        for key,bad in [('syscall_result',-1),('actual_datagram_bytes',0),('flags',32),
                        ('complete_datagram',None),('complete_dns_message',1),('schema','old-tcp')]:
            invalid=dict(events[0],**{key:bad})
            with self.subTest(key=key),self.assertRaises(ValueError):M.wire_oracle(invalid,RUN,'main',False)

    def run_workload(self,role,mutate=None):
        process,receipt,events=workload(role)
        if mutate:mutate(process,receipt,events)
        with tempfile.TemporaryDirectory() as name:
            folder=Path(name).resolve()
            (folder/'process.json').write_text(json.dumps(process))
            (folder/'receipt.json').write_text(json.dumps(receipt))
            (folder/'wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
            return M.workload_oracle(folder,'positive-'+role,RUN)

    def test_each_side_one_socket_three_transactions(self):
        for role in ['client','server']:
            result=self.run_workload(role)
            self.assertEqual(len(result[2]),3)
            self.assertEqual(len({v['tuple'] for v in result[2].values()}),1)

    def test_TCP_receipt_rejected(self):
        def mutate(p,r,e):p['protocol']='real TCP DNS'
        with self.assertRaises(ValueError):self.run_workload('client',mutate)

    def test_second_peer_or_fd_is_not_single_peer_qualification(self):
        def peer(p,r,e):e[2]['peer']['port']=18081
        def fd(p,r,e):e[2]['fd']=10
        for mutate in [peer,fd]:
            with self.assertRaises(ValueError):self.run_workload('server',mutate)

    def test_fake_server_accept_or_three_connections_rejected(self):
        for op in ['accept','udp-connect']:
            def mutate(p,r,e):r['transactions'][0]['operation']=op
            with self.assertRaises(ValueError):self.run_workload('server',mutate)

    def test_socket_setup_and_transaction_times_cannot_be_faked(self):
        def late(p,r,e):r['socket_setup']['finished_unix_ns']=r['finished_unix_ns']
        def accepted(p,r,e):r['socket_setup']['operation']='accept'
        def wrong(p,r,e):r['transactions'][0]['started_monotonic_ns']+=1
        for mutate in [late,accepted,wrong]:
            with self.assertRaises(ValueError):self.run_workload('client',mutate)

    def test_client_bound_counter_tracks_actual_explicit_bind(self):
        self.run_workload('client')
        def mutate(p,r,e):r['bound_udp_sockets']=0
        with self.assertRaises(ValueError):self.run_workload('client',mutate)

    def test_three_client_socket_claim_rejected(self):
        def mutate(p,r,e):r['owned_socket_count']=3
        with self.assertRaises(ValueError):self.run_workload('client',mutate)

    def test_native_exact_large_integer_ID_normalization_and_transaction_key(self):
        rows,expected=expected_rows()
        rows[0]['id']=int(rows[0]['id'])
        normalized,_=M.native_snapshot({'columns':['records'],'values':[[6]]},document(rows),expected,19,10,10)
        self.assertEqual(len(normalized),6)
        self.assertTrue(all(type(r['id']) is str and type(r['flow_id']) is str for r in normalized))
        self.assertEqual(normalized[0]['flow_id'],str(2**63+5))

    def test_native_float_decimal_exponent_bool_id_is_rejected(self):
        for invalid in [float(2**63),'1e18','9.0',True]:
            rows,expected=expected_rows();rows[0]['flow_id']=invalid
            with self.subTest(invalid=invalid),self.assertRaises(ValueError):
                M.native_snapshot({'columns':['records'],'values':[[6]]},document(rows),expected,19,10,10)

    def test_native_TCP_source_wrong_status_or_orphan_rejected(self):
        for key,bad in [('protocol',6),('signal_source',0),('type',0),('response_status',3),('request_id',1)]:
            rows,expected=expected_rows();rows[0][key]=bad
            with self.subTest(key=key),self.assertRaises(ValueError):
                M.native_snapshot({'columns':['records'],'values':[[6]]},document(rows),expected,19,10,10)

    def test_extra_whole_population_is_not_filtered(self):
        rows,expected=expected_rows();rows.append(copy.deepcopy(rows[0]));rows[-1]['id']='999'
        with self.assertRaises(ValueError):
            M.native_snapshot({'columns':['records'],'values':[[7]]},document(rows),expected,19,10,10)

    def test_duration_counter_float_and_range_are_rejected(self):
        for bad in [1.2,-1,2**64]:
            rows,expected=expected_rows();rows[0]['response_duration']=bad
            with self.assertRaises(ValueError):
                M.native_snapshot({'columns':['records'],'values':[[6]]},document(rows),expected,19,10,10)

    def test_native_missing_column_and_more_than64_rejected(self):
        with self.assertRaises(ValueError):M.table({'columns':['id'],'values':[['1']]},M.COLUMNS)
        with self.assertRaises(ValueError):M.table({'columns':['id'],'values':[['1']]*65},['id'])

    def test_acceptance_two_unfiltered_agent_populations_and_all_details(self):
        rows,expected=expected_rows();negative='dns-'+'b'*24
        class OfflineClient:
            def __init__(self):self.requests=0;self.sql=[];self.names=[]
            def query(self,name,base,sql):
                self.requests+=1;self.sql.append(sql);self.names.append(name)
                empty=negative in sql or 'signal_source=0' in sql or 'signal_source=4' in sql
                return ({'columns':['records'],'values':[[0 if empty else 6]]} if 'Count(row)' in sql
                        else document([] if empty else rows))
            def request(self,name,base,path,fields):
                self.requests+=1;self.names.append(name)
                selected=[] if fields.get('source') in (0,4) or fields.get('q')==negative else rows
                if 'id' in fields:selected=[r for r in selected if r['id']==fields['id']]
                return {'columns':M.API_COLUMNS,'values':[[r[k] for k in M.API_COLUMNS] for r in selected]}
        from types import SimpleNamespace
        client=OfflineClient();report={}
        M.acceptance(client,SimpleNamespace(query_base='unused',console_base='unused',time_from=10,time_to=10),
                     RUN,negative,19,expected,report)
        self.assertEqual(report['whole_marker_reads'],2);self.assertEqual(report['whole_agent_time_reads'],2)
        self.assertEqual(report['exact_detail_reads'],6);self.assertEqual(client.requests,25)
        agent_sql=[sql.split(' WHERE ',1)[1].split(' ORDER BY ',1)[0] for sql in client.sql if ' WHERE agent_id=' in sql]
        self.assertEqual(agent_sql,['agent_id=19 AND time>=10 AND time<=10']*4)
        self.assertLessEqual(client.requests,M.MAX_REQUESTS)

    def test_all_public_capture_stage_SHA_are_bound(self):
        contents={name:('public-stage-'+name).encode() for name in M.CAPTURE_SOURCE_FILES}
        manifest={name:M.digest(raw) for name,raw in contents.items()};report={}
        with patch.object(M,'read_json',return_value=manifest),patch.object(M,'read_file',side_effect=lambda p:contents[p.name]):
            M.capture_stage_sources(Path('/unused'),report)
        self.assertEqual(report['public_stage_sha256'],manifest)
        self.assertIn('ebpf-dns-udp.c',manifest);self.assertIn('verify-ebpf-dns-udp.py',manifest)

    def test_missing_or_tampered_public_stage_SHA_is_rejected(self):
        contents={name:('public-stage-'+name).encode() for name in M.CAPTURE_SOURCE_FILES}
        original={name:M.digest(raw) for name,raw in contents.items()}
        missing=dict(original);del missing['verify-ebpf-dns-udp.py']
        changed=dict(original);changed['ebpf-dns-udp.c']='0'*64
        for manifest in [missing,changed]:
            with patch.object(M,'read_json',return_value=manifest),patch.object(M,'read_file',side_effect=lambda p:contents[p.name]),self.assertRaises(ValueError):
                M.capture_stage_sources(Path('/unused'),{})

    def test_repair_worker_runtime_passes_fixed_frozen_UDP_contract(self):
        from dataclasses import FrozenInstanceError
        self.assertEqual(M.DNS_WORKER.schema,'traflens.ebpf-dns-udp.worker-runtime.v1')
        self.assertEqual(M.DNS_WORKER.purpose,'traflens.ebpf-dns-udp.worker')
        with self.assertRaises(FrozenInstanceError):M.DNS_WORKER.schema='old-tcp'
        args=(Path('/private/capture'),'positive-client',RUN,RUN,{}, {}, object())
        with patch.object(M,'checked_worker_runtime',return_value='checked') as delegated:
            self.assertEqual(M.worker_runtime(*args),'checked')
        delegated.assert_called_once_with(*args,M.DNS_WORKER)

    def test_repair_explicit_private_archive_matches_only_planned_verifier(self):
        contents={name:('public-stage-'+name).encode() for name in M.CAPTURE_SOURCE_FILES}
        manifest={name:M.digest(raw) for name,raw in contents.items()}
        planned=b'original planned verifier bytes, never execute this file'
        manifest['verify-ebpf-dns-udp.py']=M.digest(planned)
        with tempfile.TemporaryDirectory() as name:
            archive=Path(name).resolve()/'planned-verifier.py';archive.write_bytes(planned);archive.chmod(0o600)
            report={}
            with patch.object(M,'read_json',return_value=manifest),patch.object(M,'read_file',side_effect=lambda p:contents[p.name]):
                M.capture_stage_sources(Path('/unused'),report,archive)
            self.assertTrue(report['verifier_repair_applied'])
            self.assertEqual(report['planned_verifier_sha256'],M.digest(planned))
            self.assertEqual(report['planned_verifier_archive_sha256'],M.digest(planned))
            self.assertEqual(report['executed_verifier_sha256'],M.digest(contents['verify-ebpf-dns-udp.py']))
            self.assertEqual(len(report['current_producer_stage_sha256']),10)

    def test_repair_rejects_missing_bad_hash_symlink_public_and_oversize_archive(self):
        planned=b'original planned verifier, do not execute';expected=M.digest(planned)
        with tempfile.TemporaryDirectory() as name:
            folder=Path(name).resolve();archive=folder/'planned.py';archive.write_bytes(planned);archive.chmod(0o600)
            with self.assertRaises(ValueError):M.planned_verifier_archive(archive,'0'*64)
            archive.chmod(0o644)
            with self.assertRaises(ValueError):M.planned_verifier_archive(archive,expected)
            archive.chmod(0o600);link=folder/'linked.py';link.symlink_to(archive)
            with self.assertRaises(ValueError):M.planned_verifier_archive(link,expected)
            with archive.open('wb') as f:f.truncate(M.MAX_BODY+1)
            with self.assertRaises(ValueError):M.planned_verifier_archive(archive,expected)
        contents={n:('public-stage-'+n).encode() for n in M.CAPTURE_SOURCE_FILES}
        manifest={n:M.digest(raw) for n,raw in contents.items()};manifest['verify-ebpf-dns-udp.py']=expected
        with patch.object(M,'read_json',return_value=manifest),patch.object(M,'read_file',side_effect=lambda p:contents[p.name]),self.assertRaises(ValueError):
            M.capture_stage_sources(Path('/unused'),{})

    def test_repair_cannot_bypass_other_stages_or_apply_when_current_matches_plan(self):
        contents={name:('public-stage-'+name).encode() for name in M.CAPTURE_SOURCE_FILES}
        original={name:M.digest(raw) for name,raw in contents.items()};planned=b'original planned verifier'
        with tempfile.TemporaryDirectory() as name:
            archive=Path(name).resolve()/'planned.py';archive.write_bytes(planned);archive.chmod(0o600)
            tampered=dict(original);tampered['verify-ebpf-dns-udp.py']=M.digest(planned);tampered['ebpf-dns-udp.c']='0'*64
            for manifest in [original,tampered]:
                with patch.object(M,'read_json',return_value=manifest),patch.object(M,'read_file',side_effect=lambda p:contents[p.name]),self.assertRaises(ValueError):
                    M.capture_stage_sources(Path('/unused'),{},archive)

    def test_api_exact_id_and_transport_preserved(self):
        rows,_=expected_rows()
        native=[{k:str(v) if k=='flow_id' else v for k,v in r.items()} for r in rows]
        data={'columns':M.API_COLUMNS,'values':[[r[k] for k in M.API_COLUMNS] for r in native]}
        M.api_rows(data,native)
        bad=copy.deepcopy(data);bad['values'][0][M.API_COLUMNS.index('protocol')]=6
        with self.assertRaises(ValueError):M.api_rows(bad,native)


if __name__=='__main__':unittest.main()
