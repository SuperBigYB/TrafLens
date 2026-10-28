"""Offline full classic population guards; never runs network/collector endpoints."""
import contextlib
import copy
import errno
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('mysql_acceptance',HERE/'verify-ebpf-mysql.py')
V=importlib.util.module_from_spec(spec);spec.loader.exec_module(V)
spec=importlib.util.spec_from_file_location('mysql_old_independent',HERE/'mysql-traffic.py')
OLD=importlib.util.module_from_spec(spec);spec.loader.exec_module(OLD)
RUN='my-'+'a'*24


def independent_messages(scenario):
    literal=scenario+'.'+RUN
    login=struct.pack('<IIB',OLD.CAPABILITIES,65536,45)+bytes(23)+('u_'+RUN).encode()+b'\0\0'+OLD.PLUGIN+b'\0'
    result=(OLD.packet(b'\xff'+struct.pack('<H',1064)+b'#42000'+('fixture error1064 '+literal).encode(),1)
            if scenario=='error1064' else b''.join(OLD.result_frames({'column_name':literal,'row_value':literal})))
    return {'greeting':OLD.packet(OLD.greeting(),0),'login':OLD.packet(login,1),'auth':OLD.packet(OLD.OK,2),
            'query':OLD.packet(b'\x03'+("SELECT '"+literal+"'").encode(),0),'result':result,
            'quit':OLD.packet(b'\x01',0),'tcp-eof':b''}


def fixture(folder,role='client'):
    folder.mkdir(mode=0o700)
    p={'role':role,'run':RUN,'pid':12345 if role=='client' else 12346,'tid':12345 if role=='client' else 12346,
       'start_ticks':'97','netns':'net:[9001]','pidns':'pid:[9002]','comm':'mysqld' if role=='server' else 'traflens-mysql',
       'single_threaded':True,'sdk':False,'wire_fixture':True,'sql_executed':False,'empty_password':True,
       'protocol':'real MySQL classic TCP','native_source3_verified':False}
    events=[];connections=[];start=1700000000000000000
    for index,scenario in enumerate(V.SCENARIOS):
        client={'ip':'127.0.0.1','port':30001+index};server={'ip':'127.0.0.2','port':18080}
        local,peer=(client,server) if role=='client' else (server,client)
        connections.append({'scenario':scenario,'operation':'connect' if role=='client' else 'accept','fd':7,'syscalls':1,
          'initial_errno':errno.EINPROGRESS if role=='client' else 0,'complete':True,'closed':True,'shutdown_write':role=='client',
          'local':local,'peer':peer})
        for stage,raw in independent_messages(scenario).items():
            seq=len(events)+1;eof=stage=='tcp-eof'
            sends=stage in ('login','query','quit') if role=='client' else stage in ('greeting','auth','result')
            e={k:p[k] for k in V.IDENTITY}
            e.update(sequence=seq,scenario=scenario,stage=stage,operation='send' if sends else 'recv',fd=7,local=local,peer=peer,
                     started_unix_ns=start+seq*1000000,finished_unix_ns=start+seq*1000000+10000,
                     started_monotonic_ns=seq*1000000,finished_monotonic_ns=seq*1000000+10000,
                     bytes=len(raw),syscalls=1,errno=0,wire_sha256=V.digest(raw),wire_hex=raw.hex(),
                     complete_wire_event=True,complete_mysql_message=not eof,eof_observed=eof,wire_fixture=True,sql_executed=False,
                     classic_packets=len(V.classic_packets(raw)),packets=V.classic_packets(raw))
            events.append(e)
    receipt={k:p[k] for k in V.IDENTITY}
    receipt.update({'pass':True,'completed_requests':3,'expected_requests':3,'wire_events':21,'wire_data_events':18,'tcp_eof_events':3,
       'classic_packets':26,'separate_tcp_connections':True,'port':18080,'owned_sockets_closed':True,'listener_closed':True,
       'single_threaded':True,'wire_fixture':True,'sql_executed':False,'sdk':False,'native_source3_verified':False,'error':'',
       'started_unix_ns':start,'finished_unix_ns':start+30000000,'connections':connections})
    for name,value in [('process.json',p),('receipt.json',receipt)]: (folder/name).write_text(json.dumps(value))
    (folder/'wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    return p,receipt,events


def expected_observations():
    result=[]
    for index,scenario in enumerate(V.SCENARIOS):
        for side,pid in (('c-p',12345),('s-p',12346)):
            for kind in ('login','query','quit'):
                result.append({'scenario':scenario,'side':side,'kind':kind,'pid':pid,'tid':pid,'call_us':1000,
                    'tuple':('127.0.0.1',30001+index,'127.0.0.2',18080),'messages':V.expected_messages(RUN,scenario)})
    return result


def paced_fixture(folder):
    p,receipt,events=fixture(folder)
    for value in (p,receipt):value.update(pacing_only_qualification=True,pacing_ms=100)
    base=receipt['started_unix_ns'];tick=1000000;waits=[]
    for index,scenario in enumerate(V.SCENARIOS):
        conn=receipt['connections'][index]
        conn.update(started_monotonic_ns=tick,finished_monotonic_ns=tick+100,
                    started_unix_ns=base+tick,finished_unix_ns=base+tick+100)
        tick+=1000
        for offset in range(7):
            event=events[index*7+offset]
            event.update(started_monotonic_ns=tick,finished_monotonic_ns=tick+10000,
                         started_unix_ns=base+tick,finished_unix_ns=base+tick+10000)
            tick+=11000
            if offset==6:continue
            wait={k:p[k] for k in V.IDENTITY}
            wait.update(sequence=len(waits)+1,connection_index=index+1,scenario=scenario,type='after-data',
                        stage=event['stage'],wire_sequence=event['sequence'],pacing_ms=100,
                        started_monotonic_ns=tick,finished_monotonic_ns=tick+100005000,
                        started_unix_ns=base+tick,finished_unix_ns=base+tick+100005000,
                        actual_duration_ns=100005000,complete=True,clock_errno=0)
            waits.append(wait);tick+=100006000
        conn.update(close_started_monotonic_ns=tick,close_finished_monotonic_ns=tick+10000,
                    close_started_unix_ns=base+tick,close_finished_unix_ns=base+tick+10000)
        tick+=11000
        wait={k:p[k] for k in V.IDENTITY}
        wait.update(sequence=len(waits)+1,connection_index=index+1,scenario=scenario,type='after-close',stage='close',
                    wire_sequence=0,pacing_ms=100,started_monotonic_ns=tick,finished_monotonic_ns=tick+100005000,
                    started_unix_ns=base+tick,finished_unix_ns=base+tick+100005000,
                    actual_duration_ns=100005000,complete=True,clock_errno=0)
        waits.append(wait);tick+=100006000
    receipt.update(started_monotonic_ns=1,finished_monotonic_ns=tick+1,finished_unix_ns=base+tick+1,
                   pacing_waits=21,pacing_duration_ns=sum(w['actual_duration_ns'] for w in waits))
    def write():
        raw=''.join(json.dumps(w)+'\n' for w in waits).encode()
        receipt['waits_sha256']=V.digest(raw);(folder/'waits.jsonl').write_bytes(raw)
        for name,value in (('process.json',p),('receipt.json',receipt)):(folder/name).write_text(json.dumps(value))
        (folder/'wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
    write()
    return p,receipt,events,waits,write


def native_rows(expected):
    rows=[]
    for i,item in enumerate(expected):
        row=dict.fromkeys(V.COLUMNS,0);quit=item['kind']=='quit'
        flow=2**64-101-(V.SCENARIOS.index(item['scenario'])*2+(0 if item['side']=='c-p' else 1))
        row.update(id=str(2**64-1-i),flow_id=flow,start_us=1700000000000001,end_us=1700000000000001 if quit else 1700000000000101,
          time_epoch=1700000000,agent_id=14,signal_source=3,type=2,protocol=6,l7_protocol=60,tap_side=item['side'],
          l3_epc_id_0=0,l3_epc_id_1=-2,ip_0=item['tuple'][0],client_port=item['tuple'][1],ip_1=item['tuple'][2],server_port=18080,
          request_id=None,endpoint='',request_domain='',response_duration=0 if quit else 100,
          process_id_0=item['pid'] if item['side']=='c-p' else 0,process_id_1=item['pid'] if item['side']=='s-p' else 0,
          syscall_thread_0=item['tid'],syscall_thread_1=0 if quit else item['tid'],syscall_trace_id_request=0,
          syscall_trace_id_response=0 if quit else 101)
        row.update(V.record_contract(item));rows.append(row)
    return rows


def table(rows,columns=None):
    columns=columns or V.COLUMNS
    return {'columns':columns,'values':[[r[c] for c in columns] for r in rows]}


class MySQLAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.folder=Path(self.temp.name);self.folder.chmod(0o700)
        self.expected=expected_observations()
    def tearDown(self):self.temp.cleanup()
    def snapshot(self,rows):
        return V.native_population(table([{'records':len(rows)}],['records']),table(rows),self.expected,14,1700000000,1700000002)

    def test_default_offline_plan_never_reads_or_queries(self):
        out=io.StringIO()
        with patch.object(V,'application_oracle',side_effect=AssertionError('No reads')),patch.object(V,'Client',side_effect=AssertionError('No query')),contextlib.redirect_stdout(out):
            self.assertEqual(V.main([]),0)
        plan=json.loads(out.getvalue());self.assertFalse(plan['execute']);self.assertEqual(plan['max_requests'],48)

    def test_independent_m6_codec_matches_greeting_login_result_and_quit_bytes(self):
        for scenario in V.SCENARIOS:
            expected=V.expected_messages(RUN,scenario)
            for stage,raw in independent_messages(scenario).items():self.assertEqual(raw,expected[stage])
        self.assertEqual([p['sequence'] for p in V.classic_packets(independent_messages('main')['result'])],[1,2,3,4,5])

    def test_all21_events_and26_packets_include_three_real_zero_byte_eof_receipts(self):
        _,_,events=fixture(self.folder/'positive-client')
        _,_,pairs,_=V.workload_oracle(self.folder/'positive-client','positive-client',RUN)
        self.assertEqual(len(pairs),3);self.assertEqual(sum(e['eof_observed'] for e in events),3)
        self.assertEqual(sum(e['classic_packets'] for e in events),26)
        events[-1]['complete_mysql_message']=True
        (self.folder/'positive-client/wire.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
        with self.assertRaises(ValueError):V.workload_oracle(self.folder/'positive-client','positive-client',RUN)

    def test_explicit_pacing_binds21_actual100ms_waits_to18_io_and3_closes(self):
        folder=self.folder/'positive-client';p,receipt,events,waits,write=paced_fixture(folder)
        _,saved,pairs,_=V.workload_oracle(folder,'positive-client',RUN)
        self.assertTrue(saved['pacing_only_qualification']);self.assertEqual(len(pairs),3)
        self.assertEqual(len(waits),21);self.assertEqual(sum(w['type']=='after-close' for w in waits),3)
        self.assertEqual(sum(e['classic_packets'] for e in events),26)
        self.assertEqual(sum(w['actual_duration_ns'] for w in waits),receipt['pacing_duration_ns'])

    def test_pacing_rejects_short_missing_mismatched_overlapping_or_unhashed_waits(self):
        mutations=(
            lambda p,r,e,w:w.pop(),
            lambda p,r,e,w:w[0].update(actual_duration_ns=99999999),
            lambda p,r,e,w:w[0].update(stage='query'),
            lambda p,r,e,w:w[0].update(finished_monotonic_ns=w[0]['finished_monotonic_ns']+200000000,
                                     actual_duration_ns=w[0]['actual_duration_ns']+200000000),
            lambda p,r,e,w:w[6].update(started_monotonic_ns=r['connections'][0]['close_finished_monotonic_ns']-1),
            lambda p,r,e,w:r.update(pacing_duration_ns=r['pacing_duration_ns']+1),
            lambda p,r,e,w:p.pop('pacing_only_qualification'),
        )
        for index,mutation in enumerate(mutations):
            folder=self.folder/('case-'+str(index));p,r,e,w,write=paced_fixture(folder)
            mutation(p,r,e,w);write()
            with self.assertRaises(ValueError,msg=str(index)):V.workload_oracle(folder,'positive-client',RUN)
        folder=self.folder/'hash';p,r,e,w,write=paced_fixture(folder)
        r['waits_sha256']='0'*64;(folder/'receipt.json').write_text(json.dumps(r))
        with self.assertRaises(ValueError):V.workload_oracle(folder,'positive-client',RUN)

    def test_partial_header_payload_bad_sequence_and_nonbool_complete_are_rejected(self):
        _,_,events=fixture(self.folder/'positive-client')
        for value in (None,0):
            e=copy.deepcopy(events[0]);e['complete_mysql_message']=value
            with self.assertRaises(ValueError):V.wire_oracle(e,RUN,'main','greeting')
        for raw in (b'\x01\0',b'\x10\0\0\0\x03'):
            with self.assertRaises(ValueError):V.classic_packets(raw)
        event=copy.deepcopy(events[0]);raw=bytes.fromhex(event['wire_hex']);raw=raw[:3]+b'\x01'+raw[4:]
        event.update(wire_hex=raw.hex(),wire_sha256=V.digest(raw),packets=V.classic_packets(raw))
        with self.assertRaises(ValueError):V.wire_oracle(event,RUN,'main','greeting')

    def test_full18_ledger_keeps_login6_query6_and_empty_resource_quit6(self):
        rows=native_rows(self.expected);original=copy.deepcopy(rows)
        actual,mapping,sha=self.snapshot(rows)
        self.assertEqual(rows,original);self.assertEqual(len(mapping),18)
        self.assertEqual(sum(RUN in r['request_resource'] for r in actual),12)
        self.assertEqual(sum('.'+RUN in r['request_resource'] for r in actual),6)
        self.assertEqual(sum(r['request_resource']=='' for r in actual),6)
        self.assertIs(type(actual[0]['flow_id']),int);self.assertEqual(sha,V.digest(V.canonical(actual)))

    def test_omitting_auxiliary_or_extra_rows_never_becomes_six_query_success(self):
        rows=native_rows(self.expected)
        with self.assertRaises(ValueError):self.snapshot([r for r in rows if r['request_type']=='COM_QUERY'])
        with self.assertRaises(ValueError):self.snapshot(rows+[dict(rows[0],id='17')])
        bad=[r for r in rows if not (r['tap_side']=='s-p' and r['request_type']=='COM_QUIT' and r['client_port']==30001)]
        next(r for r in bad if r['tap_side']=='c-p' and r['request_type']=='COM_QUERY' and r['client_port']==30003).update(type=0,response_status=5)
        with self.assertRaises(ValueError):self.snapshot(bad)

    def test_null_success_error1064_server_status_and_quit_no_response_are_strict(self):
        rows=native_rows(self.expected)
        for field,value,index in [('response_code',0,0),('response_code',None,7),('response_status',4,7),
                                  ('response_result','fabricated SQL result',1),('syscall_thread_1',12345,2),('response_duration',1,2)]:
            bad=copy.deepcopy(rows);bad[index][field]=value
            with self.assertRaises(ValueError,msg=field):self.snapshot(bad)

    def test_float_uint64_wrong_pid_source_or_request_id_are_rejected(self):
        for field,value in [('flow_id',float(2**64-101)),('flow_id',2**64),('process_id_0',777),('signal_source',0),('request_id',1)]:
            rows=native_rows(self.expected);rows[0][field]=value
            with self.assertRaises(ValueError,msg=field):self.snapshot(rows)

    def test_api_preserves_null_and_exact_uint64_details(self):
        rows=native_rows(self.expected);api=table(rows,V.API_COLUMNS)
        V.api_records(api,rows)
        api['values'][0][V.API_COLUMNS.index('response_code')]=0
        with self.assertRaises(ValueError):V.api_records(api,rows)

    def test_whole_marker_and_agent_population_sql_do_not_hide_auxiliary(self):
        calls=[];values=native_rows(self.expected)
        class Client:
            def query(inner,name,base,sql):
                calls.append((name,sql))
                if name.endswith('marker-count'):return table([{'records':12}],['records'])
                if name.endswith('marker-all'):return table([v for v in values if RUN in v['request_resource']])
                if name.endswith('negative-count'):return table([{'records':0}],['records'])
                if name.endswith('negative-all'):return table([])
                if name.endswith('owned-count'):return table([{'records':18}],['records'])
                if name.endswith('owned-all'):return table(values)
                raise RuntimeError('Stop before any actual source control query')
        args=SimpleNamespace(query_base='http://127.0.0.1:20819',console_base='http://127.0.0.1:20820',time_from=1700000000,time_to=1700000002)
        with self.assertRaises(RuntimeError):V.acceptance(Client(),args,RUN,'my-'+'b'*24,14,self.expected,{})
        self.assertEqual(calls[0][1],"SELECT Count(row) AS records FROM l7_flow_log WHERE request_resource LIKE '%"+RUN+"%'")
        self.assertEqual(calls[4][1],'SELECT Count(row) AS records FROM l7_flow_log WHERE agent_id=14 AND time>=1700000000 AND time<=1700000002')


if __name__=='__main__':unittest.main()
