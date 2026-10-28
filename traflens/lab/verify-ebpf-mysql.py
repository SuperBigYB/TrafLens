#!/usr/bin/env python3
"""Read-only complete MySQL classic/eBPF wire-fixture acceptance. Default is offline."""
import argparse
import errno
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import struct
import sys
import time
from typing import NamedTuple
import urllib.error
import urllib.parse
import urllib.request
MAX_BODY, MAX_ROWS, MAX_REQUESTS = 4 << 20, 64, 48
SCENARIOS=('main','error1064','control')
STAGES=('greeting','login','auth','query','result','quit','tcp-eof')
ROLES=tuple(phase+'-'+role for phase in ('positive','negative') for role in ('client','server'))
IDENTITY=('role','run','pid','tid','start_ticks','netns','pidns','comm')
COLUMNS=('id,start_us,end_us,time_epoch,flow_id,agent_id,signal_source,type,protocol,l7_protocol,tap_side,'
 'l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,request_id,request_type,request_resource,endpoint,'
 'request_domain,response_code,response_status,response_result,response_exception,response_duration,process_id_0,process_id_1,'
 'syscall_thread_0,syscall_thread_1,syscall_trace_id_request,syscall_trace_id_response').split(',')
TEXT={'tap_side','ip_0','ip_1','request_type','request_resource','endpoint','request_domain','response_result','response_exception'}
NULLABLE={'request_id','response_code'}
API_COLUMNS=('id,request_resource,request_type,response_code,response_result,response_exception,response_duration,l7_protocol,'
 'agent_id,protocol,type,signal_source,tap_side,response_status,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,server_port').split(',')
CAPS=0x0008a205
PLUGIN=b'mysql_native_password'
SCRAMBLE=b'12345678abcdefghijkl'
OK=b'\x00\x00\x00\x02\x00\x00\x00'
EOF=b'\xfe\x00\x00\x02\x00'


class AcceptanceContract(NamedTuple):
    stem: str = 'mysql'
    native_source: object = None
    native_sha256: object = None


DEFAULT_CONTRACT = AcceptanceContract()
ARCHIVED_SOURCE_SHA256 = 'd097917c05cfb5de5e8a0f5fe91cfc4181ae7653e4b3c11b4488333dab17c06f'
ARCHIVED_ARTIFACT_SHA256 = '1c17c2cec2808c20c220e64e483a4ce5e213c1b2f37959b4dd6c42e0f7163136'
OLD_NATIVE_SOURCE = '3dec20af5ce6ff25c696d136b5477f5310b4962c'
OLD_NATIVE_SHA256 = '8dd5ec668a09dcdac10068727fb47f282cf8091a93a11fb71cbbc33db3853763'


def validate_acceptance_contract(contract, executing=False):
    require(isinstance(contract, AcceptanceContract) and contract.stem in ('mysql', 'mysql-fast'),
            'Explicit supported MySQL acceptance contract required')
    if contract.stem == 'mysql':
        require(contract == DEFAULT_CONTRACT, 'Default MySQL acceptance contract cannot be overridden')
    elif executing:
        require(isinstance(contract.native_source, str) and re.fullmatch('[0-9a-f]{40}', contract.native_source)
                and contract.native_source != OLD_NATIVE_SOURCE
                and isinstance(contract.native_sha256, str) and re.fullmatch('[0-9a-f]{64}', contract.native_sha256)
                and contract.native_sha256 != OLD_NATIVE_SHA256,
                'Fast acceptance requires the independently qualified new native source and binary SHA')


def fast_capture_provenance(folder, meta, current, contract, report):
    validate_acceptance_contract(contract, executing=True)
    require(meta.get('unpaced_fast_candidate') is True and meta.get('pacing_only_qualification') is False
            and meta.get('archived_workload_source_sha256') == ARCHIVED_SOURCE_SHA256
            and meta.get('archived_workload_binary_sha256') == ARCHIVED_ARTIFACT_SHA256,
            'Explicit archived unpaced fast candidate metadata required')
    state = read_json(folder/'state.json')
    args = state.get('args', {})
    require(state.get('schema') == 'traflens.ebpf-mysql-fast.capture.v1' and state.get('output') == str(folder)
            and args.get('workload_sha256') == ARCHIVED_ARTIFACT_SHA256
            and isinstance(args.get('workload_source'), str)
            and digest(read_file(Path(args['workload_source']))) == ARCHIVED_SOURCE_SHA256
            and isinstance(args.get('workload_bin'), str)
            and digest(read_file(Path(args['workload_bin']), 64 << 20)) == ARCHIVED_ARTIFACT_SHA256,
            'Actual archived unpaced source/binary provenance differs')
    require(current.get('source') == contract.native_source and current.get('binary_sha256') == contract.native_sha256,
            'Actual Agent differs from independently qualified new native artifact')
    names = ('ebpf-mysql-fast.py', 'ebpf-mysql-diagnostic.py', 'ebpf-mysql.py', 'ebpf-dns.py',
             'verify-ebpf-mysql-fast.py', 'verify-ebpf-mysql.py', 'native-mysql-observer.py', 'ebpf-mysql-fast-observed.py')
    manifest = read_json(folder/'capture-source-sha256.json')
    here = Path(__file__).resolve().parent
    require(all(manifest.get(name) == digest(read_file(here/name)) for name in names),
            'Fast capture/acceptance public stage code SHA differs')
    observer = load_module('fast_acceptance_observer_ack', 'ebpf-mysql-diagnostic.py')
    proof_path = Path(current['folder'])/'coordinator-scope-proof.json'
    proof = read_json(proof_path)
    times = {}
    for stage in ('before-first-wire', 'after-final-wire'):
        gate = state.get('observer_gates', {}).get(stage, {})
        stage_folder = folder/'observer'/stage
        request = observer.private_json(stage_folder/'request.json')
        bound = request.get('agent', {})
        require(gate.get('status') == 'completed' and request.get('schema') == 'traflens.scoped-observer-request.v1'
                and request.get('stage') == stage and request.get('run') == meta['run']
                and re.fullmatch('[0-9a-f]{32}', request.get('nonce', ''))
                and bound.get('container_id') == current['id'] and bound.get('agent_id') == current['agent_id']
                and bound.get('hostname') == current['hostname'] and bound.get('scope_inode') == current['scope_inode']
                and bound.get('pid') == proof['agent_pid'] and re.fullmatch('[1-9][0-9]*', bound.get('start_ticks', ''))
                and bound.get('native_source_commit') == contract.native_source
                and bound.get('native_binary_sha256') == contract.native_sha256
                and bound.get('scope_proof_sha256') == digest(read_file(proof_path)),
                'Fast observer gate is not bound to this actual Agent/run/scope')
        ack = observer.validate_ack(stage_folder, request)
        require(gate.get('manifest_sha256') == ack['manifest_sha256'], 'Completed observer manifest SHA differs')
        times[stage] = {'requested': number(request.get('requested_at_unix_ns'), 1),
                        'acknowledged': number(ack.get('acknowledged_at_unix_ns'), 1)}
    report.update(unpaced_fast_contract=True, archived_workload_source_sha256=ARCHIVED_SOURCE_SHA256,
                  archived_workload_binary_sha256=ARCHIVED_ARTIFACT_SHA256,
                  native_source_commit=contract.native_source, native_binary_sha256=contract.native_sha256,
                  public_stage_sha256={name: manifest[name] for name in names}, observer_gate_times=times)


def require_unpaced_workload(folder, process, receipt):
    keys = ('pacing_only_qualification', 'pacing_ms', 'pacing_waits', 'pacing_duration_ns', 'waits_sha256')
    require(not (folder/'waits.jsonl').exists() and all(not any(k in value for k in keys) for value in (process, receipt)),
            'Fast acceptance forbids paced or fabricated partial pacing evidence')


def require(ok, message):
    if not ok:
        raise ValueError(message)


def number(value, low=0, high=2**64-1):
    require(type(value) is int or isinstance(value,str) and re.fullmatch(r'-?[0-9]+',value), 'Exact integer required; floats are forbidden')
    result = int(value)
    require(low <= result <= high, 'Integer outside finite range')
    return result


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()


def read_file(path, cap=MAX_BODY):
    require(path.is_absolute() and path == path.resolve() and path.is_file(), 'Canonical regular input required')
    with path.open('rb') as stream:
        data = stream.read(cap+1)
    require(len(data) <= cap, 'Input byte budget exceeded')
    return data


def decode(raw):
    return json.loads(raw,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON')))


def read_json(path):
    value = decode(read_file(path))
    require(isinstance(value,dict), 'Original JSON object required')
    return value


def save(path,value):
    with path.open('xb') as stream:
        stream.write(canonical(value)+b'\n')


def load_module(name,file):
    here = Path(__file__).resolve().parent
    sys.path.insert(0,str(here))
    spec = importlib.util.spec_from_file_location(name,here/file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loopback(value):
    parsed = urllib.parse.urlsplit(value)
    require(parsed.scheme == 'http' and parsed.username is None and parsed.password is None and not parsed.query
            and not parsed.fragment and parsed.path in ('','/') and parsed.hostname
            and ipaddress.ip_address(parsed.hostname).is_loopback and parsed.port and 1 <= parsed.port <= 65535,
            'Explicit credential-free numeric loopback HTTP base required')
    return value.rstrip('/')


def table(value,columns):
    require(isinstance(value,dict) and isinstance(value.get('columns'),list), 'Missing native/API result schema')
    names,values=value['columns'],value.get('values')
    if values is None:
        values=[]
    require(all(isinstance(n,str) for n in names) and len(names)==len(set(names)) and set(columns)<=set(names)
            and isinstance(values,list) and len(values)<=MAX_ROWS
            and all(isinstance(row,list) and len(row)==len(names) for row in values), 'Missing/duplicate/malformed/excessive result')
    return [dict(zip(names,row)) for row in values]


def endpoint(value):
    require(isinstance(value,dict) and set(value)=={'ip','port'}, 'Actual getsockname/getpeername endpoint required')
    require(value['ip'] in ('127.0.0.1','127.0.0.2'), 'Actual DNS socket escaped owned endpoints')
    return value['ip'],number(value['port'],1,65535)


class Client:
    def __init__(self,output,deadline):
        self.output,self.deadline,self.requests=output,deadline,0
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self,*_args,**_kwargs):return None
        self.opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())

    def request(self,name,base,path,fields,post=False):
        self.requests+=1;remaining=self.deadline-time.monotonic()
        require(self.requests<=MAX_REQUESTS and remaining>0, 'Finite DNS request/deadline exhausted')
        encoded=urllib.parse.urlencode(fields)
        req=urllib.request.Request(base+path+('' if post else '?'+encoded),data=encoded.encode() if post else None,
            headers={'Content-Type':'application/x-www-form-urlencoded','X-Org-Id':'1','X-User-Id':'1','X-User-Type':'1'})
        prefix='%02d-%s'%(self.requests,name)
        save(self.output/(prefix+'.request.json'),{'path':path,'fields':fields})
        try:response=self.opener.open(req,timeout=min(12,remaining))
        except urllib.error.HTTPError as error:response=error
        with response:status,raw=response.code,response.read(MAX_BODY+1)
        with (self.output/(prefix+'.body')).open('xb') as stream:stream.write(raw)
        require(status==200 and len(raw)<=MAX_BODY, 'DNS HTTP request failed/exceeded response budget; no fallback')
        value=decode(raw)
        require(isinstance(value,dict), 'Native/API JSON object required')
        return value

    def query(self,name,base,sql):
        value=self.request(name,base,'/v1/query/',{'db':'flow_log','sql':sql},True)
        require(value.get('OPT_STATUS')=='SUCCESS', 'Native DNS query did not succeed')
        return value.get('result')


def packet(payload,sequence):
    require(isinstance(payload,bytes) and 0<len(payload)<=65536 and type(sequence) is int and 0<=sequence<=255,
            'Finite classic packet required')
    return len(payload).to_bytes(3,'little')+bytes([sequence])+payload


def classic_packets(raw):
    require(isinstance(raw,bytes) and len(raw)<=4096, 'Actual MySQL wire event exceeds finite minimum')
    result=[];offset=0
    while offset<len(raw):
        require(offset+4<=len(raw), 'Truncated classic packet header')
        length=int.from_bytes(raw[offset:offset+3],'little');end=offset+4+length
        require(0<length<=65536 and end<=len(raw) and len(result)<5, 'Truncated/excessive classic payload or packet count')
        payload=raw[offset+4:end]
        result.append({'offset':offset,'payload_bytes':length,'sequence':raw[offset+3],'wire_bytes':length+4,
                       'payload_sha256':digest(payload),'wire_sha256':digest(raw[offset:end]),'payload_hex':payload.hex()})
        offset=end
    return result


def length_string(value):
    require(isinstance(value,bytes) and len(value)<251, 'Finite one-byte length encoded string required')
    return bytes([len(value)])+value


def expected_messages(run,scenario):
    require(re.fullmatch('my-[0-9a-f]{24}',run) and scenario in SCENARIOS, 'Exact fixed MySQL fixture marker required')
    literal=scenario+'.'+run;username='u_'+run
    greeting=(b'\x0a5.7.44\0'+struct.pack('<I',1)+SCRAMBLE[:8]+b'\0'
              +struct.pack('<HBHHB',CAPS&65535,45,2,CAPS>>16,21)+bytes(10)+SCRAMBLE[8:]+b'\0'+PLUGIN+b'\0')
    login=struct.pack('<IIB',CAPS,65536,45)+bytes(23)+username.encode()+b'\0\0'+PLUGIN+b'\0'
    query="SELECT '"+literal+"'"
    if scenario=='error1064':
        exception='fixture error1064 '+literal
        result=packet(b'\xff'+struct.pack('<H',1064)+b'#42000'+exception.encode(),1)
    else:
        exception=''
        column=b''.join(length_string(v) for v in (b'def',b'',b'',b'',literal.encode(),b''))
        column+=b'\x0c'+struct.pack('<HIBHB',45,1024,0xfd,0,0)+b'\0\0'
        result=b''.join((packet(b'\x01',1),packet(column,2),packet(EOF,3),packet(length_string(literal.encode()),4),packet(EOF,5)))
    return {'greeting':packet(greeting,0),'login':packet(login,1),'auth':packet(OK,2),'query':packet(b'\x03'+query.encode(),0),
            'result':result,'quit':packet(b'\x01',0),'tcp-eof':b'',
            'sql':query,'username':username,'exception':exception}


def wire_oracle(event,run,scenario,stage):
    text=event.get('wire_hex')
    require(isinstance(text,str) and len(text)%2==0 and re.fullmatch('[0-9a-f]*',text), 'Complete actual wire hex required')
    raw=bytes.fromhex(text);packets=classic_packets(raw)
    require(raw==expected_messages(run,scenario)[stage], 'Actual classic greeting/auth/query/result/QUIT/EOF bytes differ')
    eof=stage=='tcp-eof'
    require(event.get('bytes')==len(raw) and event.get('wire_sha256')==digest(raw) and event.get('syscalls')==1
            and event.get('errno')==0 and event.get('complete_wire_event') is True
            and event.get('complete_mysql_message') is (not eof) and event.get('eof_observed') is eof
            and event.get('wire_fixture') is True and event.get('sql_executed') is False
            and event.get('classic_packets')==len(packets) and event.get('packets')==packets,
            'Actual syscall/packet slicing/hash metadata differs; EOF is not a protocol response')
    return len(packets)


def pacing_oracle(folder,process,receipt,events,connections):
    """Validate the explicitly paced fixture without rewriting unpaced history."""
    flags=[value.get('pacing_only_qualification') for value in (process,receipt)]
    if flags==[None,None]:
        require(not (folder/'waits.jsonl').exists()
                and all(not any(k in value for k in ('pacing_ms','pacing_waits','pacing_duration_ns','waits_sha256'))
                        for value in (process,receipt)), 'Unpaced history cannot acquire partial pacing receipts')
        return False
    require(flags==[True,True] and all(value.get('pacing_ms')==100 for value in (process,receipt))
            and receipt.get('pacing_waits')==21, 'Explicit finite100ms pacing receipt required')
    raw=read_file(folder/'waits.jsonl');waits=[decode(line) for line in raw.splitlines()]
    require(len(waits)==21 and all(isinstance(wait,dict) for wait in waits)
            and receipt.get('waits_sha256')==digest(raw), 'All21 original hashed pacing waits required')
    begin,end=number(receipt.get('started_unix_ns'),1),number(receipt.get('finished_unix_ns'),1)
    mono_begin,mono_end=number(receipt.get('started_monotonic_ns'),1),number(receipt.get('finished_monotonic_ns'),1)
    require(0<=end-begin<=90*10**9 and 0<=mono_end-mono_begin<=90*10**9,
            'Paced fixture exceeded finite90second lifetime')
    total=0;previous_end=mono_begin
    for index,scenario in enumerate(SCENARIOS):
        group=events[index*7:index*7+7];conn=connections[index]
        close_begin=number(conn.get('close_started_monotonic_ns'),1)
        close_end=number(conn.get('close_finished_monotonic_ns'),1)
        close_real_begin=number(conn.get('close_started_unix_ns'),1)
        close_real_end=number(conn.get('close_finished_unix_ns'),1)
        require(number(group[-1]['finished_monotonic_ns'])<=close_begin<=close_end<=mono_end
                and number(group[-1]['finished_unix_ns'])<=close_real_begin<=close_real_end<=end,
                'Actual close must follow the real zero-byte TCP EOF before its wait')
        for offset in range(7):
            pos=index*7+offset;wait=waits[pos];is_close=offset==6
            event=None if is_close else group[offset]
            lower=close_end if is_close else number(event['finished_monotonic_ns'])
            lower_real=close_real_end if is_close else number(event['finished_unix_ns'])
            upper=(number(connections[index+1]['started_monotonic_ns']) if is_close and index<2
                   else mono_end if is_close else number(group[offset+1]['started_monotonic_ns']))
            upper_real=(number(connections[index+1]['started_unix_ns']) if is_close and index<2
                        else end if is_close else number(group[offset+1]['started_unix_ns']))
            start,finish=number(wait.get('started_monotonic_ns'),1),number(wait.get('finished_monotonic_ns'),1)
            real_start,real_finish=number(wait.get('started_unix_ns'),1),number(wait.get('finished_unix_ns'),1)
            duration=number(wait.get('actual_duration_ns'),100000000,90*10**9)
            require(wait.get('sequence')==pos+1 and wait.get('connection_index')==index+1
                    and wait.get('scenario')==scenario and wait.get('type')==('after-close' if is_close else 'after-data')
                    and wait.get('stage')==('close' if is_close else event['stage'])
                    and wait.get('wire_sequence')==(0 if is_close else event['sequence'])
                    and wait.get('pacing_ms')==100 and wait.get('complete') is True and wait.get('clock_errno')==0
                    and all(wait.get(k)==process[k] for k in IDENTITY), 'Pacing wait does not uniquely bind actual phase/process/connection')
            require(previous_end<=lower<=start<=finish<=upper and begin<=lower_real<=real_start<=real_finish<=upper_real<=end
                    and finish-start==duration, 'Actual pacing interval is short, overlaps IO/close or contradicts its duration')
            previous_end=finish;total+=duration
    require(number(receipt.get('pacing_duration_ns'),1)==total, 'Pacing total does not equal all21 actual waits')
    return True


def workload_oracle(folder,full_role,run):
    phase,role=full_role.split('-',1)
    process,receipt=read_json(folder/'process.json'),read_json(folder/'receipt.json')
    require(process.get('role')==role and process.get('run')==run and process.get('comm')==('mysqld' if role=='server' else 'traflens-mysql')
            and process.get('single_threaded') is True and process.get('sdk') is False and process.get('wire_fixture') is True
            and process.get('sql_executed') is False and process.get('empty_password') is True
            and process.get('protocol')=='real MySQL classic TCP' and process.get('native_source3_verified') is False,
            'Actual finite MySQL wire producer identity missing')
    require(number(process.get('pid'),1,2**32-1)==number(process.get('tid'),1,2**32-1)
            and re.fullmatch('[1-9][0-9]*',process.get('start_ticks',''))
            and re.fullmatch(r'net:\[[1-9][0-9]*\]',process.get('netns',''))
            and re.fullmatch(r'pid:\[[1-9][0-9]*\]',process.get('pidns','')), 'Actual C process lifetime/namespace missing')
    require(all(receipt.get(k)==process[k] for k in IDENTITY) and receipt.get('pass') is True
            and receipt.get('completed_requests')==receipt.get('expected_requests')==3 and receipt.get('wire_events')==21
            and receipt.get('wire_data_events')==18 and receipt.get('tcp_eof_events')==3 and receipt.get('classic_packets')==26
            and receipt.get('separate_tcp_connections') is True and receipt.get('port')==18080
            and receipt.get('owned_sockets_closed') is True and receipt.get('listener_closed') is True
            and receipt.get('single_threaded') is True and receipt.get('wire_fixture') is True and receipt.get('sql_executed') is False
            and receipt.get('sdk') is False and receipt.get('native_source3_verified') is False and receipt.get('error')=='',
            'Actual complete classic wire fixture receipt differs')
    begin,end=number(receipt.get('started_unix_ns'),1),number(receipt.get('finished_unix_ns'),1)
    require(0<=end-begin<=95*10**9, 'Finite C fixture lifetime exceeded')
    raw=read_file(folder/'wire.jsonl');events=[decode(line) for line in raw.splitlines()]
    require(len(events)==21 and all(isinstance(e,dict) for e in events), 'All21 actual greeting-through-EOF events required')
    connections=receipt.get('connections')
    require(isinstance(connections,list) and len(connections)==3, 'Three actual new TCP connects/accepts required')
    pairs={};last_mono=0;packet_count=0
    for index,scenario in enumerate(SCENARIOS):
        stages={}
        for offset,stage in enumerate(STAGES):
            event=events[index*7+offset]
            sends=stage in ('login','query','quit') if role=='client' else stage in ('greeting','auth','result')
            operation='send' if sends else 'recv'
            require(event.get('sequence')==index*7+offset+1 and event.get('scenario')==scenario and event.get('stage')==stage
                    and event.get('operation')==operation and all(event.get(k)==process[k] for k in IDENTITY),
                    'Actual ordered wire stage/process identity differs')
            m0,m1=number(event.get('started_monotonic_ns'),1),number(event.get('finished_monotonic_ns'),1)
            require(last_mono<=m0<=m1 and begin<=number(event.get('started_unix_ns'),1)<=number(event.get('finished_unix_ns'),1)<=end,
                    'Actual C stage time/order differs')
            last_mono=m1;packet_count+=wire_oracle(event,run,scenario,stage);stages[stage]=event
        first=stages['greeting'];local,peer=endpoint(first.get('local')),endpoint(first.get('peer'))
        require(all(endpoint(e.get('local'))==local and endpoint(e.get('peer'))==peer for e in stages.values()),
                'Classic conversation changed its actual socket tuple')
        client,server=(local,peer) if role=='client' else (peer,local)
        require(client[0]=='127.0.0.1' and server==('127.0.0.2',18080), 'Actual classic tuple escaped owned endpoints')
        conn=connections[index]
        require(conn.get('scenario')==scenario and conn.get('operation')==('connect' if role=='client' else 'accept')
                and number(conn.get('syscalls'),1,1 if role=='client' else 16)>0
                and conn.get('initial_errno') in ((0,errno.EINPROGRESS) if role=='client' else (0,))
                and conn.get('complete') is True and conn.get('closed') is True and (role!='client' or conn.get('shutdown_write') is True)
                and endpoint(conn.get('local'))==local and endpoint(conn.get('peer'))==peer
                and all(number(e.get('fd'))==number(conn.get('fd')) for e in stages.values()), 'Actual TCP connect/close/half-close proof differs')
        pairs[scenario]={'tuple':(*client,*server),'stages':stages,'messages':expected_messages(run,scenario)}
    require(packet_count==26 and len({v['tuple'] for v in pairs.values()})==3, 'All classic packets/independent TCP tuples were not retained')
    pacing_oracle(folder,process,receipt,events,connections)
    return process,receipt,pairs,digest(raw)


def application_oracle(folder,report,contract=DEFAULT_CONTRACT):
    validate_acceptance_contract(contract, executing=True)
    meta,result=read_json(folder/'ingestion-metadata.json'),read_json(folder/'result.json')
    run,negative=meta.get('run'),meta.get('negative_run')
    require(isinstance(run,str) and re.fullmatch('my-[0-9a-f]{24}',run) and isinstance(negative,str)
            and re.fullmatch('my-[0-9a-f]{24}',negative) and run!=negative, 'Independent actual MySQL markers required')
    agent=number(meta.get('agent_id'),1,65535)
    require(meta.get('schema')=='traflens.ebpf-'+contract.stem+'.capture.v1' and meta.get('runtime_receipts_required') is True
            and meta.get('integration_mode')=='kernel_mysql' and meta.get('signal_source')==3 and meta.get('l7_protocol')==60
            and meta.get('transport')=='tcp' and meta.get('port')==18080, 'Public MySQL capture mode differs')
    require(result.get('schema')==meta['schema'] and result.get('run')==run and result.get('negative_run')==negative
            and result.get('agent_id')==agent and result.get('pass_execution') is True and result.get('pass') is True
            and result.get('cleaned') is True and result.get('collector_stopped') is True
            and result.get('lease_restored') is True and result.get('controller_cleaned') is True
            and result.get('positive_queries')==result.get('negative_queries')==3 and result.get('expected_query_observations')==6
            and not result.get('cleanup_errors') and result.get('error') in (None,''), 'Public MySQL execution/restoration did not complete')
    require(all(result.get('worker_exits',{}).get(role)=={'exit_code':0,'oom':False} for role in ROLES),
            'Actual MySQL worker exit/OOM proof failed')
    restoration=read_json(folder/'scope-restoration.json')
    for key in ('pass','scope_only','external_agent_exit_and_inventory_restored','tracer_exit_confirmed_before_namespace_release',
                'namespace_pins_released','original_host_bpf_inventory_restored','original_tracefs_restored',
                'preexisting_containers_still_running','released_by_coordinator','scope_proof_approved'):
        require(restoration.get(key) is True, 'Original namespace/BPF restoration failed: '+key)
    scope,current=read_json(folder/'scope-runtime.json'),read_json(folder/'agent/current.json')
    require(scope.get('schema')=='traflens.ebpf-'+contract.stem+'.scope.v1' and scope.get('agent_container_id')==current.get('id')
            and re.fullmatch('[0-9a-f]{64}',current.get('id','')) and current.get('agent_id')==agent
            and scope.get('lease_path')==current.get('lease_path'), 'Public MySQL Agent/namespace lease identity differs')
    runtime=Path(current['folder'])
    require(runtime.is_absolute() and runtime==runtime.resolve() and runtime.parent==folder/'agent', 'Exact private Agent runtime required')
    proof=read_json(runtime/'coordinator-scope-proof.json')
    require(proof.get('agent_container_id')==current['id'] and proof.get('agent_binary_sha256')==current.get('binary_sha256')
            and proof.get('source_commit')==current.get('source') and proof.get('af_packet_socket_count')==0
            and isinstance(proof.get('agent_scope_fds'),list) and 1<=len(proof['agent_scope_fds'])<=32
            and all(type(fd) is int and fd>=0 for fd in proof['agent_scope_fds']) and number(proof.get('agent_pid'),1)>0
            and all(proof.get(k) is True for k in ('scope_fd_pinned','safe_profile_verified','native_collector_started','fresh_three_listener_sync')),
            'Actual native collector/FD/no-AF_PACKET readiness proof failed')
    if contract.stem == 'mysql-fast':
        fast_capture_provenance(folder, meta, current, contract, report)
    exit_state,stopped=read_json(runtime/'exit-state.json'),read_json(runtime/'stopped.json')
    require(exit_state.get('ExitCode')==0 and exit_state.get('OOMKilled') is False and exit_state.get('Running') is False
            and all(stopped.get(k) is True for k in ('agent_stopped','container_removed','bpf_inventory_restored','tracefs_restored')),
            'Actual native Agent did not exit and restore cleanly')
    helpers=load_module('dns_runtime_pure_helpers','verify-ebpf-association.py')
    supervisor=number(scope.get('supervisor_pid'),1)
    for phase in ('positive','negative'):
        anchor=scope.get(phase,{})
        require(re.fullmatch('[0-9a-f]{64}',anchor.get('container_id','')) and number(anchor.get('pid'),1)>0
                and re.fullmatch('[1-9][0-9]*',str(anchor.get('start_ticks','')))
                and helpers.namespace(anchor.get('netns'),'net')==helpers.namespace(anchor.get('inode'),'net')
                and helpers.namespace(anchor.get('pidns'),'pid') and isinstance(anchor.get('source'),str)
                and re.fullmatch('/proc/%d/fd/[0-9]+'%supervisor,anchor['source']), 'Actual held namespace anchor missing')
    positive_inode=number(scope['positive']['inode'],1,0xffffffff)
    require(scope['positive']['container_id']!=scope['negative']['container_id']
            and positive_inode!=number(scope['negative']['inode'],1,0xffffffff), 'Positive/negative namespaces were not isolated')
    abi_path=Path(__file__).with_name('managed-http-scope-abi.json')
    validator=load_module('dns_scope_pure_validator','managed_http_scope_validation.py')
    config=validator.validate_scope_proof(read_json(runtime/'scope-map.json'),positive_inode,read_json(abi_path),digest(read_file(abi_path)))
    require(config==proof.get('scope_map'), 'Actual raw kernel scope map differs from approved collector proof')
    profile=read_json(Path(current['prepared'])/'group-profile.json')
    require(profile==meta.get('profile') and profile['processors']['request_log']['application_protocol_inference']['enabled_protocols']==['MySQL']
            and profile['processors']['request_log']['filters']['port_number_prefilters']=={'MySQL':'18080'}
            and 'MySQL' not in profile['processors']['request_log'].get('tag_extraction',{}).get('obfuscate_protocols',['Redis'])
            and profile['inputs']['proc']['enabled'] is False and profile['inputs']['integration']['enabled'] is False
            and profile['inputs']['ebpf']['profile']['on_cpu']['disabled'] is True
            and profile['inputs']['ebpf']['profile']['unwinding']['dwarf_disabled'] is True, 'MySQL-only safe profile differs')
    shared=load_module('mysql_actual_worker_helpers','verify-ebpf-dns.py')
    policy=shared.WorkerContract('traflens.ebpf-'+contract.stem+'.worker-runtime.v1',
                               'traflens.ebpf-'+contract.stem+'.worker','mysqld','traflens-mysql')
    processes,pairs,hashes,workers,lifetimes,pacing={}, {}, {}, [], [], []
    for full_role in ROLES:
        phase,_=full_role.split('-',1);nonce=run if phase=='positive' else negative
        process,receipt,wire,sha=workload_oracle(folder/full_role,full_role,nonce)
        if contract.stem == 'mysql-fast':
            require_unpaced_workload(folder/full_role,process,receipt)
        require(process['netns']==helpers.namespace(scope[phase]['inode'],'net')
                and process['pidns']==os.readlink('/proc/1/ns/pid'), 'Actual worker escaped declared isolated NET/host PID namespace')
        processes[full_role],pairs[full_role],hashes[full_role]=process,wire,sha
        pacing.append(receipt.get('pacing_only_qualification') is True)
        lifetimes.append((number(receipt['started_unix_ns'],1),number(receipt['finished_unix_ns'],1)))
        workers.append(shared.checked_worker_runtime(folder,full_role,run,nonce,process,scope,helpers,policy))
    require(len({p['pid'] for p in processes.values()})==4 and len({w[0] for w in workers})==4
            and len({w[1] for w in workers})==len({w[2] for w in workers})==1, 'Four actual isolated workers with one exact executable/image required')
    if contract.stem == 'mysql-fast':
        require({w[2] for w in workers} == {ARCHIVED_ARTIFACT_SHA256}, 'Actual worker runtime executable is not the archived unpaced fixture')
    require(all(pacing) or not any(pacing), 'Four worker pacing qualifications must agree')
    require(type(proof.get('observed_at_unix')) in (int,float) and type(stopped.get('observed_at_unix')) in (int,float)
            and 0<proof['observed_at_unix']<=min(v[0] for v in lifetimes)/10**9
            and stopped['observed_at_unix']>=max(v[1] for v in lifetimes)/10**9,
            'Actual MySQL workers did not run after kernel readiness and before Agent restoration')
    if contract.stem == 'mysql-fast':
        gates = report['observer_gate_times']
        require(gates['before-first-wire']['acknowledged'] <= min(v[0] for v in lifetimes)
                and gates['after-final-wire']['requested'] >= max(v[1] for v in lifetimes),
                'Actual fast worker lifetime escaped the acknowledged observer stages')
    expected=[]
    for phase in ('positive','negative'):
        for scenario in SCENARIOS:
            client,server=pairs[phase+'-client'][scenario],pairs[phase+'-server'][scenario]
            require(client['tuple']==server['tuple'] and all(client['stages'][stage]['wire_sha256']==server['stages'][stage]['wire_sha256']
                    and client['stages'][stage]['wire_hex']==server['stages'][stage]['wire_hex']
                    and client['stages'][stage]['local']==server['stages'][stage]['peer']
                    and client['stages'][stage]['peer']==server['stages'][stage]['local'] for stage in STAGES),
                    'All real MySQL classic peer bytes/EOF/socket tuples differ')
            if phase=='positive':
                for role,side in (('client','c-p'),('server','s-p')):
                    item=pairs[phase+'-'+role][scenario]
                    for request_stage,response_stage,kind in (('login','auth','login'),('query','result','query'),('quit',None,'quit')):
                        request=item['stages'][request_stage]
                        response=item['stages'][response_stage] if response_stage else None
                        expected.append({'scenario':scenario,'side':side,'kind':kind,'tuple':item['tuple'],
                          'pid':processes[phase+'-'+role]['pid'],'tid':processes[phase+'-'+role]['tid'],
                          'request':request,'response':response,'messages':item['messages'],
                          'call_us':(number(response['finished_monotonic_ns'])-number(request['started_monotonic_ns'])+999)//1000 if response else 0})
    report.update(scope_receipt_passed=True,actual_raw_scope_map_verified=True,actual_worker_runtime_receipts_passed=True,
                  actual_wire_sha256=hashes,application_positive_queries=3,application_negative_queries=3,
                  paced_finite_wire_qualification=all(pacing),pacing_ms=100 if all(pacing) else 0,
                  pacing_waits_per_worker=21 if all(pacing) else 0,
                  unpaced_completeness_proven=False,
                  original_runtime_sha256={p.name:digest(read_file(p)) for p in (folder/'scope-runtime.json',runtime/'coordinator-scope-proof.json',runtime/'scope-map.json')})
    return run,negative,agent,expected


def record_contract(item):
    kind=item['kind'];messages=item['messages']
    return {'request_type':{'login':'','query':'COM_QUERY','quit':'COM_QUIT'}[kind],
            'request_resource':('Login username: '+messages['username']) if kind=='login' else messages['sql'] if kind=='query' else '',
            'response_code':1064 if kind=='query' and item['scenario']=='error1064' else None,
            'response_status':3 if kind=='query' and item['scenario']=='error1064' else 0,
            'response_result':'','response_exception':messages['exception'] if kind=='query' else ''}


def native_population(count_document,document,expected,agent,start,end):
    counts=table(count_document,['records']);actual=table(document,COLUMNS)
    require(len(counts)==1 and number(counts[0]['records'])==len(actual)==len(expected)==18,
            'Entire Agent/time population does not explain all18 login/query/QUIT observations')
    seen,mapping=set(),{}
    for row in actual:
        require(isinstance(row['id'],str) and number(row['id'],1) not in seen, 'Missing/duplicate exact observation ID')
        seen.add(number(row['id'],1))
        for field in COLUMNS:
            if field in TEXT:require(isinstance(row[field],str), 'Missing original text: '+field)
            elif field in NULLABLE and row[field] is None:continue
            else:number(row[field],-2**31 if field.startswith('l3_epc') else 0,2**31-1 if field.startswith('l3_epc') else 2**64-1)
        require(number(row['agent_id'])==agent and number(row['signal_source'])==3 and number(row['type'])==2
                and number(row['protocol'])==6 and number(row['l7_protocol'])==60 and row['tap_side'] in ('c-p','s-p'),
                'Entire Agent/window contains an unexplained source/protocol/record/Agent')
        begin,finish=number(row['start_us'],1),number(row['end_us'],1)
        require(begin<=finish and start<=finish//10**6<=end and number(row['time_epoch'])==finish//10**6,
                'Original L7 event time contradicts explicit window/epoch')
        number(row['flow_id'],1)
        local=number(row['process_id_0' if row['tap_side']=='c-p' else 'process_id_1'],1,2**32-1)
        tup=(row['ip_0'],number(row['client_port'],1,65535),row['ip_1'],number(row['server_port'],1,65535))
        candidates=[item for item in expected if item['side']==row['tap_side'] and item['tuple']==tup and item['pid']==local
                    and row['request_type']==record_contract(item)['request_type'] and row['request_resource']==record_contract(item)['request_resource']]
        require(len(candidates)==1, 'Observation cannot uniquely map to actual wire phase/tuple/local PID/side')
        item=candidates[0];key=item['scenario'],item['side'],item['kind']
        require(key not in mapping and number(row['syscall_thread_0'],1)==item['tid'], 'Wire phase duplicate or request syscall TID differs')
        require((row['request_id'] is None or number(row['request_id'])==0), 'Classic packet sequence is not a prepared-statement request ID')
        for field,value in record_contract(item).items():
            observed=row[field] if field in TEXT or value is None else number(row[field])
            require(observed==value, 'Native field differs from independent actual wire: '+field)
        require(row['request_domain']=='', 'MySQL classic fixture has no recorded request domain')
        duration=number(row['response_duration'])
        if item['kind']=='quit':
            require(duration==0 and begin==finish and number(row['syscall_thread_1'])==0
                    and number(row['syscall_trace_id_response'])==0,
                    'Standalone request-only COM_QUIT acquired an invented response/RRT')
        else:
            require(number(row['syscall_thread_1'],1)==item['tid'] and abs(duration-(finish-begin))<=1
                    and duration<=item['call_us']+1, 'Native paired RRT/TID contradicts actual C call interval')
        mapping[key]=row
    require(len(mapping)==18, 'Actual phase ledger incomplete')
    for scenario in SCENARIOS:
        for side in ('c-p','s-p'):
            require(len({number(mapping[(scenario,side,kind)]['flow_id'],1) for kind in ('login','query','quit')})==1,
                    'One actual TCP conversation has inconsistent native local flow IDs')
    actual.sort(key=lambda row:number(row['id'],1))
    return actual,mapping,digest(canonical(actual))


def api_records(document,expected):
    actual=table(document,API_COLUMNS)
    require(len(actual)==len(expected), 'API all-phase/marked/query population differs')
    originals={r['id']:r for r in expected};seen=set()
    for row in actual:
        require(isinstance(row['id'],str) and row['id'] in originals and row['id'] not in seen, 'API changed/duplicated UInt64 ID')
        seen.add(row['id']);native=originals[row['id']]
        for field in API_COLUMNS:
            if field=='response_code' and native[field] is None:require(row[field] is None, 'Successful MySQL NULL error code became a numeric code')
            elif field in TEXT or field=='id':require(row[field]==native[field], 'API changed original field: '+field)
            else:require(number(row[field],-2**31 if field.startswith('l3_epc') else 0)==number(native[field],-2**31 if field.startswith('l3_epc') else 0),
                         'API changed original exact integer: '+field)


def acceptance(client,args,run,negative,agent,expected,report):
    projection=('toString(_id) AS id,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,'
                'toUnixTimestamp(time) AS time_epoch,toString(flow_id) AS flow_id,'+','.join(COLUMNS[5:]))
    marker="request_resource LIKE '%%%s%%'"%run
    owned='agent_id=%d AND time>=%d AND time<=%d'%(agent,args.time_from,args.time_to)
    def population(label,where):
        count=client.query(label+'-count',args.query_base,'SELECT Count(row) AS records FROM l7_flow_log WHERE '+where)
        rows=client.query(label+'-all',args.query_base,'SELECT '+projection+' FROM l7_flow_log WHERE '+where+' ORDER BY _id ASC LIMIT 65')
        return count,rows
    def snapshot(label):
        mc,mr=population(label+'-marker',marker)
        nc,nr=population(label+'-negative',"request_resource LIKE '%%%s%%'"%negative)
        oc,orr=population(label+'-owned',owned)
        counts,negative_rows=table(nc,['records']),table(nr,COLUMNS)
        require(len(counts)==1 and number(counts[0]['records'])==len(negative_rows)==0, 'Outside namespace marker was stored')
        actual,mapping,fingerprint=native_population(oc,orr,expected,agent,args.time_from,args.time_to)
        marker_rows=table(mr,COLUMNS);marker_count=table(mc,['records'])
        retained=sorted((row for row in actual if run in row['request_resource']),key=lambda r:number(r['id'],1))
        require(len(marker_count)==1 and number(marker_count[0]['records'])==len(marker_rows)==len(retained)==12
                and sorted(marker_rows,key=lambda r:number(r['id'],1))==retained,
                'Unfiltered whole marker did not exactly retain login+query and leave only six empty-resource QUIT records')
        return actual,mapping,fingerprint
    original,mapping,fingerprint=snapshot('first')
    for source,count in ((3,12),(0,0),(4,0)):
        control=table(client.query('source-'+str(source),args.query_base,'SELECT Count(row) AS records FROM l7_flow_log WHERE '+marker+' AND signal_source='+str(source)),['records'])
        require(len(control)==1 and number(control[0]['records'])==count, 'Whole marker source control differs')
    base={'from':args.time_from,'to':args.time_to,'agent':agent,'source':3,'proto':60,'session':1,'limit':64}
    api_records(client.request('api-all-phases',args.console_base,'/api/requests',base),original)
    marked=[r for r in original if run in r['request_resource']]
    queries=[r for r in original if r['request_type']=='COM_QUERY']
    require(len(queries)==6, 'Exactly six real query observations required as subset of all18')
    api_records(client.request('api-marker',args.console_base,'/api/requests',dict(base,q=run)),marked)
    api_records(client.request('api-queries',args.console_base,'/api/requests',dict(base,q='.'+run)),queries)
    for index,row in enumerate(original):
        api_records(client.request('api-detail-'+str(index+1),args.console_base,'/api/requests',dict(base,id=row['id'],limit=2)),[row])
    for source in (0,4):
        empty=client.request('api-empty-source-'+str(source),args.console_base,'/api/requests',dict(base,source=source,q=run))
        require(isinstance(empty.get('columns'),list) and empty.get('values')==[], 'API source control is not explicit empty')
    final,_,last=snapshot('second')
    require(final==original and last==fingerprint, 'All original IDs/raw fields changed across non-atomic reads')
    report.update(storage_acceptance_passed=True,whole_marker_reads=2,whole_agent_window_reads=2,all_observations=18,
        marked_observations=12,query_observations=6,login_observations=6,standalone_quit_observations=6,negative_stored_records=0,
        source_counts={'3':12,'0':0,'4':0},exact_detail_reads=18,original_projection_sha256=fingerprint,
        original_ids=[row['id'] for row in original],request_count=client.requests,sql_executed=False,
        counting='18 actual login/query/QUIT observations for three positive fixture conversations; not eighteen business SQL requests',
        response_code_semantics='NULL for OK/EOF/QUIT, ERR1064 status3; not HTTP00/fe codes',
        query_atomicity='Two entire unchanged marker and Agent/window populations bracket API reads; no database snapshot transaction')


def main(argv=None,contract=DEFAULT_CONTRACT):
    validate_acceptance_contract(contract)
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--capture-dir',type=Path)
    parser.add_argument('--query-base');parser.add_argument('--console-base')
    parser.add_argument('--from',dest='time_from',type=int);parser.add_argument('--to',dest='time_to',type=int)
    parser.add_argument('--agent',type=int);parser.add_argument('--output',type=Path)
    if contract.stem == 'mysql-fast':
        parser.add_argument('--native-source');parser.add_argument('--native-sha256')
    args=parser.parse_args(argv)
    if not args.execute:
        plan={'execute':False,'reads_files':False,'starts_network':False,'new_capture':False,'new_ingestion':False,
              'max_rows':MAX_ROWS,'max_requests':MAX_REQUESTS,'total_seconds':60,'per_request_seconds':12,'legacy_fallback':False}
        if contract.stem == 'mysql-fast':
            plan.update(unpaced_fast_contract=True, unpaced_completeness_proven=False, pacing_only_qualification=False,
                        requires_independently_qualified_native_source_and_sha256=True)
        print(json.dumps(plan))
        return 0
    if contract.stem == 'mysql-fast':
        contract=contract._replace(native_source=args.native_source,native_sha256=args.native_sha256)
    validate_acceptance_contract(contract,executing=True)
    args.query_base,args.console_base=loopback(args.query_base),loopback(args.console_base)
    folder,output=args.capture_dir,args.output
    require(folder and folder.is_absolute() and folder==folder.resolve() and folder.is_dir()
            and folder.stat().st_uid==os.geteuid() and not folder.stat().st_mode&0o077, 'Owned canonical private capture required')
    require(type(args.time_from) is int and type(args.time_to) is int and 0<args.time_from<=args.time_to
            and args.time_to-args.time_from<60, 'At most60 inclusive event-time seconds required')
    require(output and output.is_absolute() and output==output.resolve() and not output.exists()
            and output.parent.stat().st_uid==os.geteuid() and not output.parent.stat().st_mode&0o077, 'Fresh output below owned private parent required')
    os.umask(0o077);output.mkdir(mode=0o700);started=time.monotonic()
    report={'passed':False,'new_capture':False,'new_ingestion':False,'source':'native eBPF MySQL classic TCP source3',
            'limitations':'Finite no-SQL-execution wire fixture; no real database authentication, executed SQL, complete MySQL compatibility or performance parity.'}
    def expired(*_):raise TimeoutError('Finite60second MySQL acceptance deadline exceeded')
    previous=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,60)
    try:
        run,negative,agent,expected=application_oracle(folder,report,contract)
        require(args.agent is None or args.agent==agent, 'Explicit Agent differs from original capture')
        report.update(run=run,negative_run=negative,agent_id=agent,time_from=args.time_from,time_to=args.time_to)
        acceptance(Client(output,started+60),args,run,negative,agent,expected,report);report['passed']=True
        if contract.stem == 'mysql-fast':
            report.update(unpaced_completeness_proven=True,pacing_only_qualification=False,
                          performance_measurement=False,qualification='One bounded unpaced fixture slice with independently qualified native artifact')
    except Exception as error:report['error']=type(error).__name__+': '+str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        report['elapsed_seconds']=round(time.monotonic()-started,3);save(output/'result.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('original_ids','actual_wire_sha256')}))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
