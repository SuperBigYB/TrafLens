#!/usr/bin/env python3
"""Read-only finite DNS/TCP source3 acceptance; default is an offline plan."""
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
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY, MAX_ROWS, MAX_REQUESTS = 4 << 20, 64, 32
SCENARIOS = ('main', 'nxdomain', 'control')
ROLES = tuple(phase+'-'+role for phase in ('positive','negative') for role in ('client','server'))
COLUMNS = ('id,start_us,end_us,time_epoch,flow_id,agent_id,signal_source,type,protocol,l7_protocol,tap_side,'
           'l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,request_id,request_type,request_resource,'
           'endpoint,request_domain,response_code,response_status,response_result,response_duration,process_id_0,process_id_1,'
           'syscall_thread_0,syscall_thread_1,syscall_trace_id_request,syscall_trace_id_response').split(',')
TEXT = {'tap_side','ip_0','ip_1','request_type','request_resource','endpoint','request_domain','response_result'}
IDENTITY = ('role','run','pid','tid','start_ticks','netns','pidns')
API_COLUMNS = ('id,request_resource,request_type,response_code,response_result,response_duration,l7_protocol,agent_id,'
               'protocol,type,signal_source,tap_side,response_status,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,server_port').split(',')


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


def dns_name(message,offset,seen=None):
    seen=set() if seen is None else set(seen)
    require(offset not in seen and len(seen)<16, 'Cyclic/excessive DNS compression')
    seen.add(offset)
    labels=[]
    cursor=offset
    while True:
        require(cursor<len(message), 'Truncated DNS name')
        length=message[cursor]
        cursor+=1
        if length==0:
            break
        if length&0xc0==0xc0:
            require(cursor<len(message), 'Truncated DNS pointer')
            suffix,_=dns_name(message,((length&0x3f)<<8)|message[cursor],seen)
            labels.append(suffix)
            cursor+=1
            break
        require(1<=length<=63 and cursor+length<=len(message), 'Invalid DNS label')
        label=message[cursor:cursor+length].decode('ascii')
        require(re.fullmatch('[a-z0-9-]+',label), 'Unexpected actual fixture DNS label')
        labels.append(label)
        cursor+=length
    name='.'.join(labels)
    require(0<len(name)<=253, 'Invalid finite DNS qname')
    return name,cursor


def parse_frame(raw,run,scenario,response):
    require(isinstance(raw,bytes) and 14<=len(raw)<=512 and struct.unpack('!H',raw[:2])[0]==len(raw)-2,
            'Actual full TCP DNS frame is absent/excessive')
    message=raw[2:]
    qid,flags,qd,an,ns,ar=struct.unpack('!6H',message[:12])
    index=SCENARIOS.index(scenario)
    expected_code=3 if scenario=='nxdomain' else 0
    require(qid==0xb101+index and flags==(0x8180|expected_code if response else 0x0100)
            and qd==1 and ns==ar==0 and an==(1 if response and scenario!='nxdomain' else 0),
            'Actual DNS header/QID/RCODE differs from independent scenario')
    name,offset=dns_name(message,12)
    require(name==scenario+'.'+run+'.traflens.invalid' and offset+4<=len(message)
            and struct.unpack('!HH',message[offset:offset+4])==(1,1), 'Actual DNS question is not the unique IN A request')
    offset+=4
    answers=[]
    for _ in range(an):
        owner,offset=dns_name(message,offset)
        require(offset+10<=len(message), 'Truncated DNS answer')
        kind,klass,ttl,length=struct.unpack('!HHIH',message[offset:offset+10]);offset+=10
        require(owner==name and kind==klass==1 and ttl==60 and length==4 and offset+4<=len(message),
                'Actual DNS answer RR differs')
        address=str(ipaddress.IPv4Address(message[offset:offset+4]));offset+=4
        require(address==('198.18.0.41' if scenario=='main' else '198.18.0.42'), 'Actual owned answer address differs')
        answers.append('A='+address+' TTL=60')
    require(offset==len(message), 'Trailing/partial actual DNS bytes')
    return {'request_id':qid,'request_type':'A','request_resource':name,'endpoint':name,'request_domain':name,
            'response_code':expected_code if response else 0,'response_status':4 if expected_code else 0,
            'response_result':'; '.join(answers),'answers':an,'message_bytes':len(message)}


def wire_oracle(event,run,scenario,response):
    text=event.get('wire_hex')
    require(isinstance(text,str) and len(text)%2==0 and re.fullmatch('[0-9a-f]+',text), 'Actual complete DNS wire hex required')
    raw=bytes.fromhex(text)
    parsed=parse_frame(raw,run,scenario,response)
    require(event.get('bytes')==len(raw) and event.get('wire_sha256')==digest(raw) and event.get('syscalls')==1
            and event.get('errno')==0 and event.get('complete_dns_frame') is True
            and event.get('framing')=='tcp-u16-length-prefix' and event.get('metadata_decoded_from_complete_wire') is True
            and event.get('dns_message_bytes')==parsed['message_bytes'] and event.get('query_name')==parsed['request_resource']
            and event.get('transaction_id')==parsed['request_id'] and event.get('query_type')=='A'
            and event.get('rcode')==parsed['response_code'] and event.get('answers')==parsed['answers'],
            'Actual wire SHA/length/decoded metadata differs')
    return parsed


def workload_oracle(folder,full_role,run):
    phase,role=full_role.split('-',1)
    process,receipt=read_json(folder/'process.json'),read_json(folder/'receipt.json')
    require(process.get('role')==role and process.get('run')==run and process.get('single_threaded') is True
            and process.get('sdk') is False and process.get('protocol')=='real TCP DNS'
            and process.get('native_source3_verified') is False, 'Actual DNS C process identity missing')
    require(number(process.get('pid'),1,2**32-1)==number(process.get('tid'),1,2**32-1)
            and re.fullmatch('[1-9][0-9]*',process.get('start_ticks',''))
            and re.fullmatch(r'net:\[[1-9][0-9]*\]',process.get('netns',''))
            and re.fullmatch(r'pid:\[[1-9][0-9]*\]',process.get('pidns','')), 'Actual single-threaded process lifetime/namespace differs')
    require(all(receipt.get(k)==process[k] for k in IDENTITY) and receipt.get('pass') is True
            and receipt.get('completed_requests')==receipt.get('expected_requests')==3 and receipt.get('wire_events')==6
            and receipt.get('separate_tcp_connections') is True and receipt.get('port')==18080
            and receipt.get('owned_sockets_closed') is True and receipt.get('listener_closed') is True
            and receipt.get('single_threaded') is True and receipt.get('sdk') is False
            and receipt.get('native_source3_verified') is False and receipt.get('error')=='', 'Actual C socket completion receipt differs')
    begin,end=number(receipt.get('started_unix_ns'),1),number(receipt.get('finished_unix_ns'),1)
    require(0<=end-begin<=95*10**9, 'Actual DNS C lifetime exceeded finite bound')
    raw=read_file(folder/'wire.jsonl');events=[decode(line) for line in raw.splitlines()]
    require(len(events)==6 and all(isinstance(e,dict) for e in events), 'Exactly six complete actual wire events required')
    connections=receipt.get('connections')
    require(isinstance(connections,list) and len(connections)==3, 'Three actual new TCP connects/accepts required')
    pairs={};last_mono=0
    for index,scenario in enumerate(SCENARIOS):
        first,second=events[index*2:index*2+2]
        for event,response in ((first,False),(second,True)):
            # Client sends request then receives response; server does the inverse.
            operation='recv' if (role=='client' and response) or (role=='server' and not response) else 'send'
            require(event.get('sequence')==index*2+(2 if response else 1) and event.get('scenario')==scenario
                    and event.get('operation')==operation and event.get('response') is response
                    and all(event.get(k)==process[k] for k in IDENTITY), 'Actual ordered DNS event identity/direction differs')
            m0,m1=number(event.get('started_monotonic_ns'),1),number(event.get('finished_monotonic_ns'),1)
            require(last_mono<=m0<=m1 and begin<=number(event.get('started_unix_ns'),1)<=number(event.get('finished_unix_ns'),1)<=end,
                    'Actual C syscall ordering/time differs')
            last_mono=m1
            wire_oracle(event,run,scenario,response)
        local,peer=endpoint(first.get('local')),endpoint(first.get('peer'))
        require(endpoint(second.get('local'))==local and endpoint(second.get('peer'))==peer,
                'One actual DNS exchange changed socket endpoints')
        client,server=(local,peer) if role=='client' else (peer,local)
        require(client[0]=='127.0.0.1' and server==('127.0.0.2',18080), 'Actual DNS tuple differs')
        connection=connections[index]
        require(connection.get('scenario')==scenario and connection.get('operation')==('connect' if role=='client' else 'accept')
                and number(connection.get('syscalls'),1,1 if role=='client' else 16)>0
                and connection.get('initial_errno') in ((0,errno.EINPROGRESS) if role=='client' else (0,))
                and connection.get('complete') is True and connection.get('closed') is True
                and endpoint(connection.get('local'))==local and endpoint(connection.get('peer'))==peer
                and number(connection.get('fd'))==number(first.get('fd'))==number(second.get('fd')),
                'Actual new TCP connect/accept receipt differs from the wire socket')
        pairs[scenario]={'request':first,'response':second,'tuple':(*client,*server),
                         'parsed':parse_frame(bytes.fromhex(second['wire_hex']),run,scenario,True),
                         'call_us':(number(second['finished_monotonic_ns'])-number(first['started_monotonic_ns'])+999)//1000}
    require(len({pair['tuple'] for pair in pairs.values()})==3, 'DNS scenarios reused one TCP tuple')
    return process,receipt,pairs,digest(raw)


def worker_runtime(folder,full_role,run,workload_run,process,scope,helpers):
    document=read_json(folder/(full_role+'-runtime.json'))
    created=read_json(folder/(full_role+'-created.json'))
    phase,role=full_role.split('-',1)
    require(document.get('schema')=='traflens.ebpf-dns.worker-runtime.v1' and document.get('role')==full_role
            and document.get('scope_role')==phase and document.get('run')==run and document.get('workload_run')==workload_run
            and document.get('scope_receipt')=='scope-runtime.json'
            and document.get('agent_container_id')==scope['agent_container_id'], 'Actual DNS worker runtime identity differs')
    create,actual=document.get('create',{}),document.get('inspect',{})
    normalized=create.get('normalized',{})
    image=normalized.get('image')
    require(isinstance(image,str) and re.fullmatch('sha256:[0-9a-f]{64}',image), 'Immutable actual worker image required')
    labels={'io.traflens.purpose':'traflens.ebpf-dns.worker','io.traflens.run':run,
            'io.traflens.role':full_role,'io.traflens.output':str(folder)}
    network='container:'+scope[phase]['container_id']
    command=['--execute','--role',role,'--run',workload_run,'--output','/output','--seconds','90','--port','18080']
    fixed={'image':image,'pid_mode':'host','network_mode':network,'read_only':True,'cap_drop':['ALL'],
           'cap_add':[],'nano_cpus':500000000,'memory_bytes':67108864,'memory_swap_bytes':67108864,'pids_limit':16,
           'privileged':False,'port_bindings':{},'publish_all_ports':False,'security_opt':['no-new-privileges'],
           'restart_policy':'no','labels':labels,'entrypoint':['/workload'],'command':command}
    for key,expected in fixed.items():
        require(type(normalized.get(key)) is type(expected) and normalized[key]==expected
                and type(actual.get(key)) is type(expected) and actual[key]==expected,
                'Actual DNS worker Docker intent/inspect scope differs: '+key)
    helpers.security_option_receipt(actual)
    mounts=normalized.get('mounts')
    require(isinstance(mounts,list) and len(mounts)==2 and actual.get('mounts')==mounts and created.get('mounts')==mounts,
            'Actual DNS worker mount intent differs')
    by_target={m[1]:m for m in mounts if isinstance(m,list) and len(m)==3}
    require(set(by_target)=={'/workload','/output'} and by_target['/workload'][2] is False
            and by_target['/output']==[str(folder/full_role),'/output',True], 'Actual DNS worker mounts escape its private output')
    binary=Path(by_target['/workload'][0])
    sha=digest(read_file(binary,8<<20))
    require(actual.get('executable_sha256')==sha, 'Actual running C executable SHA differs from mounted artifact')
    require(create.get('argv_sha256')==digest(canonical(create.get('argv'))), 'Actual DNS create argv hash differs')
    flags=helpers.docker_create_options(create.get('argv'),command,image)
    for key,expected in {'--pid':['host'],'--network':[network],'--cpus':['0.5'],'--memory':['67108864'],
                         '--memory-swap':['67108864'],'--pids-limit':['16'],'--cap-drop':['ALL'],'--entrypoint':['/workload']}.items():
        require(flags.get(key)==expected, 'Actual DNS create safety flag differs: '+key)
    require(flags.get('--security-opt') in (['no-new-privileges'],['no-new-privileges:true'])
            and flags.get('--restart',['no'])==['no'] and sorted(flags.get('--label',[]))==sorted(k+'='+v for k,v in labels.items()),
            'Actual DNS create labels/privilege guard differs')
    require(actual.get('running') is True and re.fullmatch('[0-9a-f]{64}',actual.get('id',''))
            and actual['id']==created.get('id') and created.get('command')==command
            and actual.get('pid')==process['pid'] and str(actual.get('start_ticks'))==process['start_ticks']
            and helpers.namespace(actual.get('netns'),'net')==process['netns']
            and helpers.namespace(actual.get('pidns'),'pid')==process['pidns'], 'Actual Docker/proc identity does not bind the C wire producer')
    return actual['id'],image,sha


def application_oracle(folder,report):
    meta,result=read_json(folder/'ingestion-metadata.json'),read_json(folder/'result.json')
    run,negative=meta.get('run'),meta.get('negative_run')
    require(isinstance(run,str) and re.fullmatch('dns-[0-9a-f]{24}',run) and isinstance(negative,str)
            and re.fullmatch('dns-[0-9a-f]{24}',negative) and run!=negative, 'Independent actual DNS markers required')
    agent=number(meta.get('agent_id'),1,65535)
    require(meta.get('schema')=='traflens.ebpf-dns.capture.v1' and meta.get('runtime_receipts_required') is True
            and meta.get('integration_mode')=='kernel_dns' and meta.get('signal_source')==3 and meta.get('l7_protocol')==120
            and meta.get('transport')=='tcp' and meta.get('port')==18080, 'Public DNS capture mode differs')
    require(result.get('schema')==meta['schema'] and result.get('run')==run and result.get('negative_run')==negative
            and result.get('agent_id')==agent and result.get('pass_execution') is True and result.get('pass') is True
            and result.get('cleaned') is True and result.get('collector_stopped') is True
            and result.get('lease_restored') is True and result.get('controller_cleaned') is True
            and result.get('positive_queries')==result.get('negative_queries')==3 and result.get('expected_observations')==6
            and not result.get('cleanup_errors') and result.get('error') in (None,''), 'Public DNS execution/restoration did not complete')
    require(all(result.get('worker_exits',{}).get(role)=={'exit_code':0,'oom':False} for role in ROLES),
            'Actual DNS worker exit/OOM proof failed')
    restoration=read_json(folder/'scope-restoration.json')
    for key in ('pass','scope_only','external_agent_exit_and_inventory_restored','tracer_exit_confirmed_before_namespace_release',
                'namespace_pins_released','original_host_bpf_inventory_restored','original_tracefs_restored',
                'preexisting_containers_still_running','released_by_coordinator','scope_proof_approved'):
        require(restoration.get(key) is True, 'Original namespace/BPF restoration failed: '+key)
    scope,current=read_json(folder/'scope-runtime.json'),read_json(folder/'agent/current.json')
    require(scope.get('schema')=='traflens.ebpf-dns.scope.v1' and scope.get('agent_container_id')==current.get('id')
            and re.fullmatch('[0-9a-f]{64}',current.get('id','')) and current.get('agent_id')==agent
            and scope.get('lease_path')==current.get('lease_path'), 'Public DNS Agent/namespace lease identity differs')
    runtime=Path(current['folder'])
    require(runtime.is_absolute() and runtime==runtime.resolve() and runtime.parent==folder/'agent', 'Exact private Agent runtime required')
    proof=read_json(runtime/'coordinator-scope-proof.json')
    require(proof.get('agent_container_id')==current['id'] and proof.get('agent_binary_sha256')==current.get('binary_sha256')
            and proof.get('source_commit')==current.get('source') and proof.get('af_packet_socket_count')==0
            and isinstance(proof.get('agent_scope_fds'),list) and 1<=len(proof['agent_scope_fds'])<=32
            and all(type(fd) is int and fd>=0 for fd in proof['agent_scope_fds']) and number(proof.get('agent_pid'),1)>0
            and all(proof.get(k) is True for k in ('scope_fd_pinned','safe_profile_verified','native_collector_started','fresh_three_listener_sync')),
            'Actual native collector/FD/no-AF_PACKET readiness proof failed')
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
    require(profile==meta.get('profile') and profile['processors']['request_log']['application_protocol_inference']['enabled_protocols']==['DNS']
            and profile['processors']['request_log']['filters']['port_number_prefilters']=={'DNS':'18080'}
            and profile['processors']['request_log']['filters'].get('unconcerned_dns_nxdomain_response_suffixes',[])==[]
            and profile['inputs']['proc']['enabled'] is False and profile['inputs']['integration']['enabled'] is False
            and profile['inputs']['ebpf']['profile']['on_cpu']['disabled'] is True
            and profile['inputs']['ebpf']['profile']['unwinding']['dwarf_disabled'] is True, 'DNS-only safe profile differs')
    processes,pairs,hashes,workers,lifetimes={}, {}, {}, [], []
    for full_role in ROLES:
        phase,_=full_role.split('-',1);nonce=run if phase=='positive' else negative
        process,receipt,wire,sha=workload_oracle(folder/full_role,full_role,nonce)
        require(process['netns']==helpers.namespace(scope[phase]['inode'],'net')
                and process['pidns']==os.readlink('/proc/1/ns/pid'), 'Actual worker escaped declared isolated NET/host PID namespace')
        processes[full_role],pairs[full_role],hashes[full_role]=process,wire,sha
        lifetimes.append((number(receipt['started_unix_ns'],1),number(receipt['finished_unix_ns'],1)))
        workers.append(worker_runtime(folder,full_role,run,nonce,process,scope,helpers))
    require(len({p['pid'] for p in processes.values()})==4 and len({w[0] for w in workers})==4
            and len({w[1] for w in workers})==len({w[2] for w in workers})==1, 'Four actual isolated workers with one exact executable/image required')
    require(type(proof.get('observed_at_unix')) in (int,float) and type(stopped.get('observed_at_unix')) in (int,float)
            and 0<proof['observed_at_unix']<=min(v[0] for v in lifetimes)/10**9
            and stopped['observed_at_unix']>=max(v[1] for v in lifetimes)/10**9,
            'Actual DNS workers did not run after kernel readiness and before Agent restoration')
    expected=[]
    for phase in ('positive','negative'):
        for scenario in SCENARIOS:
            client,server=pairs[phase+'-client'][scenario],pairs[phase+'-server'][scenario]
            require(client['tuple']==server['tuple'] and all(client[k]['wire_sha256']==server[k]['wire_sha256']
                    and client[k]['wire_hex']==server[k]['wire_hex'] and client[k]['local']==server[k]['peer']
                    and client[k]['peer']==server[k]['local'] for k in ('request','response')), 'Actual DNS peer bytes/tuples differ')
            if phase=='positive':
                for role,side in (('client','c-p'),('server','s-p')):
                    item=pairs[phase+'-'+role][scenario]
                    expected.append(dict(item,scenario=scenario,side=side,pid=processes[phase+'-'+role]['pid'],tid=processes[phase+'-'+role]['tid']))
    report.update(scope_receipt_passed=True,actual_raw_scope_map_verified=True,actual_worker_runtime_receipts_passed=True,
                  actual_wire_sha256=hashes,application_positive_queries=3,application_negative_queries=3,
                  original_runtime_sha256={p.name:digest(read_file(p)) for p in (folder/'scope-runtime.json',runtime/'coordinator-scope-proof.json',runtime/'scope-map.json')})
    return run,negative,agent,expected


def native_snapshot(count_document,document,expected,agent,start,end):
    counts=table(count_document,['records']);actual=table(document,COLUMNS)
    require(len(counts)==1 and number(counts[0]['records'])==len(actual)==6, 'Unfiltered whole DNS marker population is not exactly six')
    seen,mapping=set(),{}
    for row in actual:
        require(isinstance(row['id'],str) and number(row['id'],1) not in seen, 'Missing/duplicate exact observation ID')
        seen.add(number(row['id'],1))
        for key in COLUMNS:
            if key in TEXT:
                require(isinstance(row[key],str), 'Missing original DNS text field: '+key)
            else:
                number(row[key],-2**31 if key.startswith('l3_epc_id') else 0,2**31-1 if key.startswith('l3_epc_id') else 2**64-1)
        require(number(row['agent_id'])==agent and number(row['signal_source'])==3 and number(row['type'])==2
                and number(row['protocol'])==6 and number(row['l7_protocol'])==120 and row['tap_side'] in ('c-p','s-p'),
                'Whole marker hid no wrong Agent/source/protocol/incomplete record')
        begin,finish=number(row['start_us'],1),number(row['end_us'],1)
        require(begin<=finish and start<=finish//10**6<=end and number(row['time_epoch'])==finish//10**6,
                'Original DNS event/report time outside explicit scope')
        require(number(row['flow_id'],1)>0, 'Actual DNS native flow identity missing')
        local=number(row['process_id_0' if row['tap_side']=='c-p' else 'process_id_1'],1,2**32-1)
        tup=(row['ip_0'],number(row['client_port'],1,65535),row['ip_1'],number(row['server_port'],1,65535))
        matches=[item for item in expected if item['side']==row['tap_side'] and item['tuple']==tup and item['pid']==local]
        require(len(matches)==1, 'DNS observation does not map uniquely by actual socket/local PID/side')
        item=matches[0];key=item['scenario'],item['side']
        require(key not in mapping and number(row['syscall_thread_0'],1)==number(row['syscall_thread_1'],1)==item['tid'],
                'Actual DNS local syscall TID/observation mapping differs')
        parsed=item['parsed']
        for field in ('request_id','request_type','request_resource','endpoint','request_domain','response_code','response_status','response_result'):
            require((number(row[field]) if field in ('request_id','response_code','response_status') else row[field])==parsed[field],
                    'DNS field differs from independently decoded real wire: '+field)
        duration=number(row['response_duration'])
        require(abs(duration-(finish-begin))<=1 and duration<=item['call_us']+1,
                'Native DNS microsecond RRT contradicts event range or actual C call interval')
        mapping[key]=row
    require(len(mapping)==len(expected)==6, 'Missing independently identified DNS observation')
    for scenario in SCENARIOS:
        a,b=mapping[(scenario,'c-p')],mapping[(scenario,'s-p')]
        require(number(a['request_id'])==number(b['request_id']), 'Actual two DNS observer transaction IDs differ')
    actual.sort(key=lambda row:number(row['id'],1))
    return actual,digest(canonical(actual))


def api_rows(value,expected):
    actual=table(value,API_COLUMNS)
    require(len(actual)==len(expected), 'API DNS observation population differs')
    originals={row['id']:row for row in expected};seen=set()
    for row in actual:
        require(isinstance(row['id'],str) and row['id'] in originals and row['id'] not in seen, 'API changed/duplicated exact DNS observation ID')
        seen.add(row['id']);original=originals[row['id']]
        for field in API_COLUMNS:
            if field in TEXT or field=='id':
                require(row[field]==original[field], 'API changed original DNS field: '+field)
            else:
                require(number(row[field],-2**31 if field.startswith('l3_epc_id') else 0)==number(original[field],-2**31 if field.startswith('l3_epc_id') else 0),
                        'API changed original exact DNS number: '+field)


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


def acceptance(client,args,run,negative,agent,expected,report):
    where="request_resource LIKE '%%%s%%'"%run
    projection=('toString(_id) AS id,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,'
                'toUnixTimestamp(time) AS time_epoch,toString(flow_id) AS flow_id,'+','.join(COLUMNS[5:]))
    def snapshot(label):
        count=client.query(label+'-count',args.query_base,'SELECT Count(row) AS records FROM l7_flow_log WHERE '+where)
        raw=client.query(label+'-all',args.query_base,'SELECT '+projection+' FROM l7_flow_log WHERE '+where+' ORDER BY _id ASC LIMIT 65')
        negative_where="request_resource LIKE '%%%s%%'"%negative
        nc=table(client.query(label+'-negative-count',args.query_base,'SELECT Count(row) AS records FROM l7_flow_log WHERE '+negative_where),['records'])
        nr=table(client.query(label+'-negative-all',args.query_base,'SELECT '+projection+' FROM l7_flow_log WHERE '+negative_where+' ORDER BY _id ASC LIMIT 65'),COLUMNS)
        require(len(nc)==1 and number(nc[0]['records'])==len(nr)==0, 'Independent outside-namespace DNS marker was stored')
        return native_snapshot(count,raw,expected,agent,args.time_from,args.time_to)
    original,fingerprint=snapshot('first')
    for source,count in ((3,6),(0,0),(4,0)):
        control=table(client.query('source-'+str(source),args.query_base,'SELECT Count(row) AS records FROM l7_flow_log WHERE '+where+' AND signal_source='+str(source)),['records'])
        require(len(control)==1 and number(control[0]['records'])==count, 'Whole DNS marker source control differs')
    params={'from':args.time_from,'to':args.time_to,'agent':agent,'source':3,'proto':120,'session':1,'q':run,'limit':64}
    api_rows(client.request('api-list',args.console_base,'/api/requests',params),original)
    for index,row in enumerate(original):
        api_rows(client.request('api-detail-'+str(index+1),args.console_base,'/api/requests',dict(params,id=row['id'],limit=2)),[row])
    for source in (0,4):
        empty=client.request('api-empty-source-'+str(source),args.console_base,'/api/requests',dict(params,source=source))
        require(isinstance(empty.get('columns'),list) and empty.get('values')==[], 'API source control is not explicit empty')
    final,last=snapshot('second')
    require(final==original and last==fingerprint, 'All original DNS IDs/fields changed across non-atomic verification')
    report.update(storage_acceptance_passed=True,whole_marker_reads=2,observations=6,positive_queries=3,negative_queries=3,
        negative_stored_records=0,source_counts={'3':6,'0':0,'4':0},exact_detail_reads=6,original_projection_sha256=fingerprint,
        request_count=client.requests,actual_host_pid_tid_tuple_verified=True,actual_dns_wire_fields_verified=True,
        original_ids=[row['id'] for row in original],rrt_scope='native microseconds; <=actual per-observer monotonic C call interval, event-floor difference<=1us; not a performance benchmark')


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--capture-dir',type=Path)
    parser.add_argument('--query-base');parser.add_argument('--console-base')
    parser.add_argument('--from',dest='time_from',type=int);parser.add_argument('--to',dest='time_to',type=int)
    parser.add_argument('--agent',type=int);parser.add_argument('--output',type=Path)
    args=parser.parse_args(argv)
    if not args.execute:
        print(json.dumps({'execute':False,'reads_files':False,'starts_network':False,'new_capture':False,
                          'max_rows':MAX_ROWS,'max_requests':MAX_REQUESTS,'total_seconds':60,'legacy_fallback':False}))
        return 0
    args.query_base,args.console_base=loopback(args.query_base),loopback(args.console_base)
    folder,output=args.capture_dir,args.output
    require(folder and folder.is_absolute() and folder==folder.resolve() and folder.is_dir()
            and folder.stat().st_uid==os.geteuid() and not folder.stat().st_mode&0o077, 'Owned canonical private capture directory required')
    require(type(args.time_from) is int and type(args.time_to) is int and 0<args.time_from<=args.time_to
            and args.time_to-args.time_from<60, 'At most60 inclusive event-time seconds required')
    require(output and output.is_absolute() and output==output.resolve() and not output.exists()
            and output.parent.stat().st_uid==os.geteuid() and not output.parent.stat().st_mode&0o077,
            'Fresh output below an owned private parent required')
    os.umask(0o077);output.mkdir(mode=0o700);started=time.monotonic()
    report={'passed':False,'new_capture':False,'new_ingestion':False,'source':'native eBPF DNS/TCP source3',
            'limitations':'Finite observed DNS/TCP Sessions, not six business queries, complete DNS compatibility, UDP/encrypted DNS, causal tracing or performance parity.'}
    def expired(*_):raise TimeoutError('Finite60second DNS acceptance deadline exceeded')
    previous=signal.signal(signal.SIGALRM,expired);signal.setitimer(signal.ITIMER_REAL,60)
    try:
        run,negative,agent,expected=application_oracle(folder,report)
        require(args.agent is None or args.agent==agent, 'Explicit Agent differs from original capture')
        report.update(run=run,negative_run=negative,agent_id=agent,time_from=args.time_from,time_to=args.time_to)
        acceptance(Client(output,started+60),args,run,negative,agent,expected,report)
        report['passed']=True
    except Exception as error:report['error']=type(error).__name__+': '+str(error)
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous)
        report['elapsed_seconds']=round(time.monotonic()-started,3);save(output/'result.json',report)
    print(json.dumps({k:v for k,v in report.items() if k not in ('original_ids','actual_wire_sha256')}))
    return 0 if report['passed'] else 1


if __name__=='__main__':
    raise SystemExit(main())
