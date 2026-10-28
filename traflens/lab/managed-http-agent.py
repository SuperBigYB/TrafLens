#!/usr/bin/env python3
"""Bounded managed HTTP Agent. Default plan is read-only; execution requires --execute."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time
import uuid

HERE=Path(__file__).resolve().parent
WORK=None
import managed_http_workload as workload
import managed_http_scope as scope_reader
from managed_http_scope_validation import validate_scope_proof
import importlib.util
import urllib.request

spec=importlib.util.spec_from_file_location('managed_http_prepare',HERE/'managed-http.py')
preparation=importlib.util.module_from_spec(spec);spec.loader.exec_module(preparation)
PURPOSE='traflens.managed-ebpf.agent'
CAPS=['SYS_ADMIN','SYS_RESOURCE','BPF','PERFMON','SYS_PTRACE']
def require(condition,message='Managed runtime contract mismatch'):
    if not condition:
        raise RuntimeError(message)

def call(args,timeout=30,check=True):
    p=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if check and p.returncode:raise RuntimeError('Command failed: '+str(args[:3])+'; '+p.stderr[:1500])
    return p
def save(path,value):path.write_text(json.dumps(value,indent=2)+'\n');path.chmod(0o600)
def load(path):return json.loads(path.read_text())
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def inspect(name):
    p=call(['docker','inspect',name],check=False)
    if p.returncode:
        if 'no such' in p.stderr.lower():return None
        raise RuntimeError('Docker identity unavailable')
    values=json.loads(p.stdout);require(len(values)==1)
    return values[0]
def ids():
    libc=ctypes.CDLL(None,use_errno=True);start=0;result=[]
    for _ in range(200000):
        attr=(ctypes.c_uint32*36)();attr[0]=start
        value=libc.syscall(321,11,ctypes.byref(attr),ctypes.sizeof(attr))
        if value:
            if ctypes.get_errno()==2:return result
            raise OSError(ctypes.get_errno(),'BPF inventory')
        start=int(attr[1]);require(not result or start>result[-1]);result.append(start)
    raise RuntimeError('BPF inventory exceeded bound')
def tracefs():
    root=Path('/sys/kernel/debug/tracing')
    return {name:(root/name).read_text() for name in ['kprobe_events','uprobe_events']}
def mounts(info):return sorted((v['Source'],v['Destination'],v['RW']) for v in info['Mounts'] if v['Type']=='bind')
def restored_programs(current,receipt):
    baseline=set(receipt['baseline']['bpf_program_ids'])
    inventory=receipt.get('worker_inventory')
    if inventory is None:return set(current)==baseline
    original=set(inventory['original_bpf_ids'])
    worker=set(inventory['owned_worker_cgroup_device_ids'])
    if original & worker or original | worker != baseline:raise RuntimeError('Worker baseline receipt mismatch')
    return original <= set(current) <= baseline
def owned(info,receipt):
    if info is None:return False
    conf,host=info['Config'],info['HostConfig'];labels=conf.get('Labels') or {}
    normalized=lambda values:sorted(str(v).removeprefix('CAP_') for v in (values or []))
    return (info['Id']==receipt['id'] and info['Name']=='/'+receipt['name'] and conf['Image']==receipt['image']
        and labels.get('io.traflens.purpose')==PURPOSE and labels.get('io.traflens.run')==receipt['run']
        and info['Image']==receipt['image'] and conf.get('Hostname')==receipt['hostname']
        and conf['Entrypoint']==['/usr/bin/timeout'] and conf['Cmd']==receipt['command']
        and 'IN_CONTAINER=yes' in (conf.get('Env') or [])
        and host['NetworkMode']=='host' and host['PidMode']=='host' and not host['Privileged']
        and host['Memory']==1073741824 and host['MemorySwap']==1073741824 and host['NanoCpus']==2000000000
        and host['PidsLimit']==384 and normalized(host.get('CapAdd'))==sorted(CAPS)
        and normalized(host.get('CapDrop'))==['ALL'] and 'no-new-privileges' in (host.get('SecurityOpt') or [])
        and 'apparmor=unconfined' in (host.get('SecurityOpt') or [])
        and mounts(info)==sorted(tuple(v) for v in receipt['mounts']))

def start(args):
    if os.geteuid()!=0 or os.uname().machine!='x86_64':
        raise RuntimeError('Qualified Linux x86_64 root runtime required')
    config_input,profile=verified_preparation(args.prepared)
    prepared,binary,libraries=verified_artifacts(args.artifacts)
    registration=controller_readback(args.controller_api,config_input,profile,args.agent_id)
    lease_path=canonical_private(args.lease,directory=True)
    lease=workload.read_private(lease_path/'lease.json')
    if (lease.get('schema')!='traflens.managed-http.lease.v1'
            or lease.get('status')!='ready_waiting_root_commands' or lease.get('phase')!=0
            or lease.get('agent_registered') is not False
            or lease.get('lease_monotonic_deadline',0)-time.monotonic()<=240):
        raise RuntimeError('Fresh prepared namespace lease with sufficient lifetime required')
    pid=lease['supervisor_pid']
    if type(pid) is not int or pid<=1 or not Path('/proc',str(pid)).exists():
        raise RuntimeError('Namespace lease holder is absent')
    scope=Path(lease['positive']['source'])
    if not re.fullmatch('/proc/'+str(pid)+r'/fd/[0-9]+',str(scope)):
        raise RuntimeError('Scope must be an FD held by the live lease supervisor')
    _,selected_port=prepared_protocol(profile)
    if lease['port']!=selected_port:
        raise RuntimeError('Workload and restricted protocol profile ports differ')
    inode_expected=lease['positive']['inode']
    root=WORK/'agent'
    if root.exists():
        raise RuntimeError('Use a fresh private work directory for each start')
    root.mkdir(mode=0o700)
    current=root/'current.json'
    image=prepared['image_id'];require(call(['docker','image','inspect',image]).returncode==0)
    active=call(['docker','ps','-aq','--filter','label=io.traflens.purpose='+PURPOSE]).stdout.strip()
    require(not active,'Another managed Agent resource exists')
    for item in Path('/proc').iterdir():
        if item.name.isdigit():
            try:comm=(item/'comm').read_text().strip()
            except OSError:continue
            require(comm not in {'deepflow-agent','deepflow_agent','socket_tracer','tlens-ebpf-gate'},'Another tracer process exists')
    baseline={'bpf_program_ids':ids(),'tracefs':tracefs()}
    require(not any('_deepflow_' in value for value in baseline['tracefs'].values()))
    namespace_fd=os.open(str(scope),os.O_RDONLY|os.O_CLOEXEC)
    try:
        require(fcntl.ioctl(namespace_fd,0xb703)==0x40000000)
        inode=os.fstat(namespace_fd).st_ino
        require(0<inode<=0xffffffff and inode!=os.stat('/proc/self/ns/net').st_ino)
        require(inode==inode_expected)
        run=uuid.uuid4().hex[:12];folder=root/run;folder.mkdir(mode=0o700)
        logs=folder/'logs';logs.mkdir(mode=0o700)
        state=folder/'state';state.mkdir(mode=0o700)
        (state/'target.netns').touch(mode=0o400)
        config=folder/'bootstrap.yaml'
        save(config,config_input)
        name='traflens-managed-agent-'+run
        bindings=[(str(binary),'/opt/traflens/deepflow-agent',False),
            (str(libraries),'/opt/traflens-libs',False),
            (str(config),'/etc/traflens/agent.yaml',False),(str(logs),'/var/log/traflens',True),
            (str(state),'/run/traflens',True),(str(scope),'/run/traflens/target.netns',False),
            ('/sys/kernel/debug','/sys/kernel/debug',False),('/sys/kernel/tracing','/sys/kernel/tracing',False),
            ('/sys/kernel/btf','/sys/kernel/btf',False)]
        command=['--signal=TERM','--kill-after=40s','180','/opt/traflens/deepflow-agent',
                 '--cgroups-disabled','-f','/etc/traflens/agent.yaml']
        argv=['docker','create','--name',name,'--network','host','--pid','host',
            '--hostname',registration['agent']['NAME'],'--cpus','2','--memory','1g','--memory-swap','1g','--pids-limit','384','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--security-opt','apparmor=unconfined','--restart','no','--stop-timeout','40',
            '--ulimit','memlock=-1:-1','--ulimit','core=0:0','--log-driver','json-file',
            '--log-opt','max-size=10m','--log-opt','max-file=2',
            '--label','io.traflens.purpose='+PURPOSE,'--label','io.traflens.run='+run,
            '--env','LD_LIBRARY_PATH=/opt/traflens-libs','--env','IN_CONTAINER=yes',
            '--env','RUST_BACKTRACE=1','--entrypoint','/usr/bin/timeout']
        for cap in CAPS:argv+=['--cap-add',cap]
        for source,dest,rw in bindings:argv+=['--mount',f'type=bind,source={source},target={dest}'+('' if rw else ',readonly')]
        argv += [image]+command
        receipt={'schema':1,'name':name,'run':run,'image':image,'command':command,'mounts':bindings,
            'binary_sha256':prepared['binary_sha256'],'source':prepared['source'],'scope_inode':inode,'scope_file':str(scope),
            'agent_id':registration['agent']['ID'],'controller_api':args.controller_api,'group_id':config_input['vtap-group-id-request'],
            'hostname':registration['agent']['NAME'],'prepared':str(args.prepared),
            'config_sha256':sha(config),'folder':str(folder),
            'baseline':baseline,'started_at_unix':time.time(),'hard_timeout_seconds':180,'kill_grace_seconds':40}
        receipt['lease_path']=str(lease_path)
        receipt['worker_inventory']=load(lease_path/'inventory-workers.json')
        require(restored_programs(baseline['bpf_program_ids'],receipt))
        save(folder/'programs-before.json',scope_reader.programs())
        save(folder/'intent.json',dict(receipt,argv=argv))
        created=call(argv).stdout.strip();receipt['id']=created
        save(current,receipt);save(folder/'created.json',receipt)
        info=inspect(created);require(owned(info,receipt),'Unexpected Agent container identity')
        call(['docker','start',created])
        info=inspect(created);require(owned(info,receipt))
        receipt['container_pid']=info['State']['Pid'];receipt['container_started_at']=info['State']['StartedAt']
        save(current,receipt);save(folder/'started.json',receipt)
        if workload.control(lease_path,{'action':'register-agent','agent_container_id':created}):
            raise RuntimeError('Namespace supervisor refused Agent registration')
        print(json.dumps({'started':info['State']['Running'],'container_id':created,'receipt':str(current),
                          'hard_timeout_seconds':220,'scope_inode':inode}))
    finally:os.close(namespace_fd)

def stop(args):
    current=WORK/'agent/current.json';receipt=load(current);folder=Path(receipt['folder'])
    info=inspect(receipt['id'])
    require(info and owned(info,receipt),'Refuse unknown Agent cleanup')
    logs=call(['docker','logs',receipt['id']],timeout=30,check=False)
    (folder/'console.log').write_text(logs.stdout+logs.stderr)
    if info['State']['Running']:call(['docker','stop','--time','40',receipt['id']],timeout=55)
    info=inspect(receipt['id']);require(owned(info,receipt) and not info['State']['Running'])
    save(folder/'exit-state.json',info['State'])
    logs=call(['docker','logs',receipt['id']],check=False)
    (folder/'console.log').write_text(logs.stdout+logs.stderr)
    call(['docker','rm',receipt['id']])
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        if restored_programs(ids(),receipt) and tracefs()==receipt['baseline']['tracefs']:break
        time.sleep(.2)
    result={'agent_stopped':True,'container_removed':inspect(receipt['id']) is None,
        'bpf_inventory_restored':restored_programs(ids(),receipt),
        'tracefs_restored':tracefs()==receipt['baseline']['tracefs'],'observed_at_unix':time.time()}
    save(folder/'stopped.json',result)
    require(all(result[v] for v in ['agent_stopped','container_removed','bpf_inventory_restored','tracefs_restored']))
    print(json.dumps(result))


def canonical_private(path, directory=False):
    path=Path(path)
    if not path.is_absolute() or path!=path.resolve():
        raise ValueError('Canonical absolute private path required')
    st=path.lstat()
    import stat
    if (st.st_uid!=os.geteuid() or st.st_mode & 0o077
            or not (stat.S_ISDIR(st.st_mode) if directory else stat.S_ISREG(st.st_mode))):
        raise ValueError('Owned private directory/file required')
    return path


def verified_preparation(path):
    path=canonical_private(path,directory=True)
    manifest=load(canonical_private(path/'manifest.json'))
    names={'group-profile.json','bootstrap.yaml'}
    if manifest.get('schema') not in ('traflens.managed-http-preparation.v1','traflens.managed-dns-preparation.v1') or set(manifest['files'])!=names:
        raise ValueError('Unsupported preparation manifest')
    for name in names:
        file=canonical_private(path/name)
        if manifest['files'][name]!={'sha256':sha(file),'bytes':file.stat().st_size}:
            raise ValueError('Prepared file hash/length differs')
    boot=load(path/'bootstrap.yaml');profile=load(path/'group-profile.json')
    comm=profile['global']['communication']
    if manifest['schema']=='traflens.managed-http-preparation.v1':
        expected=preparation.documents(boot['controller-ips'][0],boot['vtap-group-id-request'],
            boot['controller-port'],comm['ingester_ip'],comm['ingester_port'],manifest['http_port'])
    else:
        spec=importlib.util.spec_from_file_location('managed_dns_prepare',HERE/'managed-dns.py')
        dns=importlib.util.module_from_spec(spec);spec.loader.exec_module(dns)
        if manifest.get('protocol')!='DNS/TCP' or 'http_port' in manifest:
            raise ValueError('DNS manifest protocol differs')
        expected=dns.documents(boot['controller-ips'][0],boot['vtap-group-id-request'],
            boot['controller-port'],comm['ingester_ip'],comm['ingester_port'],manifest['dns_port'])
    if (profile,boot)!=expected or manifest.get('namespace_target')!=preparation.SCOPE_TARGET:
        raise ValueError('Only the exact restricted prepared protocol profile/bootstrap is supported')
    return boot,profile


def prepared_protocol(profile):
    protocols=profile['processors']['request_log']['application_protocol_inference']['enabled_protocols']
    ports=profile['processors']['request_log']['filters']['port_number_prefilters']
    if protocols==['DNS'] and ports=={'DNS':'18080'}:
        return 'DNS/TCP',18080
    if protocols==['HTTP'] and set(ports)=={'HTTP'}:
        return 'HTTP',int(ports['HTTP'])
    raise ValueError('Unsupported restricted protocol/port selection')


def verified_artifacts(path):
    path=canonical_private(path)
    value=load(path);root=path.parent
    if (not re.fullmatch('sha256:[0-9a-f]{64}',value.get('image_id',''))
            or not re.fullmatch('[0-9a-f]{40}',value.get('source',''))
            or not re.fullmatch('[0-9a-f]{64}',value.get('binary_sha256',''))):
        raise ValueError('Immutable image, source commit and binary SHA256 required')
    names={'libz.so.1','libstdc++.so.6','libgcc_s.so.1'}
    if set(value.get('libraries',{}))!=names:
        raise ValueError('Expected exactly the qualified runtime library set')
    for name in ['deepflow-agent']+['libs/'+v for v in sorted(names)]:
        file=root/name
        st=file.lstat()
        import stat
        if file.is_symlink() or not stat.S_ISREG(st.st_mode) or st.st_uid!=os.geteuid() or st.st_mode & 0o022:
            raise ValueError('Unsafe runtime artifact')
        expected=value['binary_sha256'] if name=='deepflow-agent' else value['libraries'][Path(name).name]['sha256']
        if sha(file)!=expected:
            raise ValueError('Runtime artifact hash differs')
    return value,root/'deepflow-agent',root/'libs'


def controller_readback(endpoint,boot,profile,agent_id):
    from urllib.parse import urlsplit
    url=urlsplit(endpoint)
    if (url.scheme!='http' or url.hostname not in {'127.0.0.1','::1'} or url.username or url.password
            or url.path or url.query or url.fragment or url.port is None):
        raise ValueError('Controller API must be an explicit loopback http://IP:port (SSH forward if remote)')
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,*_args,**_kwargs):
            raise RuntimeError('Controller redirect refused')
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),NoRedirect())
    def api(path):
        request=urllib.request.Request(endpoint+path,headers={'X-Org-Id':'1','X-User-Id':'1','X-User-Type':'1'})
        with opener.open(request,timeout=10) as response:
            raw=response.read(4*1024*1024+1)
        if len(raw)>4*1024*1024:
            raise RuntimeError('Controller response too large')
        value=json.loads(raw)
        if value.get('OPT_STATUS')!='SUCCESS':
            raise RuntimeError('Controller readback rejected')
        return value['DATA']
    groups=[g for g in api('/v1/vtap-groups/') if g['SHORT_UUID']==boot['vtap-group-id-request']]
    if len(groups)!=1 or not re.fullmatch('[0-9a-f-]{36}',groups[0]['LCUUID']):
        raise RuntimeError('Exact prepared group not found')
    group=groups[0]
    members=[v for key in ('VTAP_LCUUIDS','DISABLE_VTAP_LCUUIDS','PENDING_VTAP_LCUUIDS') for v in group.get(key,[]) or []]
    agents=api('/v1/vtaps/') or []
    selected=[a for a in agents if a['VTAP_GROUP_LCUUID']==group['LCUUID']]
    if (len(selected)!=1 or selected[0]['ID']!=agent_id or members!=[selected[0]['LCUUID']]
            or selected[0]['ENABLE']!=1 or not {2,4,5}<=set(selected[0]['LICENSE_FUNCTIONS'])
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',selected[0]['NAME'])):
        raise RuntimeError('Expected one explicit enabled registered Agent in the owned group')
    if json.loads(api('/v1/agent-group-configuration/'+group['LCUUID']+'/yaml'))!=profile:
        raise RuntimeError('Live Controller profile differs from restricted preparation')
    return {'group':group,'agent':selected[0]}


def ready(args):
    receipt=load(canonical_private(WORK/'agent/current.json'));folder=Path(receipt['folder'])
    boot,profile=verified_preparation(receipt['prepared'])
    if sha(folder/'bootstrap.yaml')!=receipt['config_sha256']:
        raise RuntimeError('Bound bootstrap differs from launch receipt')
    controller_readback(receipt['controller_api'],boot,profile,receipt['agent_id'])
    deadline=time.monotonic()+65
    while time.monotonic()<deadline:
        info=inspect(receipt['id'])
        if not owned(info,receipt) or not info['State']['Running']:
            raise RuntimeError('Owned Agent exited before readiness')
        output=call(['docker','logs',receipt['id']]);text=output.stdout+output.stderr
        if all(v in text for v in ['ebpf collector started','on 3 listener',
                                  'tap-interface-regex is empty, skip packet dispatcher']):
            break
        time.sleep(1)
    else:
        raise RuntimeError('Actual collector/policy readiness timed out')
    pid=int((folder/'state/deepflow-agent.pid').read_text())
    if Path('/proc',str(pid),'comm').read_text().strip()!='deepflow-agent':
        raise RuntimeError('Actual Agent process identity differs')
    expected=Path(receipt['scope_file']).stat();matched=[];sockets=set()
    for entry in Path('/proc',str(pid),'fd').iterdir():
        try:
            link=os.readlink(entry)
            if link.startswith('socket:['):
                sockets.add(link[8:-1])
            st=entry.stat()
            if st.st_ino==expected.st_ino and st.st_dev==expected.st_dev:
                fd=os.open(entry,os.O_RDONLY|os.O_CLOEXEC)
                try:
                    if fcntl.ioctl(fd,0xb703)==0x40000000:
                        matched.append(int(entry.name))
                finally:
                    os.close(fd)
        except FileNotFoundError:
            continue
    packet={line.split()[-1] for line in Path('/proc/net/packet').read_text().splitlines()[1:]}
    if not matched or sockets & packet:
        raise RuntimeError('Actual Agent scope FD missing or AF_PACKET socket present')
    proof_path=folder/'scope-map.json'
    call(['python3',str(HERE/'managed_http_scope.py'),'--baseline',str(folder/'programs-before.json'),
          '--target-netns',receipt['scope_file'],'--expected-inode',str(receipt['scope_inode']),
          '--output',str(proof_path)],timeout=15)
    abi=HERE/'managed-http-scope-abi.json'
    config=validate_scope_proof(load(proof_path),receipt['scope_inode'],load(abi),sha(abi))
    proof={'agent_container_id':receipt['id'],'scope_map':config,'scope_fd_pinned':True,
        'safe_profile_verified':True,'agent_binary_sha256':receipt['binary_sha256'],
        'source_commit':receipt['source'],'hard_timeout_seconds':180,'kill_grace_seconds':40,
        'agent_pid':pid,'agent_scope_fds':matched,'af_packet_socket_count':0,
        'native_collector_started':True,'fresh_three_listener_sync':True,'observed_at_unix':time.time()}
    save(folder/'coordinator-scope-proof.json',proof)
    if workload.control(Path(receipt['lease_path']),{'action':'approve-agent','proof':proof}):
        raise RuntimeError('Namespace supervisor refused scope proof')
    print(json.dumps({'ready':True,'http_emitted':False,'af_packet_sockets':0,
                      'proof':str(folder/'coordinator-scope-proof.json')}))


def main():
    global WORK
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',nargs='?',choices=['plan','start','ready','stop'],default='plan')
    parser.add_argument('--execute',action='store_true')
    parser.add_argument('--work',type=Path)
    parser.add_argument('--prepared',type=Path)
    parser.add_argument('--artifacts',type=Path)
    parser.add_argument('--lease',type=Path)
    parser.add_argument('--controller-api')
    parser.add_argument('--agent-id',type=int)
    args=parser.parse_args();os.umask(0o077)
    if args.action=='plan' or not args.execute:
        print(json.dumps({'starts_agent':False,'requires_execute':True,'changes_controller':False,
                          'cpu':2,'memory_mib':1024,'host_pid':True,'host_network':True,
                          'namespace_lease_required':True,'hard_timeout_seconds':180,'kill_grace_seconds':40}))
        return
    if not args.work:
        parser.error('Explicit private --work required')
    WORK=canonical_private(args.work,directory=True)
    lock=(WORK/'launcher.lock').open('a')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    if args.action=='start':
        if (WORK/'agent').exists():
            raise RuntimeError('Use a fresh private work directory; existing Agent is unchanged')
        if not all([args.prepared,args.artifacts,args.lease,args.controller_api,args.agent_id]):
            parser.error('start requires --prepared, --artifacts, --lease, --controller-api and --agent-id')
        try:
            start(args)
        except BaseException:
            # Preserve the original failure. If creation succeeded, stop only
            # the exact receipt-owned resource; cleanup failure stays visible.
            if (WORK/'agent/current.json').exists():
                stop(args)
            raise
    elif args.action=='ready':
        ready(args)
    else:
        stop(args)


if __name__=='__main__':
    main()
