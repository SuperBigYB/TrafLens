"""Read only cgroup CPU and the work-process RSS of an owned benchmark Agent."""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import threading
import time


def work_process(processes, listener_pid):
    """Validate a connected Agent pair and select the proven readiness owner."""
    if not 1 <= len(processes) <= 2 or any(type(pid) is not int or pid <= 0 for pid in processes):
        raise ValueError('Expected one Agent or a watchdog/work-process pair')
    leaves = set(processes) - {row['ppid'] for row in processes.values()}
    if len(leaves) != 1:
        raise ValueError('Agent process tree has multiple work processes or a cycle')
    leaf = next(iter(leaves)); seen = set(); current = leaf
    while current in processes:
        if current in seen:
            raise ValueError('Agent process tree has a cycle')
        seen.add(current); current = processes[current]['ppid']
    if seen != set(processes):
        raise ValueError('Agent processes are not one connected tree')
    if type(listener_pid) is not int or listener_pid not in processes:
        raise ValueError('Readiness listener does not belong to this Agent process tree')
    return listener_pid


def listener_owner(output, pids, port):
    owners=set(); matched=0
    for line in output.splitlines():
        fields=line.split()
        if len(fields)<5 or fields[0]!='LISTEN' or not fields[3].endswith(':'+str(port)):
            continue
        found={int(v) for v in re.findall(r'pid=(\d+)',line)}
        if not found or not found<=set(pids):
            raise ValueError('Readiness socket has missing or foreign process ownership')
        owners.update(found);matched+=1
    if not matched or len(owners)!=1:
        raise ValueError('Readiness owner is absent or ambiguous')
    return next(iter(owners))


def memory_peak(path):
    try:value=int(path.read_text().strip())
    except FileNotFoundError:return None
    if value<0:raise ValueError('Invalid cgroup memory peak')
    return value


def process_identity(pid):
    fields = (Path('/proc') / str(pid) / 'stat').read_text().rsplit(')', 1)[1].split()
    return {'ppid': int(fields[1]), 'start_ticks': int(fields[19])}


def require_stable(before, after):
    if before != after:
        raise ValueError('Agent PID, parent or start time changed during measurement')


class Sample:
    def __init__(self, cid, output, liveness_port=39091):
        self.cid=cid;self.output=Path(output);self.stop=threading.Event();self.rows=[];self.errors=[]
        info=json.loads(subprocess.check_output(['docker','inspect',cid],text=True))[0]
        assert info['Id']==cid and info['State']['Running'] and info['Config']['Labels']['io.traflens.purpose']=='traflens.reference-compare.agent'
        assert info['HostConfig']['NanoCpus']==2000000000 and info['HostConfig']['Memory']==1073741824
        self.parent=info['State']['Pid']
        groups=(Path('/proc')/str(self.parent)/'cgroup').read_text().splitlines();assert len(groups)==1 and groups[0].startswith('0::/')
        relative=groups[0][3:];assert cid in relative
        self.group=Path('/sys/fs/cgroup')/relative.lstrip('/');assert self.group.resolve().is_relative_to(Path('/sys/fs/cgroup'))
        rows=[r.split() for r in subprocess.check_output(['docker','top',cid,'-eo','pid,comm'],text=True).splitlines()[1:]]
        pids=[int(r[0]) for r in rows if len(r)==2 and r[1]=='deepflow-agent']
        self.processes={pid:process_identity(pid) for pid in pids};self.liveness_port=liveness_port
        self.pid=work_process(self.processes,self.readiness_owner())
        assert next(row['ppid'] for pid,row in self.processes.items() if row['ppid'] not in self.processes)==self.parent
        self.before=self.cpu();self.start=time.monotonic()
        self.thread=threading.Thread(target=self.sample);self.thread.start()

    def identity(self):
        return {pid:process_identity(pid) for pid in self.processes}

    def readiness_owner(self):
        output=subprocess.check_output(['ss','-H','-lntp','sport = :'+str(self.liveness_port)],text=True)
        return listener_owner(output,self.processes,self.liveness_port)

    def cpu(self):
        return {k:int(v) for k,v in (row.split() for row in (self.group/'cpu.stat').read_text().splitlines())}

    def sample(self):
        while not self.stop.is_set():
            try:
                require_stable(self.processes,self.identity())
                status=(Path('/proc')/str(self.pid)/'status').read_text().splitlines()
                rss=int(next(v.split()[1] for v in status if v.startswith('VmRSS:')))
                self.rows.append({'offset_seconds':time.monotonic()-self.start,'rss_kib':rss,
                                  'cgroup_memory_current_bytes':int((self.group/'memory.current').read_text())})
            except Exception as exc:self.errors.append(repr(exc));break
            self.stop.wait(.1)

    def finish(self):
        self.stop.set();self.thread.join(timeout=2);result={'pass':False,'errors':self.errors,'samples':self.rows,'source':'cgroup v2 CPU; sampled Agent work-process VmRSS','interval_seconds':.1,
            'agent_process_count':len(self.processes),'cpu_scope':'all container processes including watchdog','rss_scope':'verified readiness-listener owner; watchdog excluded'}
        try:
            require_stable(self.processes,self.identity())
            assert self.readiness_owner()==self.pid
            assert not self.thread.is_alive() and self.rows and not self.errors
            after=self.cpu();delta={k:after[k]-v for k,v in self.before.items()};assert all(v>=0 for v in delta.values())
            elapsed=time.monotonic()-self.start
            result.update(cpu_delta=delta,observation_seconds=elapsed,cpu_core_seconds=delta['usage_usec']/1e6,
                average_cpu_cores=delta['usage_usec']/1e6/elapsed,sampled_agent_rss_peak_kib=max(v['rss_kib'] for v in self.rows),
                sampled_cgroup_memory_max_bytes=max(v['cgroup_memory_current_bytes'] for v in self.rows),process_identity_stable=True,
                readiness_owner_verified=True)
            peak=memory_peak(self.group/'memory.peak')
            result.update(cgroup_memory_peak_bytes=peak,cgroup_memory_peak_available=peak is not None)
            result['pass']=True
        except Exception as exc:result['errors'].append(repr(exc))
        with self.output.open('x') as f:json.dump(result,f,indent=2)
        return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--container-id')
    parser.add_argument('--seconds',type=int,default=10);parser.add_argument('--output',type=Path)
    parser.add_argument('--liveness-port',type=int,default=39091)
    args=parser.parse_args()
    if not args.execute:
        print(json.dumps({'executes':False,'reads_payload':False,'scope':'owned benchmark Agent cgroup CPU and work-process RSS'}));return
    if not re.fullmatch('[0-9a-f]{64}',args.container_id or '') or not 1<=args.seconds<=30 or not 1024<=args.liveness_port<=65535:
        raise ValueError('Exact container ID and a 1-30 second interval required')
    if (not args.output or not args.output.is_absolute() or args.output.exists() or args.output.is_symlink()
            or args.output.parent.stat().st_uid!=os.geteuid() or args.output.parent.stat().st_mode&0o077):
        raise ValueError('New report under a private owned directory required')
    os.umask(0o077)
    sampler=Sample(args.container_id,args.output,args.liveness_port)
    try:time.sleep(args.seconds)
    finally:result=sampler.finish()
    print(json.dumps({k:v for k,v in result.items() if k not in ['samples','errors']}))
    raise SystemExit(0 if result['pass'] else 1)


if __name__=='__main__':main()
