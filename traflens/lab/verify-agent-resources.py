#!/usr/bin/env python3
"""Verify read-only benchmark resource samples and emit anonymous metrics."""
import argparse
import json
import math
from pathlib import Path


def require(condition,message):
    if not condition:raise ValueError(message)


def number(value,low=0,high=math.inf,integer=False):
    require(type(value) is int if integer else type(value) in (int,float),'Invalid numeric type')
    require(math.isfinite(value) and low<=value<=high,'Invalid numeric range')
    return value


def verify(d):
    require(d['pass'] is True and d['errors']==[] and d['process_identity_stable'] is True
            and d['readiness_owner_verified'] is True,'Incomplete process/resource proof')
    require(d['cpu_scope']=='all container processes including watchdog'
            and d['rss_scope']=='verified readiness-listener owner; watchdog excluded','Resource scope differs')
    number(d['agent_process_count'],1,2,True)
    interval=number(d['interval_seconds'],.01,1)
    elapsed=number(d['observation_seconds'],.01,40)
    rows=d['samples'];require(type(rows) is list and len(rows)>=2,'Insufficient sampling')
    offsets=[number(v['offset_seconds'],0,elapsed+.05) for v in rows]
    require(all(b>a for a,b in zip(offsets,offsets[1:])),'Sampling time is not strictly monotonic')
    gaps=[offsets[0]]+[b-a for a,b in zip(offsets,offsets[1:])]+[max(0,elapsed-offsets[-1])]
    require(max(gaps)<=max(.5,interval*5),'Sampling has an unqualified gap')
    rss=max(number(v['rss_kib'],1,1048576,True) for v in rows)
    memory=max(number(v['cgroup_memory_current_bytes'],0,1073741824,True) for v in rows)
    require(number(d['sampled_agent_rss_peak_kib'],1,1048576,True)==rss
            and number(d['sampled_cgroup_memory_max_bytes'],0,1073741824,True)==memory,'Sampled maxima disagree')
    delta=d['cpu_delta']
    for value in delta.values():number(value,0,integer=True)
    usage=delta['usage_usec'];user=delta['user_usec'];system=delta['system_usec']
    require(abs(user+system-usage)<=1000,'CPU component accounting differs')
    cpu=usage/1e6;cores=cpu/elapsed
    require(cores<=2.5,'CPU exceeds the qualified two-core quota window')
    require(math.isclose(number(d['cpu_core_seconds']),cpu,abs_tol=1e-9)
            and math.isclose(number(d['average_cpu_cores']),cores,rel_tol=1e-8,abs_tol=1e-9),'CPU units or rate differ')
    available=d['cgroup_memory_peak_available'];require(type(available) is bool,'Peak availability is not boolean')
    if available:peak=number(d['cgroup_memory_peak_bytes'],memory,1073741824,True)
    else:
        require(d['cgroup_memory_peak_bytes'] is None,'Unavailable memory peak must be null')
        peak=None
    return {'observation_seconds':elapsed,'cpu_core_seconds':cpu,'average_cpu_cores':cores,
            'cpu_user_seconds':user/1e6,'cpu_system_seconds':system/1e6,
            'cpu_throttled_periods':number(delta['nr_throttled'],0,integer=True),
            'cpu_throttled_seconds':number(delta['throttled_usec'],0,integer=True)/1e6,
            'sampled_agent_rss_peak_mib':rss/1024,'sampled_cgroup_memory_max_mib':memory/1048576,
            'kernel_cgroup_memory_peak_available':available,'kernel_cgroup_memory_peak_mib':None if peak is None else peak/1048576,
            'sample_count':len(rows),'maximum_sample_gap_seconds':max(gaps),
            'cpu_includes_watchdog':True,'rss_owner_verified':True,'rss_is_sampled_not_exact_lifetime_peak':True}


def load(path):
    def pairs(items):
        d={}
        for k,v in items:
            require(k not in d,'Duplicate JSON key');d[k]=v
        return d
    def invalid(value):raise ValueError('Nonfinite JSON value')
    return json.loads(Path(path).read_text(),object_pairs_hook=pairs,parse_constant=invalid)


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--sample',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();result=verify(load(a.sample))
    with a.output.open('x') as f:json.dump(result,f,indent=2,allow_nan=False);f.write('\n')
    print(json.dumps(result,allow_nan=False))


if __name__=='__main__':main()
