#!/usr/bin/env python3
"""Compile the actual kfunc GoTLS return body with fake map/helper boundaries."""
import argparse
import hashlib
import json
import pathlib
import re
import resource
import subprocess
import tempfile
import unittest

PARSER=argparse.ArgumentParser()
PARSER.add_argument('--root',type=pathlib.Path,required=True,help='actual candidate ebpf directory')
PARSER.add_argument('--base-root',type=pathlib.Path,required=True,help='unchanged baseline ebpf directory for type declarations')
ARGS,UNIT_ARGS=PARSER.parse_known_args()
ROOT=ARGS.root.resolve()
BASE=ARGS.base_root.resolve()

def extract_decl(text,kind,name):
    match=re.search(r'^'+kind+r' '+name+r'\s*\{.*?^}[^;\n]*;',text,re.M|re.S)
    if not match: raise ValueError('missing actual declaration '+name)
    return match.group()

def actual_body():
    source=(ROOT/'kernel/go_tls.bpf.c').read_text()
    start=source.index('UPROG(go_tls_read_exit) (struct pt_regs *ctx)')
    end=source.index('\n}',start)+2
    return source[start:end]

PREAMBLE=r'''
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <linux/types.h>
#include <linux/bpf.h>
#define LINUX_VER_KFUNC 1
#define UPROG(name) int name
#define DEFINE_DBG_DATA(x)
#define submit_debug(F,N,L)
#define submit_debug_str(F,N,P)
#define PT_GO_REGS_PARM1(ctx) ((ctx)->result)
struct pt_regs {ssize_t result;};
struct ebpf_proc_info {int opaque;};
@ACTUAL_TYPES@
static char proc_info_map,tls_conn_map,http2_tcp_seq_map;
static __u64 current_id,current_goid;
static int scope_allowed,proc_present,tls_present,register_based;
static int update_fail,lookup_fail,update_calls,lookup_calls,delete_calls,process_calls,vectors;
static struct ebpf_proc_info info;
static struct tls_conn tls;
static struct tls_conn_key fixture_tls_key;
static struct data_args_t seen_args;
static struct process_data_extra seen_extra;
static __u64 seen_id;
static ssize_t seen_count;
static int seen_direction,process_result;
static char payload[]="GET /unit HTTP/1.1\r\n\r\n";
struct entry {__u64 key; int present; struct data_args_t value;} entries[4];
#define CHECK(x) do {vectors++;assert(x);} while(0)
static struct entry *find_entry(__u64 key) {
    for(int i=0;i<4;i++)if(entries[i].present && entries[i].key==key)return &entries[i];
    return NULL;
}
static void seed(__u64 key,struct data_args_t value) {
    struct entry *e=find_entry(key);
    if(!e)for(int i=0;i<4;i++)if(!entries[i].present){e=&entries[i];break;}
    assert(e);e->present=1;e->key=key;e->value=value;
}
static bool socket_scope_matches_current(void){return scope_allowed;}
static __u64 bpf_get_current_pid_tgid(void){return current_id;}
static __u64 get_current_goroutine(void){return current_goid;}
static bool is_register_based_call(struct ebpf_proc_info *p){assert(p==&info);return register_based;}
static __u32 get_tcp_read_seq(int fd,void *a,void *b){(void)a;(void)b;assert(fd==tls.fd);return 999;}
static __u64 bpf_ktime_get_ns(void){return 123456789;}
static long bpf_probe_read_user(void *dst,size_t size,const void *src){memcpy(dst,src,size);return 0;}
static void *bpf_map_lookup_elem(void *map,const void *key){
    if(map==&proc_info_map){assert(*((const pid_t *)key)==(pid_t)(current_id>>32));return proc_present?&info:NULL;}
    if(map==&tls_conn_map){
        const struct tls_conn_key *k=key;
        assert(k->tgid==fixture_tls_key.tgid && k->goid==fixture_tls_key.goid);
        return tls_present?&tls:NULL;
    }
    assert(0);return NULL;
}
static long bpf_map_update_elem(void *map,const void *key,const void *value,__u64 flags){
    (void)flags;assert(map==&http2_tcp_seq_map);
    const struct http2_tcp_seq_key *k=key;
    assert(k->tgid==(int)(current_id>>32) && k->fd==tls.fd && k->tcp_seq_end==999);
    assert(*(const __u32 *)value==tls.tcp_seq);return 0;
}
static long bpf_map_delete_elem(void *map,const void *key){
    assert(map==&tls_conn_map);(void)key;tls_present=0;return 0;
}
static int active_read_args_map__update(__u64 *key,struct data_args_t *value){
    update_calls++;if(update_fail)return -ENOMEM;seed(*key,*value);return 0;
}
static struct data_args_t *active_read_args_map__lookup(__u64 *key){
    lookup_calls++;if(lookup_fail)return NULL;
    struct entry *e=find_entry(*key);return e?&e->value:NULL;
}
static int active_read_args_map__delete(__u64 *key){
    delete_calls++;struct entry *e=find_entry(*key);if(e)e->present=0;return 0;
}
static int process_data(struct pt_regs *ctx,__u64 id,enum traffic_direction direction,struct data_args_t *args,ssize_t count,const struct process_data_extra *extra){
    (void)ctx;process_calls++;
    struct entry *e=find_entry(id);CHECK(e!=NULL && args==&e->value);
    seen_id=id;seen_direction=direction;seen_count=count;seen_args=*args;seen_extra=*extra;
    return process_result;
}
'''

MAIN=r'''
static void reset(void){
    memset(entries,0,sizeof(entries));memset(&seen_args,0,sizeof(seen_args));memset(&seen_extra,0,sizeof(seen_extra));
    current_id=((__u64)17<<32)|41;current_goid=77;
    fixture_tls_key=(struct tls_conn_key){.tgid=17,.goid=77};
    tls=(struct tls_conn){.fd=9,.buffer=payload,.tcp_seq=123,.sp=NULL};
    scope_allowed=proc_present=tls_present=register_based=1;
    update_fail=lookup_fail=update_calls=lookup_calls=delete_calls=process_calls=0;process_result=-1;
}
static void preserve_other_key(void){
    struct entry *other=find_entry(((__u64)18<<32)|41);
    CHECK(other!=NULL && other->value.fd==88 && other->value.buf==payload+1);
}
static void seed_other_key(void){seed(((__u64)18<<32)|41,(struct data_args_t){.fd=88,.buf=payload+1});}
int main(void){
    struct pt_regs ctx={.result=19};
    reset();seed_other_key();
    CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==1 && lookup_calls==1 && process_calls==1 && delete_calls==1);
    CHECK(seen_id==current_id && seen_direction==T_INGRESS && seen_count==19);
    CHECK(seen_args.fd==9 && seen_args.buf==payload && seen_args.tcp_seq==123);
    CHECK(seen_args.enter_ts==123456789 && seen_args.sk==NULL);
    CHECK(seen_args.iov==NULL && seen_args.iovlen==0 && seen_args.extra_iov==NULL && seen_args.extra_iovlen==0);
    CHECK(seen_extra.source==DATA_SOURCE_GO_TLS_UPROBE && seen_extra.coroutine_id==77 && seen_extra.is_go_process && !seen_extra.vecs);
    CHECK(!find_entry(current_id) && tls_present==0);preserve_other_key();

    reset();seed_other_key();seed(current_id,(struct data_args_t){.fd=99,.buf=payload+2});update_fail=1;
    CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==1 && lookup_calls==0 && process_calls==0 && delete_calls==1);
    CHECK(!find_entry(current_id) && tls_present==0);preserve_other_key();

    reset();seed_other_key();lookup_fail=1;
    CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==1 && lookup_calls==1 && process_calls==0 && delete_calls==1);
    CHECK(!find_entry(current_id) && tls_present==0);preserve_other_key();

    reset();process_result=0;CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(process_calls==1 && delete_calls==1 && !find_entry(current_id));
    reset();ctx.result=0;CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==0 && process_calls==0 && tls_present==0);
    ctx.result=19;
    reset();scope_allowed=0;CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==0 && lookup_calls==0 && process_calls==0 && delete_calls==0);
    reset();proc_present=0;CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==0 && process_calls==0);
    reset();tls_present=0;CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(update_calls==0 && process_calls==0);
    // A second TID in the same TGID must not touch the first TID's entry.
    reset();seed(current_id,(struct data_args_t){.fd=66});
    __u64 first=current_id;current_id=((__u64)17<<32)|42;
    CHECK(go_tls_read_exit(&ctx)==0);
    CHECK(seen_id==current_id && find_entry(first)->value.fd==66 && !find_entry(current_id));
    printf("go_tls_map_vectors=%d\n",vectors);return 0;
}
'''

def source():
    header=(BASE/'kernel/include/socket_trace.h').read_text()
    common=(BASE/'kernel/include/common.h').read_text()
    uprobe=(BASE/'kernel/uprobe_base.bpf.c').read_text()
    decls=[extract_decl(common,'enum',name) for name in ('message_type','traffic_direction','traffic_protocol','process_data_extra_source')]
    decls += [extract_decl(header,'enum','syscall_src_func')]
    decls += [extract_decl(header,'struct',name) for name in ('data_args_t','process_data_extra','tls_conn','tls_conn_key')]
    decls += [extract_decl(uprobe,'struct','http2_tcp_seq_key')]
    body=actual_body()
    return PREAMBLE.replace('@ACTUAL_TYPES@','\n'.join(decls))+'\n'+body+'\n'+MAIN

def no_core(): resource.setrlimit(resource.RLIMIT_CORE,(0,0))

def run():
    with tempfile.TemporaryDirectory(prefix='traflens-go-tls-map-') as directory:
        path=pathlib.Path(directory)
        (path/'test.c').write_text(source())
        build=subprocess.run(['cc','-std=gnu99','-O2','-Wall','-Wextra','-Werror',str(path/'test.c'),'-o',str(path/'test')],capture_output=True,text=True,timeout=30)
        if build.returncode: raise AssertionError(build.stderr)
        return subprocess.run([str(path/'test')],capture_output=True,text=True,timeout=10,preexec_fn=no_core)

if __name__ == "__main__":
    result = run()
    if result.returncode:
        raise SystemExit(result.stderr)
    print(result.stdout, end="")
