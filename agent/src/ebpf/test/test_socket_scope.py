#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Compile real scope helpers against independent fake kernel/BTF layouts."""
from pathlib import Path
import os
import re
import resource
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CC = os.environ.get("CC", "cc")
C_TEST = r"""
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <linux/types.h>
#include <linux/btf.h>
static int reads, fail_read, write_before_error, vectors;
static void (*read_hook)(void);
static const void *regions[3]; static size_t sizes[3];
static long fake_read(void *dst, __u32 n, const void *src) {
    reads++;
    if (read_hook) read_hook();
    if (reads == fail_read && !write_before_error) return -EFAULT;
    for (int i=0;i<3;i++) {
        uintptr_t a=(uintptr_t)src,b=(uintptr_t)regions[i];
        if(a>=b && a-b<=sizes[i] && n<=sizes[i]-(a-b)) {
            memcpy(dst,src,n);
            return reads==fail_read ? -EFAULT : 0;
        }
    }
    return -EFAULT;
}
static void (*add_hook)(volatile __u64 *);
static __u64 fake_xadd_add(volatile __u64 *p,__u64 value) {
    __u64 before=__atomic_fetch_add(p,value,__ATOMIC_SEQ_CST);
    if(add_hook)add_hook(p);
    return before;
}
#define __sync_fetch_and_add(p,n) fake_xadd_add((p),(n))
#define __BPF_TRACING__ 1
#define bpf_probe_read fake_read
#include "kernel/include/socket_scope.h"
#undef __BPF_TRACING__
#include "user/socket_scope.h"
#define CHECK(x) do { vectors++; assert(x); } while(0)
static const struct socket_scope_config *hook_scope;
static void *hook_task;
static struct socket_scope_scratch *hook_scratch;
static int nested_denied;
static int handed_off;
static void drop_competing_attempt(volatile __u64 *depth) {
    add_hook=NULL;
    CHECK(__atomic_fetch_sub(depth,1,__ATOMIC_SEQ_CST)==2);
    handed_off++;
}
static void nested_hook(void) {
    if(!socket_scope_allows_task(hook_scope,hook_task,hook_scratch)) nested_denied++;
}
static struct socket_scope_config wrapper_scope;
static struct socket_scope_scratch *wrapper_scratch;
static int scratch_lookups,current_task_calls;
static void *wrapper_task;
static const struct socket_scope_config *socket_scope_map__lookup(__u32 *k) {(void)k;return &wrapper_scope;}
static struct socket_scope_scratch *socket_scope_scratch_map__lookup(__u32 *k) {(void)k;scratch_lookups++;return wrapper_scratch;}
static uint64_t fake_current_task(void) {current_task_calls++;return (uintptr_t)wrapper_task;}
#define bpf_get_current_task fake_current_task
@MATCH_CURRENT@
#undef bpf_get_current_task
struct fake_common { char padding[12]; __u32 inum; };
struct fake_net { char padding[32]; struct fake_common ns; };
struct fake_proxy { char padding[24]; struct fake_net *net; };
struct fake_task { char padding[16]; struct fake_proxy *nsproxy; };
static void kernel_vectors(void) {
    struct fake_net net={.ns.inum=42};
    struct fake_proxy proxy={.net=&net};
    struct fake_task task={.nsproxy=&proxy};
    regions[0]=&task;sizes[0]=sizeof(task);
    regions[1]=&proxy;sizes[1]=sizeof(proxy);
    regions[2]=&net;sizes[2]=sizeof(net);
    struct socket_scope_config good={.netns_id=42,.validated=1,
        .task_nsproxy_offset=offsetof(struct fake_task,nsproxy),
        .nsproxy_net_offset=offsetof(struct fake_proxy,net),
        .net_ns_offset=offsetof(struct fake_net,ns),
        .ns_inum_offset=offsetof(struct fake_common,inum)};
    struct socket_scope_config cfg=good;
    struct socket_scope_scratch scratch={0};
    reads=0; CHECK(socket_scope_allows_task(&cfg,&task,&scratch)); CHECK(reads==3);
    cfg.netns_id=0;reads=0;CHECK(socket_scope_allows_task(&cfg,NULL,&scratch));CHECK(reads==0);
    CHECK(!socket_scope_allows_task(NULL,&task,&scratch));
    cfg=good; CHECK(!socket_scope_allows_task(&cfg,NULL,&scratch));
    cfg.validated=0;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    cfg.validated=2;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    cfg=good;cfg.netns_id=43;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    cfg=good;net.ns.inum=0;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));net.ns.inum=42;
    task.nsproxy=NULL;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));task.nsproxy=&proxy;
    proxy.net=NULL;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));proxy.net=&net;
    for(int n=1;n<=3;n++) {
        reads=0;fail_read=n;write_before_error=0;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
        reads=0;write_before_error=1;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    }
    fail_read=0;write_before_error=0;
    __u32 *offsets[]={&cfg.task_nsproxy_offset,&cfg.nsproxy_net_offset,&cfg.net_ns_offset,&cfg.ns_inum_offset};
    for(int n=0;n<4;n++) {
        cfg=good;*offsets[n]=SOCKET_SCOPE_OFFSET_MAX+1;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    }
    cfg=good;cfg.net_ns_offset=65535;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    cfg=good;cfg.task_nsproxy_offset=3;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    cfg=good;task.nsproxy=(void *)1;CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    task.nsproxy=&proxy;cfg=good;reads=0;
    CHECK(!socket_scope_allows_task(&cfg,&task,NULL));
    CHECK(reads==0);
    scratch.depth=1;scratch.cursor.pointer=(void *)0x1234;
    CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    CHECK(scratch.depth==1 && scratch.cursor.pointer==(void *)0x1234 && reads==0);
    scratch.depth=0;
    for(int n=1;n<=3;n++) {
        reads=0;fail_read=n;write_before_error=1;
        CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
        CHECK(scratch.depth==0);
        fail_read=0;reads=0;write_before_error=0;
        CHECK(socket_scope_allows_task(&cfg,&task,&scratch));
        CHECK(scratch.depth==0);
    }
    hook_scope=&cfg;hook_task=&task;hook_scratch=&scratch;
    nested_denied=0;read_hook=nested_hook;reads=0;
    CHECK(socket_scope_allows_task(&cfg,&task,&scratch));
    read_hook=NULL;
    CHECK(nested_denied==3 && reads==3 && scratch.depth==0);
    struct socket_scope_scratch other_cpu={0};other_cpu.depth=1;
    CHECK(socket_scope_allows_task(&cfg,&task,&scratch));
    CHECK(!socket_scope_allows_task(&cfg,&task,&other_cpu));
    CHECK(other_cpu.depth==1 && scratch.depth==0);
    other_cpu.depth=0;
    CHECK(socket_scope_allows_task(&cfg,&task,&other_cpu));
    CHECK(other_cpu.depth==0 && scratch.depth==0);
    wrapper_scope=good;wrapper_scope.netns_id=0;wrapper_scratch=NULL;wrapper_task=NULL;
    scratch_lookups=current_task_calls=0;
    CHECK(socket_scope_matches_current());
    CHECK(scratch_lookups==0 && current_task_calls==0);
    wrapper_scope=good;wrapper_task=&task;
    CHECK(!socket_scope_matches_current());
    CHECK(scratch_lookups==1 && current_task_calls==0);
    wrapper_scratch=&scratch;
    CHECK(socket_scope_matches_current());
    CHECK(scratch_lookups==2 && current_task_calls==1 && scratch.depth==0);
    scratch.depth=2;scratch.cursor.pointer=(void *)0x4321;reads=0;
    CHECK(!socket_scope_allows_task(&cfg,&task,&scratch));
    CHECK(scratch.depth==2 && scratch.cursor.pointer==(void *)0x4321 && reads==0);
    CHECK(__atomic_fetch_sub(&scratch.depth,1,__ATOMIC_SEQ_CST)==2);
    handed_off=0;add_hook=drop_competing_attempt;
    CHECK(socket_scope_allows_task(&cfg,&task,&scratch));
    CHECK(handed_off==1 && scratch.depth==0);
    CHECK(sizeof(struct socket_scope_scratch)==16);
    printf("kernel_vectors=%d\n",vectors);
}
struct btf { int present; };
struct stype {struct btf_type t;struct btf_member members[2];};
struct itype {struct btf_type t;__u32 encoding;};
static struct stype task_t,proxy_t,net_t,common_t;
static struct btf_type pointer_proxy,pointer_net,modifier;
static struct itype integer;
static const struct btf_type *types[10];
static const char *names[]={"","task_struct","nsproxy","net","ns_common","net_ns","ns","inum","unsigned int","wrong"};
const char *btf__name_by_offset(const struct btf *b,__u32 id) {(void)b;return id<10?names[id]:NULL;}
const struct btf_type *btf__type_by_id(const struct btf *b,__u32 id) {(void)b;return id<10?types[id]:NULL;}
__s32 btf__find_by_name_kind(const struct btf *b,const char *n,__u32 kind) {
    (void)b;
    for(int i=1;i<=4;i++)if(types[i] && BTF_INFO_KIND(types[i]->info)==kind && !strcmp(names[types[i]->name_off],n))return i;
    return -1;
}
static void setup_btf(void) {
    task_t=(struct stype){.t={.name_off=1,.info=(BTF_KIND_STRUCT<<24)|1,.size=24},.members={{.name_off=2,.type=5,.offset=128}}};
    proxy_t=(struct stype){.t={.name_off=2,.info=(BTF_KIND_STRUCT<<24)|1,.size=32},.members={{.name_off=5,.type=6,.offset=192}}};
    net_t=(struct stype){.t={.name_off=3,.info=(BTF_KIND_STRUCT<<24)|1,.size=48},.members={{.name_off=6,.type=4,.offset=256}}};
    common_t=(struct stype){.t={.name_off=4,.info=(BTF_KIND_STRUCT<<24)|1,.size=16},.members={{.name_off=7,.type=7,.offset=96}}};
    pointer_proxy=(struct btf_type){.info=BTF_KIND_PTR<<24,.type=2};
    pointer_net=(struct btf_type){.info=BTF_KIND_PTR<<24,.type=3};
    integer=(struct itype){.t={.name_off=8,.info=BTF_KIND_INT<<24,.size=4},.encoding=32};
    modifier=(struct btf_type){.info=BTF_KIND_CONST<<24,.type=5};
    types[1]=&task_t.t;types[2]=&proxy_t.t;types[3]=&net_t.t;types[4]=&common_t.t;
    types[5]=&pointer_proxy;types[6]=&pointer_net;types[7]=&integer.t;types[8]=&modifier;
}
static void unsupported(struct btf *b) {
    struct socket_scope_config out;memset(&out,255,sizeof(out));
    CHECK(socket_scope_resolve(b,42,&out)==-ENOTSUP);
    struct socket_scope_config empty={0};CHECK(memcmp(&out,&empty,sizeof(out))==0);
}
static void btf_vectors(void) {
    int start=vectors;struct btf b={0};struct socket_scope_config out;
    setup_btf();CHECK(socket_scope_resolve(&b,42,&out)==0);
    CHECK(out.netns_id==42 && out.validated==1 && out.task_nsproxy_offset==16 &&
          out.nsproxy_net_offset==24 && out.net_ns_offset==32 && out.ns_inum_offset==12);
    CHECK(socket_scope_resolve(NULL,0,&out)==0 && out.netns_id==0 && out.validated==0);
    unsupported(NULL);unsupported((void *)-1);
    setup_btf();types[1]=NULL;unsupported(&b);
    setup_btf();task_t.members[0].name_off=9;unsupported(&b);
    setup_btf();task_t.members[0].offset=129;unsupported(&b);
    setup_btf();task_t.t.info|=1U<<31;task_t.members[0].offset|=8U<<24;unsupported(&b);
    setup_btf();task_t.t.size=23;unsupported(&b);
    setup_btf();task_t.members[0].offset=65536*8;task_t.t.size=65544;unsupported(&b);
    setup_btf();pointer_proxy.type=3;unsupported(&b);
    setup_btf();pointer_proxy.info=BTF_KIND_INT<<24;unsupported(&b);
    setup_btf();net_t.members[0].type=6;unsupported(&b);
    setup_btf();net_t.t.size=47;unsupported(&b);
    setup_btf();integer.t.size=8;unsupported(&b);
    setup_btf();integer.encoding=(BTF_INT_SIGNED<<24)|32;unsupported(&b);
    setup_btf();integer.encoding=31;unsupported(&b);
    setup_btf();integer.encoding=(1<<16)|32;unsupported(&b);
    setup_btf();common_t.t.size=15;unsupported(&b);
    setup_btf();task_t.t.info=(BTF_KIND_STRUCT<<24)|2;task_t.members[1]=task_t.members[0];unsupported(&b);
    setup_btf();task_t.members[0].type=8;modifier.type=8;unsupported(&b);
    setup_btf();task_t.members[0].type=8;CHECK(socket_scope_resolve(&b,42,&out)==0);
    setup_btf();common_t.members[0].offset=0;CHECK(socket_scope_resolve(&b,42,&out)==0 && out.ns_inum_offset==0);
    printf("btf_vectors=%d\n",vectors-start);
}
static void state_vectors(void) {
    int start=vectors;struct socket_scope_state s={0};
    CHECK(s.netns_id==0 && !s.frozen);
    CHECK(socket_scope_set(&s,42)==0 && s.netns_id==42);
    CHECK(socket_scope_set(&s,0)==0 && s.netns_id==0);
    CHECK(socket_scope_set(&s,UINT32_MAX)==0 && s.netns_id==UINT32_MAX);
    CHECK(socket_scope_set(&s,(uint64_t)UINT32_MAX+1)==-EINVAL && s.netns_id==UINT32_MAX);
    CHECK(socket_scope_freeze(&s)==UINT32_MAX && s.frozen);
    CHECK(socket_scope_set(&s,0)==-EBUSY && s.netns_id==UINT32_MAX);
    CHECK(socket_scope_set(&s,42)==-EBUSY && s.netns_id==UINT32_MAX);
    CHECK(socket_scope_freeze(&s)==UINT32_MAX);
    __u32 output=123;
    CHECK(socket_scope_begin(&s,&output)==-EALREADY && output==123);
    struct socket_scope_state legacy={0};
    CHECK(socket_scope_begin(&legacy,&output)==0 && output==0);
    CHECK(socket_scope_begin(&legacy,&output)==0 && output==0);
    CHECK(socket_scope_set(&legacy,42)==-EBUSY);
    CHECK(sizeof(struct socket_scope_config)==24);
    printf("state_vectors=%d\n",vectors-start);
}
int main(void) {kernel_vectors();btf_vectors();state_vectors();printf("total_vectors=%d\n",vectors);}
"""

C_RELEASE_TEST = r"""
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct list_head {struct list_head *next,*prev;};
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define list_for_each_safe(p,n,h) for(p=(h)->next,n=p->next;p!=(h);p=n,n=p->next)
static void list_head_del(struct list_head *p) {p->next->prev=p->prev;p->prev->next=p->next;}
static void add(struct list_head *p,struct list_head *h) {p->prev=h->prev;p->next=h;h->prev->next=p;h->prev=p;}
struct btf {int marker;};
struct ebpf_object {struct btf *btf,*btf_vmlinux;int fds[2];};
struct tracer_probes_conf {
    int kprobes_nr,tps_nr,kfuncs_nr;
    struct {char *func;} ksymbols[2];
    struct {char *name;} tps[2],kfuncs[2];
};
struct map_config {struct list_head list;};
struct bpf_tracer {
    struct ebpf_object *obj;
    struct tracer_probes_conf *tps;
    struct list_head maps_conf_head;
    pthread_mutex_t mutex_probes_lock;
};
static struct bpf_tracer *g_tracer;
static int object_calls,btf_calls,destroy_calls,allocated,checks;
static void *allocations[32];static int freed[32];
static void *make(size_t n) {void *p=calloc(1,n);assert(p);allocations[allocated]=p;freed[allocated++]=0;return p;}
static void tracked_free(void *p) {
    if(!p)return;
    for(int i=0;i<allocated;i++) if(allocations[i]==p) {
        assert(!freed[i]);freed[i]=1;free(p);return;
    }
    assert(0 && "unowned free");
}
static void btf__free(struct btf *b) {btf_calls++;tracked_free(b);}
static void __attribute__((unused)) release_object(struct ebpf_object *o) {
    object_calls++;assert(close(o->fds[0])==0);assert(close(o->fds[1])==0);
    btf__free(o->btf);tracked_free(o);
}
static int destroy_mutex(pthread_mutex_t *p) {destroy_calls++;return pthread_mutex_destroy(p);}
#define DF_IS_ERR_OR_NULL(p) (!(p) || (uintptr_t)(p)>=(uintptr_t)-4095)
#define free tracked_free
#define pthread_mutex_destroy destroy_mutex
@CLEANUP@
#undef pthread_mutex_destroy
#undef free
#define CHECK(x) do{checks++;assert(x);}while(0)
static void scenario(int alias,int other_global) {
    object_calls=btf_calls=destroy_calls=allocated=0;
    struct bpf_tracer tracer={0},other={0};g_tracer=other_global?&other:&tracer;
    pthread_mutex_init(&tracer.mutex_probes_lock,NULL);
    tracer.maps_conf_head.next=tracer.maps_conf_head.prev=&tracer.maps_conf_head;
    tracer.obj=make(sizeof(*tracer.obj));tracer.obj->btf=make(sizeof(struct btf));
    tracer.obj->btf_vmlinux=alias?tracer.obj->btf:make(sizeof(struct btf));
    assert(pipe(tracer.obj->fds)==0);int f0=tracer.obj->fds[0],f1=tracer.obj->fds[1];
    tracer.tps=make(sizeof(*tracer.tps));
    tracer.tps->kprobes_nr=tracer.tps->tps_nr=tracer.tps->kfuncs_nr=2;
    for(int i=0;i<2;i++) {
        tracer.tps->ksymbols[i].func=make(8);
        tracer.tps->tps[i].name=make(8);
        tracer.tps->kfuncs[i].name=make(8);
        struct map_config *cfg=make(sizeof(*cfg));add(&cfg->list,&tracer.maps_conf_head);
    }
    CHECK(release_unattached_socket_scope(&tracer)==0);
    CHECK(object_calls==1);CHECK(btf_calls==(alias?1:2));CHECK(destroy_calls==1);
    CHECK(tracer.obj==NULL && tracer.tps==NULL);
    CHECK(g_tracer==(other_global?&other:NULL));
    CHECK(tracer.maps_conf_head.next==&tracer.maps_conf_head && tracer.maps_conf_head.prev==&tracer.maps_conf_head);
    CHECK(fcntl(f0,F_GETFD)==-1 && errno==EBADF);
    CHECK(fcntl(f1,F_GETFD)==-1 && errno==EBADF);
    for(int i=0;i<allocated;i++) CHECK(freed[i]==1);
}
int main(void) {scenario(0,0);scenario(1,0);scenario(0,1);printf("release_vectors=%d\n",checks);}
"""


def no_core_dump():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def body(source, name):
    match = re.search(r"\bUPROG\(" + re.escape(name) + r"\)\s*\([^;]*?\)\s*\{", source, re.S)
    if match is None:
        match = re.search(r"\b" + re.escape(name) + r"\([^;]*?\)\s*\{", source, re.S)
    if match is None:
        raise AssertionError("missing function " + name)
    start = match.end()
    depth = 1
    for i in range(start, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[start:i]
    raise AssertionError("unterminated function " + name)


C_OUTPUT_REFCNT_TEST = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <linux/types.h>
static int fail_read,reads,copies,copy_result,finalizes;
static int bpf_probe_read(void *dst,unsigned len,const void *src) {
    if(++reads==fail_read)return -1;
    memcpy(dst,src,len);return 0;
}
#define __BPF_TRACING__ 1
#include "kernel/include/socket_scope.h"
struct net {__u32 inum;};
struct proxy {struct net *net;};
struct task {struct proxy *proxy;};
static struct net ns={42};static struct proxy proxy={&ns};
static struct task task={&proxy};
static struct socket_scope_scratch scratch;
static struct socket_scope_config scope={.netns_id=42,.validated=1};
static bool socket_scope_matches_current(void) {return socket_scope_allows_task(&scope,&task,&scratch);}
struct tracer_ctx_s {int push_buffer_refcnt;__u64 last_period_timestamp;};
struct __socket_data {int source;unsigned data_len;char data[256];};
struct __socket_data_buffer {unsigned len,events_num;char data[4096];};
struct data_args_t {const char *buf;unsigned extra_iovlen;};
enum traffic_direction {T_INGRESS,T_EGRESS};
#define DATA_SOURCE_IO_EVENT 9
#define MAX_EVENTS_BURST 32
#define PERIODIC_PUSH_DELAY_THRESHOLD_NS 100
static void *io_event_buffer__lookup(__u32 *key) {(void)key;return NULL;}
static int output_data_copy(const struct data_args_t *args,bool vecs,
struct __socket_data_buffer *b,struct __socket_data *v,int max_size,
__u32 reassembly_bytes,char *buffer) {
(void)args;(void)vecs;(void)b;(void)v;(void)max_size;(void)reassembly_bytes;(void)buffer;
copies++;return copy_result;
}
static __u64 bpf_ktime_get_ns(void) {return 0;}
static void finalize_data_output(void *ctx,struct tracer_ctx_s *t,__u64 n,__u64 d,
struct __socket_data_buffer *b) {(void)ctx;(void)t;(void)n;(void)d;(void)b;finalizes++;}
static int output_extra_data_common(struct data_args_t *a,struct __socket_data_buffer*b,
struct __socket_data*v,int m,__u32 r){(void)a;(void)b;(void)v;(void)m;(void)r;return 0;}
static int __output_data_common(void *ctx,struct tracer_ctx_s *tracer_ctx,
struct __socket_data_buffer *v_buff,const struct data_args_t *args,
enum traffic_direction dir,bool vecs,int max_size,bool is_close,__u32 reassembly_bytes)@OUTPUT_BODY@
static int assertions;
#define CHECK(c) do{assertions++;assert(c);}while(0)
static void run(int target,int read_fail,int busy,int copy_error,int close) {
    scope.netns_id=target;reads=0;fail_read=read_fail;copies=0;copy_result=copy_error?-1:4;
    scratch.depth=busy;scratch.cursor.pointer=(void*)0x1234;
    struct tracer_ctx_s t={0};struct __socket_data_buffer b={0};
    struct data_args_t args={.buf="test"};
    /* This is the acquire contract of both actual callers. */
    __sync_fetch_and_add(&t.push_buffer_refcnt,1);
    CHECK(t.push_buffer_refcnt==1);
    CHECK(__output_data_common(NULL,&t,&b,&args,T_INGRESS,false,1024,close,0)==0);
    CHECK(t.push_buffer_refcnt==0);
    CHECK(scratch.depth==(unsigned)busy);
    if(target!=42 || read_fail || busy) {
        CHECK(copies==0 && b.len==0 && b.events_num==0);
        if(busy)CHECK(scratch.cursor.pointer==(void*)0x1234);
    } else if(close)CHECK(copies==0 && b.events_num==1);
    else if(copy_error)CHECK(copies==1 && b.events_num==0);
    else CHECK(copies==1 && b.events_num==1);
}
int main(void){
    run(43,0,0,0,0);run(43,0,0,0,1);
    for(int n=1;n<=3;n++){run(42,n,0,0,0);run(42,0,0,0,0);}
    run(42,0,1,0,0);run(42,0,1,0,1);
    run(42,0,0,1,0);run(42,0,0,0,1);
    printf("{\"pass\":true,\"refcount_vectors\":12,\"c_assertions\":%d}\n",assertions);
}
'''

class SocketScopeTests(unittest.TestCase):
    def test_real_helpers_independent_layouts_and_failures(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            fake = directory / "bcc/linux"
            fake.mkdir(parents=True)
            (fake / "btf.h").write_text("#include <linux/btf.h>\n")
            source = directory / "scope.c"
            kernel = (ROOT / "kernel/socket_trace.bpf.c").read_text()
            predicate = "static bool socket_scope_matches_current(void) {" + body(kernel, "socket_scope_matches_current") + "}"
            source.write_text(C_TEST.replace("@MATCH_CURRENT@", predicate))
            output = directory / "scope"
            subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-I", str(directory), "-I", str(ROOT), str(source),
                            "-o", str(output)], check=True)
            result = subprocess.run([str(output)], text=True, capture_output=True,
                                    cwd=directory, preexec_fn=no_core_dump)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout, end="")
            self.assertIn("total_vectors=", result.stdout)

    def test_pre_attach_release_uses_owner_once_and_closes_fds(self):
        user = (ROOT / "user/socket.c").read_text()
        cleanup = "static int release_unattached_socket_scope(struct bpf_tracer *tracer) {" + body(user, "release_unattached_socket_scope") + "}"
        source_text = C_RELEASE_TEST.replace("@CLEANUP@", cleanup)
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source = directory / "release.c"
            source.write_text(source_text)
            output = directory / "release"
            subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                            str(source), "-pthread", "-o", str(output)], check=True)
            result = subprocess.run([str(output)], text=True, capture_output=True,
                                    cwd=directory, preexec_fn=no_core_dump)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            print(result.stdout, end="")
        load = body(user, "running_socket_tracer")
        scope = load[load.index("if (scope_netns != 0)"):load.index("create reader")]
        self.assertEqual(scope.count("discard_unattached_socket_scope(tracer);"), 2)
        discard = body(user, "discard_unattached_socket_scope")
        self.assertIn("tracer->release_cb = release_unattached_socket_scope", discard)
        self.assertEqual(discard.count("release_bpf_tracer(SK_TRACER_NAME)"), 1)
        self.assertNotIn("free_all_readers", cleanup)
        self.assertNotIn("tracer_hooks_detach", cleanup)

    def test_capture_paths_are_fenced_before_copy(self):
        socket = (ROOT / "kernel/socket_trace.bpf.c").read_text()
        for name in ["process_data", "__output_data_common", "__push_close_event",
                     "retrieve_ready_kern_offset"]:
            with self.subTest(function=name):
                self.assertTrue(body(socket, name).lstrip().startswith(
                    "if (!socket_scope_matches_current())") or name == "process_data" and
                    body(socket, name).lstrip().startswith("/* Reject before") or
                    name == "__output_data_common" and
                    body(socket, name).lstrip().startswith("/* Both callers"))
                self.assertIn("socket_scope_matches_current()", body(socket, name))
        io = (ROOT / "kernel/files_rw.bpf.c").read_text()
        self.assertTrue(body(io, "trace_io_event_common").lstrip().startswith(
            "if (!socket_scope_matches_current())"))
        for file in ["go_tls.bpf.c", "openssl.bpf.c", "go_http2.bpf.c"]:
            text = (ROOT / "kernel" / file).read_text()
            entries = re.findall(r"UPROG\(([^)]+)\)", text)
            self.assertTrue(entries)
            for name in entries:
                with self.subTest(file=file, entry=name):
                    start = body(text, name).lstrip()
                    if file == "go_http2.bpf.c":
                        self.assertTrue(start.startswith("struct member_fields_offset *offset = retrieve_ready_kern_offset();"))
                    else:
                        self.assertTrue(start.startswith("if (!socket_scope_matches_current())"))
        # A periodic worker can be outside the target namespace while flushing
        # records already approved at capture time.
        self.assertNotIn("socket_scope_matches_current", body(socket, "push_socket_data"))
        self.assertNotIn("socket_scope_matches_current", body(socket, "finalize_data_output"))

    def test_config_is_installed_before_any_attach(self):
        user = (ROOT / "user/socket.c").read_text()
        load = body(user, "running_socket_tracer")
        self.assertLess(load.index("socket_scope_begin"), load.index("tracer_bpf_load"))
        self.assertLess(load.index("socket_scope_resolve"), load.index("if (tracer_probes_init"))
        self.assertLess(load.index('"__socket_scope_map"'), load.index("if (tracer_hooks_attach"))
        self.assertIn("return ret;", load[load.index("socket_scope_resolve"):load.index("create reader")])
        self.assertIn("return -EIO;", load[load.index("socket_scope_resolve"):load.index("create reader")])
        setter = body(user, "set_socket_tracer_netns_scope")
        self.assertLess(setter.index("pthread_mutex_lock"), setter.index("socket_scope_set"))
        self.assertLess(setter.index("socket_scope_set"), setter.index("pthread_mutex_unlock"))
        self.assertLess(setter.index("inode > UINT32_MAX"), setter.index("EXTENDED_AI_AGENT_FILE_IO"))
        self.assertIn("EXTENDED_AI_AGENT_FILE_IO", setter)
        self.assertIn("return -ENOTSUP", setter)

    def test_adaptation_metadata_precedes_payload_fence(self):
        socket = (ROOT / "kernel/socket_trace.bpf.c").read_text()
        for function in ["infer_offset_phase_1", "infer_offset_phase_2"]:
            metadata = body(socket, function)
            self.assertIn("check_pid_validity()", metadata)
            self.assertNotIn("socket_scope_matches_current", metadata)
            self.assertNotIn("bpf_probe_read_user", metadata)
            self.assertNotIn("bpf_perf_event_output", metadata)
        send = body(socket, "do_sys_enter_sendto")
        self.assertIn("INFER_OFFSET_PHASE_1(sockfd)", send)
        self.assertNotIn("socket_scope_matches_current", send)
        self.assertLess(socket.index("INFER_OFFSET_PHASE_2(fd);"),
                        socket.index("__push_close_event(id,"))
        self.assertNotIn("socket_scope_matches_current", body(socket, "push_socket_data"))

    def test_scope_uses_existing_legacy_helpers(self):
        header = (ROOT / "kernel/include/socket_scope.h").read_text()
        self.assertNotIn("bpf_probe_read_kernel", header)
        self.assertNotIn("bpf_get_current_task_btf", header)
        self.assertNotIn("bpf_get_netns_cookie", header)
        self.assertIn("bpf_probe_read(", header)
        kernel = (ROOT / "kernel/socket_trace.bpf.c").read_text()
        predicate = body(kernel, "socket_scope_matches_current")
        self.assertLess(predicate.index("scope->netns_id == 0"), predicate.index("bpf_get_current_task()"))
        self.assertLess(predicate.index("scope->netns_id == 0"), predicate.index("socket_scope_scratch_map__lookup"))
        self.assertIn('asm volatile("" ::: "memory")', header)
        self.assertIn('asm volatile("" : "+r"(allowed) :: "memory")', header)
        self.assertIn("__sync_fetch_and_add(&scratch->depth, 1);", header)
        self.assertIn("__sync_fetch_and_add(&scratch->depth, (__u64)-1);", header)
        self.assertNotIn("__sync_val_compare_and_swap", header)
        self.assertNotIn("__atomic_", header)


    def test_output_scope_denial_releases_caller_refcount(self):
        socket = (ROOT / "kernel/socket_trace.bpf.c").read_text()
        output = body(socket, "__output_data_common")
        for name in ["__data_submit", "__push_close_event"]:
            caller = body(socket, name)
            self.assertLess(caller.index("__sync_fetch_and_add(&tracer_ctx->push_buffer_refcnt, 1)"),
                            caller.index("__output_data_common("))
        with tempfile.TemporaryDirectory(prefix="scope-refcount-") as tmp:
            directory = Path(tmp)
            source = directory / "refcount.c"
            source.write_text(C_OUTPUT_REFCNT_TEST.replace("@OUTPUT_BODY@", "{" + output + "}"))
            binary = directory / "refcount"
            subprocess.run([CC, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-parameter", "-I", str(ROOT), str(source),
                            "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True,
                                    preexec_fn=no_core_dump)
            self.assertEqual(result.returncode, 0, result.stderr)
            print(result.stdout, end="")

    def test_go_tls_map_arguments_and_failure_cleanup(self):
        helper = ROOT / "test/socket_scope_go_tls_vectors.py"
        result = subprocess.run(["python3", str(helper), "--root", str(ROOT),
                                 "--base-root", str(ROOT)],
                                capture_output=True, text=True, timeout=40)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        print(result.stdout, end="")


if __name__ == "__main__":
    unittest.main(verbosity=2)
