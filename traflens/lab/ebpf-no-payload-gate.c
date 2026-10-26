/* TrafLens bounded no-payload libtrace gate; Apache-2.0.
 * Includes pinned headers: no copied ABI layouts. Never inspect callback data. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include "user/tracer.h"
#include "user/socket.h"
#include "user/table.h"
#include "user/load.h"

static atomic_ulong callbacks;
static volatile sig_atomic_t interrupted;
static void on_signal(int sig) { (void)sig; interrupted = 1; }
static int discard_data(void *ctx, int queue, void *data) {
    (void)ctx; (void)queue; (void)data;
    atomic_fetch_add(&callbacks, 1);
    return 0;
}
static int attached_links(struct bpf_tracer *t) {
    int n=0; struct list_head *entry;
    pthread_mutex_lock(&t->mutex_probes_lock);
    for (entry=t->probes_head.next; entry!=&t->probes_head; entry=entry->next) {
        struct probe *p=container_of(entry, struct probe, list);
        if (p->link) n++;
    }
    for (int i=0;i<t->tracepoints_count;i++) if (t->tracepoints[i].link) n++;
    for (int i=0;i<t->kfuncs_count;i++) if (t->kfuncs[i].link) n++;
    pthread_mutex_unlock(&t->mutex_probes_lock);
    return n;
}
static int maps_are_closed(struct bpf_tracer *t) {
    unsigned char map[65536/8];
    if (!bpf_table_get_value(t,MAP_KPROBE_PORT_BITMAP_NAME,1,map)) return 0;
    for (size_t i=0;i<sizeof(map);i++) if (map[i]!=255) return 0;
    if (!bpf_table_get_value(t,MAP_KPROBE_PORT_BITMAP_NAME,0,map)) return 0;
    for (size_t i=0;i<sizeof(map);i++) if (map[i]!=0) return 0;
    for (int i=0;i<PROTO_NUM;i++) {
        int enabled=-1;
        if (!bpf_table_get_value(t,MAP_PROTO_FILTER_NAME,i,&enabled) || enabled!=0) return 0;
    }
    return 1;
}
static int probe_tcp(void) {
    int listener=-1,client=-1,server=-1,ok=0;
    const unsigned char synthetic[]="TrafLens-owned-no-payload-gate";
    unsigned char received[sizeof(synthetic)];
    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET; addr.sin_port=htons(18089);
    addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    struct timeval timeout={.tv_sec=1};
    listener=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if (listener<0 || bind(listener,(void*)&addr,sizeof(addr)) || listen(listener,1)) goto done;
    client=socket(AF_INET,SOCK_STREAM|SOCK_CLOEXEC,0);
    if (client<0) goto done;
    setsockopt(client,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(client,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    if (connect(client,(void*)&addr,sizeof(addr))) goto done;
    server=accept4(listener,NULL,NULL,SOCK_CLOEXEC);
    if (server<0) goto done;
    setsockopt(server,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));
    setsockopt(server,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    for (int i=0;i<20;i++) {
        if (send(client,synthetic,sizeof(synthetic),MSG_NOSIGNAL)!=sizeof(synthetic)) goto done;
        if (recv(server,received,sizeof(received),MSG_WAITALL)!=sizeof(received)) goto done;
        if (memcmp(received,synthetic,sizeof(synthetic))) goto done;
        if (send(server,synthetic,sizeof(synthetic),MSG_NOSIGNAL)!=sizeof(synthetic)) goto done;
        if (recv(client,received,sizeof(received),MSG_WAITALL)!=sizeof(received)) goto done;
        if (memcmp(received,synthetic,sizeof(synthetic))) goto done;
    }
    ok=20;
done:
    if (server>=0) close(server);
    if (client>=0) close(client);
    if (listener>=0) close(listener);
    return ok;
}
static void own_ids(FILE *f, struct bpf_tracer *t) {
    fprintf(f,",\"own_program_ids\":[");
    int first=1;
    for (int i=0;i<t->obj->progs_cnt;i++) {
        int fd=t->obj->progs[i].prog_fd;
        if (fd<0) continue;
        struct bpf_prog_info info={0};
        union bpf_attr attr={0};
        attr.info.bpf_fd=fd; attr.info.info_len=sizeof(info);
        attr.info.info=(uint64_t)&info;
        if (syscall(SYS_bpf,BPF_OBJ_GET_INFO_BY_FD,&attr,sizeof(attr))) continue;
        fprintf(f,"%s%u",first?"":",",info.id); first=0;
    }
    fprintf(f,"]");
}
int main(int argc,char **argv) {
    if (argc!=2 || strcmp(argv[1],"--execute-no-payload")) return 64;
    signal(SIGTERM,on_signal); signal(SIGINT,on_signal);
    prctl(PR_SET_NAME,"tlens-ebpf-gate",0,0,0);
    unsigned char bypass[65536/8],allow[65536/8]={0};
    _Static_assert(sizeof(struct kprobe_port_bitmap)==sizeof(bypass),"bitmap ABI");
    memset(bypass,255,sizeof(bypass));
    memset(ebpf_config_protocol_filter,0,sizeof(ebpf_config_protocol_filter));
    if (set_bypass_port_bitmap(bypass) || set_allow_port_bitmap(allow)) return 65;
    if (set_io_event_collect_mode(IO_EVENT_COLLECT_DISABLE) || set_virtual_file_collect(false)) return 66;
    /* No set_feature_pids, enable_ebpf_protocol, datadump, or profiler calls. */
    int init=bpf_tracer_init("/evidence/libtrace.log",false);
    FILE *f=fopen("/evidence/gate.json","w");
    if (!f) return 67;
    fprintf(f,"{\"init_result\":%d",init); fflush(f);
    if (init) { fprintf(f,",\"pass\":false}\n");fclose(f);return 1; }
    set_hooked_socket_syscalls(HOOKED_SOCKET_SYSCALL_ALL);
    int load=running_socket_tracer(discard_data,1,8,1024,1024,1024,1000);
    fprintf(f,",\"load_result\":%d",load);fflush(f);
    struct bpf_tracer *t=find_bpf_tracer(SK_TRACER_NAME);
    int maps_ok=load==0 && t && maps_are_closed(t),run=0,probe=0,before=0,after=-1,stop=-1;
    if (load==0 && maps_ok) {
        bpf_tracer_finish();
        for (int i=0;i<600 && !interrupted;i++) {
            if (get_socket_tracer_state()==TRACER_RUNNING) {run=1;break;}
            usleep(100000);
        }
        before=attached_links(t);
        if (run && before>0 && maps_are_closed(t)) probe=probe_tcp();
        usleep(300000);
    }
    if (t && load==0) {
        own_ids(f,t);fflush(f);
        if (get_socket_tracer_state()==TRACER_RUNNING) {
            stop=socket_tracer_stop();
            for (int i=0;i<150 && get_socket_tracer_state()!=TRACER_STOP;i++) usleep(100000);
        } else {
            /* Only this tracer; emergency synchronous detach if adaptation failed. */
            pthread_mutex_lock(&t->mutex_probes_lock);
            stop=tracer_hooks_detach(t);
            pthread_mutex_unlock(&t->mutex_probes_lock);
        }
        after=attached_links(t);
    }
    unsigned long count=atomic_load(&callbacks);
    int final_state=t?(int)get_socket_tracer_state():-1;
    int pass=load==0 && maps_ok && run && before>0 && probe==20 && stop==0 &&
             final_state==TRACER_STOP && after==0 && count==0 && !interrupted;
    fprintf(f,",\"kernel_bypass_all_ports\":%s,\"kernel_protocols_all_disabled\":%s,"
      "\"running\":%s,\"attached_links_before\":%d,\"owned_probe_roundtrips\":%d,"
      "\"stop_result\":%d,\"final_state\":%d,\"attached_links_after\":%d,"
      "\"callback_count\":%lu,\"payload_inspected_or_persisted\":false,\"pass\":%s}\n",
      maps_ok?"true":"false",maps_ok?"true":"false",run?"true":"false",before,probe,
      stop,final_state,after,count,pass?"true":"false");
    fclose(f);
    return pass?0:1;
}
