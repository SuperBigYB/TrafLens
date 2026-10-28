#define _GNU_SOURCE
/* Finite real TCP DNS in an externally owned namespace; default is offline.
 * No SDK, HTTP, fabricated TCP identity, pooling or fragmented-message support.
 * Actual complete binary frames and independent process/socket receipts remain local.
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define DNS_CAP 512
#define FRAME_CAP 514
#define EVENT_CAP 8
#define CASES 3
struct config { const char *role, *run, *output; int seconds, port; bool execute; };
struct connection { char scenario[16],local_ip[INET_ADDRSTRLEN],peer_ip[INET_ADDRSTRLEN]; int local_port,peer_port,fd,initial_errno,calls; uint64_t begin_real,end_real,begin_mono,end_mono; bool complete,closed; };
struct event { int case_index,fd,calls,error; bool response,complete; char operation[8],local_ip[INET_ADDRSTRLEN],peer_ip[INET_ADDRSTRLEN]; int local_port,peer_port; uint64_t begin_real,end_real,begin_mono,end_mono; size_t bytes; unsigned char data[FRAME_CAP]; };
static struct event events[EVENT_CAP];
static struct connection connections[CASES];
static int event_count,connection_count,completed;
static volatile sig_atomic_t stopping;
static uint64_t deadline_ns,process_start_ticks;
static long process_pid,process_tid;
static char network_namespace[128],pid_namespace[128],last_error[256];

struct sha256 { uint32_t h[8]; uint64_t bits; unsigned char block[64]; size_t used; };
static uint32_t rotr(uint32_t x, unsigned int n) { return (x >> n) | (x << (32 - n)); }
static void sha_block(struct sha256 *s) {
    static const uint32_t k[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++) w[i] = ((uint32_t)s->block[4*i] << 24) | ((uint32_t)s->block[4*i+1] << 16) | ((uint32_t)s->block[4*i+2] << 8) | s->block[4*i+3];
    for (int i = 16; i < 64; i++) {
        uint32_t a = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15] >> 3);
        uint32_t b = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] + a + w[i-7] + b;
    }
    uint32_t a=s->h[0],b=s->h[1],c=s->h[2],d=s->h[3],e=s->h[4],f=s->h[5],g=s->h[6],h=s->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t t1=h+(rotr(e,6)^rotr(e,11)^rotr(e,25))+((e&f)^(~e&g))+k[i]+w[i];
        uint32_t t2=(rotr(a,2)^rotr(a,13)^rotr(a,22))+((a&b)^(a&c)^(b&c));
        h=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;
    }
    s->h[0]+=a;s->h[1]+=b;s->h[2]+=c;s->h[3]+=d;s->h[4]+=e;s->h[5]+=f;s->h[6]+=g;s->h[7]+=h;
}
static void sha256_hex(const unsigned char *data, size_t length, char hex[65]) {
    struct sha256 s = {{0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19},0,{0},0};
    s.bits = (uint64_t)length * 8;
    for (size_t i=0;i<length;i++) { s.block[s.used++]=data[i]; if(s.used==64){sha_block(&s);s.used=0;} }
    s.block[s.used++]=0x80;
    if(s.used>56){while(s.used<64)s.block[s.used++]=0;sha_block(&s);s.used=0;}
    while(s.used<56)s.block[s.used++]=0;
    for(int i=7;i>=0;i--)s.block[s.used++]=(unsigned char)(s.bits>>(i*8));
    sha_block(&s);
    for(int i=0;i<8;i++)snprintf(hex+i*8,9,"%08" PRIx32,s.h[i]);
    hex[64]=0;
}

static uint64_t now_ns(clockid_t clock) {
    struct timespec t;
    if(clock_gettime(clock,&t)!=0)return 0;
    return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;
}
static void stop_handler(int signal_number) { (void)signal_number; stopping=1; }
static int fail(const char *message) { snprintf(last_error,sizeof(last_error),"%s",message); return -1; }
static int system_fail(const char *message) { snprintf(last_error,sizeof(last_error),"%s: %s",message,strerror(errno));return -1; }
static void json_string(FILE *f,const unsigned char *text,size_t length) {
    fputc('"',f);
    for(size_t i=0;i<length;i++) {
        unsigned char c=text[i];
        if(c=='"'||c=='\\'){fputc('\\',f);fputc(c,f);}
        else if(c<32||c>=127)fprintf(f,"\\u%04x",c);
        else fputc(c,f);
    }
    fputc('"',f);
}
static void json_text(FILE *f,const char *text) { json_string(f,(const unsigned char *)text,strlen(text)); }
static int numeric(const char *text,int low,int high,int *out) {
    char *end=NULL;errno=0;long value=strtol(text,&end,10);
    if(errno||!text[0]||!end||*end||value<low||value>high)return -1;
    *out=(int)value;return 0;
}
static bool valid_run(const char *run) {
    if(!run||strlen(run)!=28||strncmp(run,"dns-",4))return false;
    for(int i=4;i<28;i++)if(!((run[i]>='0'&&run[i]<='9')||(run[i]>='a'&&run[i]<='f')))return false;
    return true;
}
static int output_directory(const char *path) {
    char resolved[PATH_MAX];struct stat st;
    if(!path||path[0]!='/'||!realpath(path,resolved)||strcmp(path,resolved)||lstat(path,&st)||!S_ISDIR(st.st_mode)||(st.st_mode&0077)||st.st_uid!=geteuid())return fail("existing canonical owned0700 output directory required");
    int fd=open(path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    return fd<0?system_fail("open output"):fd;
}
static FILE *fresh_file(int directory,const char *name) {
    int fd=openat(directory,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if(fd<0){system_fail("create fresh evidence file");return NULL;}
    FILE *f=fdopen(fd,"w");if(!f){close(fd);system_fail("open evidence stream");}return f;
}
static int finish_file(FILE *f) {
    int ok=fflush(f)==0&&fsync(fileno(f))==0;int rc=fclose(f);
    return ok&&rc==0?0:system_fail("persist evidence");
}
static int identity(void) {
    process_pid=(long)getpid();process_tid=(long)syscall(SYS_gettid);
    char text[8192];int fd=open("/proc/self/stat",O_RDONLY|O_CLOEXEC);
    if(fd<0)return system_fail("read self identity");
    ssize_t size=read(fd,text,sizeof(text)-1);close(fd);
    if(size<=0)return fail("self stat unavailable");
    text[size]=0;
    char *end=strrchr(text,')');if(!end||end[1]!=' ')return fail("invalid self stat");
    char *state=NULL,*token=strtok_r(end+2," ",&state);
    for(int i=0;i<19&&token;i++)token=strtok_r(NULL," ",&state);
    if(!token)return fail("self start ticks missing");
    char *tail=NULL;errno=0;process_start_ticks=strtoull(token,&tail,10);
    if(errno||!process_start_ticks||!tail||*tail)return fail("invalid self start ticks");
    ssize_t n=readlink("/proc/self/ns/net",network_namespace,sizeof(network_namespace)-1);
    if(n<1)return system_fail("read self network namespace");
    network_namespace[n]=0;
    n=readlink("/proc/self/ns/pid",pid_namespace,sizeof(pid_namespace)-1);
    if(n<1)return system_fail("read self PID namespace");
    pid_namespace[n]=0;
    return 0;
}
static void emit_identity(FILE *f,const struct config *c) {
    fprintf(f,"\"role\":");json_text(f,c->role);fprintf(f,",\"run\":");json_text(f,c->run);
    fprintf(f,",\"pid\":%ld,\"tid\":%ld,\"start_ticks\":\"%" PRIu64 "\",\"netns\":",process_pid,process_tid,process_start_ticks);
    json_text(f,network_namespace);fprintf(f,",\"pidns\":");json_text(f,pid_namespace);
}

static const char *scenario(int index) { return index==0?"main":index==1?"nxdomain":"control"; }
static uint16_t u16(const unsigned char *p) { return (uint16_t)((unsigned)p[0]<<8|p[1]); }
static void put16(unsigned char *p,unsigned value) { p[0]=(unsigned char)(value>>8);p[1]=(unsigned char)value; }
static int dns_name(const struct config *c,int index,char out[128]) {
    int n=snprintf(out,128,"%s.%s.traflens.invalid",scenario(index),c->run);
    return n>0&&n<128?0:fail("finite DNS name length exceeded");
}
static int frame_message(const struct config *c,int index,bool response,unsigned char out[FRAME_CAP]) {
    char name[128];if(index<0||index>=CASES||dns_name(c,index,name))return -1;
    memset(out,0,FRAME_CAP);unsigned char *dns=out+2;
    put16(dns,0xb101U+(unsigned)index);put16(dns+2,response?(index==1?0x8183:0x8180):0x0100);
    put16(dns+4,1);put16(dns+6,response&&index!=1?1:0);
    size_t offset=12;const char *label=name;
    while(*label) {
        const char *dot=strchr(label,'.');size_t length=dot?(size_t)(dot-label):strlen(label);
        if(!length||length>63||offset+length+1+4>DNS_CAP)return fail("finite DNS label exceeds wire bounds");
        dns[offset++]=(unsigned char)length;memcpy(dns+offset,label,length);offset+=length;
        if(!dot)break;
        label=dot+1;
    }
    dns[offset++]=0;put16(dns+offset,1);put16(dns+offset+2,1);offset+=4;
    if(response&&index!=1) {
        if(offset+16>DNS_CAP)return fail("finite DNS answer exceeds bound");
        dns[offset++]=0xc0;dns[offset++]=0x0c;put16(dns+offset,1);put16(dns+offset+2,1);offset+=4;
        dns[offset++]=0;dns[offset++]=0;dns[offset++]=0;dns[offset++]=60;
        put16(dns+offset,4);offset+=2;
        dns[offset++]=198;dns[offset++]=18;dns[offset++]=0;dns[offset++]=(unsigned char)(index==0?41:42);
    }
    /* Native inference's limit includes the length prefix in the syscall count. */
    if(offset+2>DNS_CAP)return fail("framed DNS syscall exceeds512byte inference limit");
    put16(out,(unsigned)offset);return (int)(offset+2);
}
static int validate_frame(const struct config *c,int index,bool response,const unsigned char *data,size_t bytes) {
    unsigned char expected[FRAME_CAP];int n=frame_message(c,index,response,expected);
    if(n<0)return -1;
    return bytes==(size_t)n&&bytes>=14&&u16(data)==bytes-2&&!memcmp(data,expected,bytes)
        ?0:fail("actual framed DNS differs from exact question/ID/count/RCODE/answer");
}
static int wait_socket(int fd,short wanted) {
    while(!stopping&&now_ns(CLOCK_MONOTONIC)<deadline_ns) {
        struct pollfd p={fd,wanted,0};int rc=poll(&p,1,100);
        if(rc<0&&errno==EINTR)continue;
        if(rc<0)return system_fail("poll owned DNS socket");
        if(rc>0&&(p.revents&POLLNVAL))return fail("invalid owned DNS socket");
        if(rc>0&&(p.revents&(wanted|POLLHUP|POLLERR)))return 0;
    }
    return fail("finite DNS deadline or stop signal reached");
}
static int socket_address(struct sockaddr_in *a,const char *ip,int port) {
    memset(a,0,sizeof(*a));a->sin_family=AF_INET;a->sin_port=htons((uint16_t)port);
    return inet_pton(AF_INET,ip,&a->sin_addr)==1?0:fail("invalid fixed owned DNS address");
}
static int endpoints(int fd,char local[INET_ADDRSTRLEN],int *lp,char peer[INET_ADDRSTRLEN],int *pp) {
    struct sockaddr_in a,b;socklen_t n=sizeof(a);
    if(getsockname(fd,(struct sockaddr *)&a,&n)||a.sin_family!=AF_INET)return system_fail("actual local DNS socket");
    n=sizeof(b);if(getpeername(fd,(struct sockaddr *)&b,&n)||b.sin_family!=AF_INET)return system_fail("actual peer DNS socket");
    if(!inet_ntop(AF_INET,&a.sin_addr,local,INET_ADDRSTRLEN)||!inet_ntop(AF_INET,&b.sin_addr,peer,INET_ADDRSTRLEN))return system_fail("format actual DNS tuple");
    *lp=ntohs(a.sin_port);*pp=ntohs(b.sin_port);return 0;
}
static int blocking_io(int fd) {
    int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK))return system_fail("bounded blocking DNS socket");
    uint64_t now=now_ns(CLOCK_MONOTONIC);
    if(stopping||now>=deadline_ns)return fail("finite DNS deadline reached");
    uint64_t budget=deadline_ns-now;if(budget>2000000000ULL)budget=2000000000ULL;
    struct timeval timeout={(time_t)(budget/1000000000ULL),(suseconds_t)((budget%1000000000ULL+999)/1000)};
    if(timeout.tv_usec==1000000){timeout.tv_sec++;timeout.tv_usec=0;}
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)))return system_fail("bound actual DNS syscall time");
    return 0;
}
static int connect_one(const struct config *c,struct connection *record) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create owned DNS client socket");
    struct sockaddr_in local,peer;socket_address(&local,"127.0.0.1",0);socket_address(&peer,"127.0.0.2",c->port);
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))){system_fail("bind owned DNS source");close(fd);return -1;}
    record->calls++;int rc=connect(fd,(struct sockaddr *)&peer,sizeof(peer));
    record->initial_errno=rc<0?errno:0;
    if(rc<0) {
        if(errno!=EINPROGRESS||wait_socket(fd,POLLOUT)){system_fail("connect owned DNS TCP");close(fd);return -1;}
        int error=0;socklen_t n=sizeof(error);
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&n)||error){if(error)errno=error;system_fail("complete owned DNS TCP connect");close(fd);return -1;}
    }
    return fd;
}
static int listen_owned(const struct config *c) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create owned DNS listener");
    struct sockaddr_in a;socket_address(&a,"127.0.0.2",c->port);
    /* No reuse flags: a port already in use must fail instead of joining it. */
    if(bind(fd,(struct sockaddr *)&a,sizeof(a))||listen(fd,1)){system_fail("bind exclusive DNS listener");close(fd);return -1;}
    return fd;
}
static int accept_one(int listener,struct connection *record) {
    for(;;) {
        if(wait_socket(listener,POLLIN))return -1;
        struct sockaddr_in peer;socklen_t n=sizeof(peer);
        record->calls++;int fd=accept4(listener,(struct sockaddr *)&peer,&n,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(fd<0)return system_fail("accept owned DNS TCP");
        char ip[INET_ADDRSTRLEN];inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip));
        if(strcmp(ip,"127.0.0.1")){close(fd);return fail("unexpected client outside owned DNS endpoint");}
        return fd;
    }
}
static struct event *exchange_frame(int fd,const struct config *c,int index,bool response,bool sending) {
    if(event_count>=EVENT_CAP){fail("finite DNS wire event budget exceeded");return NULL;}
    struct event *e=&events[event_count++];memset(e,0,sizeof(*e));
    e->case_index=index;e->response=response;e->fd=fd;snprintf(e->operation,sizeof(e->operation),"%s",sending?"send":"recv");
    if(endpoints(fd,e->local_ip,&e->local_port,e->peer_ip,&e->peer_port))return NULL;
    unsigned char expected[FRAME_CAP];int wanted=frame_message(c,index,response,expected);if(wanted<0)return NULL;
    if(wait_socket(fd,sending?POLLOUT:POLLIN)||blocking_io(fd))return NULL;
    e->begin_real=now_ns(CLOCK_REALTIME);e->begin_mono=now_ns(CLOCK_MONOTONIC);e->calls=1;
    ssize_t n;
    if(sending){memcpy(e->data,expected,(size_t)wanted);n=send(fd,e->data,(size_t)wanted,MSG_NOSIGNAL);}
    else n=recv(fd,e->data,(size_t)wanted,MSG_WAITALL);
    e->error=n<0?errno:0;e->bytes=n>0?(size_t)n:0;e->end_real=now_ns(CLOCK_REALTIME);e->end_mono=now_ns(CLOCK_MONOTONIC);
    if(n<0){errno=e->error;system_fail("actual DNS send/recv syscall");return NULL;}
    if(n!=wanted){fail("minimal DNS path requires one complete frame per actual send/recv syscall; partial outcome retained");return NULL;}
    if(validate_frame(c,index,response,e->data,e->bytes))return NULL;
    e->complete=true;return e;
}
static int conversation(const struct config *c,int listener,int index) {
    struct connection *r=&connections[connection_count++];memset(r,0,sizeof(*r));snprintf(r->scenario,sizeof(r->scenario),"%s",scenario(index));
    r->begin_real=now_ns(CLOCK_REALTIME);r->begin_mono=now_ns(CLOCK_MONOTONIC);
    int fd=!strcmp(c->role,"client")?connect_one(c,r):accept_one(listener,r);
    r->end_real=now_ns(CLOCK_REALTIME);r->end_mono=now_ns(CLOCK_MONOTONIC);r->fd=fd;
    if(fd<0)return -1;
    int rc=-1;
    if(endpoints(fd,r->local_ip,&r->local_port,r->peer_ip,&r->peer_port))goto end;
    bool client=!strcmp(c->role,"client");
    if(!exchange_frame(fd,c,index,false,client)||!exchange_frame(fd,c,index,true,!client))goto end;
    r->complete=true;completed++;rc=0;
end:
    if(close(fd)){system_fail("close actual DNS connection");rc=-1;}else r->closed=true;
    return rc;
}
static void emit_hex(FILE *f,const unsigned char *data,size_t bytes) { fputc('"',f);for(size_t i=0;i<bytes;i++)fprintf(f,"%02x",data[i]);fputc('"',f); }
static int write_events(FILE *f,const struct config *c,int *written) {
    for(int i=*written;i<event_count;i++) {
        struct event *e=&events[i];char hash[65],name[128];sha256_hex(e->data,e->bytes,hash);dns_name(c,e->case_index,name);
        fprintf(f,"{\"sequence\":%d,",i+1);emit_identity(f,c);fprintf(f,",\"scenario\":");json_text(f,scenario(e->case_index));
        fprintf(f,",\"operation\":");json_text(f,e->operation);fprintf(f,",\"response\":%s,\"fd\":%d,\"local\":{\"ip\":",e->response?"true":"false",e->fd);
        json_text(f,e->local_ip);fprintf(f,",\"port\":%d},\"peer\":{\"ip\":",e->local_port);json_text(f,e->peer_ip);fprintf(f,",\"port\":%d}",e->peer_port);
        fprintf(f,",\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64,e->begin_real,e->end_real,e->begin_mono,e->end_mono);
        fprintf(f,",\"bytes\":%zu,\"syscalls\":%d,\"errno\":%d,\"wire_sha256\":\"%s\",\"complete_dns_frame\":%s,\"wire_hex\":",e->bytes,e->calls,e->error,hash,e->complete?"true":"false");emit_hex(f,e->data,e->bytes);
        fprintf(f,",\"query_name\":");json_text(f,name);
        fprintf(f,",\"transaction_id\":%u,\"framing\":\"tcp-u16-length-prefix\",\"dns_message_bytes\":%u,\"query_type\":\"A\",\"rcode\":%u,\"answers\":%u,\"metadata_decoded_from_complete_wire\":%s}\n",e->bytes>=4?u16(e->data+2):0,e->bytes>=2?u16(e->data):0,e->bytes>=6?(u16(e->data+4)&15U):0,e->bytes>=10?u16(e->data+8):0,e->complete?"true":"false");
    }
    *written=event_count;return fflush(f)==0&&fsync(fileno(f))==0?0:system_fail("persist actual DNS wire events");
}
static int execute(const struct config *c) {
    uint64_t started_real=now_ns(CLOCK_REALTIME),started_mono=now_ns(CLOCK_MONOTONIC);
    int directory=output_directory(c->output);if(directory<0)return -1;
    if(identity()){close(directory);return -1;}
    FILE *wire=fresh_file(directory,"wire.jsonl");if(!wire){close(directory);return -1;}
    FILE *process=fresh_file(directory,"process.json");if(!process){fclose(wire);close(directory);return -1;}
    fprintf(process,"{");emit_identity(process,c);fprintf(process,",\"single_threaded\":true,\"sdk\":false,\"protocol\":\"real TCP DNS\",\"native_source3_verified\":false}\n");
    if(finish_file(process)){fclose(wire);close(directory);return -1;}
    int listener=-1,rc=0,written=0;bool listener_closed=true;
    if(!strcmp(c->role,"server")) {
        listener=listen_owned(c);if(listener<0){rc=-1;goto finish;}
        FILE *ready=fresh_file(directory,"ready.json");if(!ready){rc=-1;goto finish;}
        fprintf(ready,"{\"event\":\"ready\",");emit_identity(ready,c);fprintf(ready,",\"listen_ip\":\"127.0.0.2\",\"listen_port\":%d,\"max_connections\":3}\n",c->port);
        if(finish_file(ready)){rc=-1;goto finish;}
        printf("{\"ready\":true,\"role\":\"server\",\"port\":%d}\n",c->port);fflush(stdout);
    }
    for(int i=0;i<CASES;i++) {
        int outcome=conversation(c,listener,i);
        if(write_events(wire,c,&written)){rc=-1;break;}
        if(outcome){rc=-1;break;}
    }
finish:
    if(listener>=0&&close(listener)){listener_closed=false;system_fail("close actual DNS listener");rc=-1;}
    if(write_events(wire,c,&written))rc=-1;
    if(finish_file(wire))rc=-1;
    FILE *receipt=fresh_file(directory,"receipt.json");
    if(receipt) {
        fprintf(receipt,"{");emit_identity(receipt,c);
        bool sockets_closed=listener_closed&&connection_count==CASES;
        for(int i=0;i<connection_count;i++)sockets_closed=sockets_closed&&connections[i].closed;
        fprintf(receipt,",\"pass\":%s,\"completed_requests\":%d,\"expected_requests\":3,\"wire_events\":%d,\"sdk\":false,\"native_source3_verified\":false,\"framing\":\"tcp-u16-length-prefix\",\"separate_tcp_connections\":true,\"single_threaded\":true,\"owned_sockets_closed\":%s,\"listener_closed\":%s,\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64 ",\"port\":%d,\"connections\":[",rc==0&&completed==CASES?"true":"false",completed,event_count,sockets_closed?"true":"false",listener_closed?"true":"false",started_real,now_ns(CLOCK_REALTIME),started_mono,now_ns(CLOCK_MONOTONIC),c->port);
        for(int i=0;i<connection_count;i++) {
            struct connection *r=&connections[i];if(i)fputc(',',receipt);fprintf(receipt,"{\"scenario\":");json_text(receipt,r->scenario);
            fprintf(receipt,",\"operation\":\"%s\",\"fd\":%d,\"syscalls\":%d,\"initial_errno\":%d,\"local\":{\"ip\":",!strcmp(c->role,"client")?"connect":"accept",r->fd,r->calls,r->initial_errno);json_text(receipt,r->local_ip);
            fprintf(receipt,",\"port\":%d},\"peer\":{\"ip\":",r->local_port);json_text(receipt,r->peer_ip);fprintf(receipt,",\"port\":%d},\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64 ",\"complete\":%s,\"closed\":%s}",r->peer_port,r->begin_real,r->end_real,r->begin_mono,r->end_mono,r->complete?"true":"false",r->closed?"true":"false");
        }
        fprintf(receipt,"],\"error\":");json_text(receipt,last_error);fprintf(receipt,"}\n");if(finish_file(receipt))rc=-1;
    }else rc=-1;
    close(directory);printf("{\"pass\":%s,\"role\":\"%s\",\"completed_requests\":%d,\"native_source3_verified\":false}\n",rc==0&&completed==CASES?"true":"false",c->role,completed);fflush(stdout);return rc;
}
int main(int argc,char **argv) {
    struct config c={NULL,NULL,NULL,90,18080,false};
    static const struct option options[]={{"execute",no_argument,0,'e'},{"role",required_argument,0,'r'},{"run",required_argument,0,'m'},{"output",required_argument,0,'o'},{"seconds",required_argument,0,'s'},{"port",required_argument,0,'p'},{0,0,0,0}};
    opterr=0;int value;
    while((value=getopt_long(argc,argv,"",options,NULL))!=-1) {
        if(value=='e')c.execute=true;else if(value=='r')c.role=optarg;else if(value=='m')c.run=optarg;else if(value=='o')c.output=optarg;
        else if(value=='s'){if(numeric(optarg,5,90,&c.seconds))return 2;}else if(value=='p'){if(numeric(optarg,18080,18080,&c.port))return 2;}else return 2;
    }
    if(optind!=argc)return 2;
    if(!c.execute){printf("{\"execute\":false,\"starts_network\":false,\"reads_files\":false,\"creates_files\":false,\"sdk\":false,\"protocol\":\"TCP DNS\",\"client\":\"127.0.0.1\",\"server\":\"127.0.0.2\",\"default_port\":18080,\"max_connections\":3,\"max_frame_bytes\":512}\n");return 0;}
    if(!c.role||!valid_run(c.run)||!c.output||(strcmp(c.role,"client")&&strcmp(c.role,"server")))return 2;
    signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_handler);signal(SIGINT,stop_handler);
    deadline_ns=now_ns(CLOCK_MONOTONIC)+(uint64_t)c.seconds*1000000000ULL;
    int rc=execute(&c);if(rc)fprintf(stderr,"%s\n",last_error);return rc?1:0;
}
