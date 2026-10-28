#define _GNU_SOURCE
/* Finite synchronous HTTP on an externally owned network namespace.
 * No tracing SDK, custom correlation header, or fabricated TCP/Span identity.
 * Actual wire events stay in memory until each complete synchronous chain ends.
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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define MESSAGE_CAP 16384
#define HEADER_CAP 8192
#define EVENT_CAP 32
#define CHAIN_CAP 4

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

struct config { const char *role, *run, *output; int seconds, requests; bool execute; };
struct header { size_t length, body_length; int status; char host[64]; };
struct event {
    char chain[32], stage[32], operation[8];
    char local_ip[INET_ADDRSTRLEN], peer_ip[INET_ADDRSTRLEN];
    int local_port, peer_port, fd, calls;
    uint64_t begin_real, end_real, begin_mono, end_mono;
    size_t bytes;
    bool complete;
    struct header header;
    unsigned char data[MESSAGE_CAP+1];
};
struct chain { char name[32]; int first_event, last_event; bool complete; };
static struct event events[EVENT_CAP];
static struct chain chains[CHAIN_CAP];
static int event_count, chain_count, completed;
static volatile sig_atomic_t stopping;
static uint64_t deadline_ns, process_start_ticks;
static long process_pid, process_tid;
static char network_namespace[128], pid_namespace[128], last_error[256];
static volatile uint64_t checksum_sink;

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
    if(!run||strlen(run)!=27||strncmp(run,"nh-",3))return false;
    for(int i=3;i<27;i++)if(!((run[i]>='0'&&run[i]<='9')||(run[i]>='a'&&run[i]<='f')))return false;
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

/* This is deliberately a finite HTTP subset: no unknown/custom headers at all.
 * Consequently traceparent/tracestate/baggage, B3, x-request-id and aliases fail
 * rather than being silently ignored. The returned hash covers the original
 * bytes through the final CRLFCRLF, before any parsing normalization.
 */
static int parse_http(const unsigned char *data,size_t bytes,bool response,struct header *out) {
    memset(out,0,sizeof(*out));
    if(bytes>MESSAGE_CAP||memchr(data,0,bytes))return fail("HTTP contains NUL or exceeds message cap");
    size_t end=0;
    for(size_t i=3;i<bytes&&i<HEADER_CAP;i++)if(!memcmp(data+i-3,"\r\n\r\n",4)){end=i+1;break;}
    if(!end)return 1;
    for(size_t i=0;i<end;i++)if(data[i]!=13&&data[i]!=10&&(data[i]<32||data[i]>126))return fail("non-ASCII finite HTTP header");
    char copy[HEADER_CAP+1];memcpy(copy,data,end);copy[end]=0;
    char *line=copy,*next=strstr(line,"\r\n");if(!next)return fail("missing HTTP start line");*next=0;
    if(response){if(strcmp(line,"HTTP/1.1 200 OK"))return fail("unexpected HTTP response status");out->status=200;}
    else if(strncmp(line,"GET /",5)||strlen(line)<14||strcmp(line+strlen(line)-9," HTTP/1.1"))return fail("unexpected finite HTTP request line");
    bool host=false,connection=false,length=false,type=false;
    line=next+2;
    while(*line) {
        next=strstr(line,"\r\n");if(!next)return fail("incomplete header line");*next=0;if(!*line)break;
        char *colon=strchr(line,':');if(!colon||colon==line)return fail("invalid HTTP header name");
        *colon=0;char *value=colon+1;while(*value==' ')value++;
        if(!strcasecmp(line,"Host")&&!response&&!host){host=true;if(strlen(value)>=sizeof(out->host))return fail("oversized Host");strcpy(out->host,value);}
        else if(!strcasecmp(line,"Connection")&&!connection){connection=true;if(strcasecmp(value,"close"))return fail("finite connections must close");}
        else if(!strcasecmp(line,"Content-Length")&&response&&!length){length=true;int count;if(numeric(value,0,MESSAGE_CAP,&count))return fail("invalid finite body length");out->body_length=(size_t)count;}
        else if(!strcasecmp(line,"Content-Type")&&response&&!type){type=true;if(strcmp(value,"application/json"))return fail("unexpected body type");}
        else return fail("unknown, duplicate or tracing/correlation HTTP header");
        line=next+2;
    }
    if(!connection||(!response&&!host)||(response&&(!length||!type)))return fail("missing required finite HTTP headers");
    out->length=end;
    if(end+out->body_length>MESSAGE_CAP)return fail("HTTP message exceeds cap");
    if(bytes>end+out->body_length)return fail("extra/pipelined HTTP bytes are outside finite workload");
    return bytes==end+out->body_length?0:1;
}
static int wait_socket(int fd,short wanted) {
    while(!stopping&&now_ns(CLOCK_MONOTONIC)<deadline_ns) {
        struct pollfd p={fd,wanted,0};int rc=poll(&p,1,100);
        if(rc<0&&errno==EINTR)continue;
        if(rc<0)return system_fail("poll");
        if(rc>0&&(p.revents&(POLLERR|POLLNVAL)))return fail("socket reported an error");
        if(rc>0&&(p.revents&(wanted|POLLHUP)))return 0;
    }
    return fail("finite deadline or stop signal reached");
}
static int endpoint(int fd,struct event *event) {
    struct sockaddr_in a,b;socklen_t size=sizeof(a);
    if(getsockname(fd,(struct sockaddr *)&a,&size)||a.sin_family!=AF_INET)return system_fail("get actual local socket");
    size=sizeof(b);if(getpeername(fd,(struct sockaddr *)&b,&size)||b.sin_family!=AF_INET)return system_fail("get actual peer socket");
    if(!inet_ntop(AF_INET,&a.sin_addr,event->local_ip,sizeof(event->local_ip))||!inet_ntop(AF_INET,&b.sin_addr,event->peer_ip,sizeof(event->peer_ip)))return system_fail("format actual socket");
    event->local_port=ntohs(a.sin_port);event->peer_port=ntohs(b.sin_port);event->fd=fd;return 0;
}
static struct event *begin_event(int fd,const char *chain,const char *stage,const char *operation) {
    if(event_count>=EVENT_CAP){fail("finite wire event budget exceeded");return NULL;}
    struct event *e=&events[event_count++];memset(e,0,sizeof(*e));
    snprintf(e->chain,sizeof(e->chain),"%s",chain);snprintf(e->stage,sizeof(e->stage),"%s",stage);snprintf(e->operation,sizeof(e->operation),"%s",operation);
    if(endpoint(fd,e))return NULL;
    e->begin_real=now_ns(CLOCK_REALTIME);e->begin_mono=now_ns(CLOCK_MONOTONIC);return e;
}
static void end_event(struct event *e) { e->end_real=now_ns(CLOCK_REALTIME);e->end_mono=now_ns(CLOCK_MONOTONIC); }
static struct event *send_http(int fd,const char *chain,const char *stage,const unsigned char *data,size_t length,bool response) {
    struct event *e=begin_event(fd,chain,stage,"send");if(!e)return NULL;
    if(length>MESSAGE_CAP){fail("send exceeds finite cap");end_event(e);return NULL;}
    memcpy(e->data,data,length);e->data[length]=0;
    while(e->bytes<length) {
        if(wait_socket(fd,POLLOUT)){end_event(e);return NULL;}
        ssize_t n=send(fd,data+e->bytes,length-e->bytes,MSG_NOSIGNAL);e->calls++;
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))continue;
        if(n<=0){system_fail("send actual HTTP");end_event(e);return NULL;}
        e->bytes+=(size_t)n;
    }
    end_event(e);if(parse_http(e->data,e->bytes,response,&e->header))return NULL;e->complete=true;return e;
}
static struct event *recv_http(int fd,const char *chain,const char *stage,bool response) {
    struct event *e=begin_event(fd,chain,stage,"recv");if(!e)return NULL;
    while(e->bytes<MESSAGE_CAP) {
        if(wait_socket(fd,POLLIN)){end_event(e);return NULL;}
        ssize_t n=recv(fd,e->data+e->bytes,MESSAGE_CAP-e->bytes,0);e->calls++;
        if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK||errno==EINTR))continue;
        if(n<=0){fail("peer closed or failed before complete HTTP message");end_event(e);return NULL;}
        e->bytes+=(size_t)n;e->data[e->bytes]=0;
        int rc=parse_http(e->data,e->bytes,response,&e->header);
        if(rc<0){end_event(e);return NULL;}
        if(rc==0){end_event(e);e->complete=true;return e;}
    }
    fail("receive exceeds finite cap");end_event(e);return NULL;
}
static int address(struct sockaddr_in *out,const char *ip,int port) {
    memset(out,0,sizeof(*out));out->sin_family=AF_INET;out->sin_port=htons((uint16_t)port);
    return inet_pton(AF_INET,ip,&out->sin_addr)==1?0:fail("invalid fixed loopback address");
}
static int connect_to(const char *local,const char *peer) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create socket");
    struct sockaddr_in src,dst;address(&src,local,0);address(&dst,peer,18080);
    if(bind(fd,(struct sockaddr *)&src,sizeof(src))){system_fail("bind actual client source");close(fd);return -1;}
    if(connect(fd,(struct sockaddr *)&dst,sizeof(dst))<0) {
        if(errno!=EINPROGRESS||wait_socket(fd,POLLOUT)){system_fail("connect finite HTTP");close(fd);return -1;}
        int error=0;socklen_t size=sizeof(error);
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error){if(error)errno=error;system_fail("complete TCP connection");close(fd);return -1;}
    }
    return fd;
}
static int listen_on(const char *ip) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create listener");
    int yes=1;struct sockaddr_in a;address(&a,ip,18080);
    if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes))||bind(fd,(struct sockaddr *)&a,sizeof(a))||listen(fd,4)){system_fail("bind finite loopback listener");close(fd);return -1;}
    return fd;
}
static int accept_one(int listener,const char *expected_peer) {
    for(;;) {
        if(wait_socket(listener,POLLIN))return -1;
        struct sockaddr_in peer;socklen_t size=sizeof(peer);int fd=accept4(listener,(struct sockaddr *)&peer,&size,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd<0&&(errno==EAGAIN||errno==EINTR))continue;
        if(fd<0)return system_fail("accept finite HTTP");
        char ip[INET_ADDRSTRLEN];inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip));
        if(strcmp(ip,expected_peer)){close(fd);return fail("unexpected client outside owned synchronous chain");}
        return fd;
    }
}
static const char *chain_name(int sequence,char name[32]) {
    if(sequence==0)return "main";
    if(sequence==1)return "control";
    snprintf(name,32,"control-%d",sequence);return name;
}
static int request_message(unsigned char out[MESSAGE_CAP+1],const struct config *c,const char *chain,const char *peer) {
    return snprintf((char *)out,MESSAGE_CAP+1,"GET /traflens-no-header/%s/%s HTTP/1.1\r\nHost: %s:18080\r\nConnection: close\r\n\r\n",c->run,chain,peer);
}
static int response_message(unsigned char out[MESSAGE_CAP+1],const char *body) {
    return snprintf((char *)out,MESSAGE_CAP+1,"HTTP/1.1 200 OK\r\nContent-Length: %zu\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n%s",strlen(body),body);
}
static int check_request(struct event *e,const struct config *c,const char *chain,const char *host) {
    unsigned char expected[MESSAGE_CAP+1];int length=request_message(expected,c,chain,host);
    return length>0&&(size_t)length==e->bytes&&!memcmp(expected,e->data,e->bytes)?0:fail("actual request differs from exact finite URL/standard headers");
}
__attribute__((noinline)) static uint64_t actual_work(void) {
    uint64_t value=now_ns(CLOCK_MONOTONIC)^(uint64_t)getpid();
    for(uint64_t i=0;i<65536;i++){value^=value<<13;value^=value>>7;value^=value<<17;value+=i;}
    checksum_sink=value;return checksum_sink;
}
static int check_backend_body(const char *body,const struct config *c,const char *chain) {
    char run[32],name[32],checksum[32];long pid,tid;int used=0;
    int n=sscanf(body,"{\"run\":\"%31[^\"]\",\"chain\":\"%31[^\"]\",\"role\":\"backend\",\"checksum\":\"%31[0-9]\",\"pid\":%ld,\"tid\":%ld}%n",run,name,checksum,&pid,&tid,&used);
    return n==5&&used>0&&body[used]==0&&!strcmp(run,c->run)&&!strcmp(name,chain)&&pid>0&&pid==tid?0:fail("actual backend execution receipt differs");
}
static int check_front_body(const char *body,const struct config *c,const char *chain) {
    char run[32],name[32];long pid,tid;int used=0;
    int n=sscanf(body,"{\"run\":\"%31[^\"]\",\"chain\":\"%31[^\"]\",\"role\":\"frontend\",\"pid\":%ld,\"tid\":%ld,\"backend\":%n",run,name,&pid,&tid,&used);
    size_t length=strlen(body);
    if(n!=4||used<=0||strcmp(run,c->run)||strcmp(name,chain)||pid<=0||pid!=tid||length<=(size_t)used||length-(size_t)used>=1024||body[length-1]!='}')return fail("actual frontend execution receipt differs");
    char nested[1024];memcpy(nested,body+used,length-(size_t)used-1);nested[length-(size_t)used-1]=0;
    return check_backend_body(nested,c,chain);
}
static int one_chain(const struct config *c,int listener,const char *name) {
    struct chain *chain=&chains[chain_count++];snprintf(chain->name,sizeof(chain->name),"%s",name);chain->first_event=event_count+1;
    int incoming=-1,outgoing=-1,rc=-1;unsigned char message[MESSAGE_CAP+1];char body[2048];
    if(!strcmp(c->role,"generate")) {
        outgoing=connect_to("127.0.0.1","127.0.0.2");if(outgoing<0)goto cleanup;
        int length=request_message(message,c,name,"127.0.0.2");
        if(length<0||!send_http(outgoing,name,"root-request",message,(size_t)length,false))goto cleanup;
        struct event *reply=recv_http(outgoing,name,"root-response",true);if(!reply||check_front_body((const char *)reply->data+reply->header.length,c,name))goto cleanup;
    } else {
        bool front=!strcmp(c->role,"frontend");
        incoming=accept_one(listener,front?"127.0.0.1":"127.0.0.2");if(incoming<0)goto cleanup;
        struct event *request=recv_http(incoming,name,"incoming-request",false);
        if(!request||check_request(request,c,name,front?"127.0.0.2":"127.0.0.3"))goto cleanup;
        if(front) {
            outgoing=connect_to("127.0.0.2","127.0.0.3");if(outgoing<0)goto cleanup;
            int length=request_message(message,c,name,"127.0.0.3");
            if(length<0||!send_http(outgoing,name,"outgoing-request",message,(size_t)length,false))goto cleanup;
            struct event *reply=recv_http(outgoing,name,"outgoing-response",true);
            if(!reply||check_backend_body((const char *)reply->data+reply->header.length,c,name))goto cleanup;
            int n=snprintf(body,sizeof(body),"{\"run\":\"%s\",\"chain\":\"%s\",\"role\":\"frontend\",\"pid\":%ld,\"tid\":%ld,\"backend\":%s}",c->run,name,process_pid,process_tid,(const char *)reply->data+reply->header.length);
            if(n<0||(size_t)n>=sizeof(body)){fail("actual response receipt exceeds cap");goto cleanup;}
        } else {
            uint64_t checksum=actual_work();
            snprintf(body,sizeof(body),"{\"run\":\"%s\",\"chain\":\"%s\",\"role\":\"backend\",\"checksum\":\"%" PRIu64 "\",\"pid\":%ld,\"tid\":%ld}",c->run,name,checksum,process_pid,process_tid);
        }
        int length=response_message(message,body);
        if(length<0||(size_t)length>MESSAGE_CAP||!send_http(incoming,name,"incoming-response",message,(size_t)length,true))goto cleanup;
    }
    chain->complete=true;completed++;rc=0;
cleanup:
    if(outgoing>=0)close(outgoing);
    if(incoming>=0)close(incoming);
    chain->last_event=event_count;return rc;
}
static int write_events(FILE *f,const struct config *c,int *written) {
    for(int i=*written;i<event_count;i++) {
        struct event *e=&events[i];char header_hash[65],message_hash[65];
        sha256_hex(e->data,e->header.length,header_hash);sha256_hex(e->data,e->bytes,message_hash);
        fprintf(f,"{\"sequence\":%d,",i+1);emit_identity(f,c);fprintf(f,",\"chain\":");json_text(f,e->chain);
        fprintf(f,",\"operation\":");json_text(f,e->operation);fprintf(f,",\"stage\":");json_text(f,e->stage);
        fprintf(f,",\"fd\":%d,\"local\":{\"ip\":",e->fd);json_text(f,e->local_ip);fprintf(f,",\"port\":%d},\"peer\":{\"ip\":",e->local_port);json_text(f,e->peer_ip);fprintf(f,",\"port\":%d}",e->peer_port);
        fprintf(f,",\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64,e->begin_real,e->end_real,e->begin_mono,e->end_mono);
        fprintf(f,",\"bytes\":%zu,\"syscalls\":%d,\"header_bytes\":%zu,\"header_sha256\":\"%s\",\"message_sha256\":\"%s\",\"complete_http_message\":%s,\"tracing_and_custom_headers_absent\":%s,\"header\":",e->bytes,e->calls,e->header.length,header_hash,message_hash,e->complete?"true":"false",e->complete?"true":"false");
        json_string(f,e->data,e->header.length);fprintf(f,",\"body\":");json_string(f,e->data+e->header.length,e->bytes-e->header.length);fprintf(f,"}\n");
    }
    *written=event_count;
    return fflush(f)==0&&fsync(fileno(f))==0?0:system_fail("persist actual wire events");
}
static int execute(const struct config *c) {
    int directory=output_directory(c->output);if(directory<0)return -1;
    if(identity()){close(directory);return -1;}
    FILE *wire=fresh_file(directory,"wire.jsonl");if(!wire){close(directory);return -1;}
    FILE *process=fresh_file(directory,"process.json");if(!process){fclose(wire);close(directory);return -1;}
    fprintf(process,"{");emit_identity(process,c);fprintf(process,",\"single_threaded\":true,\"tracing_headers\":false,\"sdk\":false,\"native_association_verified\":false}\n");
    if(finish_file(process)){fclose(wire);close(directory);return -1;}
    int listener=-1,rc=0,written=0;
    if(strcmp(c->role,"generate")) {
        const char *ip=!strcmp(c->role,"frontend")?"127.0.0.2":"127.0.0.3";
        listener=listen_on(ip);if(listener<0){rc=-1;goto finish;}
        FILE *ready=fresh_file(directory,"ready.json");if(!ready){rc=-1;goto finish;}
        fprintf(ready,"{\"event\":\"ready\",");emit_identity(ready,c);fprintf(ready,",\"listen_ip\":\"%s\",\"listen_port\":18080}\n",ip);
        if(finish_file(ready)){rc=-1;goto finish;}
        printf("{\"event\":\"ready\",\"role\":\"%s\",\"pid\":%ld,\"tid\":%ld,\"listen_ip\":\"%s\",\"listen_port\":18080}\n",c->role,process_pid,process_tid,ip);fflush(stdout);
    }
    for(int i=0;i<c->requests;i++) {
        char name[32];int outcome=one_chain(c,listener,chain_name(i,name));
        if(write_events(wire,c,&written)){rc=-1;break;}
        if(outcome){rc=-1;break;}
    }
finish:
    if(listener>=0)close(listener);
    if(write_events(wire,c,&written))rc=-1;
    if(finish_file(wire))rc=-1;
    FILE *receipt=fresh_file(directory,"receipt.json");
    if(receipt) {
        fprintf(receipt,"{");emit_identity(receipt,c);
        fprintf(receipt,",\"pass\":%s,\"completed_requests\":%d,\"expected_requests\":%d,\"wire_events\":%d,\"tracing_headers\":false,\"sdk\":false,\"native_association_verified\":false,\"url_is_only_population_marker\":true,\"same_service_thread\":true,\"application_calls\":[",rc==0&&completed==c->requests?"true":"false",completed,c->requests,event_count);
        for(int i=0;i<chain_count;i++){if(i)fputc(',',receipt);fprintf(receipt,"{\"chain\":");json_text(receipt,chains[i].name);fprintf(receipt,",\"first_event\":%d,\"last_event\":%d,\"complete\":%s}",chains[i].first_event,chains[i].last_event,chains[i].complete?"true":"false");}
        fprintf(receipt,"],\"error\":");json_text(receipt,last_error);fprintf(receipt,"}\n");if(finish_file(receipt))rc=-1;
    } else rc=-1;
    close(directory);
    printf("{\"pass\":%s,\"role\":\"%s\",\"completed_requests\":%d,\"wire_events\":%d,\"native_association_verified\":false}\n",rc==0&&completed==c->requests?"true":"false",c->role,completed,event_count);fflush(stdout);
    return rc;
}
int main(int argc,char **argv) {
    struct config c={NULL,NULL,NULL,90,2,false};
    static const struct option options[]={{"execute",no_argument,0,'e'},{"role",required_argument,0,'r'},{"run",required_argument,0,'m'},{"output",required_argument,0,'o'},{"seconds",required_argument,0,'s'},{"requests",required_argument,0,'n'},{0,0,0,0}};
    opterr=0;int value;
    while((value=getopt_long(argc,argv,"",options,NULL))!=-1) {
        if(value=='e')c.execute=true;else if(value=='r')c.role=optarg;else if(value=='m')c.run=optarg;else if(value=='o')c.output=optarg;
        else if(value=='s'){if(numeric(optarg,5,90,&c.seconds))return 2;}else if(value=='n'){if(numeric(optarg,1,4,&c.requests))return 2;}else return 2;
    }
    if(optind!=argc)return 2;
    if(!c.execute){printf("{\"execute\":false,\"starts_network\":false,\"creates_files\":false,\"sdk\":false,\"tracing_headers\":false,\"port\":18080,\"frontend\":\"127.0.0.2\",\"backend\":\"127.0.0.3\",\"max_requests\":4}\n");return 0;}
    if(!c.role||!valid_run(c.run)||!c.output||(strcmp(c.role,"frontend")&&strcmp(c.role,"backend")&&strcmp(c.role,"generate")))return 2;
    signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_handler);signal(SIGINT,stop_handler);
    deadline_ns=now_ns(CLOCK_MONOTONIC)+(uint64_t)c.seconds*1000000000ULL;
    int rc=execute(&c);if(rc)fprintf(stderr,"%s\n",last_error);
    return rc&&!stopping?1:0;
}
