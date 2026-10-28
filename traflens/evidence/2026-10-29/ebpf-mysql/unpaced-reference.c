#define _GNU_SOURCE
/* Finite actual MySQL classic wire protocol in owned namespaces; offline by default.
 * No database, SQL execution, password, TLS, SDK or fabricated capture events.
 * Server self-comm mysqld is an explicit native direction hint, not a DB identity.
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
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define WIRE_CAP 2048
#define EVENT_CAP 24
#define CASES 3
#define PHASES 6
struct config { const char *role,*run,*output; int seconds,port; bool execute; };
struct connection { char scenario[16],local_ip[INET_ADDRSTRLEN],peer_ip[INET_ADDRSTRLEN]; int local_port,peer_port,fd,initial_errno,calls; uint64_t begin_real,end_real,begin_mono,end_mono; bool complete,closed,shutdown_write; };
struct event { int case_index,phase,fd,calls,error; bool complete,eof; char operation[8],local_ip[INET_ADDRSTRLEN],peer_ip[INET_ADDRSTRLEN]; int local_port,peer_port; uint64_t begin_real,end_real,begin_mono,end_mono; size_t bytes; unsigned char data[WIRE_CAP]; };
static struct event events[EVENT_CAP];
static struct connection connections[CASES];
static int event_count,connection_count,completed;
static volatile sig_atomic_t stopping;
static uint64_t deadline_ns,process_start_ticks;
static long process_pid,process_tid;
static char network_namespace[128],pid_namespace[128],process_comm[32],last_error[256];

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
    if(!run||strlen(run)!=27||strncmp(run,"my-",3))return false;
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
    if(prctl(PR_GET_NAME,process_comm,0,0,0))return system_fail("read actual self comm");
    return 0;
}
static void emit_identity(FILE *f,const struct config *c) {
    fprintf(f,"\"role\":");json_text(f,c->role);fprintf(f,",\"run\":");json_text(f,c->run);
    fprintf(f,",\"pid\":%ld,\"tid\":%ld,\"start_ticks\":\"%" PRIu64 "\",\"netns\":",process_pid,process_tid,process_start_ticks);
    json_text(f,network_namespace);fprintf(f,",\"pidns\":");json_text(f,pid_namespace);fprintf(f,",\"comm\":");json_text(f,process_comm);
}

static int wait_socket(int fd,short wanted) {
    while(!stopping&&now_ns(CLOCK_MONOTONIC)<deadline_ns) {
        struct pollfd p={fd,wanted,0};int rc=poll(&p,1,100);
        if(rc<0&&errno==EINTR)continue;
        if(rc<0)return system_fail("poll owned MySQL socket");
        if(rc>0&&(p.revents&POLLNVAL))return fail("invalid owned MySQL socket");
        if(rc>0&&(p.revents&(wanted|POLLHUP|POLLERR)))return 0;
    }
    return fail("finite MySQL deadline or stop signal reached");
}
static int socket_address(struct sockaddr_in *a,const char *ip,int port) {
    memset(a,0,sizeof(*a));a->sin_family=AF_INET;a->sin_port=htons((uint16_t)port);
    return inet_pton(AF_INET,ip,&a->sin_addr)==1?0:fail("invalid fixed owned MySQL address");
}
static int endpoints(int fd,char local[INET_ADDRSTRLEN],int *lp,char peer[INET_ADDRSTRLEN],int *pp) {
    struct sockaddr_in a,b;socklen_t n=sizeof(a);
    if(getsockname(fd,(struct sockaddr *)&a,&n)||a.sin_family!=AF_INET)return system_fail("actual local MySQL socket");
    n=sizeof(b);if(getpeername(fd,(struct sockaddr *)&b,&n)||b.sin_family!=AF_INET)return system_fail("actual peer MySQL socket");
    if(!inet_ntop(AF_INET,&a.sin_addr,local,INET_ADDRSTRLEN)||!inet_ntop(AF_INET,&b.sin_addr,peer,INET_ADDRSTRLEN))return system_fail("format actual MySQL tuple");
    *lp=ntohs(a.sin_port);*pp=ntohs(b.sin_port);return 0;
}
static int blocking_io(int fd) {
    int flags=fcntl(fd,F_GETFL,0);if(flags<0||fcntl(fd,F_SETFL,flags&~O_NONBLOCK))return system_fail("bounded blocking MySQL socket");
    uint64_t now=now_ns(CLOCK_MONOTONIC);
    if(stopping||now>=deadline_ns)return fail("finite MySQL deadline reached");
    uint64_t budget=deadline_ns-now;if(budget>2000000000ULL)budget=2000000000ULL;
    struct timeval timeout={(time_t)(budget/1000000000ULL),(suseconds_t)((budget%1000000000ULL+999)/1000)};
    if(timeout.tv_usec==1000000){timeout.tv_sec++;timeout.tv_usec=0;}
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))||setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)))return system_fail("bound actual MySQL syscall time");
    return 0;
}
static int connect_one(const struct config *c,struct connection *record) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create owned MySQL client socket");
    struct sockaddr_in local,peer;socket_address(&local,"127.0.0.1",0);socket_address(&peer,"127.0.0.2",c->port);
    if(bind(fd,(struct sockaddr *)&local,sizeof(local))){system_fail("bind owned MySQL source");close(fd);return -1;}
    record->calls++;int rc=connect(fd,(struct sockaddr *)&peer,sizeof(peer));
    record->initial_errno=rc<0?errno:0;
    if(rc<0) {
        if(errno!=EINPROGRESS||wait_socket(fd,POLLOUT)){system_fail("connect owned MySQL TCP");close(fd);return -1;}
        int error=0;socklen_t n=sizeof(error);
        if(getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&n)||error){if(error)errno=error;system_fail("complete owned MySQL TCP connect");close(fd);return -1;}
    }
    return fd;
}
static int listen_owned(const struct config *c) {
    int fd=socket(AF_INET,SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC,0);if(fd<0)return system_fail("create owned MySQL listener");
    struct sockaddr_in a;socket_address(&a,"127.0.0.2",c->port);
    /* No reuse flags: a port already in use must fail instead of joining it. */
    if(bind(fd,(struct sockaddr *)&a,sizeof(a))||listen(fd,1)){system_fail("bind exclusive MySQL listener");close(fd);return -1;}
    return fd;
}
static int accept_one(int listener,struct connection *record) {
    for(;;) {
        if(wait_socket(listener,POLLIN))return -1;
        struct sockaddr_in peer;socklen_t n=sizeof(peer);
        record->calls++;int fd=accept4(listener,(struct sockaddr *)&peer,&n,SOCK_NONBLOCK|SOCK_CLOEXEC);
        if(fd<0&&(errno==EINTR||errno==EAGAIN))continue;
        if(fd<0)return system_fail("accept owned MySQL TCP");
        char ip[INET_ADDRSTRLEN];inet_ntop(AF_INET,&peer.sin_addr,ip,sizeof(ip));
        if(strcmp(ip,"127.0.0.1")){close(fd);return fail("unexpected client outside owned MySQL endpoint");}
        return fd;
    }
}
#define CAPABILITIES 0x0008a205U
static const char *scenario(int index) { return index==0?"main":index==1?"error1064":"control"; }
static const char *stage(int phase) { static const char *names[]={"greeting","login","auth","query","result","quit","tcp-eof"};return names[phase]; }
static unsigned u24(const unsigned char *p) { return (unsigned)p[0]|((unsigned)p[1]<<8)|((unsigned)p[2]<<16); }
static void le16(unsigned char *p,unsigned v) { p[0]=(unsigned char)v;p[1]=(unsigned char)(v>>8); }
static void le32(unsigned char *p,uint32_t v) { for(int i=0;i<4;i++)p[i]=(unsigned char)(v>>(8*i)); }
static int append(unsigned char out[WIRE_CAP],size_t *used,const void *data,size_t bytes) {
    if(*used+bytes>WIRE_CAP)return fail("finite MySQL wire bound exceeded");
    memcpy(out+*used,data,bytes);*used+=bytes;return 0;
}
static int stringz(unsigned char out[WIRE_CAP],size_t *used,const char *text) { return append(out,used,text,strlen(text)+1); }
static int length_string(unsigned char out[WIRE_CAP],size_t *used,const char *text) {
    size_t n=strlen(text);unsigned char length=(unsigned char)n;
    if(n>=251)return fail("finite MySQL length string exceeded");
    return append(out,used,&length,1)||append(out,used,text,n)?-1:0;
}
static int packet(unsigned char out[WIRE_CAP],size_t *used,unsigned sequence,const unsigned char *payload,size_t bytes) {
    if(!bytes||bytes>=10000||bytes>WIRE_CAP||sequence>255)return fail("classic MySQL packet outside finite limits");
    unsigned char header[4]={(unsigned char)bytes,(unsigned char)(bytes>>8),(unsigned char)(bytes>>16),(unsigned char)sequence};
    return append(out,used,header,4)||append(out,used,payload,bytes)?-1:0;
}
static int literal(const struct config *c,int index,char value[128]) {
    int n=snprintf(value,128,"%s.%s",scenario(index),c->run);return n>0&&n<128?0:fail("finite query literal exceeded");
}
static int build_message(const struct config *c,int index,int phase,unsigned char out[WIRE_CAP]) {
    if(index<0||index>=CASES||phase<0||phase>=PHASES)return fail("unknown finite MySQL message");
    unsigned char payload[WIRE_CAP],field[32];size_t n=0,total=0;char value[128];
    static const char scramble[]="12345678abcdefghijkl",plugin[]="mysql_native_password";
    static const unsigned char ok[]={0,0,0,2,0,0,0},eof[]={0xfe,0,0,2,0};
    if(literal(c,index,value))return -1;
    if(phase==0) {
        payload[n++]=0x0a;if(stringz(payload,&n,"5.7.44"))return -1;
        le32(field,1);if(append(payload,&n,field,4)||append(payload,&n,scramble,8))return -1;
        payload[n++]=0;le16(field,CAPABILITIES&0xffff);if(append(payload,&n,field,2))return -1;
        payload[n++]=45;le16(field,2);if(append(payload,&n,field,2))return -1;
        le16(field,CAPABILITIES>>16);if(append(payload,&n,field,2))return -1;
        payload[n++]=21;memset(payload+n,0,10);n+=10;
        if(append(payload,&n,scramble+8,12))return -1;
        payload[n++]=0;if(stringz(payload,&n,plugin)||packet(out,&total,0,payload,n))return -1;
    }else if(phase==1) {
        le32(payload,CAPABILITIES);le32(payload+4,65536);payload[8]=45;memset(payload+9,0,23);n=32;
        char user[64];int size=snprintf(user,sizeof(user),"u_%s",c->run);
        if(size<1||size>32||stringz(payload,&n,user))return fail("finite empty-password login username exceeded");
        payload[n++]=0;if(stringz(payload,&n,plugin)||packet(out,&total,1,payload,n))return -1;
    }else if(phase==2) {
        if(packet(out,&total,2,ok,sizeof(ok)))return -1;
    }else if(phase==3) {
        payload[n++]=3;int length=snprintf((char *)payload+n,WIRE_CAP-n,"SELECT '%s'",value);
        if(length<1||(size_t)length>=WIRE_CAP-n)return fail("finite COM_QUERY exceeded");
        n+=(size_t)length;if(packet(out,&total,0,payload,n))return -1;
    }else if(phase==4&&index==1) {
        payload[n++]=0xff;le16(payload+n,1064);n+=2;
        if(append(payload,&n,"#42000",6))return -1;
        int length=snprintf((char *)payload+n,WIRE_CAP-n,"fixture error1064 %s",value);
        if(length<1||(size_t)length>=WIRE_CAP-n)return fail("finite error message exceeded");
        n+=(size_t)length;if(packet(out,&total,1,payload,n))return -1;
    }else if(phase==4) {
        payload[0]=1;if(packet(out,&total,1,payload,1))return -1;n=0;
        for(int i=0;i<6;i++)if(length_string(payload,&n,i==0?"def":i==4?value:""))return -1;
        payload[n++]=0x0c;le16(payload+n,45);n+=2;le32(payload+n,1024);n+=4;
        payload[n++]=0xfd;le16(payload+n,0);n+=2;payload[n++]=0;payload[n++]=0;payload[n++]=0;
        if(packet(out,&total,2,payload,n)||packet(out,&total,3,eof,sizeof(eof)))return -1;
        n=0;if(length_string(payload,&n,value)||packet(out,&total,4,payload,n)||packet(out,&total,5,eof,sizeof(eof)))return -1;
    }else {
        payload[0]=1;if(packet(out,&total,0,payload,1))return -1;
    }
    if(!total||total>=10000)return fail("MySQL syscall bundle exceeds inference bound");
    return (int)total;
}
static int validate_message(const struct config *c,int index,int phase,const unsigned char *data,size_t bytes) {
    unsigned char expected[WIRE_CAP];int wanted=build_message(c,index,phase,expected);
    return wanted>0&&bytes==(size_t)wanted&&!memcmp(data,expected,bytes)?0:fail("actual classic MySQL wire differs from exact finite protocol exchange");
}
static int packet_count(const unsigned char *data,size_t bytes) {
    size_t offset=0;int packets=0;
    while(offset<bytes) {
        if(bytes-offset<4)return -1;
        unsigned n=u24(data+offset);if(!n||n>=10000||offset+4+n>bytes)return -1;
        packets++;offset+=4+n;
    }
    return packets;
}
static struct event *exchange_message(int fd,const struct config *c,int index,int phase,bool sending) {
    if(event_count>=EVENT_CAP){fail("finite MySQL event bound exceeded");return NULL;}
    struct event *e=&events[event_count++];memset(e,0,sizeof(*e));e->case_index=index;e->phase=phase;e->fd=fd;
    snprintf(e->operation,sizeof(e->operation),"%s",sending?"send":"recv");
    if(endpoints(fd,e->local_ip,&e->local_port,e->peer_ip,&e->peer_port))return NULL;
    unsigned char expected[WIRE_CAP];int wanted=phase==6?0:build_message(c,index,phase,expected);if(wanted<0)return NULL;
    if(wait_socket(fd,sending?POLLOUT:POLLIN)||blocking_io(fd))return NULL;
    e->begin_real=now_ns(CLOCK_REALTIME);e->begin_mono=now_ns(CLOCK_MONOTONIC);e->calls=1;
    ssize_t n;
    if(sending){memcpy(e->data,expected,(size_t)wanted);n=send(fd,e->data,(size_t)wanted,MSG_NOSIGNAL);}
    else n=recv(fd,e->data,phase==6?1:(size_t)wanted,MSG_WAITALL);
    e->error=n<0?errno:0;e->bytes=n>0?(size_t)n:0;e->end_real=now_ns(CLOCK_REALTIME);e->end_mono=now_ns(CLOCK_MONOTONIC);
    if(n<0){errno=e->error;system_fail("actual MySQL send/recv syscall");return NULL;}
    if(n!=wanted){fail("minimal MySQL requires complete known bundle per syscall; partial bytes retained");return NULL;}
    if(phase==6)e->eof=true;
    else if(validate_message(c,index,phase,e->data,e->bytes))return NULL;
    e->complete=true;return e;
}
static int conversation(const struct config *c,int listener,int index) {
    struct connection *r=&connections[connection_count++];memset(r,0,sizeof(*r));snprintf(r->scenario,sizeof(r->scenario),"%s",scenario(index));
    r->begin_real=now_ns(CLOCK_REALTIME);r->begin_mono=now_ns(CLOCK_MONOTONIC);
    bool client=!strcmp(c->role,"client");int fd=client?connect_one(c,r):accept_one(listener,r);
    r->end_real=now_ns(CLOCK_REALTIME);r->end_mono=now_ns(CLOCK_MONOTONIC);r->fd=fd;if(fd<0)return -1;
    int rc=-1;if(endpoints(fd,r->local_ip,&r->local_port,r->peer_ip,&r->peer_port))goto end;
    for(int phase=0;phase<PHASES;phase++) {
        bool server_sends=phase==0||phase==2||phase==4;
        if(!exchange_message(fd,c,index,phase,client?!server_sends:server_sends))goto end;
    }
    if(client){if(shutdown(fd,SHUT_WR)){system_fail("actual client half-close after COM_QUIT");goto end;}r->shutdown_write=true;}
    if(!exchange_message(fd,c,index,6,false))goto end;
    r->complete=true;completed++;rc=0;
end:
    if(close(fd)){system_fail("close actual MySQL connection");rc=-1;}else r->closed=true;
    return rc;
}
static void emit_hex(FILE *f,const unsigned char *data,size_t bytes) { fputc('"',f);for(size_t i=0;i<bytes;i++)fprintf(f,"%02x",data[i]);fputc('"',f); }
static void emit_packets(FILE *f,const struct event *e) {
    fprintf(f,"[");size_t offset=0;int i=0;
    while(offset+4<=e->bytes) {
        unsigned n=u24(e->data+offset);if(!n||offset+4+n>e->bytes)break;
        char payload_hash[65],wire_hash[65];sha256_hex(e->data+offset+4,n,payload_hash);sha256_hex(e->data+offset,4+n,wire_hash);
        if(i++)fputc(',',f);
        fprintf(f,"{\"offset\":%zu,\"payload_bytes\":%u,\"sequence\":%u,\"wire_bytes\":%u,\"payload_sha256\":\"%s\",\"wire_sha256\":\"%s\",\"payload_hex\":",offset,n,e->data[offset+3],n+4,payload_hash,wire_hash);
        emit_hex(f,e->data+offset+4,n);fprintf(f,"}");offset+=4+n;
    }
    fprintf(f,"]");
}
static int write_events(FILE *f,const struct config *c,int *written) {
    for(int i=*written;i<event_count;i++) {
        struct event *e=&events[i];char hash[65];sha256_hex(e->data,e->bytes,hash);
        fprintf(f,"{\"sequence\":%d,",i+1);emit_identity(f,c);fprintf(f,",\"scenario\":");json_text(f,scenario(e->case_index));
        fprintf(f,",\"stage\":");json_text(f,stage(e->phase));fprintf(f,",\"operation\":");json_text(f,e->operation);
        fprintf(f,",\"fd\":%d,\"local\":{\"ip\":",e->fd);json_text(f,e->local_ip);fprintf(f,",\"port\":%d},\"peer\":{\"ip\":",e->local_port);json_text(f,e->peer_ip);fprintf(f,",\"port\":%d}",e->peer_port);
        fprintf(f,",\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64,e->begin_real,e->end_real,e->begin_mono,e->end_mono);
        fprintf(f,",\"bytes\":%zu,\"syscalls\":%d,\"errno\":%d,\"wire_sha256\":\"%s\",\"complete_wire_event\":%s,\"complete_mysql_message\":%s,\"eof_observed\":%s,\"wire_fixture\":true,\"sql_executed\":false,\"wire_hex\":",e->bytes,e->calls,e->error,hash,e->complete?"true":"false",e->complete&&e->phase!=6?"true":"false",e->eof?"true":"false");emit_hex(f,e->data,e->bytes);
        fprintf(f,",\"classic_packets\":%d,\"packets\":",packet_count(e->data,e->bytes));emit_packets(f,e);fprintf(f,"}\n");
    }
    *written=event_count;return fflush(f)==0&&fsync(fileno(f))==0?0:system_fail("persist actual MySQL wire events");
}
static int execute(const struct config *c) {
    uint64_t started_real=now_ns(CLOCK_REALTIME),started_mono=now_ns(CLOCK_MONOTONIC);
    int directory=output_directory(c->output);if(directory<0)return -1;if(identity()){close(directory);return -1;}
    FILE *wire=fresh_file(directory,"wire.jsonl");if(!wire){close(directory);return -1;}
    FILE *process=fresh_file(directory,"process.json");if(!process){fclose(wire);close(directory);return -1;}
    fprintf(process,"{");emit_identity(process,c);fprintf(process,",\"single_threaded\":true,\"sdk\":false,\"protocol\":\"real MySQL classic TCP\",\"wire_fixture\":true,\"sql_executed\":false,\"empty_password\":true,\"native_source3_verified\":false}\n");
    if(finish_file(process)){fclose(wire);close(directory);return -1;}
    int listener=-1,rc=0,written=0;bool listener_closed=true;
    if(!strcmp(c->role,"server")) {
        listener=listen_owned(c);if(listener<0){rc=-1;goto finish;}
        FILE *ready=fresh_file(directory,"ready.json");if(!ready){rc=-1;goto finish;}
        fprintf(ready,"{\"event\":\"ready\",");emit_identity(ready,c);fprintf(ready,",\"listen_ip\":\"127.0.0.2\",\"listen_port\":18080,\"max_connections\":3,\"wire_fixture\":true,\"sql_executed\":false}\n");
        if(finish_file(ready)){rc=-1;goto finish;}
        printf("{\"ready\":true,\"role\":\"server\",\"port\":18080}\n");fflush(stdout);
    }
    for(int i=0;i<CASES;i++) { int outcome=conversation(c,listener,i);if(write_events(wire,c,&written)){rc=-1;break;}if(outcome){rc=-1;break;} }
finish:
    if(listener>=0&&close(listener)){listener_closed=false;system_fail("close actual MySQL listener");rc=-1;}
    if(write_events(wire,c,&written))rc=-1;
    if(finish_file(wire))rc=-1;
    FILE *receipt=fresh_file(directory,"receipt.json");
    if(receipt) {
        bool sockets_closed=listener_closed&&connection_count==CASES;for(int i=0;i<connection_count;i++)sockets_closed=sockets_closed&&connections[i].closed;
        int packets=0,data_events=0,eof_events=0;
        for(int i=0;i<event_count;i++){int count=packet_count(events[i].data,events[i].bytes);if(count>0)packets+=count;if(events[i].phase<6)data_events++;if(events[i].eof)eof_events++;}
        fprintf(receipt,"{");emit_identity(receipt,c);
        fprintf(receipt,",\"pass\":%s,\"completed_requests\":%d,\"expected_requests\":3,\"wire_events\":%d,\"wire_data_events\":%d,\"tcp_eof_events\":%d,\"classic_packets\":%d,\"wire_fixture\":true,\"sql_executed\":false,\"sdk\":false,\"native_source3_verified\":false,\"framing\":\"mysql-classic-u24le-seq\",\"separate_tcp_connections\":true,\"single_threaded\":true,\"owned_sockets_closed\":%s,\"listener_closed\":%s,\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64 ",\"port\":18080,\"connections\":[",rc==0&&completed==CASES?"true":"false",completed,event_count,data_events,eof_events,packets,sockets_closed?"true":"false",listener_closed?"true":"false",started_real,now_ns(CLOCK_REALTIME),started_mono,now_ns(CLOCK_MONOTONIC));
        for(int i=0;i<connection_count;i++) {
            struct connection *r=&connections[i];if(i)fputc(',',receipt);fprintf(receipt,"{\"scenario\":");json_text(receipt,r->scenario);
            fprintf(receipt,",\"operation\":\"%s\",\"fd\":%d,\"syscalls\":%d,\"initial_errno\":%d,\"local\":{\"ip\":",!strcmp(c->role,"client")?"connect":"accept",r->fd,r->calls,r->initial_errno);json_text(receipt,r->local_ip);fprintf(receipt,",\"port\":%d},\"peer\":{\"ip\":",r->local_port);json_text(receipt,r->peer_ip);
            fprintf(receipt,",\"port\":%d},\"started_unix_ns\":%" PRIu64 ",\"finished_unix_ns\":%" PRIu64 ",\"started_monotonic_ns\":%" PRIu64 ",\"finished_monotonic_ns\":%" PRIu64 ",\"complete\":%s,\"closed\":%s,\"shutdown_write\":%s}",r->peer_port,r->begin_real,r->end_real,r->begin_mono,r->end_mono,r->complete?"true":"false",r->closed?"true":"false",r->shutdown_write?"true":"false");
        }
        fprintf(receipt,"],\"error\":");json_text(receipt,last_error);fprintf(receipt,"}\n");if(finish_file(receipt))rc=-1;
    }else rc=-1;
    close(directory);printf("{\"pass\":%s,\"role\":\"%s\",\"completed_requests\":%d,\"sql_executed\":false,\"native_source3_verified\":false}\n",rc==0&&completed==CASES?"true":"false",c->role,completed);fflush(stdout);return rc;
}
int main(int argc,char **argv) {
    struct config c={NULL,NULL,NULL,90,18080,false};
    static const struct option options[]={{"execute",no_argument,0,'e'},{"role",required_argument,0,'r'},{"run",required_argument,0,'m'},{"output",required_argument,0,'o'},{"seconds",required_argument,0,'s'},{"port",required_argument,0,'p'},{0,0,0,0}};
    opterr=0;int value;while((value=getopt_long(argc,argv,"",options,NULL))!=-1) {
        if(value=='e')c.execute=true;else if(value=='r')c.role=optarg;else if(value=='m')c.run=optarg;else if(value=='o')c.output=optarg;
        else if(value=='s'){if(numeric(optarg,5,90,&c.seconds))return 2;}else if(value=='p'){if(numeric(optarg,18080,18080,&c.port))return 2;}else return 2;
    }
    if(optind!=argc)return 2;
    if(!c.execute){printf("{\"execute\":false,\"starts_network\":false,\"reads_files\":false,\"creates_files\":false,\"wire_fixture\":true,\"sql_executed\":false,\"sdk\":false,\"protocol\":\"MySQL classic TCP\",\"client\":\"127.0.0.1\",\"server\":\"127.0.0.2\",\"port\":18080,\"max_connections\":3}\n");return 0;}
    if(!c.role||!valid_run(c.run)||!c.output||(strcmp(c.role,"client")&&strcmp(c.role,"server")))return 2;
    if(prctl(PR_SET_NAME,!strcmp(c.role,"server")?"mysqld":"traflens-mysql",0,0,0)){perror("set own fixture direction comm");return 1;}
    signal(SIGPIPE,SIG_IGN);signal(SIGTERM,stop_handler);signal(SIGINT,stop_handler);
    deadline_ns=now_ns(CLOCK_MONOTONIC)+(uint64_t)c.seconds*1000000000ULL;
    int rc=execute(&c);if(rc)fprintf(stderr,"%s\n",last_error);return rc?1:0;
}
