/* SPDX-License-Identifier: Apache-2.0
 * Bounded synthetic HTTP / exclusive-netns libtrace validation.
 * Runtime evidence is private. No copied libtrace ABI declarations.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#if defined(__has_include)
#if __has_include(<linux/nsfs.h>)
#include <linux/nsfs.h>
#endif
#endif
#ifndef NS_GET_NSTYPE
#define NS_GET_NSTYPE _IO(0xb7, 0x3) /* Linux UAPI nsfs.h, network namespace type */
#endif
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000
#endif
#ifndef GATE_TRAFFIC_ONLY
#include "user/tracer.h"
#include "user/socket.h"
#include "user/table.h"
#include "user/load.h"
#include "kernel/include/socket_scope.h"
#include "trace_utils.h"
#endif

#ifndef GATE_TRAFFIC_ONLY
/* Standalone binaries have no Rust logger subscriber. Preserve SDK metadata
 * diagnostics in the private console; this is not a payload/datadump hook. */
void __real__ebpf_log(int how_to_die, char *function_name, char *file_path, int line_number,
		      char *fmt, ...);
void __wrap__ebpf_log(int how_to_die, char *function_name, char *file_path, int line_number,
		      char *fmt, ...)
{
	char message[2048];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(message, sizeof(message), fmt, ap);
	va_end(ap);
	fprintf(stderr, "libtrace %s:%d %s\n", file_path ? file_path : "", line_number, message);
	/* Preserve the original fatal/abort behavior after private diagnostics. */
	__real__ebpf_log(how_to_die, function_name, file_path, line_number, "%s", message);
}
#endif
#define DEFAULT_HTTP_PORT 18089
#define POSITIVE_COUNT 20
#define MAX_RECORDS 40
#define WIRE_MAX 512
struct options {
	const char *command, *role, *mode, *marker, *target_ns, *control, *evidence;
	uint64_t inode;
	uint32_t positive_tgid;
	unsigned seconds, port;
};
static struct options opts = {.mode = "scoped",
			      .control = "/control",
			      .evidence = "/evidence",
			      .seconds = 180,
			      .port = DEFAULT_HTTP_PORT};
static volatile sig_atomic_t cancelled;
static atomic_bool failed;
static double deadline;
static int control_fd = -1, evidence_fd = -1;
static void diagnostic_crash(int signum)
{
	void *frames[32];
	int count = backtrace(frames, 32);
	backtrace_symbols_fd(frames, count, STDERR_FILENO);
	_exit(128 + signum);
}
static void interrupted(int signum)
{
	(void)signum;
	cancelled = 1;
}
static double monotonic(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t)) {
		cancelled = 1;
		return 0;
	}
	return (double)t.tv_sec + (double)t.tv_nsec / 1000000000.0;
}
static bool alive(void) { return !cancelled && !atomic_load(&failed) && monotonic() < deadline; }
static void tick(void)
{
	struct timespec t = {.tv_nsec = 20000000};
	nanosleep(&t, NULL);
}
static bool marker_valid(const char *s)
{
	if (!s || strlen(s) < 8 || strlen(s) > 24)
		return false;
	for (; *s; s++)
		if (!((*s >= '0' && *s <= '9') || (*s >= 'a' && *s <= 'z') ||
		      (*s >= 'A' && *s <= 'Z')))
			return false;
	return true;
}
static bool number(const char *s, uint64_t *out)
{
	if (!s || !*s)
		return false;
	for (const char *p = s; *p; p++)
		if (*p < '0' || *p > '9')
			return false;
	errno = 0;
	char *end;
	unsigned long long n = strtoull(s, &end, 10);
	if (errno || *end)
		return false;
	*out = n;
	return true;
}
static bool parse_options(int argc, char **argv)
{
	if (argc < 2)
		return false;
	opts.command = argv[1];
	if (!strcmp(opts.command, "self-test"))
		return argc == 2;
	for (int i = 2; i < argc; i += 2) {
		if (i + 1 >= argc)
			return false;
		const char *k = argv[i], *v = argv[i + 1];
		uint64_t n;
		if (!strcmp(k, "--role"))
			opts.role = v;
		else if (!strcmp(k, "--mode"))
			opts.mode = v;
		else if (!strcmp(k, "--marker"))
			opts.marker = v;
		else if (!strcmp(k, "--target-netns"))
			opts.target_ns = v;
		else if (!strcmp(k, "--control"))
			opts.control = v;
		else if (!strcmp(k, "--evidence"))
			opts.evidence = v;
		else if (!strcmp(k, "--expected-inode")) {
			if (!number(v, &opts.inode))
				return false;
		} else if (!strcmp(k, "--positive-tgid")) {
			if (!number(v, &n) || !n || n > INT_MAX)
				return false;
			opts.positive_tgid = (uint32_t)n;
		} else if (!strcmp(k, "--port")) {
			if (!number(v, &n) || !n || n > UINT16_MAX)
				return false;
			opts.port = (unsigned)n;
		} else if (!strcmp(k, "--seconds")) {
			if (!number(v, &n) || n < 30 || n > 240)
				return false;
			opts.seconds = (unsigned)n;
		} else
			return false;
	}
	if (!marker_valid(opts.marker))
		return false;
	if (!strcmp(opts.command, "traffic"))
		return opts.role &&
		       (!strcmp(opts.role, "positive") || !strcmp(opts.role, "negative"));
	if (strcmp(opts.command, "trace") || !opts.positive_tgid)
		return false;
	if (!strcmp(opts.mode, "legacy"))
		return opts.inode == 0 && opts.target_ns == NULL;
	if (strcmp(opts.mode, "scoped") && strcmp(opts.mode, "deny"))
		return false;
	return opts.target_ns && opts.inode > 0 && opts.inode <= UINT32_MAX;
}
static int open_private_dir(const char *path)
{
	struct stat st;
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() ||
	    (st.st_mode & 0022)) {
		close(fd);
		return -1;
	}
	return fd;
}
static bool filename(char *out, size_t size, const char *suffix)
{
	int n = snprintf(out, size, "%s", suffix);
	return n > 0 && (size_t)n < size;
}
static bool publish(const char *suffix, const char *format, ...)
{
	char name[128], temp[136];
	if (!filename(name, sizeof(name), suffix))
		return false;
	if (snprintf(temp, sizeof(temp), "%s.tmp", name) >= (int)sizeof(temp))
		return false;
	int fd =
	    openat(evidence_fd, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	if (fd < 0)
		return false;
	FILE *f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlinkat(evidence_fd, temp, 0);
		return false;
	}
	va_list ap;
	va_start(ap, format);
	int n = vfprintf(f, format, ap);
	va_end(ap);
	bool ok = n >= 0 && fflush(f) == 0 && fsync(fd) == 0;
	if (fclose(f))
		ok = false;
	/* Exclusive publish: refuse stale/reused markers instead of overwriting. */
	if (ok && linkat(evidence_fd, temp, evidence_fd, name, 0))
		ok = false;
	unlinkat(evidence_fd, temp, 0);
	return ok;
}
static int read_small(int dir, const char *name, char *buffer, size_t size)
{
	int fd = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? 0 : -1;
	ssize_t n = read(fd, buffer, size - 1);
	close(fd);
	if (n < 0 || (size_t)n >= size - 1)
		return -1;
	buffer[n] = 0;
	return (int)n;
}
static bool stop_requested(void)
{
	int fd = openat(control_fd, "stop", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return false;
	close(fd);
	return true;
}
static int decode_command(const char *role, int expected, const char *text, int n, int *rounds)
{
	int phase = 0, count = 0, used = 0;
	if (sscanf(text, "%d %d %n", &phase, &count, &used) != 2 || used != n)
		return -1;
	int wanted = phase == 1 ? 10 : phase == 2 ? 20 : phase == 3 ? 10 : 0;
	if (!wanted || count != wanted || (!strcmp(role, "positive") && phase != 2) ||
	    phase > expected)
		return -1;
	if (phase < expected)
		return 0;
	*rounds = count;
	return 1;
}
static int command_for(const char *role, int expected, int *rounds)
{
	char name[64], text[64];
	snprintf(name, sizeof(name), "%s.command", role);
	int n = read_small(control_fd, name, text, sizeof(text));
	if (n <= 0)
		return n;
	return decode_command(role, expected, text, n, rounds);
}
static int http_wire(const char *marker, const char *role, int index, char *request,
		     size_t *request_len, char *response, size_t *response_len)
{
	char body[96];
	int n = snprintf(body, sizeof(body), "%s/%s/%02d", marker, role, index);
	if (n <= 0 || n >= (int)sizeof(body))
		return -1;
	int a = snprintf(
	    request, WIRE_MAX,
	    "GET /traflens-ebpf/%s/%s/%02d HTTP/1.1\r\n"
	    "Host: traflens-ebpf.invalid\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
	    marker, role, index);
	int b = snprintf(
	    response, WIRE_MAX,
	    "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: keep-alive\r\n\r\n%s", n, body);
	if (a <= 0 || b <= 0 || a >= WIRE_MAX || b >= WIRE_MAX)
		return -1;
	*request_len = (size_t)a;
	*response_len = (size_t)b;
	return 0;
}
static int traffic_batch(int first, int count)
{
	int listener = -1, client = -1, server = -1, completed = 0;
	struct sockaddr_in address = {0};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(opts.port);
	listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (listener < 0)
		goto done;
	int reuse = 1;
	if (setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) ||
	    bind(listener, (void *)&address, sizeof(address)) || listen(listener, 1))
		goto done;
	client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (client < 0)
		goto done;
	struct timeval timeout = {.tv_sec = 1};
	setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(client, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	if (connect(client, (void *)&address, sizeof(address)))
		goto done;
	server = accept4(listener, NULL, NULL, SOCK_CLOEXEC);
	if (server < 0)
		goto done;
	setsockopt(server, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	setsockopt(server, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	for (int i = first; i < first + count && alive(); i++) {
		char request[WIRE_MAX], response[WIRE_MAX], received[WIRE_MAX];
		size_t q, r;
		if (http_wire(opts.marker, opts.role, i, request, &q, response, &r))
			break;
		if (send(client, request, q, MSG_NOSIGNAL) != (ssize_t)q)
			break;
		if (recv(server, received, q, MSG_WAITALL) != (ssize_t)q ||
		    memcmp(received, request, q))
			break;
		if (send(server, response, r, MSG_NOSIGNAL) != (ssize_t)r)
			break;
		if (recv(client, received, r, MSG_WAITALL) != (ssize_t)r ||
		    memcmp(received, response, r))
			break;
		completed++;
		struct timespec pace = {.tv_nsec = 50000000};
		nanosleep(&pace, NULL);
	}
done:
	if (server >= 0)
		close(server);
	if (client >= 0)
		close(client);
	if (listener >= 0)
		close(listener);
	return completed;
}
#ifndef GATE_TRAFFIC_ONLY
static int native_self_test(void);
static bool remember_program_ids(struct bpf_tracer *tracer);
#endif
static int pure_self_test(void)
{
	const char *marker = "scopeunit01234567";
	for (int i = 1; i <= MAX_RECORDS; i++) {
		char pq[WIRE_MAX], pr[WIRE_MAX], nq[WIRE_MAX], nr[WIRE_MAX];
		size_t pql, prl, nql, nrl;
		if (http_wire(marker, "positive", i, pq, &pql, pr, &prl) ||
		    http_wire(marker, "negative", i, nq, &nql, nr, &nrl) || pql != nql ||
		    prl != nrl || !memcmp(pq, nq, pql) || !memcmp(pr, nr, prl) ||
		    !strstr(pq, "\r\n\r\n") || !strstr(pr, "\r\n\r\n"))
			return 1;
	}
	if (!marker_valid(marker) || marker_valid("../invalid") || marker_valid("short"))
		return 1;
	struct options saved = opts;
	const char *ports[] = {
	    "1", "18080", "18089", "65535", "0", "65536", "-1", "1x", "18446744073709551616"};
	for (unsigned i = 0; i < sizeof(ports) / sizeof(ports[0]); i++) {
		opts = saved;
		char *args[] = {"gate",	    "traffic",		 "--role", "positive",
				"--marker", "scopeunit01234567", "--port", (char *)ports[i]};
		if (parse_options(8, args) != (i < 4))
			return 1;
	}
	opts = saved;
	int rounds = 0;
	if (decode_command("positive", 2, "2 20\n", 5, &rounds) != 1 || rounds != 20 ||
	    decode_command("positive", 2, "1 10\n", 5, &rounds) != -1 ||
	    decode_command("negative", 1, "2 20\n", 5, &rounds) != -1 ||
	    decode_command("negative", 2, "1 10\n", 5, &rounds) != 0 ||
	    decode_command("negative", 3, "3 10\n", 5, &rounds) != 1 ||
	    decode_command("negative", 3, "3 20\n", 5, &rounds) != -1 ||
	    decode_command("negative", 3, "0 10\n", 5, &rounds) != -1 ||
	    decode_command("negative", 3, "3 10 x", 6, &rounds) != -1)
		return 1;
#ifndef GATE_TRAFFIC_ONLY
	if (native_self_test())
		return 1;
#endif
	puts(
	    "{\"pass\":true,\"equal_length_http_vectors\":40,\"network_or_tracer_started\":false}");
	return 0;
}
/* Phase orchestration and native callback code follow below. */

#ifndef GATE_TRAFFIC_ONLY
struct capture_stats {
	uint64_t callbacks, foreign_pid, invalid_metadata, invalid_wire, payload_reads,
	    close_records;
	unsigned requests[POSITIVE_COUNT][2], responses[POSITIVE_COUNT][2];
};
static struct capture_stats stats;
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static int namespace_fd = -1;
static uint32_t program_ids[256];
static unsigned program_count;
static int capture_http(void *context, int queue, void *raw)
{
	(void)context;
	(void)queue;
	pthread_mutex_lock(&stats_mutex);
	stats.callbacks++;
	if (!raw) {
		stats.invalid_metadata++;
		goto bad;
	}
	struct socket_bpf_data *event = raw;
	/* Outside PID: read no field beyond process_id and never cap_data. */
	if (event->process_id != opts.positive_tgid) {
		stats.foreign_pid++;
		goto bad;
	}
	if (strcmp(opts.mode, "scoped")) {
		stats.invalid_metadata++;
		goto bad;
	}
	if (event->source != DATA_SOURCE_SYSCALL || event->l7_protocal_hint != PROTO_HTTP1) {
		stats.invalid_metadata++;
		goto bad;
	}
	if (event->cap_len == 0 && event->msg_type == MSG_CLOSE) {
		stats.close_records++;
		pthread_mutex_unlock(&stats_mutex);
		return 0;
	}
	/* The SYSCALL producer emits MSG_COMMON for ordinary data. Role and
	 * direction identify the endpoint operation; exact bytes remain the oracle. */
	if (event->msg_type != MSG_COMMON) {
		stats.invalid_metadata++;
		goto bad;
	}
	bool request = (event->socket_role == ROLE_CLIENT && event->direction == T_EGRESS) ||
		       (event->socket_role == ROLE_SERVER && event->direction == T_INGRESS);
	bool response = (event->socket_role == ROLE_SERVER && event->direction == T_EGRESS) ||
			(event->socket_role == ROLE_CLIENT && event->direction == T_INGRESS);
	int slot = -1;
	if (request) {
		if (event->socket_role == ROLE_CLIENT && event->direction == T_EGRESS)
			slot = 0;
		if (event->socket_role == ROLE_SERVER && event->direction == T_INGRESS)
			slot = 1;
	} else if (response) {
		if (event->socket_role == ROLE_SERVER && event->direction == T_EGRESS)
			slot = 0;
		if (event->socket_role == ROLE_CLIENT && event->direction == T_INGRESS)
			slot = 1;
	}
	if (slot < 0 || !event->cap_len || event->cap_len >= WIRE_MAX || !event->cap_data) {
		stats.invalid_metadata++;
		goto bad;
	}
	/* Only the known owned positive process can reach this payload-read point. */
	stats.payload_reads++;
	for (int i = 0; i < POSITIVE_COUNT; i++) {
		char expected_request[WIRE_MAX], expected_response[WIRE_MAX];
		size_t q, r;
		if (http_wire(opts.marker, "positive", i + 1, expected_request, &q,
			      expected_response, &r)) {
			stats.invalid_wire++;
			goto bad;
		}
		const char *expected = request ? expected_request : expected_response;
		size_t expected_size = request ? q : r;
		if (event->cap_len == expected_size &&
		    !memcmp(event->cap_data, expected, expected_size)) {
			unsigned *seen =
			    request ? &stats.requests[i][slot] : &stats.responses[i][slot];
			if (++*seen != 1) {
				stats.invalid_wire++;
				goto bad;
			}
			pthread_mutex_unlock(&stats_mutex);
			return 0;
		}
	}
	stats.invalid_wire++;
bad:
	atomic_store(&failed, true);
	pthread_mutex_unlock(&stats_mutex);
	return 0;
}
static struct capture_stats snapshot(void)
{
	pthread_mutex_lock(&stats_mutex);
	struct capture_stats copy = stats;
	pthread_mutex_unlock(&stats_mutex);
	return copy;
}
static bool no_bad_events(struct capture_stats *s)
{
	return !s->foreign_pid && !s->invalid_metadata && !s->invalid_wire;
}
static bool exact_positive(struct capture_stats *s)
{
	if (!no_bad_events(s))
		return false;
	if (strcmp(opts.mode, "scoped"))
		return s->callbacks == 0 && s->payload_reads == 0;
	if (s->payload_reads != POSITIVE_COUNT * 4)
		return false;
	for (int i = 0; i < POSITIVE_COUNT; i++)
		for (int j = 0; j < 2; j++)
			if (s->requests[i][j] != 1 || s->responses[i][j] != 1)
				return false;
	return true;
}
static bool quiet_for(double seconds, bool require_exact, uint64_t expected_callbacks)
{
	double since = monotonic(), until = monotonic() + 12;
	uint64_t previous = expected_callbacks;
	while (alive() && monotonic() < until) {
		struct capture_stats s = snapshot();
		if (!no_bad_events(&s))
			return false;
		if (s.callbacks != previous) {
			previous = s.callbacks;
			since = monotonic();
		}
		if (require_exact && !exact_positive(&s))
			since = monotonic();
		if (monotonic() - since >= seconds)
			return true;
		tick();
	}
	return false;
}
static int native_self_test(void)
{
	/* A registered tracer can exist before its object has loaded. */
	struct bpf_tracer *empty = calloc(1, sizeof(*empty));
	if (!empty)
		return 1;
	bool rejected = !remember_program_ids(NULL) && !remember_program_ids(empty);
	struct ebpf_object missing_programs = {.progs_cnt = 1};
	empty->obj = &missing_programs;
	rejected = rejected && !remember_program_ids(empty);
	free(empty);
	if (!rejected)
		return 1;
	opts.marker = "scopeunit01234567";
	opts.mode = "scoped";
	opts.positive_tgid = 1234;
	struct socket_bpf_data event = {0};
	event.process_id = 4321;
	event.cap_len = 20;
	event.cap_data = (char *)1;
	capture_http(NULL, 0, &event);
	if (stats.foreign_pid != 1 || stats.payload_reads != 0 || !atomic_load(&failed))
		return 1;
	memset(&stats, 0, sizeof(stats));
	atomic_store(&failed, false);
	event.process_id = opts.positive_tgid;
	event.source = DATA_SOURCE_SYSCALL;
	event.l7_protocal_hint = PROTO_HTTP1;
	event.msg_type = MSG_COMMON;
	event.socket_role = ROLE_CLIENT;
	event.direction = T_EGRESS;
	event.cap_len = WIRE_MAX;
	capture_http(NULL, 0, &event);
	if (stats.invalid_metadata != 1 || stats.payload_reads != 0)
		return 1;
	memset(&stats, 0, sizeof(stats));
	atomic_store(&failed, false);
	opts.mode = "deny";
	event.cap_len = 20;
	capture_http(NULL, 0, &event);
	if (stats.invalid_metadata != 1 || stats.payload_reads != 0)
		return 1;
	memset(&stats, 0, sizeof(stats));
	atomic_store(&failed, false);
	opts.mode = "scoped";
	/* Invalid metadata cannot cause a payload read, even with a poison pointer. */
	const unsigned invalid_messages[] = {MSG_UNKNOWN, MSG_REQUEST, MSG_RESPONSE};
	event.cap_data = (char *)1;
	event.cap_len = 20;
	for (unsigned i = 0; i < sizeof(invalid_messages) / sizeof(invalid_messages[0]); i++) {
		event.msg_type = invalid_messages[i];
		capture_http(NULL, 0, &event);
		if (stats.invalid_metadata != 1 || stats.payload_reads != 0)
			return 1;
		memset(&stats, 0, sizeof(stats));
		atomic_store(&failed, false);
	}
	event.msg_type = MSG_COMMON;
	event.socket_role = ROLE_UNKNOWN;
	capture_http(NULL, 0, &event);
	if (stats.invalid_metadata != 1 || stats.payload_reads != 0)
		return 1;
	memset(&stats, 0, sizeof(stats));
	atomic_store(&failed, false);
	event.socket_role = ROLE_CLIENT;
	event.direction = 2;
	capture_http(NULL, 0, &event);
	if (stats.invalid_metadata != 1 || stats.payload_reads != 0)
		return 1;
	memset(&stats, 0, sizeof(stats));
	atomic_store(&failed, false);
	for (int i = 1; i <= POSITIVE_COUNT; i++) {
		char request[WIRE_MAX], response[WIRE_MAX];
		size_t q, r;
		if (http_wire(opts.marker, "positive", i, request, &q, response, &r))
			return 1;
		event.msg_type = MSG_COMMON;
		event.cap_data = request;
		event.cap_len = (uint32_t)q;
		event.socket_role = ROLE_CLIENT;
		event.direction = T_EGRESS;
		capture_http(NULL, 0, &event);
		event.socket_role = ROLE_SERVER;
		event.direction = T_INGRESS;
		capture_http(NULL, 0, &event);
		event.msg_type = MSG_COMMON;
		event.cap_data = response;
		event.cap_len = (uint32_t)r;
		event.socket_role = ROLE_SERVER;
		event.direction = T_EGRESS;
		capture_http(NULL, 0, &event);
		event.socket_role = ROLE_CLIENT;
		event.direction = T_INGRESS;
		capture_http(NULL, 0, &event);
	}
	if (!exact_positive(&stats) || stats.payload_reads != 80)
		return 1;
	event.msg_type = MSG_CLOSE;
	event.cap_len = 0;
	event.cap_data = (char *)1;
	capture_http(NULL, 0, &event);
	if (stats.close_records != 1 || stats.payload_reads != 80)
		return 1;
	char request[WIRE_MAX], response[WIRE_MAX];
	size_t q, r;
	if (http_wire(opts.marker, "positive", 1, request, &q, response, &r))
		return 1;
	event.msg_type = MSG_COMMON;
	event.cap_data = request;
	event.cap_len = (uint32_t)q;
	event.socket_role = ROLE_CLIENT;
	event.direction = T_EGRESS;
	capture_http(NULL, 0, &event);
	if (stats.invalid_wire != 1 || !atomic_load(&failed))
		return 1;
	puts("{\"callback_self_test\":true,\"expected_payload_callbacks\":80,\"poison_pointer_"
	     "denied\":true,\"failed_load_object_guards\":true}");
	return 0;
}
static int attached_wrappers(struct bpf_tracer *tracer)
{
	int count = 0;
	struct list_head *entry;
	pthread_mutex_lock(&tracer->mutex_probes_lock);
	for (entry = tracer->probes_head.next; entry != &tracer->probes_head; entry = entry->next)
		if (container_of(entry, struct probe, list)->link)
			count++;
	for (int i = 0; i < tracer->tracepoints_count; i++)
		if (tracer->tracepoints[i].link)
			count++;
	for (int i = 0; i < tracer->kfuncs_count; i++)
		if (tracer->kfuncs[i].link)
			count++;
	pthread_mutex_unlock(&tracer->mutex_probes_lock);
	return count;
}
static bool remember_program_ids(struct bpf_tracer *tracer)
{
	if (!tracer || !tracer->obj || !tracer->obj->progs)
		return false;
	for (int i = 0; i < tracer->obj->progs_cnt; i++) {
		int fd = tracer->obj->progs[i].prog_fd;
		if (fd < 0)
			continue;
		if (program_count >= sizeof(program_ids) / sizeof(program_ids[0]))
			return false;
		struct bpf_prog_info info = {0};
		union bpf_attr attr = {0};
		attr.info.bpf_fd = fd;
		attr.info.info_len = sizeof(info);
		attr.info.info = (uint64_t)&info;
		if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &attr, sizeof(attr)))
			return false;
		program_ids[program_count++] = info.id;
	}
	return program_count > 0;
}
static bool verify_maps(struct bpf_tracer *tracer)
{
	bool legacy = !strcmp(opts.mode, "legacy");
	unsigned char ports[65536 / 8];
	struct socket_scope_config scope = {0};
	if (!bpf_table_get_value(tracer, "__socket_scope_map", 0, &scope))
		return false;
	if (legacy) {
		struct socket_scope_config zero = {0};
		if (memcmp(&scope, &zero, sizeof(scope)))
			return false;
	} else if (scope.netns_id != opts.inode || scope.validated != 1 ||
		   scope.task_nsproxy_offset > SOCKET_SCOPE_OFFSET_MAX ||
		   scope.nsproxy_net_offset > SOCKET_SCOPE_OFFSET_MAX ||
		   scope.net_ns_offset > SOCKET_SCOPE_OFFSET_MAX ||
		   scope.ns_inum_offset > SOCKET_SCOPE_OFFSET_MAX)
		return false;
	if (!bpf_table_get_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 0, ports))
		return false;
	for (size_t i = 0; i < sizeof(ports); i++)
		if (ports[i])
			return false;
	if (!bpf_table_get_value(tracer, MAP_KPROBE_PORT_BITMAP_NAME, 1, ports))
		return false;
	for (size_t i = 0; i < sizeof(ports); i++)
		if (ports[i] != (legacy ? 255 : 0))
			return false;
	for (int protocol = 0; protocol < PROTO_NUM; protocol++) {
		int enabled = -1;
		if (!bpf_table_get_value(tracer, MAP_PROTO_FILTER_NAME, protocol, &enabled) ||
		    enabled != (!legacy && protocol == PROTO_HTTP1))
			return false;
		if (!bpf_table_get_value(tracer, MAP_PROTO_PORTS_BITMAPS_NAME, protocol, ports))
			return false;
		for (size_t i = 0; i < sizeof(ports); i++) {
			unsigned char expected =
			    (!legacy && protocol == PROTO_HTTP1 && i == opts.port / 8)
				? 1U << (opts.port % 8)
				: 0;
			if (ports[i] != expected)
				return false;
		}
	}
	/* Per-CPU tracer context: checked API setters must also reach the map. */
	int cpus = get_num_possible_cpus();
	if (cpus <= 0 || cpus > MAX_CPU_NR)
		return false;
	_Static_assert(sizeof(struct tracer_ctx_s) % 8 == 0, "per-CPU context stride");
	struct tracer_ctx_s *contexts = calloc((size_t)cpus, sizeof(*contexts));
	if (!contexts)
		return false;
	bool context_ok = bpf_table_get_value(tracer, MAP_TRACER_CTX_NAME, 0, contexts);
	for (int i = 0; i < cpus && context_ok; i++)
		if (contexts[i].io_event_collect_mode != 0 ||
		    contexts[i].virtual_file_collect_enabled || contexts[i].data_limit_max != 1024)
			context_ok = false;
	free(contexts);
	return context_ok;
}
static bool pin_namespace(void)
{
	if (!strcmp(opts.mode, "legacy"))
		return true;
	namespace_fd = open(opts.target_ns, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (namespace_fd < 0)
		return false;
	struct stat target, loader;
	if (fstat(namespace_fd, &target) || target.st_ino != opts.inode ||
	    ioctl(namespace_fd, NS_GET_NSTYPE) != CLONE_NEWNET ||
	    stat("/proc/self/ns/net", &loader))
		return false;
	/* The deny-control FD must be an independently verified, held, quiet
	 * owned namespace selected by the supervisor (loader namespace or a
	 * separate idle namespace), never an arbitrary numeric inode. */
	if (!strcmp(opts.mode, "deny"))
		return true;
	return loader.st_ino != target.st_ino;
}
static bool start_tracer(struct bpf_tracer **out, int *links)
{
	char port_text[6];
	if (snprintf(port_text, sizeof(port_text), "%u", opts.port) <= 0)
		return false;
	*out = NULL;
	*links = 0;
	if (!pin_namespace())
		return false;
	if (strcmp(opts.mode, "legacy") && set_socket_tracer_netns_scope(opts.inode))
		return false;
	unsigned char allow[65536 / 8] = {0}, bypass[65536 / 8] = {0};
	if (!strcmp(opts.mode, "legacy"))
		memset(bypass, 255, sizeof(bypass));
	if (set_allow_port_bitmap(allow) || set_bypass_port_bitmap(bypass) ||
	    set_io_event_collect_mode(IO_EVENT_COLLECT_DISABLE) ||
	    set_virtual_file_collect(false) || set_data_limit_max(1024) != 1024)
		return false;
	/* No profiler, feature PID/uprobe or datadump initialization. */
	if (strcmp(opts.mode, "legacy")) {
		if (enable_ebpf_protocol(PROTO_HTTP1) ||
		    set_protocol_ports_bitmap(PROTO_HTTP1, port_text))
			return false;
	}
	char logname[128], logpath[PATH_MAX];
	if (!filename(logname, sizeof(logname), "libtrace.log") ||
	    snprintf(logpath, sizeof(logpath), "%s/%s", opts.evidence, logname) >=
		(int)sizeof(logpath))
		return false;
	int init_result = bpf_tracer_init(logpath, true);
	fprintf(stderr, "gate_start init_result=%d\n", init_result);
	if (init_result)
		return false;
	fputs("gate_start configuring_syscalls\n", stderr);
	set_hooked_socket_syscalls(HOOKED_SOCKET_SYSCALL_ALL);
	fputs("gate_start loading\n", stderr);
	int loaded = running_socket_tracer(capture_http, 1, 8, 1024, 1024, 1024, 1000);
	*out = find_bpf_tracer(SK_TRACER_NAME);
	fprintf(stderr, "gate_start raw_load_result=%d tracer=%d object=%d\n", loaded, *out != NULL,
		*out && (*out)->obj != NULL);
	bool remembered = loaded == 0 && *out && remember_program_ids(*out);
	bool maps = loaded == 0 && *out && (*out)->obj && verify_maps(*out);
	fprintf(stderr, "gate_start load_result=%d tracer=%d program_ids=%d maps=%d\n", loaded,
		*out != NULL, remembered, maps);
	if (loaded || !*out || !remembered || !maps)
		return false;
	bpf_tracer_finish();
	double until = monotonic() + 60;
	while (alive() && monotonic() < until) {
		if (get_socket_tracer_state() == TRACER_RUNNING) {
			*links = attached_wrappers(*out);
			return *links > 0 && verify_maps(*out);
		}
		tick();
	}
	return false;
}
static bool stop_tracer(struct bpf_tracer *tracer, int *remaining)
{
	if (!tracer) {
		*remaining = 0;
		return false;
	}
	int stopped;
	if (get_socket_tracer_state() == TRACER_RUNNING) {
		stopped = socket_tracer_stop();
		double until = monotonic() + 12;
		while (get_socket_tracer_state() != TRACER_STOP && monotonic() < until)
			tick();
	} else {
		pthread_mutex_lock(&tracer->mutex_probes_lock);
		stopped = tracer_hooks_detach(tracer);
		pthread_mutex_unlock(&tracer->mutex_probes_lock);
	}
	*remaining = attached_wrappers(tracer);
	return stopped == 0 && get_socket_tracer_state() == TRACER_STOP && *remaining == 0;
}
#endif

static int run_traffic(void)
{
	struct stat ns;
	if (stat("/proc/self/ns/net", &ns))
		return 1;
	char name[64];
	snprintf(name, sizeof(name), "%s.ready.json", opts.role);
	if (!publish(name,
		     "{\"ready\":true,\"role\":\"%s\",\"marker\":\"%s\",\"netns_inode\":%llu}\n",
		     opts.role, opts.marker, (unsigned long long)ns.st_ino))
		return 1;
	bool positive = !strcmp(opts.role, "positive"), ok = true;
	int total = 0, first = 1;
	int phases[3] = {1, 2, 3}, phase_count = positive ? 1 : 3;
	if (positive)
		phases[0] = 2;
	for (int stage = 0; stage < phase_count && alive(); stage++) {
		int phase = phases[stage], rounds = 0, command = 0;
		while (alive() && !stop_requested() &&
		       (command = command_for(opts.role, phase, &rounds)) == 0)
			tick();
		if (!alive() || stop_requested() || command != 1) {
			ok = false;
			break;
		}
		int count = traffic_batch(first, rounds);
		total += count;
		snprintf(name, sizeof(name), "%s.%d.done", opts.role, phase);
		if (!publish(name,
			     "{\"pass\":%s,\"phase\":%d,\"rounds_requested\":%d,\"roundtrips\":%d,"
			     "\"marker\":\"%s\",\"role\":\"%s\",\"first_index\":%d}\n",
			     count == rounds ? "true" : "false", phase, rounds, count, opts.marker,
			     opts.role, first))
			ok = false;
		if (count != rounds) {
			ok = false;
			break;
		}
		first += rounds;
	}
	ok = ok && total == (positive ? 20 : 40) && alive();
	char report[16384];
	size_t used = 0;
	int n = snprintf(
	    report, sizeof(report),
	    "{\"pass\":%s,\"roundtrips\":%d,\"role\":\"%s\",\"marker\":\"%s\",\"records\":[",
	    ok ? "true" : "false", total, opts.role, opts.marker);
	if (n < 0 || n >= (int)sizeof(report))
		return 1;
	used = (size_t)n;
	for (int i = 1; i <= total; i++) {
		char q[WIRE_MAX], a[WIRE_MAX];
		size_t ql, al;
		if (http_wire(opts.marker, opts.role, i, q, &ql, a, &al))
			return 1;
		n = snprintf(report + used, sizeof(report) - used,
			     "%s{\"request_resource\":\"/traflens-ebpf/%s/%s/%02d\","
			     "\"request_type\":\"GET\",\"response_code\":200,\"request_bytes\":%zu,"
			     "\"response_bytes\":%zu}",
			     i == 1 ? "" : ",", opts.marker, opts.role, i, ql, al);
		if (n < 0 || (size_t)n >= sizeof(report) - used)
			return 1;
		used += (size_t)n;
	}
	n = snprintf(report + used, sizeof(report) - used, "]}\n");
	if (n < 0 || (size_t)n >= sizeof(report) - used)
		return 1;
	snprintf(name, sizeof(name), "%s.result.json", opts.role);
	if (!publish(name, "%s", report))
		return 1;
	return ok ? 0 : 1;
}
#ifndef GATE_TRAFFIC_ONLY
static int receipt(const char *role, int phase, int expected)
{
	char name[64], text[512], pass[6], marker[25], worker[9];
	int p = 0, rounds = 0, completed = 0;
	snprintf(name, sizeof(name), "%s.%d.done", role, phase);
	int n = read_small(evidence_fd, name, text, sizeof(text));
	if (n <= 0)
		return n;
	if (sscanf(text,
		   "{\"pass\":%5[a-z],\"phase\":%d,\"rounds_requested\":%d,\"roundtrips\":%d,"
		   "\"marker\":\"%24[0-9a-zA-Z]\",\"role\":\"%8[a-z]\"",
		   pass, &p, &rounds, &completed, marker, worker) != 6)
		return -1;
	return !strcmp(pass, "true") && p == phase && rounds == expected && completed == expected &&
		       !strcmp(marker, opts.marker) && !strcmp(worker, role)
		   ? 1
		   : -1;
}
static bool wait_receipts(int phase)
{
	while (alive() && !stop_requested()) {
		int negative = receipt("negative", phase, phase == 2 ? 20 : 10);
		int positive = phase == 2 ? receipt("positive", 2, 20) : 1;
		if (negative < 0 || positive < 0)
			return false;
		if (negative == 1 && positive == 1)
			return true;
		static double last_status;
		if (monotonic() - last_status >= 1) {
			struct capture_stats current = snapshot();
			printf("{\"status\":\"await_receipts\",\"phase\":%d,\"callbacks\":%llu,"
			       "\"payload_reads\":%llu}\n",
			       phase, (unsigned long long)current.callbacks,
			       (unsigned long long)current.payload_reads);
			fflush(stdout);
			last_status = monotonic();
		}
		tick();
	}
	return false;
}
static bool publish_final(bool pass, const char *reason, struct capture_stats *s, int loaded_links,
			  int remaining, struct socket_trace_stats *drops)
{
	char report[16384];
	size_t used = 0;
	int n =
	    snprintf(report, sizeof(report),
		     "{\"pass\":%s,\"reason\":\"%s\",\"mode\":\"%s\",\"marker\":\"%s\","
		     "\"callbacks\":%llu,\"foreign_pid_records\":%llu,\"invalid_metadata\":%llu,"
		     "\"invalid_wire\":%llu,\"payload_reads\":%llu,\"close_records\":%llu,"
		     "\"attached_wrappers_before\":%d,\"attached_wrappers_after\":%d,"
		     "\"kern_lost\":%llu,\"user_enqueue_lost\":%llu,\"mem_alloc_failures\":%llu,"
		     "\"outside_pid_payload_read\":false,\"own_program_ids\":[",
		     pass ? "true" : "false", reason, opts.mode, opts.marker,
		     (unsigned long long)s->callbacks, (unsigned long long)s->foreign_pid,
		     (unsigned long long)s->invalid_metadata, (unsigned long long)s->invalid_wire,
		     (unsigned long long)s->payload_reads, (unsigned long long)s->close_records,
		     loaded_links, remaining, (unsigned long long)drops->kern_lost,
		     (unsigned long long)drops->user_enqueue_lost,
		     (unsigned long long)drops->mem_alloc_fail_count);
	if (n < 0 || n >= (int)sizeof(report))
		return false;
	used = (size_t)n;
	for (unsigned i = 0; i < program_count; i++) {
		n = snprintf(report + used, sizeof(report) - used, "%s%u", i ? "," : "",
			     program_ids[i]);
		if (n < 0 || (size_t)n >= sizeof(report) - used)
			return false;
		used += (size_t)n;
	}
	n = snprintf(report + used, sizeof(report) - used, "],\"positive_request_copies\":[");
	if (n < 0 || (size_t)n >= sizeof(report) - used)
		return false;
	used += (size_t)n;
	for (int i = 0; i < POSITIVE_COUNT; i++) {
		n = snprintf(report + used, sizeof(report) - used, "%s[%u,%u]", i ? "," : "",
			     s->requests[i][0], s->requests[i][1]);
		if (n < 0 || (size_t)n >= sizeof(report) - used)
			return false;
		used += (size_t)n;
	}
	n = snprintf(report + used, sizeof(report) - used, "],\"positive_response_copies\":[");
	if (n < 0 || (size_t)n >= sizeof(report) - used)
		return false;
	used += (size_t)n;
	for (int i = 0; i < POSITIVE_COUNT; i++) {
		n = snprintf(report + used, sizeof(report) - used, "%s[%u,%u]", i ? "," : "",
			     s->responses[i][0], s->responses[i][1]);
		if (n < 0 || (size_t)n >= sizeof(report) - used)
			return false;
		used += (size_t)n;
	}
	n = snprintf(report + used, sizeof(report) - used, "]}\n");
	if (n < 0 || (size_t)n >= sizeof(report) - used)
		return false;
	return publish("gate.json", "%s", report);
}
static int run_trace(void)
{
	struct bpf_tracer *tracer = NULL;
	int links = 0, remaining = -1;
	bool pass = false, started = false;
	const char *reason = "start_failed";
	uint64_t after_before = 0, after_drain = 0;
	if (!start_tracer(&tracer, &links))
		goto cleanup;
	started = true;
	if (!publish(
		"ready.json",
		"{\"ready\":true,\"running\":true,\"maps_verified\":true,"
		"\"mode\":\"%s\",\"marker\":\"%s\",\"loaded_programs\":%u,\"attached_wrappers\":%d,"
		"\"target_inode\":%llu,\"positive_tgid\":%u}\n",
		opts.mode, opts.marker, program_count, links, (unsigned long long)opts.inode,
		opts.positive_tgid)) {
		reason = "ready_publish_failed";
		goto cleanup;
	}
	/* Supervisor sends negative.command=1 10 only after ready.json. */
	reason = "negative_before_failed";
	if (!wait_receipts(1) || !quiet_for(1, false, 0))
		goto cleanup;
	struct capture_stats s = snapshot();
	if (s.callbacks != 0 || !no_bad_events(&s))
		goto cleanup;
	after_before = s.callbacks;
	if (!publish("negative-before.checked.json", "{\"pass\":true,\"callbacks\":%llu}\n",
		     (unsigned long long)after_before))
		goto cleanup;
	/* Supervisor waits for this barrier, then issues both phase-2 commands. */
	reason = "mixed_wire_failed";
	if (!wait_receipts(2))
		goto cleanup;
	reason = "positive_drain_failed";
	if (!quiet_for(1, true, snapshot().callbacks))
		goto cleanup;
	s = snapshot();
	if (!exact_positive(&s))
		goto cleanup;
	after_drain = s.callbacks;
	if (!publish("drained.json",
		     "{\"pass\":true,\"callbacks\":%llu,\"payload_reads\":%llu,"
		     "\"close_records\":%llu,\"quiet_seconds\":1}\n",
		     (unsigned long long)s.callbacks, (unsigned long long)s.payload_reads,
		     (unsigned long long)s.close_records))
		goto cleanup;
	/* Negative phase 3 cannot start until the supervisor sees drained.json. */
	reason = "negative_after_failed";
	if (!wait_receipts(3) || !quiet_for(2, true, after_drain))
		goto cleanup;
	s = snapshot();
	if (s.callbacks != after_drain || !exact_positive(&s))
		goto cleanup;
	if (!publish("negative-after.checked.json",
		     "{\"pass\":true,\"callbacks\":%llu,\"quiet_seconds\":2}\n",
		     (unsigned long long)s.callbacks))
		goto cleanup;
	reason = "missing_stop";
	while (alive() && !stop_requested()) {
		s = snapshot();
		if (s.callbacks != after_drain || !exact_positive(&s))
			goto cleanup;
		/* Metadata-only periodic status; never log payload or raw event IDs. */
		static double last;
		if (monotonic() - last >= 1) {
			printf("{\"phase\":\"await_stop\",\"callbacks\":%llu,\"payload_reads\":%"
			       "llu}\n",
			       (unsigned long long)s.callbacks,
			       (unsigned long long)s.payload_reads);
			fflush(stdout);
			last = monotonic();
		}
		tick();
	}
	if (!stop_requested() || !alive())
		goto cleanup;
	pass = true;
	reason = "ok";
cleanup:;
	bool detached = stop_tracer(tracer, &remaining);
	struct capture_stats final = snapshot();
	struct socket_trace_stats drops = {0};
	if (started)
		drops = socket_tracer_stats();
	if (pass && !exact_positive(&final))
		reason = "final_accounting_failed";
	if (pass && (drops.kern_lost || drops.user_enqueue_lost || drops.mem_alloc_fail_count))
		reason = "loss_or_allocation_failure";
	pass = pass && detached && exact_positive(&final) &&
	       (!started ||
		(!drops.kern_lost && !drops.user_enqueue_lost && !drops.mem_alloc_fail_count));
	if (!detached && !strcmp(reason, "ok"))
		reason = "detach_failed";
	/* A failed detach retains this pin until process exit; the supervisor
	 * also holds an independent nsfs FD until it confirms tracer termination. */
	if (namespace_fd >= 0 && detached)
		close(namespace_fd);
	bool saved = publish_final(pass, reason, &final, links, remaining, &drops);
	return pass && saved ? 0 : 1;
}
#endif
int main(int argc, char **argv)
{
	setvbuf(stdout, NULL, _IONBF, 0);
	if (!parse_options(argc, argv)) {
		fputs("Invalid arguments. Use traffic|trace with explicit role/mode, marker and "
		      "bounded seconds.\n",
		      stderr);
		return 64;
	}
	if (!strcmp(opts.command, "self-test"))
		return pure_self_test();
	umask(0077);
	signal(SIGSEGV, diagnostic_crash);
	signal(SIGABRT, diagnostic_crash);
	signal(SIGINT, interrupted);
	signal(SIGTERM, interrupted);
	signal(SIGALRM, interrupted);
	deadline = monotonic() + opts.seconds;
	alarm(opts.seconds);
	control_fd = open_private_dir(opts.control);
	evidence_fd = open_private_dir(opts.evidence);
	if (control_fd < 0 || evidence_fd < 0)
		return 65;
	if (!strcmp(opts.command, "trace")) {
		struct rlimit core_limit = {0, 0};
		if (setrlimit(RLIMIT_CORE, &core_limit))
			return 65;
		int sdk_log = openat(evidence_fd, "sdk-console.log",
				     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
		if (sdk_log < 0 || dup2(sdk_log, STDOUT_FILENO) < 0 ||
		    dup2(sdk_log, STDERR_FILENO) < 0)
			return 65;
		close(sdk_log);
	}
	prctl(PR_SET_NAME, !strcmp(opts.command, "trace") ? "tlens-ebpf-gate" : "tlens-http-wire",
	      0, 0, 0);
	int result;
	if (!strcmp(opts.command, "traffic"))
		result = run_traffic();
#if !defined(GATE_TRAFFIC_ONLY) && !defined(GATE_ABI_SELF_TEST)
	else
		result = run_trace();
#else
	else {
		fputs("This self-test/traffic-only build cannot start a tracer.\n", stderr);
		result = 77;
	}
#endif
	close(control_fd);
	close(evidence_fd);
	return result;
}
