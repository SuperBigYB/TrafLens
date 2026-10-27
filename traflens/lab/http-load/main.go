// A finite open-loop HTTP/1.1 workload for the trusted direct bench link.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type config struct {
	Mode, Interface, Bind, Peer, Marker, Output string
	Port, Rate, Seconds, Concurrency, TimeoutMS int
	Execute                                     bool
}

func (c config) validate() error {
	if c.Mode != "client" && c.Mode != "server" {
		return errors.New("mode must be client or server")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`).MatchString(c.Interface) {
		return errors.New("explicit interface required")
	}
	for _, a := range []string{c.Bind, c.Peer} {
		ip := net.ParseIP(a)
		if ip == nil || ip.To4() != nil || !ip.IsLinkLocalUnicast() {
			return errors.New("numeric IPv6 link-local addresses without zones required")
		}
	}
	if net.ParseIP(c.Bind).Equal(net.ParseIP(c.Peer)) {
		return errors.New("peer must differ from local address")
	}
	if !regexp.MustCompile(`^[a-z0-9-]{1,48}$`).MatchString(c.Marker) {
		return errors.New("invalid fresh marker")
	}
	if c.Port < 1024 || c.Port > 65535 || c.Rate < 1 || c.Rate > 10000 || c.Seconds < 1 || c.Seconds > 30 || c.Rate*c.Seconds > 200000 || c.Concurrency < 1 || c.Concurrency > 128 || c.TimeoutMS < 100 || c.TimeoutMS > 5000 {
		return errors.New("workload exceeds bounded contract")
	}
	if !filepath.IsAbs(c.Output) {
		return errors.New("new absolute private output path required")
	}
	return nil
}

type record struct {
	Sequence    int    `json:"sequence"`
	State       string `json:"state"`
	ScheduledNS int64  `json:"scheduled_ns"`
	StartedNS   int64  `json:"started_ns"`
	ServiceNS   int64  `json:"service_ns"`
	OfferedNS   int64  `json:"offered_latency_ns"`
}

type report struct {
	Schema           string   `json:"schema"`
	Mode             string   `json:"mode"`
	Marker           string   `json:"marker"`
	Pass             bool     `json:"pass"`
	Config           config   `json:"private_config"`
	Scheduled        int      `json:"scheduled"`
	Attempted        int      `json:"attempted"`
	Completed        int      `json:"completed"`
	Failed           int      `json:"failed"`
	Skipped          int      `json:"skipped"`
	ElapsedSeconds   float64  `json:"elapsed_seconds"`
	ServiceP50NS     int64    `json:"service_p50_ns"`
	ServiceP99NS     int64    `json:"service_p99_ns"`
	OfferedP99NS     int64    `json:"offered_p99_ns"`
	CPUUserSeconds   float64  `json:"process_cpu_user_seconds"`
	CPUSystemSeconds float64  `json:"process_cpu_system_seconds"`
	MaxRSSKiB        int64    `json:"process_peak_rss_kib"`
	Records          []record `json:"records"`
	Error            string   `json:"error,omitempty"`
}

func expectedBody(marker string, seq int) []byte {
	return []byte(fmt.Sprintf(`{"marker":%q,"sequence":%d}`, marker, seq))
}

func resource(marker string, seq int) string {
	return "/traflens-load/" + marker + "/" + strconv.Itoa(seq)
}

func responseValid(response *http.Response, marker string, seq int) error {
	defer response.Body.Close()
	want := expectedBody(marker, seq)
	if response.StatusCode != 200 || response.ProtoMajor != 1 || response.ProtoMinor != 1 || response.ContentLength != int64(len(want)) || response.Header.Get("Content-Type") != "application/json" {
		return errors.New("response headers differ")
	}
	got, err := io.ReadAll(io.LimitReader(response.Body, int64(len(want)+1)))
	if err != nil || string(got) != string(want) {
		return errors.New("response body differs")
	}
	return nil
}

func percentile(values []int64, p float64) int64 {
	if len(values) == 0 {
		return 0
	}
	values = append([]int64(nil), values...)
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	return values[int(math.Ceil(p*float64(len(values))))-1]
}

func summarize(r *report) {
	var service, offered []int64
	for _, row := range r.Records {
		switch row.State {
		case "completed":
			r.Attempted++
			r.Completed++
			service = append(service, row.ServiceNS)
			offered = append(offered, row.OfferedNS)
		case "failed":
			r.Attempted++
			r.Failed++
		default:
			r.Skipped++
		}
	}
	r.ServiceP50NS, r.ServiceP99NS, r.OfferedP99NS = percentile(service, .5), percentile(service, .99), percentile(offered, .99)
	r.Pass = r.Error == "" && r.Scheduled == len(r.Records) && r.Completed == r.Scheduled && r.Failed == 0 && r.Skipped == 0
}

type requestFunc func(context.Context, int) error

func runClient(ctx context.Context, c config, request requestFunc) report {
	count := c.Rate * c.Seconds
	r := report{Schema: "traflens.http-load.v1", Mode: "client", Marker: c.Marker, Config: c, Scheduled: count, Records: make([]record, count)}
	start := time.Now()
	var pending sync.WaitGroup
	slots := make(chan struct{}, c.Concurrency)
	interval := time.Second / time.Duration(c.Rate)
	for seq := 0; seq < count; seq++ {
		due := start.Add(time.Duration(seq) * interval)
		r.Records[seq] = record{Sequence: seq, State: "cancelled", ScheduledNS: int64(time.Duration(seq) * interval)}
		if ctx.Err() != nil {
			continue
		}
		wait := time.NewTimer(time.Until(due))
		select {
		case <-ctx.Done():
			wait.Stop()
			continue
		case <-wait.C:
		}
		// A ready timer does not give cancellation priority in select.
		if ctx.Err() != nil {
			continue
		}
		if time.Since(due) > interval {
			r.Records[seq].State = "schedule_late"
			continue
		}
		select {
		case slots <- struct{}{}:
			pending.Add(1)
			go func(seq int, due time.Time) {
				defer pending.Done()
				defer func() { <-slots }()
				row := &r.Records[seq]
				if ctx.Err() != nil {
					return
				}
				began := time.Now()
				row.StartedNS = began.Sub(start).Nanoseconds()
				requestCtx, cancel := context.WithTimeout(ctx, time.Duration(c.TimeoutMS)*time.Millisecond)
				err := request(requestCtx, seq)
				cancel()
				row.ServiceNS, row.OfferedNS = time.Since(began).Nanoseconds(), time.Since(due).Nanoseconds()
				row.State = "completed"
				if err != nil {
					row.State = "failed"
				}
			}(seq, due)
		default:
			r.Records[seq].State = "concurrency_full"
		}
	}
	pending.Wait()
	r.ElapsedSeconds = time.Since(start).Seconds()
	if ctx.Err() != nil {
		r.Error = "overall deadline or cancellation"
	}
	summarize(&r)
	return r
}

func httpRequest(c config) (requestFunc, func()) {
	local := &net.TCPAddr{IP: net.ParseIP(c.Bind), Zone: c.Interface}
	dialer := &net.Dialer{LocalAddr: local, Timeout: time.Duration(c.TimeoutMS) * time.Millisecond}
	peer := net.JoinHostPort(c.Peer+"%"+c.Interface, strconv.Itoa(c.Port))
	transport := &http.Transport{Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		MaxConnsPerHost: c.Concurrency, MaxResponseHeaderBytes: 4096,
		ResponseHeaderTimeout: time.Duration(c.TimeoutMS) * time.Millisecond,
		DialContext:           func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.DialContext(ctx, "tcp6", peer) }}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, seq int) error {
		request, err := http.NewRequestWithContext(ctx, "GET", "http://traflens-load.invalid"+resource(c.Marker, seq), nil)
		if err != nil {
			return err
		}
		request.Close = true
		response, err := client.Do(request)
		if err != nil {
			return err
		}
		return responseValid(response, c.Marker, seq)
	}, transport.CloseIdleConnections
}

type serverState struct {
	mu                                         sync.Mutex
	seen                                       []bool
	complete, rejected, duplicate, writeErrors int
	done                                       chan struct{}
	c                                          config
}

func (s *serverState) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	prefix := "/traflens-load/" + s.c.Marker + "/"
	text := strings.TrimPrefix(r.URL.Path, prefix)
	seq, err := strconv.Atoi(text)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil || !strings.HasPrefix(r.URL.Path, prefix) || text != strconv.Itoa(seq) || seq < 0 || seq >= len(s.seen) || r.URL.RawQuery != "" || r.Method != "GET" || r.Host != "traflens-load.invalid" || r.ContentLength != 0 {
		s.rejected++
		http.Error(w, "invalid request", 400)
		return
	}
	if s.seen[seq] {
		s.duplicate++
		http.Error(w, "duplicate", 409)
		return
	}
	s.seen[seq] = true
	body := expectedBody(s.c.Marker, seq)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Connection", "close")
	n, writeErr := w.Write(body)
	if writeErr != nil || n != len(body) {
		s.writeErrors++
		return
	}
	s.complete++
	if s.complete == len(s.seen) {
		close(s.done)
	}
}

// Bound accepted connections as well as client concurrency; net/http's default
// listener alone does not provide this process-level goroutine bound.
type boundedListener struct {
	net.Listener
	slots chan struct{}
	stop  chan struct{}
	once  sync.Once
}
type boundedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *boundedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *boundedListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.stop:
		return nil, net.ErrClosed
	}
	c, err := l.Listener.Accept()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &boundedConn{Conn: c, release: func() { <-l.slots }}, nil
}
func (l *boundedListener) Close() error {
	l.once.Do(func() { close(l.stop) })
	return l.Listener.Close()
}

func runServer(ctx context.Context, c config, listener net.Listener) report {
	count := c.Rate * c.Seconds
	s := &serverState{seen: make([]bool, count), done: make(chan struct{}), c: c}
	l := &boundedListener{Listener: listener, slots: make(chan struct{}, c.Concurrency), stop: make(chan struct{})}
	server := &http.Server{Handler: s, ReadHeaderTimeout: time.Second, ReadTimeout: time.Duration(c.TimeoutMS) * time.Millisecond,
		WriteTimeout: time.Duration(c.TimeoutMS) * time.Millisecond, IdleTimeout: time.Second, MaxHeaderBytes: 4096}
	finished := make(chan error, 1)
	start := time.Now()
	go func() { finished <- server.Serve(l) }()
	var serveErr error
	select {
	case <-ctx.Done():
	case <-s.done:
	case serveErr = <-finished:
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		server.Close()
		serveErr = err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r := report{Schema: "traflens.http-load.v1", Mode: "server", Marker: c.Marker, Config: c, Scheduled: count,
		Completed: s.complete, Attempted: s.complete + s.writeErrors, Failed: s.writeErrors, Skipped: count - s.complete,
		ElapsedSeconds: time.Since(start).Seconds()}
	r.Pass = s.complete == count && s.rejected == 0 && s.duplicate == 0 && s.writeErrors == 0 && serveErr == nil
	if !r.Pass {
		r.Error = fmt.Sprintf("incomplete=%d rejected=%d duplicate=%d write_errors=%d", count-s.complete, s.rejected, s.duplicate, s.writeErrors)
	}
	return r
}

func save(path string, r report) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

func usageCPU() syscall.Rusage {
	var r syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return r
}
func seconds(t syscall.Timeval) float64 { return float64(t.Sec) + float64(t.Usec)/1e6 }

func main() {
	c := config{}
	flag.StringVar(&c.Mode, "mode", "client", "client or server")
	flag.BoolVar(&c.Execute, "execute", false, "explicitly run network workload")
	flag.StringVar(&c.Interface, "interface", "", "local scope interface")
	flag.StringVar(&c.Bind, "bind", "", "local link-local IPv6")
	flag.StringVar(&c.Peer, "peer", "", "peer link-local IPv6")
	flag.StringVar(&c.Marker, "marker", "", "fresh unique marker")
	flag.StringVar(&c.Output, "output", "", "new absolute private JSON file")
	flag.IntVar(&c.Port, "port", 18080, "unprivileged TCP port")
	flag.IntVar(&c.Rate, "rate", 100, "scheduled requests/sec")
	flag.IntVar(&c.Seconds, "seconds", 5, "offered-load seconds")
	flag.IntVar(&c.Concurrency, "concurrency", 16, "maximum in-flight requests/connections")
	flag.IntVar(&c.TimeoutMS, "timeout-ms", 1000, "per-request timeout milliseconds")
	flag.Parse()
	if !c.Execute {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"executes": false, "capture": false, "protocol": "HTTP/1.1", "connection": "one TCP connection per request", "schedule": "open loop; skips explicitly counted"})
		return
	}
	if err := c.validate(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	parent, err := os.Stat(filepath.Dir(c.Output))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		fmt.Fprintln(os.Stderr, "output parent must exist and be private")
		os.Exit(2)
	}
	if _, err := os.Lstat(c.Output); !os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "output must not exist")
		os.Exit(2)
	}
	before := usageCPU()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(c.Seconds)*time.Second+time.Duration(c.TimeoutMS)*time.Millisecond+10*time.Second)
	defer cancel()
	var r report
	if c.Mode == "client" {
		request, closeTransport := httpRequest(c)
		defer closeTransport()
		r = runClient(ctx, c, request)
	} else {
		listener, err := net.ListenTCP("tcp6", &net.TCPAddr{IP: net.ParseIP(c.Bind), Zone: c.Interface, Port: c.Port})
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"event": "ready", "marker": c.Marker})
		r = runServer(ctx, c, listener)
	}
	after := usageCPU()
	r.CPUUserSeconds = seconds(after.Utime) - seconds(before.Utime)
	r.CPUSystemSeconds = seconds(after.Stime) - seconds(before.Stime)
	r.MaxRSSKiB = after.Maxrss
	if err := save(c.Output, r); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(map[string]any{"pass": r.Pass, "mode": r.Mode, "scheduled": r.Scheduled, "completed": r.Completed, "failed": r.Failed, "skipped": r.Skipped})
	if !r.Pass {
		os.Exit(1)
	}
}
