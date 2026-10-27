package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validConfig() config {
	return config{Mode: "client", Interface: "ethA", Bind: "fe80::1", Peer: "fe80::2", Marker: "synthetic-unit", Port: 18080, Rate: 10, Seconds: 1, Concurrency: 2, TimeoutMS: 1000, Output: "/private/new.json"}
}

func TestInputBounds(t *testing.T) {
	good := validConfig()
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*config){
		"global": func(c *config) { c.Peer = "2001:db8::1" }, "zone": func(c *config) { c.Bind = "fe80::1%ethA" },
		"same host": func(c *config) { c.Peer = c.Bind }, "interface": func(c *config) { c.Interface = "../ethA" },
		"mode": func(c *config) { c.Mode = "other" }, "port": func(c *config) { c.Port = 80 },
		"rate": func(c *config) { c.Rate = 10001 }, "duration": func(c *config) { c.Seconds = 31 },
		"total": func(c *config) { c.Rate = 10000; c.Seconds = 30 }, "concurrency": func(c *config) { c.Concurrency = 129 },
		"deadline": func(c *config) { c.TimeoutMS = 0 }, "output": func(c *config) { c.Output = "relative" },
		"marker": func(c *config) { c.Marker = "x/y" },
	} {
		t.Run(name, func(t *testing.T) {
			c := good
			change(&c)
			if c.validate() == nil {
				t.Fatal("invalid contract accepted")
			}
		})
	}
}

func TestClientDoesNotBurstOrHideOverload(t *testing.T) {
	c := validConfig()
	c.Rate = 20
	c.Concurrency = 1
	var active, peak atomic.Int32
	r := runClient(context.Background(), c, func(ctx context.Context, seq int) error {
		n := active.Add(1)
		defer active.Add(-1)
		for old := peak.Load(); n > old && !peak.CompareAndSwap(old, n); old = peak.Load() {
		}
		select {
		case <-time.After(140 * time.Millisecond):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})
	if r.Pass || r.Scheduled != 20 || r.Completed == 0 || r.Skipped == 0 || r.Attempted+r.Skipped != 20 || peak.Load() > 1 {
		t.Fatalf("overload hidden or unbounded: %+v peak=%d", r, peak.Load())
	}
	for _, row := range r.Records {
		if row.State == "completed" && row.StartedNS < row.ScheduledNS {
			t.Fatal("request sent before scheduled time")
		}
	}
}

func TestPrecancelledWorkloadNeverInvokesRequest(t *testing.T) {
	c := validConfig()
	c.Rate = 10000
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i := 0; i < 20; i++ {
		r := runClient(ctx, c, func(context.Context, int) error {
			t.Error("pre-cancelled workload invoked request")
			return nil
		})
		if r.Pass || r.Attempted != 0 || r.Skipped != r.Scheduled || r.Error == "" {
			t.Fatalf("pass=%t scheduled=%d attempted=%d skipped=%d error=%q", r.Pass, r.Scheduled, r.Attempted, r.Skipped, r.Error)
		}
	}
}

func TestDeadlineAndFailuresCannotPass(t *testing.T) {
	c := validConfig()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := runClient(ctx, c, func(context.Context, int) error { t.Fatal("cancelled workload emitted request"); return nil })
	if r.Pass || r.Attempted != 0 || r.Skipped != r.Scheduled {
		t.Fatal(r)
	}
	r = runClient(context.Background(), c, func(context.Context, int) error { return context.DeadlineExceeded })
	if r.Pass || r.Failed == 0 || r.Completed != 0 {
		t.Fatal(r)
	}
}

func TestLatencyIncludesScheduleDelayAndPercentileIsNearestRank(t *testing.T) {
	r := report{Scheduled: 3, Records: []record{{State: "completed", ServiceNS: 10, OfferedNS: 100}, {State: "completed", ServiceNS: 20, OfferedNS: 200}, {State: "completed", ServiceNS: 30, OfferedNS: 300}}}
	summarize(&r)
	if !r.Pass || r.ServiceP50NS != 20 || r.ServiceP99NS != 30 || r.OfferedP99NS != 300 {
		t.Fatal(r)
	}
}

func TestStrictResponseRejectsRedirectWrongBodyAndExcessData(t *testing.T) {
	for _, bad := range []string{"status", "body", "length", "protocol", "content-type"} {
		t.Run(bad, func(t *testing.T) {
			body := string(expectedBody("unit", 1))
			r := &http.Response{StatusCode: 200, ProtoMajor: 1, ProtoMinor: 1, ContentLength: int64(len(body)), Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
			switch bad {
			case "status":
				r.StatusCode = 302
			case "body":
				r.Body = io.NopCloser(strings.NewReader(strings.Replace(body, "unit", "evil", 1)))
			case "length":
				r.ContentLength++
			case "protocol":
				r.ProtoMinor = 0
			case "content-type":
				r.Header.Set("Content-Type", "text/plain")
			}
			if responseValid(r, "unit", 1) == nil {
				t.Fatal("malformed response passed")
			}
		})
	}
}

func TestHandlerRejectsInvalidSequenceAndDuplicates(t *testing.T) {
	c := validConfig()
	s := &serverState{c: c, seen: make([]bool, 2), done: make(chan struct{})}
	for _, path := range []string{resource(c.Marker, 0) + "?x=1", "/other/0", resource(c.Marker, 0) + "0", resource(c.Marker, 2)} {
		r := httptest.NewRequest("GET", "http://traflens-load.invalid"+path, nil)
		r.ContentLength = 0
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != 400 {
			t.Fatal(path, w.Code)
		}
	}
	for n := 0; n < 2; n++ {
		r := httptest.NewRequest("GET", "http://traflens-load.invalid"+resource(c.Marker, 0), nil)
		r.ContentLength = 0
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if (n == 0 && w.Code != 200) || (n == 1 && w.Code != 409) {
			t.Fatal(w.Code)
		}
	}
	if s.complete != 1 || s.duplicate != 1 || s.rejected != 4 {
		t.Fatal(s)
	}
}

func TestFiniteServerWithoutClientFailsAndClosesListener(t *testing.T) {
	c := validConfig()
	c.Mode = "server"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	r := runServer(ctx, c, l)
	if r.Pass || r.Completed != 0 {
		t.Fatal(r)
	}
	conn, err := net.DialTimeout("tcp", l.Addr().String(), 50*time.Millisecond)
	if err == nil {
		conn.Close()
		t.Fatal("listener leaked")
	}
}

func TestReportNeverOverwritesExistingEvidence(t *testing.T) {
	p := filepath.Join(t.TempDir(), "result.json")
	if err := save(p, report{Scheduled: 1}); err != nil {
		t.Fatal(err)
	}
	if save(p, report{Scheduled: 2}) == nil {
		t.Fatal("evidence overwritten")
	}
}
