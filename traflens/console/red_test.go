package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func redResult(text string) *result {
	var value result
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		panic(err)
	}
	return &value
}

func TestREDWindowSessionAndPositiveDurationContract(t *testing.T) {
	v := url.Values{"from": {"100"}, "to": {"110"}, "source": {"3"}, "server_port": {"18080"}}
	queries, seconds, err := redQueries(v, 1000)
	if err != nil || seconds != 11 || len(queries) != 2 || v.Has("session") {
		t.Fatalf("window/input mutation: %v %d %v", queries, seconds, err)
	}
	for _, query := range queries {
		if !strings.Contains(query, "type = 2") || !strings.Contains(query, "server_port = 18080") || !strings.Contains(query, "signal_source = 3") {
			t.Fatal("RED scope differs from drill-down")
		}
	}
	if !strings.HasSuffix(queries[1], " AND response_duration > 0") {
		t.Fatal("zero/missing durations included in latency mean")
	}
	for _, text := range []string{"id=1", "limit=1", "session=0", "session=1&session=1", "error=all", "error=", "min_ms=0", "min_ms=600001", "min_ms=1.5", "min_ms=1+OR+1=1"} {
		values, _ := url.ParseQuery(text)
		if _, _, err := redQueries(values, time.Now().Unix()); err == nil {
			t.Errorf("unsafe RED filter accepted: %s", text)
		}
	}
}

func TestREDPositiveSamplesEmptyNullsAndExactCounts(t *testing.T) {
	a := redResult(`{"columns":["records","client_errors","server_errors"],"values":[[3,1,1]]}`)
	b := redResult(`{"columns":["duration_samples","avg_us","max_us"],"values":[[2,150,200]]}`)
	stats, err := parseRED(a, b, 11)
	if err != nil || stats.Records != "3" || stats.Errors != "2" || stats.Unmeasured != "1" || *stats.AverageUS != 150 || *stats.MaximumUS != "200" || stats.DurationSamples != "2" {
		t.Fatalf("mean/sample semantics: %+v %v", stats, err)
	}
	stats, err = parseRED(nil, nil, 11)
	if err != nil || stats.Records != "0" || stats.ErrorRatio != nil || stats.AverageUS != nil || stats.MaximumUS != nil {
		t.Fatal("empty metrics invented zero latency/error ratio")
	}
	a = redResult(`{"columns":["records","client_errors","server_errors"],"values":[[18446744073709551615,18446744073709551614,1]]}`)
	stats, err = parseRED(a, redResult(`{"columns":["duration_samples","avg_us","max_us"],"values":[[0,0,0]]}`), 1)
	if err != nil || stats.Errors != "18446744073709551615" || stats.Records != stats.Errors || stats.AverageUS != nil {
		t.Fatalf("UInt64 counter precision lost: %+v %v", stats, err)
	}
}

func TestREDRejectsInconsistentSnapshotsAndMalformedMetrics(t *testing.T) {
	a := redResult(`{"columns":["records","client_errors","server_errors"],"values":[[1,0,0]]}`)
	if _, err := parseRED(a, nil, 1); err == nil {
		t.Fatal("missing second aggregate accepted")
	}
	for _, text := range []string{
		`{"columns":["duration_samples","avg_us","max_us"],"values":[[2,100,200]]}`,
		`{"columns":["duration_samples","avg_us","max_us"],"values":[[1,null,200]]}`,
		`{"columns":["duration_samples","avg_us","max_us"],"values":[[1,-1,200]]}`,
		`{"columns":["duration_samples","avg_us","max_us"],"values":[[1,100,0]]}`,
	} {
		if _, err := parseRED(a, redResult(text), 1); err == nil {
			t.Fatal("inconsistent/malformed duration accepted")
		}
	}
	for _, text := range []string{
		`{"columns":["records","client_errors","server_errors"],"values":[[1,1,1]]}`,
		`{"columns":["records","client_errors","server_errors"],"values":[[-1,0,0]]}`,
	} {
		if _, err := parseRED(redResult(text), nil, 1); err == nil {
			t.Fatal("invalid counter accepted")
		}
	}
}

func TestREDErrorSlowAndTracePredicatesSharedAcrossViews(t *testing.T) {
	var queries []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		queries = append(queries, r.Form.Get("sql"))
		fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":null}`)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	for _, route := range []string{"/api/requests", "/api/overview", "/api/services", "/api/red"} {
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", route+"?error=any&min_ms=100&trace="+strings.Repeat("a", 32), nil))
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", route, rr.Code, rr.Body.String())
		}
	}
	if len(queries) != 6 {
		t.Fatal("unexpected RED request count")
	}
	for _, query := range queries {
		for _, predicate := range []string{"type = 2", "response_status IN (3,4)", "response_duration >= 100000", "trace_id = '" + strings.Repeat("a", 32) + "'"} {
			if !strings.Contains(query, predicate) {
				t.Fatalf("predicate lost: %s", query)
			}
		}
	}
}

func TestREDDoesNotPublishPartialSuccessfulQuery(t *testing.T) {
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		if strings.Contains(r.Form.Get("sql"), "duration_samples") {
			fmt.Fprint(w, `{"OPT_STATUS":"FAILED"}`)
		} else {
			fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["records","client_errors","server_errors"],"values":[[3,0,0]]}}`)
		}
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/red", nil))
	if rr.Code != 502 || strings.Contains(rr.Body.String(), `"records"`) {
		t.Fatal("failed second query became a healthy partial metric response")
	}
}
