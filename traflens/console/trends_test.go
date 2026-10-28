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

func emptyTrendCounts() *result {
	return &result{Columns: []string{"bucket", "records", "client_errors", "server_errors"}}
}

func emptyTrendDurations() *result {
	return &result{Columns: []string{"bucket", "duration_samples", "avg_us", "max_us"}}
}

func TestTrendQueriesBoundAlignedBucketsAndShareSessionScope(t *testing.T) {
	values := url.Values{"from": {"59"}, "to": {"60"}, "step": {"60"}, "q": {"/orders"},
		"source": {"0"}, "agent": {"7"}, "server_port": {"18080"}, "point": {"c"},
		"trace": {strings.Repeat("a", 32)}, "error": {"any"}, "min_ms": {"100"}}
	plan, err := trendQueries(values, 1000)
	if err != nil || plan.From != 59 || plan.To != 60 || plan.Step != 60 || len(plan.Queries) != 2 || values.Has("session") {
		t.Fatalf("invalid partial-bucket plan or input mutation: %+v %v", plan, err)
	}
	for _, query := range plan.Queries {
		for _, predicate := range []string{"time(time,60) AS bucket", "time >= 59 AND time <= 60", "type = 2", "agent_id = 7", "server_port = 18080", "signal_source = 0", "request_resource LIKE '%/orders%'", "observation_point = 'c'", "trace_id = '" + strings.Repeat("a", 32) + "'", "response_status IN (3,4)", "response_duration >= 100000", "GROUP BY bucket ORDER BY bucket LIMIT 241"} {
			if !strings.Contains(query, predicate) {
				t.Fatalf("shared predicate missing: %s in %s", predicate, query)
			}
		}
	}
	if !strings.Contains(plan.Queries[1], " AND response_duration > 0 GROUP BY") {
		t.Fatal("latency query included non-positive samples")
	}
	plan, err = trendQueries(url.Values{"from": {"100"}, "to": {fmt.Sprint(100 + 31*86400)}}, 100+31*86400)
	if err != nil || plan.Step != 14400 || plan.To/plan.Step-plan.From/plan.Step+1 > 240 {
		t.Fatalf("31-day auto range not bounded: %+v %v", plan, err)
	}
	plan, err = trendQueries(url.Values{"from": {"60"}, "to": {"60"}}, 1000)
	if err != nil || plan.From != plan.To {
		t.Fatalf("single-second drilldown rejected: %+v %v", plan, err)
	}
}

func TestTrendsRejectUnsafeInputsAndExplicitOverfullRange(t *testing.T) {
	for _, query := range []string{"id=1", "limit=500", "unknown=1", "session=0", "session=1&session=1",
		"step=", "step=1", "step=21600", "step=86400", "step=60&step=300", "step=60%27+OR+1=1",
		"from=0&to=14400&step=60", "from=61&to=60", "from=0&to=2678401", "agent=7&agent=8"} {
		v, _ := url.ParseQuery(query)
		if _, err := trendQueries(v, 4000000); err == nil {
			t.Errorf("accepted %s", query)
		}
	}
	c := console{"", "", nil}
	rr := httptest.NewRecorder()
	c.trends(rr, httptest.NewRequest("GET", "/api/trends?step=%zz", nil))
	if rr.Code != 400 {
		t.Fatal("invalid encoding silently widened trend query")
	}
}

func TestTrendsPartialWindowsZeroFillAndUnmeasuredSamples(t *testing.T) {
	plan := trendPlan{From: 59, To: 120, Step: 60}
	a := redResult(`{"columns":["bucket","records","client_errors","server_errors"],"values":[[60,3,1,1]]}`)
	d, err := parseTrends(a, emptyTrendDurations(), plan)
	if err != nil || len(d.Buckets) != 3 || d.Atomic || d.StepSeconds != 60 || d.Counting != "session_observation_records" || d.DurationUnit != "us" {
		t.Fatalf("bounded empty fill: %+v %v", d, err)
	}
	for index, want := range []struct{ from, to, window int64 }{{59, 59, 1}, {60, 119, 60}, {120, 120, 1}} {
		b := d.Buckets[index]
		if b.From != want.from || b.To != want.to || b.WindowSeconds != want.window {
			t.Fatal("partial bucket window widened")
		}
	}
	if d.Buckets[0].Records != "0" || d.Buckets[0].ErrorRatio != nil || d.Buckets[0].AverageUS != nil || d.Buckets[0].MaximumUS != nil {
		t.Fatal("empty bucket invented zero latency/healthy error ratio")
	}
	b := d.Buckets[1]
	if b.Records != "3" || b.Errors != "2" || b.Unmeasured != "3" || b.DurationSamples != "0" || b.AverageUS != nil || b.MaximumUS != nil || b.RecordRate != .05 || *b.ErrorRatio != 2.0/3 {
		t.Fatal("missing positive-duration group not interpreted as zero positive samples")
	}
	d, err = parseTrends(emptyTrendCounts(), emptyTrendDurations(), trendPlan{From: 59, To: 60, Step: 60})
	if err != nil || len(d.Buckets) != 2 || d.Buckets[0].WindowSeconds != 1 || d.Buckets[1].WindowSeconds != 1 {
		t.Fatal("inclusive boundary seconds did not produce two one-second windows")
	}
}

func TestTrendsPreserveUInt64CountsAndMaximum(t *testing.T) {
	a := redResult(`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,18446744073709551615,18446744073709551614,1]]}`)
	b := redResult(`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,1,123.5,18446744073709551615]]}`)
	d, err := parseTrends(a, b, trendPlan{From: 0, To: 0, Step: 60})
	if err != nil || len(d.Buckets) != 1 || d.Buckets[0].Records != "18446744073709551615" || d.Buckets[0].Errors != "18446744073709551615" || *d.Buckets[0].MaximumUS != "18446744073709551615" || d.Buckets[0].Unmeasured != "18446744073709551614" || *d.Buckets[0].AverageUS != 123.5 {
		t.Fatalf("precision lost: %+v %v", d, err)
	}
}

func TestTrendsRejectMalformedBucketsColumnsAndContradictorySnapshots(t *testing.T) {
	plan := trendPlan{From: 0, To: 119, Step: 60}
	a := redResult(`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,1,0,0]]}`)
	for _, missing := range []*result{nil, {}, {Columns: []string{}}} {
		if _, err := parseTrends(missing, emptyTrendDurations(), plan); err == nil {
			t.Fatal("missing summary result/schema accepted as successful empty counts")
		}
		if _, err := parseTrends(a, missing, plan); err == nil {
			t.Fatal("missing duration result/schema accepted as successful empty samples")
		}
	}
	for _, text := range []string{
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[null,1,0,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[["0",1,0,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[-60,1,0,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[1,1,0,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[120,1,0,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,1,0,0],[0,1,0,0]]}`,
		`{"columns":["bucket","records","client_errors"],"values":[[0,1,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors","records"],"values":[[0,1,0,0,1]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,1,0]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,1,1,1]]}`,
		`{"columns":["bucket","records","client_errors","server_errors"],"values":[[0,-1,0,0]]}`,
	} {
		if _, err := parseTrends(redResult(text), emptyTrendDurations(), plan); err == nil {
			t.Fatalf("accepted malformed summary: %s", text)
		}
	}
	for _, text := range []string{
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,2,100,200]]}`,
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[60,1,100,200]]}`,
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,0,0,0]]}`,
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,1,null,200]]}`,
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,1,100,0]]}`,
		`{"columns":["bucket","duration_samples","avg_us","max_us"],"values":[[0,1,300,200]]}`,
		`{"columns":["bucket","duration_samples","avg_us"],"values":[]}`,
	} {
		if _, err := parseTrends(a, redResult(text), plan); err == nil {
			t.Fatalf("accepted contradictory duration: %s", text)
		}
	}
	tooMany := &result{Columns: []string{"bucket", "records", "client_errors", "server_errors"}, Values: make([][]json.RawMessage, 241)}
	if _, err := parseTrends(tooMany, emptyTrendDurations(), plan); err == nil {
		t.Fatal("truncation sentinel published as complete trend")
	}
}

func TestTrendsDoNotPublishPartiallySuccessfulQueries(t *testing.T) {
	for _, fail := range []bool{false, true} {
		queries := []string{}
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.ParseForm()
			queries = append(queries, r.Form.Get("sql"))
			if r.Method != "POST" || r.Form.Get("db") != "flow_log" || !strings.Contains(r.Form.Get("sql"), "agent_id = 7") {
				t.Error("fixed query or resource scope lost")
			}
			if fail && len(queries) == 2 {
				fmt.Fprint(w, `{"OPT_STATUS":"FAILED"}`)
			} else if strings.Contains(r.Form.Get("sql"), "duration_samples") {
				fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["bucket","duration_samples","avg_us","max_us"],"values":null}}`)
			} else {
				fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["bucket","records","client_errors","server_errors"],"values":null}}`)
			}
		}))
		c := console{backend.URL, backend.URL, backend.Client()}
		rr := httptest.NewRecorder()
		c.trends(rr, httptest.NewRequest("GET", "/api/trends?from=59&to=60&agent=7", nil))
		if len(queries) != 2 || fail && (rr.Code != 502 || strings.Contains(rr.Body.String(), `"buckets"`)) || !fail && rr.Code != 200 {
			t.Fatalf("query failure/empty confused: %d %s", rr.Code, rr.Body.String())
		}
		backend.Close()
	}
	// An unavailable backend cannot become a successful zero-record series.
	c := console{"http://127.0.0.1:1", "", &http.Client{Timeout: time.Second}}
	rr := httptest.NewRecorder()
	c.trends(rr, httptest.NewRequest("GET", "/api/trends?from=59&to=60", nil))
	if rr.Code != 502 {
		t.Fatal("failed backend turned into empty successful trend")
	}
}

func TestTrendsMissingResultNeverBecomesSuccessfulZeroFill(t *testing.T) {
	for _, body := range []string{`{"OPT_STATUS":"SUCCESS"}`, `{"OPT_STATUS":"SUCCESS","result":null}`,
		`{"OPT_STATUS":"SUCCESS","result":{"columns":[],"values":null}}`} {
		backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := console{backend.URL, backend.URL, backend.Client()}
		rr := httptest.NewRecorder()
		c.trends(rr, httptest.NewRequest("GET", "/api/trends?from=59&to=60", nil))
		if rr.Code != 502 || strings.Contains(rr.Body.String(), `"buckets"`) {
			t.Fatalf("missing result became a successful zero-filled series: %d %s", rr.Code, rr.Body.String())
		}
		backend.Close()
	}
}
