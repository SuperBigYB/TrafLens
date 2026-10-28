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

func TestTraceLookupRejectsInvalidAndScopeOverrides(t *testing.T) {
	trace := strings.Repeat("a", 32)
	for _, query := range []string{"", "trace=", "trace=" + strings.Repeat("0", 32),
		"trace=" + strings.Repeat("A", 32), "trace=" + trace[:31], "trace=a%27+OR+1=1",
		"trace=" + trace + "&trace=" + trace, "trace=" + trace + "&limit=1",
		"trace=" + trace + "&server_port=18080", "trace=" + trace + "&q=orders"} {
		values, _ := url.ParseQuery(query)
		if _, err := traceSelection(values, time.Now().Unix()); err == nil {
			t.Errorf("accepted invalid trace query: %s", query)
		}
	}
}

func TestTracePredicateSharedAcrossRoutes(t *testing.T) {
	trace := strings.Repeat("a", 32)
	var queries []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		queries = append(queries, r.Form.Get("sql"))
		fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":null}`)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	for _, route := range []string{"/api/requests", "/api/overview", "/api/services", "/api/trace"} {
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", route+"?trace="+trace+"&source=0", nil))
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", route, rr.Code, rr.Body.String())
		}
	}
	if len(queries) != 5 {
		t.Fatal("unexpected query count")
	}
	for _, sql := range queries {
		if !strings.Contains(sql, "trace_id = '"+trace+"'") || !strings.Contains(sql, "signal_source = 0") {
			t.Fatalf("exact trace/source predicate lost: %s", sql)
		}
	}
	if !strings.HasSuffix(queries[4], "ORDER BY time ASC,_id ASC LIMIT 501") {
		t.Fatal("unbounded/unstable trace lookup")
	}
}

func TestTraceTruncationAndExactRecordIdentity(t *testing.T) {
	rows := strings.TrimSuffix(strings.Repeat(`["18446744073709551615"],`, 501), ",")
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["id"],"values":[%s]}}`, rows)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/trace?trace="+strings.Repeat("a", 32), nil))
	var d struct {
		Records   result `json:"records"`
		Truncated bool   `json:"truncated"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &d) != nil || !d.Truncated || len(d.Records.Values) != 500 || string(d.Records.Values[0][0]) != `"18446744073709551615"` {
		t.Fatalf("trace identity/limit: %d %s", rr.Code, rr.Body.String())
	}
}

func TestTraceEmptyAndUnavailableStayDistinct(t *testing.T) {
	for _, body := range []string{`{"OPT_STATUS":"SUCCESS","result":null}`, `{"OPT_STATUS":"FAILED"}`} {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := console{b.URL, b.URL, b.Client()}
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/trace?trace="+strings.Repeat("a", 32), nil))
		want := 502
		if strings.Contains(body, `"result":null`) {
			want = 200
		}
		if rr.Code != want {
			t.Fatalf("trace empty/error: %d != %d", rr.Code, want)
		}
		b.Close()
	}
}
