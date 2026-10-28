package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSelection(t *testing.T) {
	now := time.Now().Unix()
	for _, q := range []string{"q=%27+OR+1%3D1", "limit=501", "from=-1", "id=18446744073709551616", "id=1&id=2", "sql=SELECT+1", "from=1&to=4000000"} {
		v, _ := url.ParseQuery(q)
		if _, e := selection(v, now); e == nil {
			t.Errorf("accepted %s", q)
		}
	}
	v := url.Values{"id": {"18446744073709551615"}}
	s, e := selection(v, now)
	if e != nil || !strings.Contains(s, "_id = 18446744073709551615") || !strings.HasSuffix(s, "LIMIT 1") {
		t.Fatalf("detail query: %s %v", s, e)
	}
}
func TestRealAPIAdapter(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/query/" {
			r.ParseForm()
			if r.Method != "POST" || r.Form.Get("db") != "flow_log" || !strings.Contains(r.Form.Get("sql"), "FROM l7_flow_log") {
				t.Error("invalid query request")
			}
			w.Write([]byte(`{"OPT_STATUS":"SUCCESS","result":{"columns":["id"],"values":[["18446744073709551615"]]}}`))
			return
		}
		if r.Header.Get("X-Org-Id") != "1" {
			t.Error("missing controller organization")
		}
		w.Write([]byte(`{"OPT_STATUS":"SUCCESS","DATA":[{"ID":1,"NAME":"demo","STATE":1,"ENABLE":1,"CTRL_MAC":"private"}]}`))
	}))
	defer backend.Close()
	c := console{backend.URL, backend.URL, backend.Client()}
	for _, path := range []string{"/api/requests", "/api/agents", "/"} {
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 || strings.Contains(rr.Body.String(), "private") {
			t.Fatalf("%s: %d %s", path, rr.Code, rr.Body.String())
		}
		if path == "/api/requests" && !strings.Contains(rr.Body.String(), `"18446744073709551615"`) {
			t.Error("request id precision lost")
		}
	}
}
func TestEmptyAndFailedBackends(t *testing.T) {
	for _, body := range []string{`{"OPT_STATUS":"SUCCESS","result":null}`, `{"OPT_STATUS":"FAILED"}`, `{"OPT_STATUS":"SUCCESS"}trailing`} {
		t.Run(body, func(t *testing.T) {
			b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(body)) }))
			defer b.Close()
			c := console{b.URL, b.URL, b.Client()}
			rr := httptest.NewRecorder()
			c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/requests", nil))
			want := 502
			if strings.Contains(body, `"result":null`) {
				want = 200
			}
			if rr.Code != want {
				t.Fatalf("got %d, want %d", rr.Code, want)
			}
		})
	}
}
func TestCanceledBackendRequest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := console{"", "", &http.Client{Timeout: time.Second}}
	if _, e := c.upstream(ctx, "http://127.0.0.1:1", "GET", nil, false); e == nil {
		t.Fatal("canceled query accepted")
	}
}

func TestOverviewUsesSameFilterAndExactTotal(t *testing.T) {
	var queries []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		q := r.Form.Get("sql")
		queries = append(queries, q)
		if !strings.Contains(q, "l7_protocol = 20") || !strings.Contains(q, "request_resource LIKE '%/orders%'") {
			t.Error("overview lost filters")
		}
		if strings.Contains(q, "GROUP BY") {
			w.Write([]byte(`{"OPT_STATUS":"SUCCESS","result":{"columns":["l7_protocol","requests"],"values":[[20,2000]]}}`))
		} else {
			w.Write([]byte(`{"OPT_STATUS":"SUCCESS","result":{"columns":["requests"],"values":[[2000]]}}`))
		}
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/overview?q=%2Forders&proto=20", nil))
	if rr.Code != 200 || len(queries) != 2 || !strings.Contains(rr.Body.String(), "2000") {
		t.Fatalf("overview: %d %s", rr.Code, rr.Body.String())
	}
	for _, query := range []string{"id=1", "limit=10", "proto=invalid", "proto=0"} {
		rr = httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/overview?"+query, nil))
		if rr.Code != 400 {
			t.Error("accepted invalid overview filter")
		}
	}
}
