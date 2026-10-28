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

func TestRelationshipFiltersRejectWideningAndInjection(t *testing.T) {
	now := time.Now().Unix()
	for _, query := range []string{
		"client_ip=hostname", "server_ip=127.0.0.1%27+OR+1=1", "client_ip=fe80::1%25eth0",
		"server_port=65536", "server_port=-1", "server_port=", "agent=65536", "transport=256",
		"client_epc=2147483648", "server_epc=-2147483649", "point=c%27", "point=a_b",
		"agent=1&agent=2", "client_ip=203.0.113.1&client_ip=203.0.113.2",
	} {
		v, _ := url.ParseQuery(query)
		if _, err := selection(v, now); err == nil {
			t.Errorf("accepted unsafe relationship filter: %s", query)
		}
	}
	for _, query := range []string{"id=1", "limit=1", "unknown=1"} {
		v, _ := url.ParseQuery(query)
		if _, err := serviceSelection(v, now); err == nil {
			t.Errorf("accepted aggregate override: %s", query)
		}
	}
	for _, v := range []url.Values{{"client_ip": {"::ffff:203.0.113.1"}}, {"point": {""}}, {"server_port": {"0"}}} {
		if _, err := selection(v, now); err != nil {
			t.Fatalf("valid explicit unknown/canonical address rejected: %v", err)
		}
	}
}

func TestRelationshipDrilldownSharesEveryPredicate(t *testing.T) {
	values := url.Values{"q": {"/orders"}, "source": {"3"}, "proto": {"20"}, "agent": {"7"},
		"client_ip": {"2001:db8::1"}, "server_ip": {"2001:db8::2"}, "server_port": {"18080"},
		"client_epc": {"-2"}, "server_epc": {"42"}, "transport": {"6"}, "point": {"s-p"}}
	var queries []string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		queries = append(queries, r.Form.Get("sql"))
		fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":null}`)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	for _, route := range []string{"/api/services", "/api/overview", "/api/requests"} {
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", route+"?"+values.Encode(), nil))
		if rr.Code != 200 {
			t.Fatalf("%s: %d %s", route, rr.Code, rr.Body.String())
		}
	}
	for _, sql := range queries {
		for _, predicate := range []string{"signal_source = 3", "l7_protocol = 20", "agent_id = 7",
			"ip_0 = '2001:db8::1'", "ip_1 = '2001:db8::2'", "server_port = 18080",
			"l3_epc_id_0 = -2", "l3_epc_id_1 = 42", "protocol = 6", "observation_point = 's-p'",
			"request_resource LIKE '%/orders%'"} {
			if !strings.Contains(sql, predicate) {
				t.Errorf("predicate %q missing from %s", predicate, sql)
			}
		}
	}
	if len(queries) != 4 || !strings.Contains(queries[0], "GROUP BY "+relationshipFields) || !strings.HasSuffix(queries[0], "LIMIT 101") {
		t.Fatalf("aggregate scope/limit: %v", queries)
	}
}

func TestRelationshipCountsPreserveUInt64AndExposeTruncation(t *testing.T) {
	rows := strings.TrimSuffix(strings.Repeat(`[18446744073709551615],`, 101), ",")
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["records"],"values":[%s]}}`, rows)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/services", nil))
	var d struct {
		Relations result `json:"relations"`
		Truncated bool   `json:"truncated"`
		Counting  string `json:"counting"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &d) != nil || !d.Truncated || len(d.Relations.Values) != 100 || d.Counting != "observation_records" {
		t.Fatalf("invalid bounded response: %d %s", rr.Code, rr.Body.String())
	}
	if string(d.Relations.Values[0][0]) != `"18446744073709551615"` {
		t.Fatal("UInt64 count lost precision")
	}
}

func TestServiceEmptyAndFailedResponsesStayDistinct(t *testing.T) {
	for _, body := range []string{`{"OPT_STATUS":"SUCCESS","result":null}`,
		`{"OPT_STATUS":"FAILED"}`, `{"OPT_STATUS":"SUCCESS","result":{"columns":["records"],"values":[[-1]]}}`} {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c := console{b.URL, b.URL, b.Client()}
		rr := httptest.NewRecorder()
		c.handler().ServeHTTP(rr, httptest.NewRequest("GET", "/api/services", nil))
		want := 502
		if strings.Contains(body, `"result":null`) {
			want = 200
		}
		if rr.Code != want {
			t.Fatalf("%d != %d: %s", rr.Code, want, rr.Body.String())
		}
		b.Close()
	}
}
