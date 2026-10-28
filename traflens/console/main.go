package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

//go:embed index.html
var assets embed.FS

const fields = "toString(_id) AS id,time,request_resource,request_type,response_code,response_duration,l7_protocol,agent_id,protocol,type,signal_source,tap_side,response_status,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,server_port,observation_point,trace_id,span_id,parent_span_id"

var resourceFilter = regexp.MustCompile(`^[A-Za-z0-9/_:.?=&%+ -]{0,200}$`)

type console struct {
	query, controller string
	client            *http.Client
}
type result struct {
	Columns []string            `json:"columns"`
	Values  [][]json.RawMessage `json:"values"`
}
type envelope struct {
	Status      string          `json:"OPT_STATUS"`
	Description string          `json:"DESCRIPTION"`
	Result      *result         `json:"result"`
	Data        json.RawMessage `json:"DATA"`
}

func selection(v url.Values, now int64) (string, error) {
	for k, values := range v {
		if k != "from" && k != "to" && k != "q" && k != "limit" && k != "id" && k != "proto" && k != "source" && k != "trace" && !isRelationshipFilter(k) {
			return "", errors.New("unknown filter")
		}
		if len(values) != 1 {
			return "", errors.New("duplicate filter")
		}
	}
	from, to := now-86400, now
	var err error
	if v.Has("from") {
		from, err = strconv.ParseInt(v.Get("from"), 10, 64)
		if err != nil {
			return "", errors.New("invalid start time")
		}
	}
	if v.Has("to") {
		to, err = strconv.ParseInt(v.Get("to"), 10, 64)
		if err != nil {
			return "", errors.New("invalid end time")
		}
	}
	if from < 0 || to <= from || to-from > 31*86400 || to > now+300 {
		return "", errors.New("time range must be positive and at most 31 days")
	}
	where := fmt.Sprintf("time >= %d AND time <= %d", from, to)
	if id := v.Get("id"); id != "" {
		n, e := strconv.ParseUint(id, 10, 64)
		if e != nil || n == 0 {
			return "", errors.New("invalid request id")
		}
		where += fmt.Sprintf(" AND _id = %d", n)
	}
	if v.Get("proto") != "" {
		n, e := strconv.ParseUint(v.Get("proto"), 10, 16)
		if e != nil || n == 0 {
			return "", errors.New("invalid application protocol")
		}
		where += fmt.Sprintf(" AND l7_protocol = %d", n)
	}
	if v.Has("source") {
		if v.Get("source") != "0" && v.Get("source") != "3" {
			return "", errors.New("source must be packet (0) or eBPF (3)")
		}
		where += " AND signal_source = " + v.Get("source")
	}
	if v.Has("trace") {
		if !validTraceID(v.Get("trace")) {
			return "", errors.New("trace must be a nonzero lowercase32-hex W3C ID")
		}
		where += " AND trace_id = '" + v.Get("trace") + "'"
	}
	q := v.Get("q")
	if !resourceFilter.MatchString(q) {
		return "", errors.New("resource filter accepts up to 200 URL characters")
	}
	if q != "" {
		where += " AND request_resource LIKE '%" + q + "%'"
	}
	for _, key := range []string{"client_ip", "server_ip", "client_epc", "server_epc", "agent", "server_port", "transport", "point"} {
		if v.Has(key) {
			predicate, e := relationshipFilter(key, v.Get(key))
			if e != nil {
				return "", e
			}
			where += " AND " + predicate
		}
	}
	limit := 100
	if v.Has("limit") {
		limit, err = strconv.Atoi(v.Get("limit"))
		if err != nil || limit < 1 || limit > 500 {
			return "", errors.New("limit must be 1..500")
		}
	}
	if v.Get("id") != "" {
		limit = 1
	}
	return "SELECT " + fields + " FROM l7_flow_log WHERE " + where + fmt.Sprintf(" ORDER BY time DESC LIMIT %d", limit), nil
}
func (c *console) upstream(ctx context.Context, endpoint, method string, form url.Values, controller bool) (envelope, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return envelope{}, err
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if controller {
		req.Header.Set("X-Org-Id", "1")
		req.Header.Set("X-User-Id", "1")
		req.Header.Set("X-User-Type", "1")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return envelope{}, errors.New("backend unavailable")
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024+1))
	if err != nil || len(raw) > 4*1024*1024 {
		return envelope{}, errors.New("backend response too large or unreadable")
	}
	var d envelope
	if resp.StatusCode != 200 || json.Unmarshal(raw, &d) != nil || d.Status != "SUCCESS" {
		return envelope{}, errors.New("backend rejected the request")
	}
	return d, nil
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func (c *console) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/services", c.services)
	mux.HandleFunc("GET /api/trace", c.trace)
	mux.HandleFunc("GET /api/requests", func(w http.ResponseWriter, r *http.Request) {
		sql, err := selection(r.URL.Query(), time.Now().Unix())
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		d, err := c.upstream(r.Context(), c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {sql}}, false)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		// Empty successful queries can have a null result on the existing backend.
		if d.Result == nil {
			d.Result = &result{Columns: []string{}, Values: [][]json.RawMessage{}}
		}
		if d.Result.Values == nil {
			d.Result.Values = [][]json.RawMessage{}
		}
		writeJSON(w, 200, d.Result)
	})
	mux.HandleFunc("GET /api/overview", func(w http.ResponseWriter, r *http.Request) {
		v := r.URL.Query()
		if v.Has("id") || v.Has("limit") {
			writeJSON(w, 400, map[string]string{"error": "overview does not accept id or limit"})
			return
		}
		where, err := selectionWhere(v, time.Now().Unix())
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		results := make([]*result, 0, 2)
		for _, query := range []string{"SELECT Count(row) AS requests FROM l7_flow_log WHERE " + where, "SELECT l7_protocol, Count(row) AS requests FROM l7_flow_log WHERE " + where + " GROUP BY l7_protocol ORDER BY requests DESC LIMIT 32"} {
			d, e := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {query}}, false)
			if e != nil {
				writeJSON(w, 502, map[string]string{"error": e.Error()})
				return
			}
			if d.Result == nil {
				d.Result = &result{Columns: []string{}, Values: [][]json.RawMessage{}}
			}
			if d.Result.Values == nil {
				d.Result.Values = [][]json.RawMessage{}
			}
			results = append(results, d.Result)
		}
		writeJSON(w, 200, map[string]any{"total": results[0], "protocols": results[1]})
	})
	mux.HandleFunc("GET /api/agents", func(w http.ResponseWriter, r *http.Request) {
		d, err := c.upstream(r.Context(), c.controller+"/v1/vtaps/", "GET", nil, true)
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": err.Error()})
			return
		}
		var agents []struct {
			ID     int    `json:"ID"`
			Name   string `json:"NAME"`
			State  int    `json:"STATE"`
			Enable int    `json:"ENABLE"`
		}
		if err = json.Unmarshal(d.Data, &agents); err != nil {
			writeJSON(w, 502, map[string]string{"error": "invalid agent inventory"})
			return
		}
		if agents == nil {
			agents = make([]struct {
				ID     int    `json:"ID"`
				Name   string `json:"NAME"`
				State  int    `json:"STATE"`
				Enable int    `json:"ENABLE"`
			}, 0)
		}
		writeJSON(w, 200, agents)
	})
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := assets.ReadFile("index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}
func main() {
	listen := flag.String("listen", "127.0.0.1:20880", "loopback HTTP listen address")
	query := flag.String("query", "http://127.0.0.1:20416", "query API base")
	controller := flag.String("controller", "http://127.0.0.1:20417", "controller API base")
	flag.Parse()
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		log.Fatal("listen must use a numeric loopback address; use an SSH tunnel for remote access")
	}
	for _, s := range []string{*query, *controller} {
		u, e := url.Parse(s)
		if e != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
			log.Fatal("invalid backend base URL")
		}
	}
	c := console{strings.TrimRight(*query, "/"), strings.TrimRight(*controller, "/"), &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}}
	srv := http.Server{Addr: *listen, Handler: c.handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024}
	log.Printf("TrafLens console: http://%s", *listen)
	log.Fatal(srv.ListenAndServe())
}
