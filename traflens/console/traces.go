package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

var w3cTraceID = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validTraceID(value string) bool {
	return w3cTraceID.MatchString(value) && value != strings.Repeat("0", 32)
}

func traceSelection(v url.Values, now int64) (string, error) {
	for key := range v {
		if key != "from" && key != "to" && key != "source" && key != "trace" {
			return "", errors.New("trace lookup accepts only from, to, source and trace")
		}
	}
	if !validTraceID(v.Get("trace")) {
		return "", errors.New("trace must be a nonzero lowercase32-hex W3C ID")
	}
	where, err := selectionWhere(v, now)
	if err != nil {
		return "", err
	}
	// 501 is a truncation sentinel. Ordering is only presentation, not a
	// claim that timestamps prove causal parent/child relationships.
	return "SELECT " + fields + " FROM l7_flow_log WHERE " + where + " ORDER BY time ASC,_id ASC LIMIT 501", nil
}

func (c *console) trace(w http.ResponseWriter, r *http.Request) {
	sql, err := traceSelection(r.URL.Query(), time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	d, err := c.upstream(r.Context(), c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {sql}}, false)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if d.Result == nil {
		d.Result = &result{Columns: []string{}}
	}
	if d.Result.Values == nil {
		d.Result.Values = [][]json.RawMessage{}
	}
	truncated := len(d.Result.Values) > 500
	if truncated {
		d.Result.Values = d.Result.Values[:500]
	}
	writeJSON(w, 200, map[string]any{"records": d.Result, "trace": r.URL.Query().Get("trace"),
		"truncated": truncated, "limit": 500, "counting": "observation_records"})
}
