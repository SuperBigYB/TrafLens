package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const spanRowLimit = 256
const spanSignalSource = 4

var explicitSpanID = regexp.MustCompile(`^[0-9a-f]{16}$`)
var errSpanRows = errors.New("Span slice exceeds 256 observations; narrow the time or Agent scope")

var spanColumns = []string{"id", "trace_id", "span_id", "parent_span_id", "app_service", "app_instance", "span_kind", "endpoint", "start_us", "end_us", "response_duration", "agent_id", "signal_source", "type"}

type spanScope struct {
	Trace string
	From  int64
	To    int64
	Agent *uint16
}

type spanObservation struct {
	ID             string   `json:"id"`
	SpanID         string   `json:"span_id"`
	ParentSpanID   string   `json:"parent_span_id"`
	AppService     string   `json:"app_service"`
	AppInstance    string   `json:"app_instance"`
	SpanKind       uint8    `json:"span_kind"`
	Endpoint       string   `json:"endpoint"`
	StartUS        string   `json:"start_us"`
	EndUS          string   `json:"end_us"`
	DurationUS     string   `json:"duration_us"`
	AgentID        uint16   `json:"agent_id"`
	States         []string `json:"states"`
	ParentRecordID *string  `json:"parent_record_id"`
}

type spanEdge struct {
	ParentRecordID string `json:"parent_record_id"`
	ChildRecordID  string `json:"child_record_id"`
}

type spanDiagnostics struct {
	DuplicateSpanIDs       []string `json:"duplicate_span_ids"`
	ConflictingSpanIDs     []string `json:"conflicting_span_ids"`
	MissingParentRecords   []string `json:"missing_parent_records"`
	AmbiguousParentRecords []string `json:"ambiguous_parent_records"`
	CycleRecords           []string `json:"cycle_records"`
	InvalidSpanRecords     []string `json:"invalid_span_records"`
}

type spanResponse struct {
	Trace        string            `json:"trace"`
	From         int64             `json:"from"`
	To           int64             `json:"to"`
	AgentID      *uint16           `json:"agent_id,omitempty"`
	SignalSource int               `json:"signal_source"`
	TimeUnit     string            `json:"time_unit"`
	Limit        int               `json:"limit"`
	Records      string            `json:"records"`
	Nodes        []spanObservation `json:"nodes"`
	Edges        []spanEdge        `json:"edges"`
	Diagnostics  spanDiagnostics   `json:"diagnostics"`
	Scope        map[string]int    `json:"scope"`
	Association  string            `json:"association"`
}

func spanSelection(raw string, now int64) (spanScope, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return spanScope{}, errors.New("invalid Span scope encoding")
	}
	for key, values := range v {
		if len(values) != 1 || key != "from" && key != "to" && key != "trace" && key != "agent" {
			return spanScope{}, errors.New("Span scope accepts trace, from, to and agent once")
		}
	}
	s := spanScope{Trace: v.Get("trace"), From: now - 86400, To: now}
	if !validTraceID(s.Trace) {
		return spanScope{}, errors.New("trace must be a nonzero lowercase32-hex W3C ID")
	}
	if v.Has("from") {
		s.From, err = strconv.ParseInt(v.Get("from"), 10, 64)
		if err != nil {
			return spanScope{}, errors.New("invalid Span start time")
		}
	}
	if v.Has("to") {
		s.To, err = strconv.ParseInt(v.Get("to"), 10, 64)
		if err != nil {
			return spanScope{}, errors.New("invalid Span end time")
		}
	}
	if s.From < 1 || s.To < s.From || s.To-s.From > 31*86400 || s.To > now+300 {
		return spanScope{}, errors.New("Span time range must be positive, inclusive and at most 31 days")
	}
	if v.Has("agent") {
		n, e := strconv.ParseUint(v.Get("agent"), 10, 16)
		if e != nil || n == 0 {
			return spanScope{}, errors.New("Span Agent ID must be 1..65535")
		}
		id := uint16(n)
		s.Agent = &id
	}
	return s, nil
}

func spanQuery(scope spanScope) string {
	where := fmt.Sprintf("time >= %d AND time <= %d AND trace_id = '%s' AND signal_source = 4 AND type = 2", scope.From, scope.To, scope.Trace)
	if scope.Agent != nil {
		where += fmt.Sprintf(" AND agent_id = %d", *scope.Agent)
	}
	return "SELECT toString(_id) AS id,trace_id,span_id,parent_span_id,app_service,app_instance,span_kind,endpoint,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,response_duration,agent_id,signal_source,type FROM l7_flow_log WHERE " + where + " ORDER BY time ASC,_id ASC LIMIT 257"
}

func spanText(raw json.RawMessage) (string, error) {
	var value *string
	if json.Unmarshal(raw, &value) != nil || value == nil || !utf8.ValidString(*value) || len(*value) > 4096 {
		return "", errors.New("invalid Span text field")
	}
	return *value, nil
}

func validExplicitSpanID(id string) bool {
	return explicitSpanID.MatchString(id) && id != strings.Repeat("0", 16)
}

func normalizeSpans(value *result, scope spanScope) (spanResponse, error) {
	out := spanResponse{Trace: scope.Trace, From: scope.From, To: scope.To, AgentID: scope.Agent,
		SignalSource: spanSignalSource, TimeUnit: "microseconds", Limit: spanRowLimit,
		Nodes: []spanObservation{}, Edges: []spanEdge{}, Scope: map[string]int{"org_id": 1, "user_id": 1},
		Association: "Explicit stored OTel parent Span IDs within this bounded time/Agent slice; observations are not deduplicated transactions and absent parents do not prove a complete trace.",
		Diagnostics: spanDiagnostics{[]string{}, []string{}, []string{}, []string{}, []string{}, []string{}}}
	if value == nil {
		return out, errors.New("missing Span result")
	}
	if len(value.Values) > spanRowLimit {
		return out, errSpanRows
	}
	columns := make(map[string]int)
	for i, key := range value.Columns {
		if _, exists := columns[key]; exists {
			return out, errors.New("duplicate Span column")
		}
		columns[key] = i
	}
	for _, key := range spanColumns {
		if _, ok := columns[key]; !ok {
			return out, errors.New("missing Span column")
		}
	}
	seenRecords := make(map[string]bool)
	for _, values := range value.Values {
		if len(values) != len(value.Columns) {
			return out, errors.New("invalid Span row width")
		}
		row := make(map[string]json.RawMessage, len(columns))
		for key, i := range columns {
			row[key] = values[i]
		}
		text := make(map[string]string)
		for _, key := range []string{"trace_id", "span_id", "parent_span_id", "app_service", "app_instance", "endpoint"} {
			v, err := spanText(row[key])
			if err != nil {
				return out, err
			}
			text[key] = v
		}
		numbers := make(map[string]uint64)
		for _, key := range []string{"id", "start_us", "end_us", "response_duration", "agent_id", "signal_source", "type", "span_kind"} {
			n, err := countMetric(row, key)
			if err != nil {
				return out, errors.New("invalid Span numeric field")
			}
			numbers[key] = n
		}
		id := strconv.FormatUint(numbers["id"], 10)
		start, end := numbers["start_us"], numbers["end_us"]
		if numbers["id"] == 0 || seenRecords[id] || text["trace_id"] != scope.Trace || numbers["signal_source"] != spanSignalSource || numbers["type"] != 2 ||
			numbers["agent_id"] > 65535 || scope.Agent != nil && numbers["agent_id"] != uint64(*scope.Agent) || numbers["span_kind"] > 5 ||
			start == 0 || end < start || end/1000000 < uint64(scope.From) || end/1000000 > uint64(scope.To) || numbers["response_duration"] != end-start {
			return out, errors.New("Span metadata, timestamp or identity contradicts the fixed scope")
		}
		seenRecords[id] = true
		out.Nodes = append(out.Nodes, spanObservation{ID: id, SpanID: text["span_id"], ParentSpanID: text["parent_span_id"], AppService: text["app_service"], AppInstance: text["app_instance"],
			SpanKind: uint8(numbers["span_kind"]), Endpoint: text["endpoint"], StartUS: strconv.FormatUint(start, 10), EndUS: strconv.FormatUint(end, 10),
			DurationUS: strconv.FormatUint(numbers["response_duration"], 10), AgentID: uint16(numbers["agent_id"]), States: []string{}})
	}
	out.Records = strconv.Itoa(len(out.Nodes))
	buildSpanEdges(&out)
	return out, nil
}

func sameStoredSpan(a, b spanObservation) bool {
	return a.ParentSpanID == b.ParentSpanID && a.StartUS == b.StartUS && a.EndUS == b.EndUS && a.AppService == b.AppService && a.AppInstance == b.AppInstance && a.SpanKind == b.SpanKind && a.Endpoint == b.Endpoint
}

func buildSpanEdges(out *spanResponse) {
	indices := make(map[string][]int)
	for i := range out.Nodes {
		n := &out.Nodes[i]
		if !validExplicitSpanID(n.SpanID) {
			n.States = append(n.States, "invalid_span_id")
			out.Diagnostics.InvalidSpanRecords = append(out.Diagnostics.InvalidSpanRecords, n.ID)
			continue
		}
		indices[n.SpanID] = append(indices[n.SpanID], i)
	}
	for id, group := range indices {
		if len(group) < 2 {
			continue
		}
		out.Diagnostics.DuplicateSpanIDs = append(out.Diagnostics.DuplicateSpanIDs, id)
		conflict := false
		for _, i := range group[1:] {
			conflict = conflict || !sameStoredSpan(out.Nodes[group[0]], out.Nodes[i])
		}
		if conflict {
			out.Diagnostics.ConflictingSpanIDs = append(out.Diagnostics.ConflictingSpanIDs, id)
		}
		for _, i := range group {
			out.Nodes[i].States = append(out.Nodes[i].States, "duplicate_span_id")
			if conflict {
				out.Nodes[i].States = append(out.Nodes[i].States, "conflicting_span_id")
			}
		}
	}
	parents := make([]int, len(out.Nodes))
	for i := range parents {
		parents[i] = -1
		n := &out.Nodes[i]
		if !validExplicitSpanID(n.SpanID) {
			continue
		}
		switch {
		case n.ParentSpanID == "":
			n.States = append(n.States, "root")
		case !validExplicitSpanID(n.ParentSpanID):
			n.States = append(n.States, "invalid_parent_span_id")
			out.Diagnostics.InvalidSpanRecords = append(out.Diagnostics.InvalidSpanRecords, n.ID)
		case len(indices[n.ParentSpanID]) == 0:
			n.States = append(n.States, "missing_parent")
			out.Diagnostics.MissingParentRecords = append(out.Diagnostics.MissingParentRecords, n.ID)
		case len(indices[n.ParentSpanID]) > 1:
			n.States = append(n.States, "ambiguous_parent")
			out.Diagnostics.AmbiguousParentRecords = append(out.Diagnostics.AmbiguousParentRecords, n.ID)
		default:
			parents[i] = indices[n.ParentSpanID][0]
		}
	}
	// Candidate edges come only from explicit IDs. Suppress the edges in a cycle;
	// sorting by start time is never used to infer a parent.
	colors := make([]uint8, len(parents))
	cycle := make([]bool, len(parents))
	var visit func(int)
	visit = func(i int) {
		colors[i] = 1
		p := parents[i]
		if p >= 0 {
			if colors[p] == 0 {
				visit(p)
			} else if colors[p] == 1 {
				for j := p; ; j = parents[j] {
					cycle[j] = true
					if parents[j] == p {
						break
					}
				}
			}
		}
		colors[i] = 2
	}
	for i := range parents {
		if colors[i] == 0 {
			visit(i)
		}
	}
	for i, p := range parents {
		if cycle[i] {
			out.Nodes[i].States = append(out.Nodes[i].States, "cycle")
			out.Diagnostics.CycleRecords = append(out.Diagnostics.CycleRecords, out.Nodes[i].ID)
		} else if p >= 0 {
			id := out.Nodes[p].ID
			out.Nodes[i].ParentRecordID = &id
			out.Nodes[i].States = append(out.Nodes[i].States, "linked")
			out.Edges = append(out.Edges, spanEdge{id, out.Nodes[i].ID})
		}
	}
	sort.Strings(out.Diagnostics.DuplicateSpanIDs)
	sort.Strings(out.Diagnostics.ConflictingSpanIDs)
}

func (c *console) spans(w http.ResponseWriter, r *http.Request) {
	scope, err := spanSelection(r.URL.RawQuery, time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	d, err := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {spanQuery(scope)}}, true)
	if err == nil {
		var response spanResponse
		response, err = normalizeSpans(d.Result, scope)
		if err == nil {
			writeJSON(w, 200, response)
			return
		}
	}
	if errors.Is(err, errSpanRows) {
		writeJSON(w, 413, map[string]string{"error": err.Error(), "code": "span_rows_exceeded"})
		return
	}
	writeJSON(w, 502, map[string]string{"error": err.Error()})
}
