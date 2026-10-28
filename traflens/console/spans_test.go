package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const spanTestTrace = "11111111111111111111111111111111"
const spanTestRoot = "1111111111111111"
const spanTestChild = "2222222222222222"

func spanRaw(v any) json.RawMessage {
	raw, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return raw
}

func spanFixture(id, span, parent string) []json.RawMessage {
	values := []any{id, spanTestTrace, span, parent, "checkout", "checkout-1", 2, "GET /checkout", 100000001, 100001002, 1001, 19, 4, 2}
	row := make([]json.RawMessage, len(values))
	for i, value := range values {
		row[i] = spanRaw(value)
	}
	return row
}

func spanResult(rows ...[]json.RawMessage) *result {
	return &result{Columns: append([]string(nil), spanColumns...), Values: rows}
}

func spanTestScope() spanScope { return spanScope{Trace: spanTestTrace, From: 100, To: 100} }

func TestSpanSelectionRejectsWideningAndPreservesSingleSecond(t *testing.T) {
	for _, raw := range []string{"", "trace=", "trace=" + strings.Repeat("0", 32), "trace=" + strings.Repeat("A", 32), "trace=x%27OR1", "trace=" + spanTestTrace + "&trace=" + spanTestTrace,
		"trace=" + spanTestTrace + "&agent=0", "trace=" + spanTestTrace + "&agent=65536", "trace=" + spanTestTrace + "&from=0", "trace=" + spanTestTrace + "&from=200&to=100",
		"trace=" + spanTestTrace + "&from=1&to=2678402", "trace=" + spanTestTrace + "&source=0", "trace=" + spanTestTrace + "&limit=500", "trace=" + spanTestTrace + "&id=1", "trace=" + spanTestTrace + "&app=x", "trace=%zz"} {
		if _, err := spanSelection(raw, 4000000); err == nil {
			t.Errorf("unsafe or widened Span selection accepted: %s", raw)
		}
	}
	scope, err := spanSelection("trace="+spanTestTrace+"&from=100&to=100&agent=65535", 1000)
	if err != nil || scope.From != 100 || scope.To != 100 || scope.Agent == nil || *scope.Agent != 65535 {
		t.Fatalf("inclusive exact scope rejected: %+v %v", scope, err)
	}
}

func TestSpansUsesOnlyFixedOTelQueryAndPreciseStoredParent(t *testing.T) {
	calls := 0
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/v1/query/" || r.Method != "POST" || r.Header.Get("X-Org-Id") != "1" || r.Header.Get("X-User-Id") != "1" || r.Header.Get("X-User-Type") != "1" {
			t.Error("Span query changed backend or organization scope")
		}
		_ = r.ParseForm()
		if r.Form.Get("db") != "flow_log" {
			t.Error("wrong Span database")
		}
		for _, clause := range []string{"time >= 100 AND time <= 100", "trace_id = '" + spanTestTrace + "'", "signal_source = 4", "type = 2", "agent_id = 19", "toUnixTimestamp64Micro(start_time) AS start_us", "toUnixTimestamp64Micro(end_time) AS end_us", "LIMIT 257"} {
			if !strings.Contains(r.Form.Get("sql"), clause) {
				t.Errorf("missing fixed scope or precise projection: %s", clause)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"OPT_STATUS": "SUCCESS", "result": spanResult(spanFixture("18446744073709551615", spanTestRoot, ""), spanFixture("9007199254740993", spanTestChild, spanTestRoot))})
	}))
	defer b.Close()
	c := console{b.URL, "http://127.0.0.1:1", b.Client()}
	rr := httptest.NewRecorder()
	c.spans(rr, httptest.NewRequest("GET", "/api/spans?trace="+spanTestTrace+"&from=100&to=100&agent=19", nil))
	var out spanResponse
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &out) != nil || out.Records != "2" || out.SignalSource != 4 || out.TimeUnit != "microseconds" || calls != 1 || len(out.Edges) != 1 || out.Edges[0].ParentRecordID != "18446744073709551615" || out.Edges[0].ChildRecordID != "9007199254740993" || out.Nodes[1].StartUS != "100000001" || out.Nodes[1].DurationUS != "1001" || out.Nodes[1].ParentRecordID == nil || *out.Nodes[1].ParentRecordID != out.Nodes[0].ID {
		t.Fatalf("explicit relation/precision contract: %d %s", rr.Code, rr.Body.String())
	}
}

func TestSpansSuccessfulEmptyRequiresCompleteSchema(t *testing.T) {
	out, err := normalizeSpans(spanResult(), spanTestScope())
	if err != nil || out.Records != "0" || out.Nodes == nil || out.Edges == nil || out.Diagnostics.CycleRecords == nil || len(out.Nodes) != 0 {
		t.Fatalf("successful empty result confused with failure: %+v %v", out, err)
	}
	for _, input := range []*result{nil, {}, {Columns: []string{"id"}}, {Columns: append(append([]string{}, spanColumns...), "id")}, spanResult([]json.RawMessage{spanRaw(1)})} {
		if _, err := normalizeSpans(input, spanTestScope()); err == nil {
			t.Error("missing/duplicate/malformed schema became a successful empty trace")
		}
	}
}

func TestSpansRejectsMismatchedScopeMalformedFieldsAndDuplicateRecords(t *testing.T) {
	for index, value := range map[int]any{0: "0", 1: strings.Repeat("2", 32), 4: nil, 6: nil, 8: -1, 9: 999, 10: 1000, 11: 65536, 12: 3, 13: 1} {
		row := spanFixture("1", spanTestRoot, "")
		row[index] = spanRaw(value)
		if _, err := normalizeSpans(spanResult(row), spanTestScope()); err == nil {
			t.Errorf("contradictory or malformed Span field accepted: %d", index)
		}
	}
	row := spanFixture("1", spanTestRoot, "")
	if _, err := normalizeSpans(spanResult(row, row), spanTestScope()); err == nil {
		t.Fatal("duplicate record ID accepted as two observations")
	}
	id := uint16(20)
	scope := spanTestScope()
	scope.Agent = &id
	if _, err := normalizeSpans(spanResult(row), scope); err == nil {
		t.Fatal("wrong historical Agent accepted")
	}
}

func TestSpansDuplicateObservationsRemainSeparateAndParentsAreAmbiguous(t *testing.T) {
	root1 := spanFixture("1", spanTestRoot, "")
	root2 := spanFixture("2", spanTestRoot, "")
	child := spanFixture("3", spanTestChild, spanTestRoot)
	out, err := normalizeSpans(spanResult(root1, root2, child), spanTestScope())
	if err != nil || out.Records != "3" || len(out.Nodes) != 3 || len(out.Edges) != 0 || len(out.Diagnostics.DuplicateSpanIDs) != 1 || len(out.Diagnostics.ConflictingSpanIDs) != 0 || len(out.Diagnostics.AmbiguousParentRecords) != 1 || out.Nodes[2].ParentRecordID != nil {
		t.Fatalf("duplicate observation silently deduplicated or parent invented: %+v %v", out, err)
	}
	root2[4] = spanRaw("conflicting-service")
	out, err = normalizeSpans(spanResult(root1, root2, child), spanTestScope())
	if err != nil || len(out.Diagnostics.ConflictingSpanIDs) != 1 || len(out.Edges) != 0 {
		t.Fatalf("conflicting duplicate Span not exposed: %+v %v", out, err)
	}
}

func TestSpansReportsMissingParentsInvalidIDsAndCyclesWithoutInventingEdges(t *testing.T) {
	rows := [][]json.RawMessage{
		spanFixture("1", spanTestRoot, spanTestChild), spanFixture("2", spanTestChild, spanTestRoot),
		spanFixture("3", "3333333333333333", "4444444444444444"),
		spanFixture("4", "5555555555555555", strings.Repeat("0", 16)),
		spanFixture("5", "not-a-span", ""), spanFixture("6", "6666666666666666", "6666666666666666"),
	}
	out, err := normalizeSpans(spanResult(rows...), spanTestScope())
	if err != nil || len(out.Edges) != 0 || len(out.Diagnostics.CycleRecords) != 3 || len(out.Diagnostics.MissingParentRecords) != 1 || len(out.Diagnostics.InvalidSpanRecords) != 2 {
		t.Fatalf("invalid/missing/cyclic relationships hidden or inferred: %+v %v", out, err)
	}
	for _, node := range out.Nodes {
		if node.ParentRecordID != nil {
			t.Fatal("invalid relation acquired a parent edge")
		}
	}
}

func TestSpansBoundFailureIsNotPartialAndNeverFallsBack(t *testing.T) {
	rows := make([][]json.RawMessage, 257)
	for i := range rows {
		rows[i] = spanFixture(fmt.Sprint(i+1), fmt.Sprintf("%016x", i+1), "")
	}
	for _, trial := range []struct {
		status int
		body   any
		want   int
	}{{200, map[string]any{"OPT_STATUS": "SUCCESS", "result": spanResult(rows...)}, 413},
		{200, map[string]any{"OPT_STATUS": "SUCCESS"}, 502}, {500, map[string]any{"OPT_STATUS": "SERVER_ERROR"}, 502}, {404, map[string]any{}, 502}} {
		calls := 0
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(trial.status)
			json.NewEncoder(w).Encode(trial.body)
		}))
		c := console{b.URL, "", b.Client()}
		rr := httptest.NewRecorder()
		c.spans(rr, httptest.NewRequest("GET", "/api/spans?trace="+spanTestTrace+"&from=100&to=100", nil))
		b.Close()
		if rr.Code != trial.want || calls != 1 || strings.Contains(rr.Body.String(), `"nodes"`) {
			t.Fatalf("failed/over-limit response became partial or fallback: %d %s calls=%d", rr.Code, rr.Body.String(), calls)
		}
	}
}

type spanRoundTrip func(*http.Request) (*http.Response, error)

func (f spanRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSpansSharesBoundedDeadlineAndRejectsOversizedResponse(t *testing.T) {
	client := &http.Client{Transport: spanRoundTrip(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 12*time.Second {
			t.Error("Span query lacks the bounded shared deadline")
		}
		return &http.Response{StatusCode: 200, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	c := console{"http://example.invalid", "", client}
	rr := httptest.NewRecorder()
	c.spans(rr, httptest.NewRequest("GET", "/api/spans?trace="+spanTestTrace+"&from=100&to=100", nil))
	if rr.Code != 502 {
		t.Fatal("unreadable response became a successful trace")
	}
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat(" ", 4*1024*1024+1))
	}))
	defer b.Close()
	c.query, c.client = b.URL, b.Client()
	rr = httptest.NewRecorder()
	c.spans(rr, httptest.NewRequest("GET", "/api/spans?trace="+spanTestTrace+"&from=100&to=100", nil))
	if rr.Code != 502 {
		t.Fatal("oversized response bypassed the body limit")
	}
}
