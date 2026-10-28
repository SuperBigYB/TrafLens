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

func associationFixture(id, side string) associationNode {
	return associationNode{ID: id, StartUS: "100000001", EndUS: "100001002", AgentID: 19, SignalSource: 3, Type: 2, Protocol: 6, L7Protocol: 20,
		TapSide: side, ClientEPC: 0, ServerEPC: -2, ClientIP: "127.0.0.1", ServerIP: "127.0.0.1", ClientPort: 40000, ServerPort: 8080,
		RequestTCPSeq: 101, ResponseTCPSeq: 201, RequestSyscallID: "9007199254740993", ResponseSyscallID: "18446744073709551615",
		RequestCaptureSeq: 5, ResponseCaptureSeq: 7, ClientPID: 11, ServerPID: 22, RequestThread: 55, ResponseThread: 66, FlowID: id, Resource: "/same"}
}

func associationTestScope() associationScope {
	return associationScope{ID: "1", From: 100, To: 100, Agent: 19}
}

func associationResult(nodes ...associationNode) *result {
	value := &result{Columns: append([]string(nil), associationColumns...)}
	for _, n := range nodes {
		raw, _ := json.Marshal(n)
		var object map[string]json.RawMessage
		_ = json.Unmarshal(raw, &object)
		row := []json.RawMessage{}
		for _, key := range value.Columns {
			row = append(row, object[key])
		}
		value.Values = append(value.Values, row)
	}
	return value
}

func handoffFixtures() (associationNode, associationNode) {
	upstream, downstream := associationFixture("1", "s-p"), associationFixture("2", "c-p")
	upstream.ServerPID, downstream.ClientPID = 44, 44
	downstream.ClientPort, downstream.ServerPort = 40001, 8081
	return upstream, downstream
}

func TestAssociationScopeRequiresExactIDAgentAndFiniteWindow(t *testing.T) {
	valid := "id=18446744073709551615&agent=19&from=100&to=159"
	scope, err := associationSelection(valid, 1000)
	if err != nil || scope.ID != "18446744073709551615" || scope.To-scope.From+1 != 60 {
		t.Fatalf("valid exact UInt64/60-second scope rejected: %+v %v", scope, err)
	}
	for _, raw := range []string{"", "id=1&agent=19&from=100", "id=0&agent=19&from=100&to=100", "id=1&agent=0&from=100&to=100",
		"id=1&agent=65536&from=100&to=100", "id=1&agent=19&from=0&to=10", "id=1&agent=19&from=100&to=99", "id=1&agent=19&from=100&to=160",
		valid + "&source=0", valid + "&q=same", valid + "&limit=500", valid + "&id=2", valid + "&trace=x", "id=%zz&agent=19&from=100&to=100"} {
		if _, err := associationSelection(raw, 1000); err == nil {
			t.Errorf("unsafe or broadened evidence scope accepted: %s", raw)
		}
	}
}

func TestAssociationRowsRequireScopeAndKeepExactIdentifiers(t *testing.T) {
	a := associationFixture("18446744073709551615", "c-p")
	nodes, err := associationRows(associationResult(a), associationTestScope())
	if err != nil || len(nodes) != 1 || nodes[0].ID != a.ID || nodes[0].RequestSyscallID != "9007199254740993" || nodes[0].ResponseSyscallID != "18446744073709551615" || nodes[0].ServerEPC != -2 || nodes[0].StartUS != "100000001" {
		t.Fatalf("exact identifier/scope projection lost: %+v %v", nodes, err)
	}
	for _, value := range []*result{nil, {}, {Columns: []string{"id"}}, {Columns: append(append([]string{}, associationColumns...), "id")}, associationResult(a, a)} {
		if _, err := associationRows(value, associationTestScope()); err == nil {
			t.Fatal("incomplete/duplicate schema or record ID became valid evidence")
		}
	}
	for column, bad := range map[string]any{"agent_id": 20, "signal_source": 0, "type": 1, "l7_protocol": 21, "protocol": 17, "ip_0": "not-an-ip", "l3_epc_id_1": nil, "syscall_thread_0": uint64(1) << 32, "req_tcp_seq": -1, "end_us": 1} {
		value := associationResult(a)
		for i, key := range value.Columns {
			if key == column {
				value.Values[0][i], _ = json.Marshal(bad)
			}
		}
		if _, err := associationRows(value, associationTestScope()); err == nil {
			t.Errorf("missing/mismatched evidence field accepted: %s", column)
		}
	}
}

func TestAssociationNetworkPairUsesTupleAndBothTCPSequencesNeverURL(t *testing.T) {
	a, b := associationFixture("1", "c-p"), associationFixture("2", "s-p")
	a.Resource, b.Resource = "/different-a", "/different-b"
	out := buildAssociations([]associationNode{a, b}, associationTestScope())
	if len(out.Edges) != 1 || out.Edges[0].Kind != "network_pair" || out.Edges[0].FromID != "1" || out.Edges[0].ToID != "2" || out.Edges[0].Evidence["req_tcp_seq"] != "101" || out.Records != "2" {
		t.Fatalf("complete native network evidence failed: %+v", out)
	}
	changes := []func(*associationNode){func(n *associationNode) { n.RequestTCPSeq = 0 }, func(n *associationNode) { n.ResponseTCPSeq++ },
		func(n *associationNode) { n.ClientPort++ }, func(n *associationNode) { n.ServerEPC++ }, func(n *associationNode) { n.ServerIP = "127.0.0.2" }, func(n *associationNode) { n.TapSide = "c-p" }}
	for _, change := range changes {
		changed := b
		change(&changed)
		a.Resource, changed.Resource = "/same", "/same"
		out = buildAssociations([]associationNode{a, changed}, associationTestScope())
		if len(out.Edges) != 0 {
			t.Fatal("URL/time proximity or incomplete/reversed network evidence created an edge")
		}
	}
}

func TestAssociationIdentityReuseIsAmbiguousAndIncludesConflictingRecords(t *testing.T) {
	a, b := associationFixture("1", "c-p"), associationFixture("2", "s-p")
	duplicate := b
	duplicate.ID, duplicate.FlowID = "3", "3"
	for _, repeated := range []associationNode{duplicate, func() associationNode { n := duplicate; n.ResponseTCPSeq++; return n }()} {
		out := buildAssociations([]associationNode{a, b, repeated}, associationTestScope())
		if len(out.Edges) != 0 || out.Diagnostics.AmbiguousGroups == 0 {
			t.Fatalf("duplicate/reused identity was linked: %+v", out)
		}
		found := false
		for _, c := range out.Candidates {
			if c.Kind == "network_pair" && c.Reason == "ambiguous_identity_reuse" && len(c.RecordIDs) == 3 {
				found = true
			}
		}
		if !found {
			t.Fatal("ambiguous candidate concealed the actual conflicting observation")
		}
	}
}

func TestAssociationSyscallHandoffRequiresEndpointPIDAndBothPhasesAndThreads(t *testing.T) {
	a, b := handoffFixtures()
	out := buildAssociations([]associationNode{a, b}, associationTestScope())
	if len(out.Edges) != 1 || out.Edges[0].Kind != "syscall_handoff" || out.Edges[0].FromID != "1" || out.Edges[0].ToID != "2" || out.Edges[0].Evidence["process_id"] != "44" || out.Edges[0].Evidence["syscall_trace_id_response"] != "18446744073709551615" {
		t.Fatalf("actual bidirectional same-process handoff failed: %+v", out)
	}
	changes := []func(*associationNode){func(n *associationNode) { n.ClientPID++ }, func(n *associationNode) { n.RequestSyscallID = "0" },
		func(n *associationNode) { n.ResponseSyscallID = "9007199254740993" }, func(n *associationNode) { n.RequestThread++ },
		func(n *associationNode) { n.ResponseThread = 0 }, func(n *associationNode) { n.FlowID = a.FlowID }, func(n *associationNode) { n.TapSide = "s-p" }}
	for _, change := range changes {
		changed := b
		change(&changed)
		if got := buildAssociations([]associationNode{a, changed}, associationTestScope()); len(got.Edges) != 0 {
			t.Fatalf("wrong-phase/side/PID/socket/absent field created handoff: %+v", got)
		}
	}
}

func TestAssociationSyscallSinglePhaseReuseOrUnsupportedSideNeverPicksNearest(t *testing.T) {
	a, b := handoffFixtures()
	third := b
	third.ID, third.FlowID, third.ResponseSyscallID = "3", "3", "123"
	third.StartUS = "100000002"
	out := buildAssociations([]associationNode{a, b, third}, associationTestScope())
	if len(out.Edges) != 0 || out.Diagnostics.AmbiguousGroups == 0 {
		t.Fatal("reused request TraceID was resolved by full-key matching or nearest time")
	}
	third.TapSide = "unknown-side"
	out = buildAssociations([]associationNode{a, b, third}, associationTestScope())
	if len(out.Edges) != 0 || out.Diagnostics.AmbiguousGroups == 0 {
		t.Fatal("unsupported-side observation concealed possible PID-scoped identity reuse")
	}
}

func TestAssociationSeedComponentExcludesControlAndReportsMissingVersusEmpty(t *testing.T) {
	a, b := associationFixture("1", "c-p"), associationFixture("2", "s-p")
	c, d := associationFixture("3", "c-p"), associationFixture("4", "s-p")
	c.RequestTCPSeq, c.ResponseTCPSeq, d.RequestTCPSeq, d.ResponseTCPSeq = 301, 401, 301, 401
	c.RequestSyscallID, c.ResponseSyscallID, d.RequestSyscallID, d.ResponseSyscallID = "501", "601", "501", "601"
	out := buildAssociations([]associationNode{a, b, c, d}, associationTestScope())
	if out.WindowRecords != "4" || out.Records != "2" || len(out.Edges) != 1 || !out.Diagnostics.SeedFound {
		t.Fatalf("independent control became part of selected seed: %+v", out)
	}
	for _, n := range out.Nodes {
		if n.ID == "3" || n.ID == "4" || !n.InSeedComponent {
			t.Fatal("unrelated control observation claimed a seed association")
		}
	}
	a.RequestTCPSeq, a.ResponseTCPSeq, a.ClientPID = 0, 0, 0
	out = buildAssociations([]associationNode{a}, associationTestScope())
	if len(out.Edges) != 0 || len(out.Nodes) != 1 || len(out.Diagnostics.MissingFields) != 1 || len(out.Candidates) != 2 {
		t.Fatal("missing identifiers were confused with missing observation or fabricated evidence")
	}
	scope := associationTestScope()
	scope.ID = "99"
	out = buildAssociations([]associationNode{a}, scope)
	if out.Diagnostics.SeedFound || out.Nodes == nil || len(out.Nodes) != 0 || out.Candidates == nil || out.Records != "0" {
		t.Fatal("missing exact seed did not remain an explicit empty component")
	}
}

func TestAssociationAPIUsesOneBoundedFixedQueryAndFailsClosed(t *testing.T) {
	a, b := associationFixture("1", "c-p"), associationFixture("2", "s-p")
	calls := 0
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		_ = r.ParseForm()
		sql := r.Form.Get("sql")
		if r.URL.Path != "/v1/query/" || r.Method != "POST" || r.Header.Get("X-Org-Id") != "1" || r.Header.Get("X-User-Id") != "1" || r.Form.Get("db") != "flow_log" {
			t.Error("kernel evidence backend scope changed")
		}
		for _, clause := range []string{"time >= 100 AND time <= 100", "agent_id = 19", "signal_source = 3", "type = 2", "protocol = 6", "l7_protocol = 20", "LIMIT 65", "syscall_thread_0", "syscall_thread_1"} {
			if !strings.Contains(sql, clause) {
				t.Errorf("missing fixed evidence query bound: %s", clause)
			}
		}
		if strings.Contains(sql, "WHERE _id") || strings.Contains(sql, "request_resource LIKE") {
			t.Error("population was hidden behind the seed or URL")
		}
		json.NewEncoder(w).Encode(map[string]any{"OPT_STATUS": "SUCCESS", "result": associationResult(a, b)})
	}))
	defer backend.Close()
	c := console{backend.URL, "", backend.Client()}
	rr := httptest.NewRecorder()
	c.associations(rr, httptest.NewRequest("GET", "/api/associations?id=1&agent=19&from=100&to=100", nil))
	if rr.Code != 200 || calls != 1 {
		t.Fatalf("bounded single-query evidence failed: %d %s", rr.Code, rr.Body.String())
	}
	for _, value := range []*result{nil, {}, associationResult(make([]associationNode, 65)...)} {
		trialCalls := 0
		trial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			trialCalls++
			json.NewEncoder(w).Encode(map[string]any{"OPT_STATUS": "SUCCESS", "result": value})
		}))
		c.query, c.client = trial.URL, trial.Client()
		rr = httptest.NewRecorder()
		c.associations(rr, httptest.NewRequest("GET", "/api/associations?id=1&agent=19&from=100&to=100", nil))
		trial.Close()
		want := 502
		if value != nil && len(value.Values) > 64 {
			want = 413
		}
		if rr.Code != want || trialCalls != 1 || strings.Contains(rr.Body.String(), `"nodes"`) {
			t.Fatalf("failed/over-cap response became partial evidence or fallback: %d %s", rr.Code, rr.Body.String())
		}
	}
	client := &http.Client{Transport: spanRoundTrip(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > 12*time.Second {
			t.Error("kernel evidence lacks a finite query deadline")
		}
		return nil, fmt.Errorf("offline backend unavailable")
	})}
	c.query, c.client = "http://example.invalid", client
	rr = httptest.NewRecorder()
	c.associations(rr, httptest.NewRequest("GET", "/api/associations?id=1&agent=19&from=100&to=100", nil))
	if rr.Code != 502 {
		t.Fatal("backend failure became an empty successful component")
	}
}
