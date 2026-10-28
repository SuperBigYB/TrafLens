package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func profileNativeFixture(samples uint64) map[string]any {
	return map[string]any{"functions": []string{"cpu-demo", "main.hot"}, "function_types": []string{"P", "L"},
		"function_values": map[string]any{"columns": []string{"self_value", "total_value"}, "values": [][]any{{0, samples}, {samples, samples}}},
		"node_values":     map[string]any{"columns": []string{"function_id", "parent_node_id", "self_value", "total_value"}, "values": [][]any{{0, -1, 0, samples}, {1, 0, samples, samples}}},
		"bounds_applied":  true, "max_rows": 256, "input_rows": 2,
		"budgets": map[string]any{"compressed_bytes": 4194304, "decoded_stack_bytes": 1048576, "total_decoded_stack_bytes": 8388608, "nodes": 8192, "stack_depth": 512}}
}

func profileRaw(value any) json.RawMessage {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

func TestProfileScopeRejectsWideningInjectionAndUnsupportedSignals(t *testing.T) {
	for _, query := range []string{"app=", "app=a'OR1", "app=a&app=b", "app=with+space", "agent=0", "agent=65536", "agent=1&agent=2", "source=3", "proto=20", "trace=x", "q=x", "sql=SELECT+1", "max_rows=10000", "from=0", "from=110&to=100", "from=1&to=2678402", "from=%zz"} {
		if _, err := profileSelection(query, 4000000, false); err == nil {
			t.Errorf("unsafe profile scope accepted: %s", query)
		}
	}
	if _, err := profileSelection("from=100&to=100&agent=17&app=cpu-demo", 1000, true); err != nil {
		t.Fatalf("valid exact historical scope/single second rejected: %v", err)
	}
	if _, err := profileSelection("", 100000, true); err == nil {
		t.Fatal("detail query accepted missing exact application")
	}
	c := console{"", "", nil}
	for _, detail := range []bool{false, true} {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/api/profiles?source=3", nil)
		if detail {
			c.profile(rr, r)
		} else {
			c.profiles(rr, r)
		}
		if rr.Code != 400 {
			t.Fatal("unsupported signal scope reached the backend")
		}
	}
}

func TestProfileDirectoryQueriesHistoricalDataAndKeepsExactCounts(t *testing.T) {
	scope := "from=100&to=110&agent=17&app=cpu-demo"
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/query/" || r.Method != "POST" || r.Header.Get("X-Org-Id") != "1" || r.Header.Get("X-User-Id") != "1" || r.Header.Get("X-User-Type") != "1" {
			t.Error("profile directory changed fixed backend/scope or joined current registrations")
		}
		r.ParseForm()
		if r.Form.Get("db") != "profile" {
			t.Fatal("wrong profile database")
		}
		sql := r.Form.Get("sql")
		for _, clause := range []string{"FROM in_process", "time >= 100 AND time <= 110", "agent_id = 17", "app_service = 'cpu-demo'", "profile_event_type = 'cpu'", "profile_language_type = 'Golang'", "profile_value_unit = 'samples'", "LIMIT 101"} {
			if !strings.Contains(sql, clause) {
				t.Errorf("missing fixed profile scope: %s", clause)
			}
		}
		fmt.Fprint(w, `{"OPT_STATUS":"SUCCESS","result":{"columns":["app_service","agent_id","profile_language_type","profile_event_type","profile_value_unit","records","samples"],"values":[["cpu-demo",17,"Golang","cpu","samples",2,9007199254740993]]}}`)
	}))
	defer b.Close()
	c := console{b.URL, "http://127.0.0.1:1", b.Client()}
	rr := httptest.NewRecorder()
	c.profiles(rr, httptest.NewRequest("GET", "/api/profiles?"+scope, nil))
	var response struct {
		Profiles []profileApplication `json:"profiles"`
		Scope    map[string]int       `json:"scope"`
		Identity string               `json:"os_identity"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &response) != nil || len(response.Profiles) != 1 || response.Profiles[0].Samples != "9007199254740993" || response.Profiles[0].Records != "2" || response.Profiles[0].AgentID != 17 || response.Scope["org_id"] != 1 || response.Identity != "not_proven" {
		t.Fatalf("historical/precision semantics: %d %s", rr.Code, rr.Body.String())
	}
}

func TestProfileDirectoryEmptyTruncationAndMalformedData(t *testing.T) {
	columns := []string{"app_service", "agent_id", "profile_language_type", "profile_event_type", "profile_value_unit", "records", "samples"}
	empty := &result{Columns: columns}
	apps, truncated, err := normalizeProfileApplications(empty, profileScope{})
	if err != nil || truncated || apps == nil || len(apps) != 0 {
		t.Fatal("successful empty directory confused with failure")
	}
	full := &result{Columns: columns}
	for i := 0; i < 101; i++ {
		var row []json.RawMessage
		json.Unmarshal(profileRaw([]any{fmt.Sprintf("cpu-%03d", i), 17, "Golang", "cpu", "samples", 2, 800}), &row)
		full.Values = append(full.Values, row)
	}
	apps, truncated, err = normalizeProfileApplications(full, profileScope{})
	if err != nil || !truncated || len(apps) != 100 {
		t.Fatal("directory failed to expose top100 truncation")
	}
	for _, value := range []*result{nil, {}, {Columns: []string{"app_service"}}, {Columns: columns, Values: [][]json.RawMessage{full.Values[0], full.Values[0]}}} {
		if _, _, err := normalizeProfileApplications(value, profileScope{}); err == nil {
			t.Fatal("missing/malformed/duplicate directory became successful")
		}
	}
	for index, bad := range map[int]any{1: 0, 2: "eBPF", 3: "on-cpu", 4: "microseconds", 5: 801, 6: -1} {
		row := append([]json.RawMessage(nil), full.Values[0]...)
		row[index] = profileRaw(bad)
		if _, _, err := normalizeProfileApplications(&result{Columns: columns, Values: [][]json.RawMessage{row}}, profileScope{}); err == nil {
			t.Errorf("wrong fixed metadata/aggregate accepted: field%d", index)
		}
	}
}

func TestProfileBoundedRequestAndExactTreeNormalization(t *testing.T) {
	called := 0
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		if r.Method != "POST" || r.URL.Path != "/v1/profile/ProfileTracingBounded" || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("X-Org-Id") != "1" || r.Header.Get("X-User-Id") != "1" {
			t.Error("bounded detail path/scope changed")
		}
		var request map[string]any
		json.NewDecoder(r.Body).Decode(&request)
		if request["max_rows"] != float64(256) || request["app_service"] != "cpu-demo" || request["profile_event_type"] != "cpu" || request["profile_language_type"] != "Golang" || request["time_start"] != float64(100) || request["time_end"] != float64(110) || request["tag_filter"] != "agent_id=17 AND profile_value_unit='samples'" {
			t.Errorf("unsafe or widened bounded request: %v", request)
		}
		json.NewEncoder(w).Encode(map[string]any{"OPT_STATUS": "SUCCESS", "result": profileNativeFixture(9007199254740993)})
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.profile(rr, httptest.NewRequest("GET", "/api/profile?app=cpu-demo&agent=17&from=100&to=110", nil))
	var response profileDetail
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &response) != nil || !response.BoundsApplied || response.MaxRows != 256 || response.InputRows != 2 || response.TotalSamples != "9007199254740993" || response.Nodes[0].ParentID != -1 || response.Functions[1].Self != "9007199254740993" || response.Nodes[1].Total != "9007199254740993" || response.Empty || called != 1 {
		t.Fatalf("bounded tree precision/root contract: %d %s", rr.Code, rr.Body.String())
	}
}

func TestProfileEmptyBoundedTreeHasNoInventedSamplesOrIdentity(t *testing.T) {
	tree := profileNativeFixture(0)
	tree["input_rows"] = 0
	tree["functions"], tree["function_types"] = []string{}, []string{}
	tree["function_values"] = map[string]any{"columns": []string{}, "values": [][]any{}}
	tree["node_values"] = map[string]any{"columns": []string{}, "values": [][]any{}}
	detail, err := normalizeProfileTree(profileRaw(tree), profileScope{App: "cpu-demo"})
	if err != nil || !detail.Empty || detail.TotalSamples != "0" || detail.InputRows != 0 || detail.Functions == nil || detail.Nodes == nil || len(detail.Functions) != 0 || detail.Identity != "not_proven" {
		t.Fatalf("empty tree contract: %+v %v", detail, err)
	}
}

func TestProfileRejectsUnboundedMalformedAndContradictoryNativeTrees(t *testing.T) {
	mutations := []func(map[string]any){
		func(v map[string]any) { delete(v, "bounds_applied") },
		func(v map[string]any) { v["bounds_applied"] = false },
		func(v map[string]any) { delete(v, "budgets") },
		func(v map[string]any) { v["max_rows"] = 1000000 },
		func(v map[string]any) { v["input_rows"] = 257 },
		func(v map[string]any) { v["input_rows"] = 0 },
		func(v map[string]any) { v["functions"] = []string{"wrong-app", "main.hot"} },
		func(v map[string]any) { v["budgets"].(map[string]any)["nodes"] = 1000000 },
		func(v map[string]any) { v["node_values"].(map[string]any)["values"].([][]any)[1][1] = 1 },
		func(v map[string]any) { v["node_values"].(map[string]any)["values"].([][]any)[1][3] = 799 },
		func(v map[string]any) { v["function_values"].(map[string]any)["values"].([][]any)[1][0] = 799 },
		func(v map[string]any) {
			v["function_values"].(map[string]any)["columns"] = []string{"self_value", "self_value"}
		},
	}
	for index, mutate := range mutations {
		tree := profileNativeFixture(800)
		mutate(tree)
		if _, err := normalizeProfileTree(profileRaw(tree), profileScope{App: "cpu-demo"}); err == nil {
			t.Errorf("invalid native bound/tree accepted: case%d", index)
		}
	}
}

func TestProfileUnsupportedBudgetAndBackendFailuresNeverFallback(t *testing.T) {
	for _, check := range []struct {
		status int
		body   string
		want   int
	}{{404, "missing route", 501}, {400, `{"OPT_STATUS":"RESOURCE_NUM_EXCEEDED"}`, 413},
		{500, `{"OPT_STATUS":"SERVER_ERROR"}`, 502}, {200, `{"OPT_STATUS":"SUCCESS","result":null}`, 502},
		{200, `{"OPT_STATUS":"SUCCESS","result":{}}`, 502}, {200, strings.Repeat(" ", profileBodyLimit+1), 413}} {
		calls := 0
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if r.URL.Path != "/v1/profile/ProfileTracingBounded" {
				t.Error("unsafe fallback to legacy profile endpoint")
			}
			w.WriteHeader(check.status)
			fmt.Fprint(w, check.body)
		}))
		c := console{b.URL, b.URL, b.Client()}
		rr := httptest.NewRecorder()
		c.profile(rr, httptest.NewRequest("GET", "/api/profile?app=cpu-demo", nil))
		if rr.Code != check.want || calls != 1 || strings.Contains(rr.Body.String(), `"functions"`) {
			t.Fatalf("error/fallback contract: %d != %d (%s)", rr.Code, check.want, rr.Body.String())
		}
		b.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := console{"http://127.0.0.1:1", "", &http.Client{Timeout: time.Second}}
	rr := httptest.NewRecorder()
	c.profile(rr, httptest.NewRequest("GET", "/api/profile?app=cpu-demo", nil).WithContext(ctx))
	if rr.Code != 502 {
		t.Fatal("canceled query became empty successful profile")
	}
}

func TestProfileNoAgentStillRequiresNativeSamplesUnit(t *testing.T) {
	var filter string
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		json.NewDecoder(r.Body).Decode(&body)
		filter, _ = body["tag_filter"].(string)
		fmt.Fprint(w, `{"OPT_STATUS":"RESOURCE_NUM_EXCEEDED"}`)
	}))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	_, err := c.boundedProfile(context.Background(), profileScope{App: "cpu-demo", From: 100, To: 110})
	if err == nil || filter != "profile_value_unit='samples'" {
		t.Fatal("missing optional Agent widened unit or invented numeric identity")
	}
	query := profileListQuery(profileScope{App: "cpu-demo", From: 100, To: 110})
	if strings.Contains(query, "agent_id =") {
		t.Fatal("unselected Agent silently narrowed the historical directory")
	}
	if _, err := profileSelection(url.Values{"app": {"cpu-demo"}, "from": {"100"}, "to": {"110"}}.Encode(), 1000, true); err != nil {
		t.Fatal(err)
	}
}
