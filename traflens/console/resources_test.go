package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func resourceFixture(id int) map[string]any {
	return map[string]any{"ID": id, "LCUUID": fmt.Sprintf("registration-%d", id), "NAME": "fixture",
		"CTRL_IP": "203.0.113.10", "TYPE": 5, "STATE": 0, "ENABLE": 1, "TEAM_ID": 1}
}

func resourceRequest(t *testing.T, body, query string) *httptest.ResponseRecorder {
	t.Helper()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
	defer b.Close()
	c := console{b.URL, b.URL, b.Client()}
	rr := httptest.NewRecorder()
	c.resources(rr, httptest.NewRequest("GET", "/api/resources"+query, nil))
	return rr
}

func TestResourcesProjectCurrentInventoryAndFixedScope(t *testing.T) {
	row := resourceFixture(7)
	row["CTRL_MAC"], row["LICENSE_FUNCTIONS"] = "private-extra-field", []int{2, 4, 5}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/vtaps/" || r.URL.RawQuery != "" {
			t.Error("inventory request changed path/method/scope")
		}
		for key, value := range map[string]string{"X-Org-Id": "1", "X-User-Id": "1", "X-User-Type": "1"} {
			if r.Header.Get(key) != value {
				t.Errorf("fixed scope missing: %s", key)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"OPT_STATUS": "SUCCESS", "DATA": []any{row}})
	}))
	defer backend.Close()
	c := console{backend.URL, backend.URL, backend.Client()}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/resources?agent=7", nil)
	req.Header.Set("X-Org-Id", "999")
	c.resources(rr, req)
	var response struct {
		Resources   []map[string]any `json:"resources"`
		Scope       map[string]int   `json:"scope"`
		Association string           `json:"association"`
	}
	if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &response) != nil || len(response.Resources) != 1 {
		t.Fatalf("unexpected inventory: %d %s", rr.Code, rr.Body.String())
	}
	if response.Resources[0]["STATE"] != float64(0) || response.Resources[0]["ENABLE"] != float64(1) || len(response.Resources[0]) != 8 {
		t.Fatal("raw current state or field projection changed")
	}
	if response.Scope["org_id"] != 1 || response.Scope["user_id"] != 1 || !strings.Contains(response.Association, "Historical ID reuse") {
		t.Fatal("registration/observation scope lost")
	}
	if strings.Contains(rr.Body.String(), "private-extra-field") || strings.Contains(rr.Body.String(), "LICENSE_FUNCTIONS") {
		t.Fatal("unselected Controller fields leaked")
	}
}

func TestResourcesBoundListButExactMatchSearchesWholeInventory(t *testing.T) {
	rows := []any{resourceFixture(65535)}
	for id := 101; id >= 1; id-- {
		rows = append(rows, resourceFixture(id))
	}
	body, _ := json.Marshal(map[string]any{"OPT_STATUS": "SUCCESS", "DATA": rows})
	for _, check := range []struct {
		query     string
		count     int
		truncated bool
		first     int32
	}{{"", 100, true, 1}, {"?agent=65535", 1, false, 65535}, {"?agent=200", 0, false, 0}} {
		rr := resourceRequest(t, string(body), check.query)
		var response struct {
			Resources []agentResource `json:"resources"`
			Truncated bool            `json:"truncated"`
			Limit     int             `json:"limit"`
		}
		if rr.Code != 200 || json.Unmarshal(rr.Body.Bytes(), &response) != nil || len(response.Resources) != check.count || response.Truncated != check.truncated || response.Limit != 100 {
			t.Fatalf("%s: %d %s", check.query, rr.Code, rr.Body.String())
		}
		if check.count > 0 && response.Resources[0].ID != check.first {
			t.Fatal("sort or exact Agent identity lost")
		}
	}
}

func TestResourcesRejectBadInputsBeforeUpstream(t *testing.T) {
	c := console{"", "", nil}
	for _, query := range []string{"?agent=", "?agent=0", "?agent=-1", "?agent=65536", "?agent=1.0",
		"?agent=1&agent=2", "?agent=7&team=1", "?org=2", "?limit=1000", "?agent=1%27+OR+1=1", "?agent=%zz"} {
		rr := httptest.NewRecorder()
		c.resources(rr, httptest.NewRequest("GET", "/api/resources"+query, nil))
		if rr.Code != 400 {
			t.Errorf("accepted %s: %d", query, rr.Code)
		}
	}
	rr := httptest.NewRecorder()
	c.resources(rr, httptest.NewRequest("POST", "/api/resources", nil))
	if rr.Code != 405 || rr.Header().Get("Allow") != "GET" {
		t.Fatal("resource endpoint accepted mutation")
	}
}

func TestResourcesEmptyInventoryAndFailuresStayDistinct(t *testing.T) {
	for _, check := range []struct {
		body string
		code int
	}{{`{"OPT_STATUS":"SUCCESS","DATA":[]}`, 200},
		{`{"OPT_STATUS":"SUCCESS","DATA":null}`, 502}, {`{"OPT_STATUS":"SUCCESS"}`, 502},
		{`{"OPT_STATUS":"SUCCESS","DATA":{}}`, 502}, {`{"OPT_STATUS":"SUCCESS","DATA":[null]}`, 502},
		{`{"OPT_STATUS":"FAILED","DATA":[]}`, 502}} {
		rr := resourceRequest(t, check.body, "")
		if rr.Code != check.code {
			t.Errorf("%s: %d != %d", check.body, rr.Code, check.code)
		}
		if check.code == 200 && !strings.Contains(rr.Body.String(), `"resources":[]`) {
			t.Fatal("explicit empty inventory did not stay an empty list")
		}
	}
}

func TestResourcesRejectMissingMalformedAndDuplicateIdentity(t *testing.T) {
	for _, field := range []string{"ID", "LCUUID", "NAME", "CTRL_IP", "TYPE", "STATE", "ENABLE", "TEAM_ID"} {
		row := resourceFixture(7)
		delete(row, field)
		body, _ := json.Marshal(map[string]any{"OPT_STATUS": "SUCCESS", "DATA": []any{row}})
		if rr := resourceRequest(t, string(body), ""); rr.Code != 502 {
			t.Errorf("missing %s accepted", field)
		}
	}
	for key, bad := range map[string]any{"ID": 65536, "LCUUID": "", "TYPE": -1, "STATE": "0", "ENABLE": 2, "TEAM_ID": -1} {
		row := resourceFixture(7)
		row[key] = bad
		body, _ := json.Marshal(map[string]any{"OPT_STATUS": "SUCCESS", "DATA": []any{row}})
		if rr := resourceRequest(t, string(body), ""); rr.Code != 502 {
			t.Errorf("invalid %s accepted", key)
		}
	}
	for _, duplicate := range []map[string]any{resourceFixture(7), resourceFixture(8)} {
		duplicate["LCUUID"] = "registration-7"
		body, _ := json.Marshal(map[string]any{"OPT_STATUS": "SUCCESS", "DATA": []any{resourceFixture(7), duplicate}})
		if rr := resourceRequest(t, string(body), "?agent=7"); rr.Code != 502 {
			t.Fatal("duplicate identity hidden by exact filter")
		}
	}
}
