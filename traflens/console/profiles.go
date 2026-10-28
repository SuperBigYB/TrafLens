package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const profileListLimit = 100
const profileRowLimit = 256
const profileBodyLimit = 4 * 1024 * 1024

var profileApp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

type profileScope struct {
	From  int64
	To    int64
	Agent *uint16
	App   string
}

type profileApplication struct {
	App      string `json:"app"`
	AgentID  uint16 `json:"agent_id"`
	Language string `json:"language"`
	Event    string `json:"event"`
	Unit     string `json:"unit"`
	Records  string `json:"records"`
	Samples  string `json:"samples"`
}

type profileFunction struct {
	ID    int    `json:"id"`
	Name  string `json:"name"`
	Self  string `json:"self"`
	Total string `json:"total"`
}

type profileNode struct {
	ID         int    `json:"id"`
	ParentID   int    `json:"parent_id"`
	FunctionID int    `json:"function_id"`
	Self       string `json:"self"`
	Total      string `json:"total"`
}

type profileBudgets struct {
	CompressedBytes        int `json:"compressed_bytes"`
	DecodedStackBytes      int `json:"decoded_stack_bytes"`
	TotalDecodedStackBytes int `json:"total_decoded_stack_bytes"`
	Nodes                  int `json:"nodes"`
	StackDepth             int `json:"stack_depth"`
}

type profileDetail struct {
	App           string            `json:"app"`
	AgentID       *uint16           `json:"agent_id,omitempty"`
	Language      string            `json:"language"`
	Event         string            `json:"event"`
	Unit          string            `json:"unit"`
	BoundsApplied bool              `json:"bounds_applied"`
	MaxRows       int               `json:"max_rows"`
	InputRows     int               `json:"input_rows"`
	TotalSamples  string            `json:"total_samples"`
	Functions     []profileFunction `json:"functions"`
	Nodes         []profileNode     `json:"nodes"`
	Budgets       profileBudgets    `json:"budgets"`
	Empty         bool              `json:"empty"`
	Scope         map[string]int    `json:"scope"`
	Identity      string            `json:"os_identity"`
}

func profileSelection(raw string, now int64, detail bool) (profileScope, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return profileScope{}, errors.New("invalid profile query encoding")
	}
	for key, values := range v {
		if len(values) != 1 || key != "from" && key != "to" && key != "agent" && key != "app" {
			return profileScope{}, errors.New("profile scope only accepts from, to, agent and app once")
		}
	}
	s := profileScope{From: now - 86400, To: now}
	if v.Has("from") {
		s.From, err = strconv.ParseInt(v.Get("from"), 10, 64)
		if err != nil {
			return profileScope{}, errors.New("invalid profile start time")
		}
	}
	if v.Has("to") {
		s.To, err = strconv.ParseInt(v.Get("to"), 10, 64)
		if err != nil {
			return profileScope{}, errors.New("invalid profile end time")
		}
	}
	if s.From < 1 || s.To < s.From || s.To-s.From > 31*86400 || s.To > now+300 {
		return profileScope{}, errors.New("profile time range must be inclusive and at most 31 days")
	}
	if v.Has("agent") {
		id, e := strconv.ParseUint(v.Get("agent"), 10, 16)
		if e != nil || id == 0 {
			return profileScope{}, errors.New("profile Agent ID must be 1..65535")
		}
		n := uint16(id)
		s.Agent = &n
	}
	s.App = v.Get("app")
	if detail || v.Has("app") {
		if !profileApp.MatchString(s.App) {
			return profileScope{}, errors.New("profile app requires 1..128 safe ASCII name characters")
		}
	}
	return s, nil
}

func (s profileScope) where() string {
	where := fmt.Sprintf("time >= %d AND time <= %d AND profile_language_type = 'Golang' AND profile_event_type = 'cpu' AND profile_value_unit = 'samples'", s.From, s.To)
	if s.Agent != nil {
		where += fmt.Sprintf(" AND agent_id = %d", *s.Agent)
	}
	if s.App != "" {
		where += " AND app_service = '" + s.App + "'"
	}
	return where
}

func profileListQuery(scope profileScope) string {
	group := "app_service,agent_id,profile_language_type,profile_event_type,profile_value_unit"
	return "SELECT " + group + ",Count(row) AS records,Sum(profile_value) AS samples FROM in_process WHERE " + scope.where() + " GROUP BY " + group + " ORDER BY samples DESC,app_service ASC,agent_id ASC LIMIT 101"
}

func profileRows(value *result) ([]map[string]json.RawMessage, error) {
	if value == nil || len(value.Values) > profileListLimit+1 {
		return nil, errors.New("missing or over-limit profile application response")
	}
	seen := make(map[string]bool)
	for _, key := range value.Columns {
		if seen[key] {
			return nil, errors.New("duplicate profile application column")
		}
		seen[key] = true
	}
	for _, key := range []string{"app_service", "agent_id", "profile_language_type", "profile_event_type", "profile_value_unit", "records", "samples"} {
		if !seen[key] {
			return nil, errors.New("missing profile application column")
		}
	}
	rows := make([]map[string]json.RawMessage, 0, len(value.Values))
	for _, values := range value.Values {
		if len(values) != len(value.Columns) {
			return nil, errors.New("invalid profile application row width")
		}
		row := make(map[string]json.RawMessage)
		for index, column := range value.Columns {
			row[column] = values[index]
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func normalizeProfileApplications(value *result, scope profileScope) ([]profileApplication, bool, error) {
	rows, err := profileRows(value)
	if err != nil {
		return nil, false, err
	}
	apps := make([]profileApplication, 0, len(rows))
	seen := make(map[string]bool)
	for _, row := range rows {
		var app, language, event, unit string
		var agent *uint16
		if json.Unmarshal(row["app_service"], &app) != nil || json.Unmarshal(row["agent_id"], &agent) != nil || agent == nil || *agent == 0 || !profileApp.MatchString(app) ||
			json.Unmarshal(row["profile_language_type"], &language) != nil || language != "Golang" ||
			json.Unmarshal(row["profile_event_type"], &event) != nil || event != "cpu" ||
			json.Unmarshal(row["profile_value_unit"], &unit) != nil || unit != "samples" || scope.App != "" && scope.App != app || scope.Agent != nil && *scope.Agent != *agent {
			return nil, false, errors.New("profile application metadata differs from fixed scope")
		}
		records, e := countMetric(row, "records")
		samples, se := countMetric(row, "samples")
		key := app + "/" + strconv.Itoa(int(*agent))
		if e != nil || se != nil || records == 0 || samples < records || samples > math.MaxInt64 || seen[key] {
			return nil, false, errors.New("invalid or duplicate profile application aggregate")
		}
		seen[key] = true
		apps = append(apps, profileApplication{app, *agent, language, event, unit, strconv.FormatUint(records, 10), strconv.FormatUint(samples, 10)})
	}
	truncated := len(apps) > profileListLimit
	if truncated {
		apps = apps[:profileListLimit]
	}
	return apps, truncated, nil
}

func (c *console) profiles(w http.ResponseWriter, r *http.Request) {
	scope, err := profileSelection(r.URL.RawQuery, time.Now().Unix(), false)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	d, err := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"profile"}, "sql": {profileListQuery(scope)}}, true)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	apps, truncated, err := normalizeProfileApplications(d.Result, scope)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"profiles": apps, "truncated": truncated, "limit": profileListLimit,
		"scope": map[string]int{"org_id": 1, "user_id": 1}, "os_identity": "not_proven"})
}

type profileFailure struct {
	status int
	code   string
	text   string
}

func (e *profileFailure) Error() string { return e.text }

func (c *console) boundedProfile(ctx context.Context, scope profileScope) (json.RawMessage, error) {
	filter := "profile_value_unit='samples'"
	if scope.Agent != nil {
		filter = fmt.Sprintf("agent_id=%d AND ", *scope.Agent) + filter
	}
	payload, _ := json.Marshal(map[string]any{"app_service": scope.App, "profile_event_type": "cpu", "profile_language_type": "Golang", "time_start": scope.From, "time_end": scope.To,
		"tag_filter": filter, "max_rows": profileRowLimit, "max_kernel_stack_depth": -1})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.query+"/v1/profile/ProfileTracingBounded", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for _, key := range []string{"X-Org-Id", "X-User-Id", "X-User-Type"} {
		req.Header.Set(key, "1")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, errors.New("bounded profile backend unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 404 {
		return nil, &profileFailure{501, "bounded_backend_unsupported", "backend does not support bounded profiles"}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, profileBodyLimit+1))
	if err != nil {
		return nil, errors.New("bounded profile response unreadable")
	}
	if len(raw) > profileBodyLimit {
		return nil, &profileFailure{413, "profile_budget_exceeded", "bounded profile response exceeded the byte budget"}
	}
	var d struct {
		Status string          `json:"OPT_STATUS"`
		Result json.RawMessage `json:"result"`
	}
	if !utf8.Valid(raw) || json.Unmarshal(raw, &d) != nil {
		return nil, errors.New("invalid bounded profile envelope")
	}
	if d.Status == "RESOURCE_NUM_EXCEEDED" {
		return nil, &profileFailure{413, "profile_budget_exceeded", "profile exceeds the backend bounded-query budget; narrow the scope"}
	}
	if resp.StatusCode != 200 || d.Status != "SUCCESS" || len(d.Result) == 0 || string(d.Result) == "null" {
		return nil, errors.New("bounded profile backend rejected the request")
	}
	return d.Result, nil
}

func profileTreeNumber(raw json.RawMessage) (uint64, error) {
	n, err := countMetric(map[string]json.RawMessage{"value": raw}, "value")
	if err != nil || n > math.MaxInt64 {
		return 0, errors.New("invalid exact profile tree value")
	}
	return n, nil
}

func profileTreeIndex(raw json.RawMessage) (int, error) {
	var n *int
	if json.Unmarshal(raw, &n) != nil || n == nil {
		return 0, errors.New("invalid profile tree index")
	}
	return *n, nil
}

func normalizeProfileTree(raw json.RawMessage, scope profileScope) (profileDetail, error) {
	var tree struct {
		Functions      []string       `json:"functions"`
		FunctionTypes  []string       `json:"function_types"`
		FunctionValues result         `json:"function_values"`
		NodeValues     result         `json:"node_values"`
		BoundsApplied  *bool          `json:"bounds_applied"`
		MaxRows        *int           `json:"max_rows"`
		InputRows      *int           `json:"input_rows"`
		Budgets        profileBudgets `json:"budgets"`
	}
	if json.Unmarshal(raw, &tree) != nil || tree.BoundsApplied == nil || !*tree.BoundsApplied || tree.MaxRows == nil || *tree.MaxRows != profileRowLimit || tree.InputRows == nil || *tree.InputRows < 0 || *tree.InputRows > profileRowLimit {
		return profileDetail{}, errors.New("missing or contradictory bounded profile metadata")
	}
	b := tree.Budgets
	if b.CompressedBytes <= 0 || b.CompressedBytes > profileBodyLimit || b.DecodedStackBytes <= 0 || b.DecodedStackBytes > 1024*1024 || b.TotalDecodedStackBytes <= 0 || b.TotalDecodedStackBytes > 8*1024*1024 || b.Nodes <= 0 || b.Nodes > 8192 || b.StackDepth <= 0 || b.StackDepth > 512 {
		return profileDetail{}, errors.New("missing or unsupported native profile budgets")
	}
	d := profileDetail{App: scope.App, AgentID: scope.Agent, Language: "Golang", Event: "cpu", Unit: "samples", BoundsApplied: true, MaxRows: profileRowLimit, InputRows: *tree.InputRows, TotalSamples: "0",
		Functions: make([]profileFunction, 0), Nodes: make([]profileNode, 0), Budgets: b, Scope: map[string]int{"org_id": 1, "user_id": 1}, Identity: "not_proven"}
	if d.InputRows == 0 {
		if len(tree.Functions) != 0 || len(tree.FunctionTypes) != 0 || len(tree.NodeValues.Values) != 0 || len(tree.FunctionValues.Values) != 0 ||
			len(tree.FunctionValues.Columns) != 0 && strings.Join(tree.FunctionValues.Columns, ",") != "self_value,total_value" ||
			len(tree.NodeValues.Columns) != 0 && strings.Join(tree.NodeValues.Columns, ",") != "function_id,parent_node_id,self_value,total_value" {
			return profileDetail{}, errors.New("nonempty tree contradicts empty bounded input")
		}
		d.Empty = true
		return d, nil
	}
	if len(tree.Functions) < 2 || len(tree.Functions) > b.Nodes || len(tree.NodeValues.Values) < 2 || len(tree.NodeValues.Values) > b.Nodes || len(tree.FunctionTypes) != len(tree.Functions) || len(tree.FunctionValues.Values) != len(tree.Functions) ||
		strings.Join(tree.FunctionValues.Columns, ",") != "self_value,total_value" || strings.Join(tree.NodeValues.Columns, ",") != "function_id,parent_node_id,self_value,total_value" || tree.Functions[0] != scope.App {
		return profileDetail{}, errors.New("invalid bounded function/node schema")
	}
	functionSelf, functionTotal := make([]uint64, len(tree.Functions)), make([]uint64, len(tree.Functions))
	parents, totals, ownValues := make([]int, len(tree.NodeValues.Values)), make([]uint64, len(tree.NodeValues.Values)), make([]uint64, len(tree.NodeValues.Values))
	var totalSelf uint64
	for index, row := range tree.NodeValues.Values {
		if len(row) != 4 {
			return profileDetail{}, errors.New("invalid bounded profile node width")
		}
		function, fe := profileTreeIndex(row[0])
		parent, pe := profileTreeIndex(row[1])
		own, se := profileTreeNumber(row[2])
		total, te := profileTreeNumber(row[3])
		if fe != nil || pe != nil || se != nil || te != nil || function < 0 || function >= len(tree.Functions) || parent < -1 || parent >= len(tree.NodeValues.Values) || parent == index || own > total || (index == 0) != (parent == -1) || index == 0 && function != 0 || totalSelf > math.MaxInt64-own || functionSelf[function] > math.MaxInt64-own || functionTotal[function] > math.MaxInt64-total {
			return profileDetail{}, errors.New("invalid bounded profile node/weight")
		}
		parents[index], totals[index], ownValues[index] = parent, total, own
		totalSelf += own
		functionSelf[function] += own
		functionTotal[function] += total
		d.Nodes = append(d.Nodes, profileNode{index, parent, function, strconv.FormatUint(own, 10), strconv.FormatUint(total, 10)})
	}
	if totals[0] == 0 || totals[0] != totalSelf {
		return profileDetail{}, errors.New("profile root and self samples differ")
	}
	d.TotalSamples = strconv.FormatUint(totals[0], 10)
	depths := make(map[int]int)
	depths[0] = 0
	for index := 1; index < len(parents); index++ {
		path, seen, current := []int{}, make(map[int]bool), index
		for {
			if _, known := depths[current]; known {
				break
			}
			if current < 0 || seen[current] || len(path) >= b.StackDepth {
				return profileDetail{}, errors.New("profile tree cycle/depth exceeds bounds")
			}
			seen[current] = true
			path = append(path, current)
			current = parents[current]
		}
		for j := len(path) - 1; j >= 0; j-- {
			node := path[j]
			depths[node] = depths[parents[node]] + 1
			if depths[node] > b.StackDepth {
				return profileDetail{}, errors.New("profile tree depth exceeds bounds")
			}
		}
	}
	children := make([]uint64, len(parents))
	for index := 1; index < len(parents); index++ {
		parent := parents[index]
		if children[parent] > math.MaxInt64-totals[index] {
			return profileDetail{}, errors.New("profile tree child total overflow")
		}
		children[parent] += totals[index]
	}
	for index := range totals {
		if children[index] > math.MaxInt64-ownValues[index] || children[index]+ownValues[index] != totals[index] {
			return profileDetail{}, errors.New("profile node weight differs from children/self")
		}
	}
	for index, name := range tree.Functions {
		row := tree.FunctionValues.Values[index]
		if name == "" || !utf8.ValidString(name) || len(row) != 2 {
			return profileDetail{}, errors.New("invalid bounded profile function")
		}
		own, e := profileTreeNumber(row[0])
		total, te := profileTreeNumber(row[1])
		if e != nil || te != nil || own != functionSelf[index] || total != functionTotal[index] {
			return profileDetail{}, errors.New("profile function weight differs from nodes")
		}
		d.Functions = append(d.Functions, profileFunction{index, name, strconv.FormatUint(own, 10), strconv.FormatUint(total, 10)})
	}
	return d, nil
}

func (c *console) profile(w http.ResponseWriter, r *http.Request) {
	scope, err := profileSelection(r.URL.RawQuery, time.Now().Unix(), true)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	raw, err := c.boundedProfile(ctx, scope)
	if err == nil {
		var detail profileDetail
		detail, err = normalizeProfileTree(raw, scope)
		if err == nil {
			writeJSON(w, 200, detail)
			return
		}
	}
	var bounded *profileFailure
	if errors.As(err, &bounded) {
		writeJSON(w, bounded.status, map[string]string{"error": bounded.text, "code": bounded.code})
		return
	}
	writeJSON(w, 502, map[string]string{"error": err.Error(), "code": "profile_backend_failure"})
}
