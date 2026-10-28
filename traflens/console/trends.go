package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const trendLimit = 240

// These sub-day intervals divide the qualified backend's UTC+8 offset. Longer
// calendar-day intervals would not establish UTC epoch alignment on that backend.
var trendSteps = [...]int64{60, 300, 900, 3600, 14400}

type trendPlan struct {
	Queries []string
	From    int64
	To      int64
	Step    int64
}

type trendBucket struct {
	From int64 `json:"from"`
	To   int64 `json:"to"`
	redStats
}

type trendStats struct {
	Buckets      []trendBucket `json:"buckets"`
	StepSeconds  int64         `json:"step_seconds"`
	MaxBuckets   int           `json:"max_buckets"`
	Counting     string        `json:"counting"`
	DurationUnit string        `json:"duration_unit"`
	Atomic       bool          `json:"atomic"`
}

func trendQueries(input url.Values, now int64) (trendPlan, error) {
	if input.Has("id") || input.Has("limit") {
		return trendPlan{}, errors.New("trends does not accept id or limit")
	}
	values := make(url.Values)
	for key, items := range input {
		values[key] = append([]string(nil), items...)
	}
	step := int64(0)
	if values.Has("step") {
		var err error
		step, err = strconv.ParseInt(values.Get("step"), 10, 64)
		allowed := false
		for _, candidate := range trendSteps {
			allowed = allowed || step == candidate
		}
		if err != nil || len(values["step"]) != 1 || !allowed {
			return trendPlan{}, errors.New("step must be 60, 300, 900, 3600 or 14400 seconds")
		}
		values.Del("step")
	}
	if values.Has("session") && (len(values["session"]) != 1 || values.Get("session") != "1") {
		return trendPlan{}, errors.New("session must be 1")
	}
	values.Set("session", "1")
	where, err := selectionWhere(values, now)
	if err != nil {
		return trendPlan{}, err
	}
	from, to := now-86400, now
	if values.Has("from") {
		from, _ = strconv.ParseInt(values.Get("from"), 10, 64)
	}
	if values.Has("to") {
		to, _ = strconv.ParseInt(values.Get("to"), 10, 64)
	}
	if step == 0 {
		for _, candidate := range trendSteps {
			if to/candidate-from/candidate+1 <= trendLimit {
				step = candidate
				break
			}
		}
	}
	if step == 0 || to/step-from/step+1 > trendLimit {
		return trendPlan{}, errors.New("selected step exceeds 240 aligned buckets")
	}
	tail := " GROUP BY bucket ORDER BY bucket LIMIT 241"
	prefix := fmt.Sprintf("SELECT time(time,%d) AS bucket,", step)
	return trendPlan{Queries: []string{
		prefix + "Count(row) AS records,Sum(client_error) AS client_errors,Sum(server_error) AS server_errors FROM l7_flow_log WHERE " + where + tail,
		prefix + "Count(row) AS duration_samples,Avg(response_duration) AS avg_us,Max(response_duration) AS max_us FROM l7_flow_log WHERE " + where + " AND response_duration > 0" + tail,
	}, From: from, To: to, Step: step}, nil
}

func trendRows(value *result, columns []string, plan trendPlan) (map[int64]map[string]json.RawMessage, error) {
	rows := make(map[int64]map[string]json.RawMessage)
	if value == nil {
		return nil, errors.New("missing trend aggregate result")
	}
	if len(value.Values) > trendLimit {
		return nil, errors.New("trend aggregate exceeded bounded bucket count")
	}
	seen := make(map[string]bool)
	for _, column := range value.Columns {
		if seen[column] {
			return nil, errors.New("duplicate trend aggregate column")
		}
		seen[column] = true
	}
	for _, column := range append([]string{"bucket"}, columns...) {
		if !seen[column] {
			return nil, errors.New("missing trend aggregate column")
		}
	}
	for _, values := range value.Values {
		if len(values) != len(value.Columns) {
			return nil, errors.New("invalid trend aggregate row width")
		}
		row := make(map[string]json.RawMessage)
		for index, column := range value.Columns {
			row[column] = values[index]
		}
		var parsed *int64
		if json.Unmarshal(row["bucket"], &parsed) != nil || parsed == nil {
			return nil, errors.New("invalid epoch bucket value")
		}
		bucket := *parsed
		if bucket < 0 || bucket%plan.Step != 0 || bucket < plan.From/plan.Step*plan.Step || bucket > plan.To/plan.Step*plan.Step || rows[bucket] != nil {
			return nil, errors.New("invalid, out-of-range or duplicate epoch bucket")
		}
		rows[bucket] = row
	}
	return rows, nil
}

func trendAggregate(row map[string]json.RawMessage, columns []string) *result {
	if row == nil {
		return nil
	}
	values := make([]json.RawMessage, len(columns))
	for index, column := range columns {
		values[index] = row[column]
	}
	return &result{Columns: columns, Values: [][]json.RawMessage{values}}
}

func parseTrends(summary, duration *result, plan trendPlan) (trendStats, error) {
	if plan.Step < 1 || plan.From < 0 || plan.To < plan.From || plan.To/plan.Step-plan.From/plan.Step+1 > trendLimit {
		return trendStats{}, errors.New("invalid bounded trend plan")
	}
	countColumns := []string{"records", "client_errors", "server_errors"}
	durationColumns := []string{"duration_samples", "avg_us", "max_us"}
	counts, err := trendRows(summary, countColumns, plan)
	if err != nil {
		return trendStats{}, err
	}
	durations, err := trendRows(duration, durationColumns, plan)
	if err != nil {
		return trendStats{}, err
	}
	for bucket, row := range durations {
		samples, e := countMetric(row, "duration_samples")
		if e != nil || samples == 0 || counts[bucket] == nil {
			return trendStats{}, errors.New("duration bucket contradicts count snapshot")
		}
	}
	d := trendStats{Buckets: make([]trendBucket, 0), StepSeconds: plan.Step, MaxBuckets: trendLimit,
		Counting: "session_observation_records", DurationUnit: "us", Atomic: false}
	for bucket := plan.From / plan.Step * plan.Step; bucket <= plan.To; bucket += plan.Step {
		from, to := bucket, bucket+plan.Step-1
		if from < plan.From {
			from = plan.From
		}
		if to > plan.To {
			to = plan.To
		}
		a := trendAggregate(counts[bucket], countColumns)
		b := trendAggregate(durations[bucket], durationColumns)
		if b == nil && a != nil {
			// GROUP BY over positive durations normally omits all-zero buckets.
			// This is different from a failed query or missing required column.
			b = &result{Columns: durationColumns, Values: [][]json.RawMessage{{json.RawMessage("0"), json.RawMessage("null"), json.RawMessage("null")}}}
		}
		stats, e := parseRED(a, b, to-from+1)
		if e != nil {
			return trendStats{}, e
		}
		if stats.AverageUS != nil {
			maximum, _ := strconv.ParseUint(*stats.MaximumUS, 10, 64)
			if *stats.AverageUS > float64(maximum) {
				return trendStats{}, errors.New("duration mean exceeds maximum")
			}
		}
		d.Buckets = append(d.Buckets, trendBucket{From: from, To: to, redStats: stats})
	}
	return d, nil
}

func (c *console) trends(w http.ResponseWriter, r *http.Request) {
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid trend query"})
		return
	}
	plan, err := trendQueries(values, time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	results := make([]*result, 0, 2)
	for _, sql := range plan.Queries {
		value, e := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {sql}}, false)
		if e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		results = append(results, value.Result)
	}
	stats, err := parseTrends(results[0], results[1], plan)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, stats)
}
