package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type redStats struct {
	Records         string   `json:"records"`
	ClientErrors    string   `json:"client_errors"`
	ServerErrors    string   `json:"server_errors"`
	Errors          string   `json:"errors"`
	DurationSamples string   `json:"duration_samples"`
	Unmeasured      string   `json:"unmeasured_duration_records"`
	WindowSeconds   int64    `json:"window_seconds"`
	RecordRate      float64  `json:"record_rate"`
	ErrorRatio      *float64 `json:"error_ratio"`
	AverageUS       *float64 `json:"avg_us"`
	MaximumUS       *string  `json:"max_us"`
	Counting        string   `json:"counting"`
	DurationUnit    string   `json:"duration_unit"`
}

func redQueries(input url.Values, now int64) ([]string, int64, error) {
	if input.Has("id") || input.Has("limit") {
		return nil, 0, errors.New("RED does not accept id or limit")
	}
	values := make(url.Values)
	for key, items := range input {
		values[key] = append([]string(nil), items...)
	}
	if values.Has("session") && (len(values["session"]) != 1 || values.Get("session") != "1") {
		return nil, 0, errors.New("session must be 1")
	}
	values.Set("session", "1")
	where, err := selectionWhere(values, now)
	if err != nil {
		return nil, 0, err
	}
	from, to := now-86400, now
	if values.Has("from") {
		from, _ = strconv.ParseInt(values.Get("from"), 10, 64)
	}
	if values.Has("to") {
		to, _ = strconv.ParseInt(values.Get("to"), 10, 64)
	}
	return []string{
		"SELECT Count(row) AS records,Sum(client_error) AS client_errors,Sum(server_error) AS server_errors FROM l7_flow_log WHERE " + where,
		"SELECT Count(row) AS duration_samples,Avg(response_duration) AS avg_us,Max(response_duration) AS max_us FROM l7_flow_log WHERE " + where + " AND response_duration > 0",
	}, to - from + 1, nil
}

func metricRow(value *result) (map[string]json.RawMessage, error) {
	if value == nil || len(value.Values) == 0 {
		return nil, nil
	}
	if len(value.Values) != 1 || len(value.Values[0]) != len(value.Columns) {
		return nil, errors.New("invalid RED aggregate row")
	}
	row := make(map[string]json.RawMessage)
	for i, column := range value.Columns {
		row[column] = value.Values[0][i]
	}
	return row, nil
}

func countMetric(row map[string]json.RawMessage, key string) (uint64, error) {
	if row == nil {
		return 0, nil
	}
	n, err := strconv.ParseUint(strings.Trim(string(row[key]), `"`), 10, 64)
	if err != nil {
		return 0, errors.New("invalid RED count")
	}
	return n, nil
}

func parseRED(summary, duration *result, window int64) (redStats, error) {
	a, err := metricRow(summary)
	if err != nil {
		return redStats{}, err
	}
	b, err := metricRow(duration)
	if err != nil {
		return redStats{}, err
	}
	counts := make([]uint64, 4)
	for i, key := range []string{"records", "client_errors", "server_errors", "duration_samples"} {
		row := a
		if i == 3 {
			row = b
		}
		counts[i], err = countMetric(row, key)
		if err != nil {
			return redStats{}, err
		}
	}
	n, client, server, samples := counts[0], counts[1], counts[2], counts[3]
	if n > 0 && b == nil {
		return redStats{}, errors.New("missing duration aggregate")
	}
	if window <= 0 || client > n || server > n-client || samples > n {
		return redStats{}, errors.New("inconsistent RED aggregate snapshots")
	}
	d := redStats{Records: strconv.FormatUint(n, 10), ClientErrors: strconv.FormatUint(client, 10),
		ServerErrors: strconv.FormatUint(server, 10), Errors: strconv.FormatUint(client+server, 10),
		DurationSamples: strconv.FormatUint(samples, 10), Unmeasured: strconv.FormatUint(n-samples, 10),
		WindowSeconds: window, RecordRate: float64(n) / float64(window), Counting: "session_observation_records", DurationUnit: "us"}
	if n > 0 {
		ratio := float64(client+server) / float64(n)
		d.ErrorRatio = &ratio
	}
	if samples > 0 {
		var average float64
		if json.Unmarshal(b["avg_us"], &average) != nil || math.IsNaN(average) || math.IsInf(average, 0) || average <= 0 {
			return redStats{}, errors.New("invalid positive duration mean")
		}
		maximum, e := countMetric(b, "max_us")
		if e != nil || maximum == 0 {
			return redStats{}, errors.New("invalid positive duration maximum")
		}
		text := strconv.FormatUint(maximum, 10)
		d.AverageUS, d.MaximumUS = &average, &text
	}
	return d, nil
}

func (c *console) red(w http.ResponseWriter, r *http.Request) {
	queries, window, err := redQueries(r.URL.Query(), time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	results := make([]*result, 0, 2)
	for _, sql := range queries {
		value, e := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {sql}}, false)
		if e != nil {
			writeJSON(w, 502, map[string]string{"error": e.Error()})
			return
		}
		results = append(results, value.Result)
	}
	stats, err := parseRED(results[0], results[1], window)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": fmt.Sprint(err)})
		return
	}
	writeJSON(w, 200, stats)
}
