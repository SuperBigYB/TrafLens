package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestInclusiveSingleSecondDrillDown(t *testing.T) {
	v := url.Values{"from": {"100"}, "to": {"100"}, "agent": {"7"}, "source": {"0"}}
	query, err := selection(v, 1000)
	if err != nil || !strings.Contains(query, "time >= 100 AND time <= 100") || !strings.Contains(query, "agent_id = 7") {
		t.Fatalf("single-second detail range lost its exact scope: %s %v", query, err)
	}
	queries, seconds, err := redQueries(v, 1000)
	if err != nil || seconds != 1 || len(queries) != 2 {
		t.Fatalf("inclusive single-second RED interval rejected: %v %d %v", queries, seconds, err)
	}
	v.Set("to", "99")
	if _, err := selection(v, 1000); err == nil {
		t.Fatal("reversed interval accepted")
	}
}
