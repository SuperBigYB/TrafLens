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
)

func connectionFixture() *result {
	v := make([]json.RawMessage, len(connectionColumns))
	text := map[string]string{"id": "18446744073709551614", "flow_id": "18446744073709551613", "start_us": "100000001", "end_us": "101000001", "duration": "1000000", "time_epoch": "101", "tap_side": "c", "ip_0": "192.0.2.1", "ip_1": "192.0.2.2"}
	for i, k := range connectionColumns {
		if s, ok := text[k]; ok {
			v[i], _ = json.Marshal(s)
			continue
		}
		n := 0
		switch k {
		case "agent_id":
			n = 23
		case "protocol":
			n = 6
		case "client_port":
			n = 40001
		case "server_port":
			n = 18081
		case "close_type":
			n = 1
		case "packet_tx", "packet_rx":
			n = 3
		case "byte_tx", "byte_rx":
			n = 200
		case "l7_protocol":
			n = 20
		}
		v[i] = json.RawMessage(fmt.Sprint(n))
	}
	return &result{Columns: append([]string{}, connectionColumns...), Values: [][]json.RawMessage{v}}
}
func connectionSet(d *result, key string, value any) {
	for i, k := range d.Columns {
		if k == key {
			d.Values[0][i], _ = json.Marshal(value)
		}
	}
}
func TestConnectionSelectionRequiresBoundedExactScope(t *testing.T) {
	for _, raw := range []string{"", "from=100&to=400&agent=23", "from=100&to=101&agent=0", "from=100&to=101&agent=23&id=0", "from=100&to=101&agent=23&flow=1&flow=2", "from=100&to=101&agent=23&q=needle", "from=100&to=101&agent=23&server_port=65536"} {
		if _, e := connectionSelection(raw, 1000, false); e == nil {
			t.Fatal(raw)
		}
	}
	s, e := connectionSelection("from=100&to=399&agent=23&id=18446744073709551614&server_port=18081", 1000, false)
	if e != nil || s.ID != "18446744073709551614" || !strings.Contains(connectionQuery(s), "LIMIT 65") {
		t.Fatal(s, e)
	}
	if _, e = connectionSelection("from=100&to=101&agent=23&flow=1", 1000, true); e == nil {
		t.Fatal("linked lookup lacked exact observation")
	}
}
func TestConnectionRawPrecisionAndUnmeasuredRTT(t *testing.T) {
	rows, e := connectionRows(connectionFixture(), connectionScope{From: 100, To: 102, Agent: 23})
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	n := rows[0]
	if n["id"] != "18446744073709551614" || n["flow_id"] != "18446744073709551613" || n["rtt"] != "0" || n["rtt_available"] != false || n["close_type_name"] != "Normal" {
		t.Fatal(n)
	}
	d := connectionFixture()
	connectionSet(d, "close_type", 65535)
	connectionSet(d, "rtt", 19)
	rows, e = connectionRows(d, connectionScope{From: 100, To: 102, Agent: 23})
	if e != nil || rows[0]["close_type_known"] != false || rows[0]["rtt_available"] != true {
		t.Fatal(rows, e)
	}
}
func TestConnectionMissingMalformedAndOverBudgetAreErrors(t *testing.T) {
	s := connectionScope{From: 100, To: 102, Agent: 23}
	if _, e := connectionRows(nil, s); e == nil {
		t.Fatal("missing result")
	}
	if rows, e := connectionRows(&result{Columns: connectionColumns}, s); e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
	for k, v := range map[string]any{"agent_id": 24, "signal_source": 3, "protocol": 17, "end_us": "99000000", "id": "0", "flow_id": nil, "byte_rx": 1.5} {
		d := connectionFixture()
		connectionSet(d, k, v)
		if _, e := connectionRows(d, s); e == nil {
			t.Fatal(k)
		}
	}
	d := connectionFixture()
	d.Values = make([][]json.RawMessage, 65)
	if _, e := connectionRows(d, s); e != errConnectionLimit {
		t.Fatal(e)
	}
	d = connectionFixture()
	d.Columns = d.Columns[:len(d.Columns)-1]
	if _, e := connectionRows(d, s); e == nil {
		t.Fatal("missing column")
	}
}
func TestConnectionHTTPFailureAndEmptyScopesStayDistinct(t *testing.T) {
	s := connectionScope{From: 100, To: 102, Agent: 23}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if !strings.Contains(r.Form.Get("sql"), "signal_source = 0") {
			t.Error("lost source")
		}
		writeJSON(w, 200, map[string]any{"OPT_STATUS": "SUCCESS", "result": nil})
	}))
	defer up.Close()
	c := &console{query: up.URL, client: up.Client()}
	if _, e := c.loadConnections(context.Background(), s); e == nil {
		t.Fatal("missing result became empty")
	}
	w := httptest.NewRecorder()
	c.connections(w, httptest.NewRequest("GET", "/api/connections?from=100&to=102&agent=23", nil))
	if w.Code != 502 {
		t.Fatal(w.Code, w.Body.String())
	}
}
func connectionHTTPFixture(n map[string]any) *result {
	names := strings.Split("id,flow_id,start_us,end_us,agent_id,signal_source,protocol,l7_protocol,type,ip_0,ip_1,client_port,server_port,l3_epc_id_0,l3_epc_id_1,request_resource", ",")
	row := make([]json.RawMessage, len(names))
	for i, k := range names {
		v := n[k]
		switch k {
		case "id":
			v = "18446744073709551612"
		case "type":
			v = 2
		case "request_resource":
			v = "/owned/normal"
		}
		row[i], _ = json.Marshal(v)
	}
	return &result{Columns: names, Values: [][]json.RawMessage{row}}
}
func TestConnectionLinkedHTTPRequiresNativeFlowAndTuple(t *testing.T) {
	s := connectionScope{From: 100, To: 102, Agent: 23}
	rows, e := connectionRows(connectionFixture(), s)
	if e != nil {
		t.Fatal(e)
	}
	n := rows[0]
	d := connectionHTTPFixture(n)
	if e = validateConnectionRequests(d, s, n); e != nil {
		t.Fatal(e)
	}
	for k, v := range map[string]any{"flow_id": "18446744073709551611", "ip_0": "192.0.2.9", "client_port": 40002, "signal_source": 3, "type": 0, "agent_id": 24, "l3_epc_id_0": -2} {
		d = connectionHTTPFixture(n)
		connectionSet(d, k, v)
		if e = validateConnectionRequests(d, s, n); e == nil {
			t.Fatal(k)
		}
	}
	sql := connectionRequestQuery(s, n)
	for _, want := range []string{"flow_id = 18446744073709551613", "agent_id = 23", "signal_source = 0", "client_port = 40001", "type = 2", "LIMIT 65"} {
		if !strings.Contains(sql, want) {
			t.Fatal(want, sql)
		}
	}
}
func TestConnectionLinkAbsentObservationDoesNotQueryL7(t *testing.T) {
	calls := 0
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		writeJSON(w, 200, map[string]any{"OPT_STATUS": "SUCCESS", "result": &result{Columns: connectionColumns}})
	}))
	defer up.Close()
	c := &console{query: up.URL, client: up.Client()}
	w := httptest.NewRecorder()
	q := url.Values{"from": {"100"}, "to": {"102"}, "agent": {"23"}, "id": {"1"}}
	c.connectionRequests(w, httptest.NewRequest("GET", "/api/connection-requests?"+q.Encode(), nil))
	var d map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &d)
	if w.Code != 200 || calls != 1 || d["connection_found"] != false {
		t.Fatal(w.Code, calls, w.Body.String())
	}
}

func TestConnectionClosingDeadlineDoesNotInventPacketDuration(t *testing.T) {
	d := connectionFixture()
	connectionSet(d, "duration", "7")
	rows, e := connectionRows(d, connectionScope{From: 100, To: 102, Agent: 23})
	if e != nil || rows[0]["duration"] != "7" {
		t.Fatal(rows, e)
	}
	connectionSet(d, "time_epoch", "100")
	if _, e = connectionRows(d, connectionScope{From: 100, To: 102, Agent: 23}); e == nil {
		t.Fatal("native time/end equation contradicted")
	}
}

func TestConnectionNativeNumericFlowStaysExact(t *testing.T) {
	s := connectionScope{From: 100, To: 102, Agent: 23}
	nodes, err := connectionRows(connectionFixture(), s)
	if err != nil {
		t.Fatal(err)
	}
	n := nodes[0]
	d := connectionHTTPFixture(n)
	connectionSet(d, "flow_id", json.Number("18446744073709551613"))
	if err := validateConnectionRequests(d, s, n); err != nil {
		t.Fatal(err)
	}
	for i, k := range d.Columns {
		if k == "flow_id" && string(d.Values[0][i]) != "\"18446744073709551613\"" {
			t.Fatal(string(d.Values[0][i]))
		}
	}
	for _, invalid := range []json.Number{"18446744073709551612", "18446744073709551613.0", "1.8446744073709552e19", "18446744073709551616"} {
		d := connectionHTTPFixture(n)
		connectionSet(d, "flow_id", invalid)
		if err := validateConnectionRequests(d, s, n); err == nil {
			t.Fatal(invalid)
		}
	}
}
