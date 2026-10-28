package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const connectionLimit = 64

var errConnectionLimit = errors.New("TCP observation window exceeds64 rows; narrow its scope")
var connectionColumns = strings.Split("id,flow_id,start_us,end_us,time_epoch,duration,agent_id,signal_source,tap_side,protocol,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,close_type,packet_tx,packet_rx,byte_tx,byte_rx,total_packet_tx,total_packet_rx,total_byte_tx,total_byte_rx,l3_byte_tx,l3_byte_rx,l4_byte_tx,l4_byte_rx,rtt,rtt_client,rtt_server,retrans_tx,retrans_rx,l7_protocol", ",")
var connectionCloseNames = map[uint64]string{0: "Others", 1: "Normal", 2: "Transfer - Server RST", 3: "Transfer - Timeout", 5: "Force Report", 7: "Est. - Server SYN Miss", 8: "Close - Server Half Close", 9: "Transfer - Client RST", 10: "Est. - Client ACK Miss", 11: "Close - Client Half Close", 13: "Est. - Client Port Reuse", 15: "Est. - Server Direct RST", 17: "Transfer - Server Queue Overflow", 18: "Est. - Client Other RST", 19: "Est. - Server Other RST", 20: "Normal - Client RST"}

type connectionScope struct {
	From, To int64
	Agent    uint16
	ID, Flow string
	Port     uint16
}

func connectionSelection(raw string, now int64, linked bool) (connectionScope, error) {
	v, e := url.ParseQuery(raw)
	if e != nil {
		return connectionScope{}, errors.New("invalid connection scope encoding")
	}
	for k, x := range v {
		if len(x) != 1 || k != "from" && k != "to" && k != "agent" && k != "id" && (linked || k != "flow" && k != "server_port") {
			return connectionScope{}, errors.New("connection scope accepts from,to,agent and optional id,flow,server_port once")
		}
	}
	f, e1 := strconv.ParseInt(v.Get("from"), 10, 64)
	t, e2 := strconv.ParseInt(v.Get("to"), 10, 64)
	a, e3 := strconv.ParseUint(v.Get("agent"), 10, 16)
	if e1 != nil || e2 != nil || e3 != nil || f < 1 || t < f || t-f >= 300 || t > now+300 || a == 0 {
		return connectionScope{}, errors.New("explicit Agent1..65535 and at most300 inclusive seconds required")
	}
	s := connectionScope{From: f, To: t, Agent: uint16(a)}
	for _, k := range []string{"id", "flow", "server_port"} {
		if !v.Has(k) {
			continue
		}
		bits := 64
		if k == "server_port" {
			bits = 16
		}
		n, e := strconv.ParseUint(v.Get(k), 10, bits)
		if e != nil || n == 0 {
			return s, errors.New("connection identifiers and port must be nonzero exact unsigned integers")
		}
		switch k {
		case "id":
			s.ID = strconv.FormatUint(n, 10)
		case "flow":
			s.Flow = strconv.FormatUint(n, 10)
		case "server_port":
			s.Port = uint16(n)
		}
	}
	if linked && s.ID == "" {
		return s, errors.New("exact L4 observation ID required for request lookup")
	}
	return s, nil
}
func connectionQuery(s connectionScope) string {
	projection := "toString(_id) AS id,toString(flow_id) AS flow_id,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us,toUnixTimestamp(time) AS time_epoch," + strings.Join(connectionColumns[5:], ",")
	where := fmt.Sprintf("time >= %d AND time <= %d AND agent_id = %d AND signal_source = 0 AND protocol = 6", s.From, s.To, s.Agent)
	if s.ID != "" {
		where += " AND _id = " + s.ID
	}
	if s.Flow != "" {
		where += " AND flow_id = " + s.Flow
	}
	if s.Port != 0 {
		where += fmt.Sprintf(" AND server_port = %d", s.Port)
	}
	return "SELECT " + projection + " FROM l4_flow_log WHERE " + where + " ORDER BY _id ASC LIMIT 65"
}
func connectionRows(d *result, s connectionScope) ([]map[string]any, error) {
	if d == nil {
		return nil, errors.New("missing L4 result")
	}
	if len(d.Values) > connectionLimit {
		return nil, errConnectionLimit
	}
	idx := map[string]int{}
	for i, k := range d.Columns {
		if _, ok := idx[k]; ok {
			return nil, errors.New("duplicate L4 column")
		}
		idx[k] = i
	}
	for _, k := range connectionColumns {
		if _, ok := idx[k]; !ok {
			return nil, errors.New("missing L4 column")
		}
	}
	out := make([]map[string]any, 0, len(d.Values))
	seen := map[string]bool{}
	for _, values := range d.Values {
		if len(values) != len(d.Columns) {
			return nil, errors.New("invalid L4 row width")
		}
		raw := map[string]json.RawMessage{}
		for k, i := range idx {
			raw[k] = values[i]
		}
		n := map[string]uint64{}
		node := map[string]any{}
		for _, k := range connectionColumns {
			switch k {
			case "tap_side", "ip_0", "ip_1":
				text, e := associationText(raw[k])
				if e != nil {
					return nil, e
				}
				if k != "tap_side" {
					ip, e := netip.ParseAddr(text)
					if e != nil || ip.Zone() != "" {
						return nil, errors.New("invalid L4 IP")
					}
					text = ip.Unmap().String()
				}
				node[k] = text
			case "l3_epc_id_0", "l3_epc_id_1":
				value := string(raw[k])
				if len(value) >= 2 && value[0] == '"' {
					if json.Unmarshal(raw[k], &value) != nil {
						return nil, errors.New("invalid L4 EPC")
					}
				}
				number, e := strconv.ParseInt(value, 10, 32)
				if e != nil {
					return nil, errors.New("invalid L4 EPC")
				}
				node[k] = int32(number)
			default:
				number, e := countMetric(raw, k)
				if e != nil {
					return nil, errors.New("invalid exact L4 integer")
				}
				n[k] = number
				switch k {
				case "agent_id", "signal_source", "protocol", "client_port", "server_port", "close_type", "l7_protocol":
					node[k] = number
				default:
					node[k] = strconv.FormatUint(number, 10)
				}
			}
		}
		id := strconv.FormatUint(n["id"], 10)
		if n["id"] == 0 || n["flow_id"] == 0 || seen[id] || n["agent_id"] != uint64(s.Agent) || n["signal_source"] != 0 || n["protocol"] != 6 || n["start_us"] == 0 || n["end_us"] < n["start_us"] || n["end_us"]/1000000 < uint64(s.From) || n["end_us"]/1000000 > uint64(s.To) || n["time_epoch"] != n["end_us"]/1000000 || n["client_port"] > 65535 || n["server_port"] > 65535 || n["close_type"] > 65535 || n["l7_protocol"] > 65535 || s.ID != "" && id != s.ID || s.Flow != "" && node["flow_id"] != s.Flow || s.Port != 0 && n["server_port"] != uint64(s.Port) {
			return nil, errors.New("L4 metadata contradicts fixed scope")
		}
		seen[id] = true
		label, known := connectionCloseNames[n["close_type"]]
		if !known {
			label = "Unknown close code"
		}
		node["close_type_name"] = label
		node["close_type_known"] = known
		node["rtt_available"] = n["rtt"] > 0
		node["rtt_client_available"] = n["rtt_client"] > 0
		node["rtt_server_available"] = n["rtt_server"] > 0
		out = append(out, node)
	}
	if s.ID != "" && len(out) > 1 {
		return nil, errors.New("duplicate exact L4 observation")
	}
	return out, nil
}
func (c *console) loadConnections(ctx context.Context, s connectionScope) ([]map[string]any, error) {
	d, e := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {connectionQuery(s)}}, false)
	if e != nil {
		return nil, e
	}
	return connectionRows(d.Result, s)
}
func connectionFailure(w http.ResponseWriter, e error) {
	if errors.Is(e, errConnectionLimit) {
		writeJSON(w, 413, map[string]string{"error": "connection_rows_exceeded", "message": e.Error()})
		return
	}
	writeJSON(w, 502, map[string]string{"error": "connection_backend_failed", "message": e.Error()})
}
func (c *console) connections(w http.ResponseWriter, r *http.Request) {
	s, e := connectionSelection(r.URL.RawQuery, time.Now().Unix(), false)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	rows, e := c.loadConnections(ctx, s)
	if e != nil {
		connectionFailure(w, e)
		return
	}
	writeJSON(w, 200, map[string]any{"from": s.From, "to": s.To, "agent_id": s.Agent, "signal_source": 0, "limit": connectionLimit, "records": strconv.Itoa(len(rows)), "connections": rows,
		"semantics": map[string]string{"counting": "L4 observation reports, not unique business connections; Force Report is periodic", "duration_unit": "us", "rtt_unit": "us; TCP handshake/max-side measurement, not HTTP response time", "zero_rtt": "no positive measurement; missing/unmeasured or below resolution, not healthy zero delay", "packet": "observed packets in this report", "byte": "observed packet length, including headers; not application bytes", "total": "flow lifetime cumulative; do not sum totals across periodic reports", "identity": "native packet source0/Agent/flow/tuple scope; no process generation or inferred causality"}})
}
func connectionRequestQuery(s connectionScope, n map[string]any) string {
	return "SELECT " + fields + ",toString(flow_id) AS flow_id,client_port,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us FROM l7_flow_log WHERE " +
		fmt.Sprintf("time >= %d AND time <= %d AND agent_id = %d AND signal_source = 0 AND protocol = 6 AND l7_protocol = 20 AND type = 2 AND flow_id = %s AND ip_0 = '%s' AND ip_1 = '%s' AND client_port = %d AND server_port = %d AND l3_epc_id_0 = %d AND l3_epc_id_1 = %d",
			s.From, s.To, s.Agent, n["flow_id"], n["ip_0"], n["ip_1"], n["client_port"], n["server_port"], n["l3_epc_id_0"], n["l3_epc_id_1"]) + " ORDER BY _id ASC LIMIT 65"
}
func validateConnectionRequests(d *result, s connectionScope, n map[string]any) error {
	if d == nil {
		return errors.New("missing same-flow HTTP result")
	}
	if len(d.Values) > connectionLimit {
		return errConnectionLimit
	}
	idx := map[string]int{}
	for i, k := range d.Columns {
		if _, ok := idx[k]; ok {
			return errors.New("duplicate same-flow HTTP column")
		}
		idx[k] = i
	}
	needed := strings.Split("id,flow_id,start_us,end_us,agent_id,signal_source,protocol,l7_protocol,type,ip_0,ip_1,client_port,server_port,l3_epc_id_0,l3_epc_id_1,request_resource", ",")
	for _, k := range needed {
		if _, ok := idx[k]; !ok {
			return errors.New("missing same-flow HTTP identity column")
		}
	}
	seen := map[string]bool{}
	for _, v := range d.Values {
		if len(v) != len(d.Columns) {
			return errors.New("invalid same-flow HTTP row width")
		}
		raw := map[string]json.RawMessage{}
		for k, i := range idx {
			raw[k] = v[i]
		}
		id, e := associationText(raw["id"])
		if e != nil {
			return e
		}
		number, e := strconv.ParseUint(id, 10, 64)
		if e != nil || number == 0 || seen[id] {
			return errors.New("invalid same-flow HTTP ID")
		}
		seen[id] = true
		for _, k := range []string{"agent_id", "signal_source", "protocol", "l7_protocol", "type", "client_port", "server_port"} {
			value, e := countMetric(raw, k)
			expected := uint64(0)
			switch k {
			case "agent_id":
				expected = uint64(s.Agent)
			case "protocol":
				expected = 6
			case "l7_protocol":
				expected = 20
			case "type":
				expected = 2
			case "client_port", "server_port":
				expected = n[k].(uint64)
			}
			if e != nil || value != expected {
				return errors.New("same-flow HTTP scope mismatch")
			}
		}
		// The native translator may return toString(flow_id) as an unquoted
		// UInt64. Parse its raw decimal bytes, never through float64, then
		// return a string so browsers also preserve every identity bit.
		flow, flowError := countMetric(raw, "flow_id")
		if flowError != nil || flow == 0 || strconv.FormatUint(flow, 10) != n["flow_id"] {
			return errors.New("same-flow HTTP flow identity mismatch")
		}
		v[idx["flow_id"]], _ = json.Marshal(strconv.FormatUint(flow, 10))
		for _, k := range []string{"ip_0", "ip_1"} {
			value, e := associationText(raw[k])
			if e != nil || value != n[k] {
				return errors.New("same-flow HTTP identity mismatch")
			}
		}
		for _, k := range []string{"l3_epc_id_0", "l3_epc_id_1"} {
			var value json.Number
			if json.Unmarshal(raw[k], &value) != nil {
				return errors.New("invalid HTTP EPC")
			}
			i, e := strconv.ParseInt(value.String(), 10, 32)
			if e != nil || int32(i) != n[k] {
				return errors.New("same-flow HTTP EPC mismatch")
			}
		}
		start, e1 := countMetric(raw, "start_us")
		end, e2 := countMetric(raw, "end_us")
		if e1 != nil || e2 != nil || start == 0 || end < start || end/1000000 < uint64(s.From) || end/1000000 > uint64(s.To) {
			return errors.New("same-flow HTTP time mismatch")
		}
		if _, e := associationText(raw["request_resource"]); e != nil {
			return e
		}
	}
	return nil
}
func (c *console) connectionRequests(w http.ResponseWriter, r *http.Request) {
	s, e := connectionSelection(r.URL.RawQuery, time.Now().Unix(), true)
	if e != nil {
		writeJSON(w, 400, map[string]string{"error": e.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	rows, e := c.loadConnections(ctx, s)
	if e != nil {
		connectionFailure(w, e)
		return
	}
	response := map[string]any{"connection_found": len(rows) == 1, "connection_id": s.ID, "flow_id": "", "relation": "native_packet_same_flow_scope", "requests": &result{Columns: []string{}, Values: [][]json.RawMessage{}}, "meaning": "HTTP Session observations with same recorded native flow/Agent/source/tuple/EPC in the selected window; not one request per connection or causality within a periodic report"}
	if len(rows) == 1 {
		d, e := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {connectionRequestQuery(s, rows[0])}}, false)
		if e != nil {
			connectionFailure(w, e)
			return
		}
		if e = validateConnectionRequests(d.Result, s, rows[0]); e != nil {
			connectionFailure(w, e)
			return
		}
		if d.Result.Values == nil {
			d.Result.Values = [][]json.RawMessage{}
		}
		response["flow_id"] = rows[0]["flow_id"]
		response["requests"] = d.Result
	}
	writeJSON(w, 200, response)
}
