package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const associationLimit = 64

var errAssociationLimit = errors.New("kernel evidence window exceeds 64 observations; narrow the time range")
var associationColumns = strings.Split("id,start_us,end_us,agent_id,signal_source,type,protocol,l7_protocol,tap_side,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,client_port,server_port,req_tcp_seq,resp_tcp_seq,syscall_trace_id_request,syscall_trace_id_response,syscall_cap_seq_0,syscall_cap_seq_1,process_id_0,process_id_1,syscall_thread_0,syscall_thread_1,flow_id,request_resource", ",")

type associationScope struct {
	ID    string
	From  int64
	To    int64
	Agent uint16
}

type associationNode struct {
	ID                 string `json:"id"`
	StartUS            string `json:"start_us"`
	EndUS              string `json:"end_us"`
	AgentID            uint16 `json:"agent_id"`
	SignalSource       uint16 `json:"signal_source"`
	Type               uint8  `json:"type"`
	Protocol           uint8  `json:"protocol"`
	L7Protocol         uint16 `json:"l7_protocol"`
	TapSide            string `json:"tap_side"`
	ClientEPC          int32  `json:"l3_epc_id_0"`
	ServerEPC          int32  `json:"l3_epc_id_1"`
	ClientIP           string `json:"ip_0"`
	ServerIP           string `json:"ip_1"`
	ClientPort         uint16 `json:"client_port"`
	ServerPort         uint16 `json:"server_port"`
	RequestTCPSeq      uint32 `json:"req_tcp_seq"`
	ResponseTCPSeq     uint32 `json:"resp_tcp_seq"`
	RequestSyscallID   string `json:"syscall_trace_id_request"`
	ResponseSyscallID  string `json:"syscall_trace_id_response"`
	RequestCaptureSeq  uint32 `json:"syscall_cap_seq_0"`
	ResponseCaptureSeq uint32 `json:"syscall_cap_seq_1"`
	ClientPID          uint32 `json:"process_id_0"`
	ServerPID          uint32 `json:"process_id_1"`
	RequestThread      uint32 `json:"syscall_thread_0"`
	ResponseThread     uint32 `json:"syscall_thread_1"`
	FlowID             string `json:"flow_id"`
	Resource           string `json:"request_resource"`
	InSeedComponent    bool   `json:"in_seed_component"`
}

type associationEdge struct {
	Kind     string            `json:"kind"`
	FromID   string            `json:"from_id"`
	ToID     string            `json:"to_id"`
	Evidence map[string]string `json:"evidence"`
}

type associationCandidate struct {
	Kind      string            `json:"kind"`
	RecordIDs []string          `json:"record_ids"`
	Reason    string            `json:"reason"`
	Evidence  map[string]string `json:"evidence"`
}

type associationMissing struct {
	RecordID string   `json:"record_id"`
	Fields   []string `json:"fields"`
}

type associationDiagnostics struct {
	SeedFound       bool                 `json:"seed_found"`
	AmbiguousGroups int                  `json:"ambiguous_groups"`
	MissingFields   []associationMissing `json:"missing_fields"`
}

type associationResponse struct {
	SeedID        string                 `json:"seed_id"`
	From          int64                  `json:"from"`
	To            int64                  `json:"to"`
	AgentID       uint16                 `json:"agent_id"`
	SignalSource  uint16                 `json:"signal_source"`
	Limit         int                    `json:"limit"`
	WindowRecords string                 `json:"window_records"`
	Records       string                 `json:"records"`
	Nodes         []associationNode      `json:"nodes"`
	Edges         []associationEdge      `json:"edges"`
	Candidates    []associationCandidate `json:"candidates"`
	Diagnostics   associationDiagnostics `json:"diagnostics"`
	Scope         map[string]int         `json:"scope"`
	Association   string                 `json:"association"`
}

func associationSelection(raw string, now int64) (associationScope, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return associationScope{}, errors.New("invalid kernel evidence scope encoding")
	}
	for key, values := range v {
		if len(values) != 1 || key != "id" && key != "from" && key != "to" && key != "agent" {
			return associationScope{}, errors.New("kernel evidence accepts only id, from, to and agent once")
		}
	}
	if len(v) != 4 {
		return associationScope{}, errors.New("exact id, Agent and explicit inclusive time range are required")
	}
	id, e1 := strconv.ParseUint(v.Get("id"), 10, 64)
	agent, e2 := strconv.ParseUint(v.Get("agent"), 10, 16)
	from, e3 := strconv.ParseInt(v.Get("from"), 10, 64)
	to, e4 := strconv.ParseInt(v.Get("to"), 10, 64)
	if e1 != nil || id == 0 || e2 != nil || agent == 0 || e3 != nil || e4 != nil || from < 1 || to < from || to-from >= 60 || to > now+300 {
		return associationScope{}, errors.New("kernel evidence needs a nonzero UInt64 ID, Agent1..65535 and at most60 inclusive seconds")
	}
	return associationScope{strconv.FormatUint(id, 10), from, to, uint16(agent)}, nil
}

func associationQuery(s associationScope) string {
	projection := "toString(_id) AS id,toUnixTimestamp64Micro(start_time) AS start_us,toUnixTimestamp64Micro(end_time) AS end_us," + strings.Join(associationColumns[3:], ",")
	return "SELECT " + projection + fmt.Sprintf(" FROM l7_flow_log WHERE time >= %d AND time <= %d AND agent_id = %d AND signal_source = 3 AND type = 2 AND protocol = 6 AND l7_protocol = 20 ORDER BY _id ASC LIMIT 65", s.From, s.To, s.Agent)
}

func associationText(raw json.RawMessage) (string, error) {
	var value *string
	if json.Unmarshal(raw, &value) != nil || value == nil || !utf8.ValidString(*value) || len(*value) > 4096 {
		return "", errors.New("invalid kernel evidence string field")
	}
	return *value, nil
}

func associationRows(value *result, s associationScope) ([]associationNode, error) {
	if value == nil {
		return nil, errors.New("missing kernel evidence result")
	}
	if len(value.Values) > associationLimit {
		return nil, errAssociationLimit
	}
	columns := make(map[string]int)
	for i, name := range value.Columns {
		if _, ok := columns[name]; ok {
			return nil, errors.New("duplicate kernel evidence column")
		}
		columns[name] = i
	}
	for _, name := range associationColumns {
		if _, ok := columns[name]; !ok {
			return nil, errors.New("missing kernel evidence scope or identifier column")
		}
	}
	nodes := make([]associationNode, 0, len(value.Values))
	ids := make(map[string]bool)
	for _, values := range value.Values {
		if len(values) != len(value.Columns) {
			return nil, errors.New("malformed kernel evidence row width")
		}
		row := make(map[string]json.RawMessage)
		for key, i := range columns {
			row[key] = values[i]
		}
		numbers := make(map[string]uint64)
		text := make(map[string]string)
		epcs := make(map[string]int32)
		for _, key := range associationColumns {
			switch key {
			case "tap_side", "ip_0", "ip_1", "request_resource":
				value, err := associationText(row[key])
				if err != nil {
					return nil, err
				}
				text[key] = value
			case "l3_epc_id_0", "l3_epc_id_1":
				v, err := strconv.ParseInt(strings.Trim(string(row[key]), `"`), 10, 32)
				if err != nil {
					return nil, errors.New("invalid kernel evidence EPC scope")
				}
				epcs[key] = int32(v)
			default:
				v, err := countMetric(row, key)
				if err != nil {
					return nil, errors.New("invalid exact kernel evidence integer")
				}
				numbers[key] = v
			}
		}
		for _, key := range []string{"process_id_0", "process_id_1", "syscall_thread_0", "syscall_thread_1", "req_tcp_seq", "resp_tcp_seq", "syscall_cap_seq_0", "syscall_cap_seq_1"} {
			if numbers[key] > 1<<32-1 {
				return nil, errors.New("kernel evidence UInt32 overflow")
			}
		}
		id := strconv.FormatUint(numbers["id"], 10)
		if numbers["id"] == 0 || ids[id] || numbers["agent_id"] != uint64(s.Agent) || numbers["signal_source"] != 3 || numbers["type"] != 2 || numbers["protocol"] != 6 || numbers["l7_protocol"] != 20 ||
			numbers["start_us"] == 0 || numbers["end_us"] < numbers["start_us"] || numbers["end_us"]/1000000 < uint64(s.From) || numbers["end_us"]/1000000 > uint64(s.To) || numbers["client_port"] > 65535 || numbers["server_port"] > 65535 {
			return nil, errors.New("kernel evidence metadata contradicts fixed scope")
		}
		for _, key := range []string{"ip_0", "ip_1"} {
			ip, err := netip.ParseAddr(text[key])
			if err != nil || ip.Zone() != "" {
				return nil, errors.New("kernel evidence IP scope is not numeric")
			}
			text[key] = ip.Unmap().String()
		}
		ids[id] = true
		nodes = append(nodes, associationNode{ID: id, StartUS: strconv.FormatUint(numbers["start_us"], 10), EndUS: strconv.FormatUint(numbers["end_us"], 10), AgentID: s.Agent, SignalSource: 3, Type: 2, Protocol: 6, L7Protocol: 20,
			TapSide: text["tap_side"], ClientEPC: epcs["l3_epc_id_0"], ServerEPC: epcs["l3_epc_id_1"], ClientIP: text["ip_0"], ServerIP: text["ip_1"], ClientPort: uint16(numbers["client_port"]), ServerPort: uint16(numbers["server_port"]),
			RequestTCPSeq: uint32(numbers["req_tcp_seq"]), ResponseTCPSeq: uint32(numbers["resp_tcp_seq"]), RequestSyscallID: strconv.FormatUint(numbers["syscall_trace_id_request"], 10), ResponseSyscallID: strconv.FormatUint(numbers["syscall_trace_id_response"], 10),
			RequestCaptureSeq: uint32(numbers["syscall_cap_seq_0"]), ResponseCaptureSeq: uint32(numbers["syscall_cap_seq_1"]), ClientPID: uint32(numbers["process_id_0"]), ServerPID: uint32(numbers["process_id_1"]), RequestThread: uint32(numbers["syscall_thread_0"]), ResponseThread: uint32(numbers["syscall_thread_1"]),
			FlowID: strconv.FormatUint(numbers["flow_id"], 10), Resource: text["request_resource"]})
	}
	return nodes, nil
}

func associationTuple(n associationNode) string {
	return fmt.Sprintf("%d/%d/%d/%s/%s/%d/%d/%d/%d", n.AgentID, n.ClientEPC, n.ServerEPC, n.ClientIP, n.ServerIP, n.ClientPort, n.ServerPort, n.Protocol, n.L7Protocol)
}

func associationPID(n associationNode) uint32 {
	if n.TapSide == "c-p" {
		return n.ClientPID
	}
	if n.TapSide == "s-p" {
		return n.ServerPID
	}
	return 0
}

func associationEvidence(n associationNode, kind string) map[string]string {
	e := map[string]string{"agent_id": strconv.Itoa(int(n.AgentID))}
	if kind == "network_pair" {
		for key, value := range map[string]string{"l3_epc_id_0": fmt.Sprint(n.ClientEPC), "l3_epc_id_1": fmt.Sprint(n.ServerEPC), "ip_0": n.ClientIP, "ip_1": n.ServerIP, "client_port": fmt.Sprint(n.ClientPort), "server_port": fmt.Sprint(n.ServerPort), "protocol": fmt.Sprint(n.Protocol), "l7_protocol": fmt.Sprint(n.L7Protocol), "req_tcp_seq": fmt.Sprint(n.RequestTCPSeq), "resp_tcp_seq": fmt.Sprint(n.ResponseTCPSeq)} {
			e[key] = value
		}
	} else {
		e["process_id"] = fmt.Sprint(associationPID(n))
		e["syscall_trace_id_request"], e["syscall_trace_id_response"] = n.RequestSyscallID, n.ResponseSyscallID
		e["syscall_thread_0"], e["syscall_thread_1"] = fmt.Sprint(n.RequestThread), fmt.Sprint(n.ResponseThread)
	}
	return e
}

func buildAssociations(nodes []associationNode, s associationScope) associationResponse {
	out := associationResponse{SeedID: s.ID, From: s.From, To: s.To, AgentID: s.Agent, SignalSource: 3, Limit: associationLimit, WindowRecords: strconv.Itoa(len(nodes)), Records: "0",
		Nodes: []associationNode{}, Edges: []associationEdge{}, Candidates: []associationCandidate{}, Scope: map[string]int{"org_id": 1, "user_id": 1},
		Diagnostics: associationDiagnostics{MissingFields: []associationMissing{}},
		Association: "Finite source3 TCP/HTTP kernel evidence matches, not inferred Span parents or complete AutoTracing. Agent/PID generations and namespace leases are not stored here. URL, timing, capture sequence and flow ID alone never create an edge; only the seed evidence component and its direct candidates are shown."}
	network, syscall := make(map[string][]associationNode), make(map[string][]associationNode)
	netReq, netResp, sysReq, sysResp := make(map[string][]string), make(map[string][]string), make(map[string][]string), make(map[string][]string)
	missing := make(map[string][]string)
	allEdges := []associationEdge{}
	allCandidates := []associationCandidate{}
	for _, n := range nodes {
		if n.ID == s.ID {
			out.Diagnostics.SeedFound = true
		}
		tuple := associationTuple(n)
		if n.RequestTCPSeq != 0 {
			key := tuple + "/" + fmt.Sprint(n.RequestTCPSeq)
			netReq[key] = append(netReq[key], n.ID)
		}
		if n.ResponseTCPSeq != 0 {
			key := tuple + "/" + fmt.Sprint(n.ResponseTCPSeq)
			netResp[key] = append(netResp[key], n.ID)
		}
		pid := associationPID(n)
		pidKey := fmt.Sprintf("%d/%d/", n.AgentID, pid)
		if pid != 0 && n.RequestSyscallID != "0" {
			key := pidKey + n.RequestSyscallID
			sysReq[key] = append(sysReq[key], n.ID)
		}
		if pid != 0 && n.ResponseSyscallID != "0" {
			key := pidKey + n.ResponseSyscallID
			sysResp[key] = append(sysResp[key], n.ID)
		}
		if pid == 0 {
			// An unsupported side cannot establish a local process, but a known
			// endpoint PID can still make another observation's ID reuse ambiguous.
			possible := map[uint32]bool{n.ClientPID: true, n.ServerPID: true}
			for candidatePID := range possible {
				if candidatePID == 0 {
					continue
				}
				key := fmt.Sprintf("%d/%d/", n.AgentID, candidatePID)
				if n.RequestSyscallID != "0" {
					sysReq[key+n.RequestSyscallID] = append(sysReq[key+n.RequestSyscallID], n.ID)
				}
				if n.ResponseSyscallID != "0" {
					sysResp[key+n.ResponseSyscallID] = append(sysResp[key+n.ResponseSyscallID], n.ID)
				}
			}
		}
		netMissing := []string{}
		for key, absent := range map[string]bool{"req_tcp_seq": n.RequestTCPSeq == 0, "resp_tcp_seq": n.ResponseTCPSeq == 0, "client_port": n.ClientPort == 0, "server_port": n.ServerPort == 0, "ip_0": n.ClientIP == "0.0.0.0" || n.ClientIP == "::", "ip_1": n.ServerIP == "0.0.0.0" || n.ServerIP == "::"} {
			if absent {
				netMissing = append(netMissing, key)
			}
		}
		if n.TapSide != "c-p" && n.TapSide != "s-p" {
			netMissing = append(netMissing, "supported_tap_side")
		}
		if len(netMissing) == 0 {
			network[tuple+fmt.Sprintf("/%d/%d", n.RequestTCPSeq, n.ResponseTCPSeq)] = append(network[tuple+fmt.Sprintf("/%d/%d", n.RequestTCPSeq, n.ResponseTCPSeq)], n)
		} else {
			allCandidates = append(allCandidates, associationCandidate{"network_pair", []string{n.ID}, "insufficient_nonzero_identifiers", associationEvidence(n, "network_pair")})
		}
		sysMissing := []string{}
		for key, absent := range map[string]bool{"side_process_id": pid == 0, "syscall_trace_id_request": n.RequestSyscallID == "0", "syscall_trace_id_response": n.ResponseSyscallID == "0", "syscall_thread_0": n.RequestThread == 0, "syscall_thread_1": n.ResponseThread == 0, "flow_id": n.FlowID == "0"} {
			if absent {
				sysMissing = append(sysMissing, key)
			}
		}
		if len(sysMissing) == 0 {
			key := pidKey + n.RequestSyscallID + "/" + n.ResponseSyscallID + fmt.Sprintf("/%d/%d", n.RequestThread, n.ResponseThread)
			syscall[key] = append(syscall[key], n)
		} else {
			allCandidates = append(allCandidates, associationCandidate{"syscall_handoff", []string{n.ID}, "insufficient_nonzero_identifiers", associationEvidence(n, "syscall_handoff")})
		}
		missing[n.ID] = append(netMissing, sysMissing...)
		sort.Strings(missing[n.ID])
	}
	for _, kind := range []string{"network_pair", "syscall_handoff"} {
		groups := network
		if kind == "syscall_handoff" {
			groups = syscall
		}
		keys := make([]string, 0, len(groups))
		for key := range groups {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			group := groups[key]
			client, server := []associationNode{}, []associationNode{}
			ids := []string{}
			for _, n := range group {
				ids = append(ids, n.ID)
				if n.TapSide == "c-p" {
					client = append(client, n)
				} else {
					server = append(server, n)
				}
			}
			n := group[0]
			reason := ""
			if len(client) != 1 || len(server) != 1 {
				reason = "missing_counterpart"
				if len(client) > 1 || len(server) > 1 {
					reason = "ambiguous_identity_reuse"
				}
			} else if kind == "network_pair" {
				tuple := associationTuple(n)
				if len(netReq[tuple+"/"+fmt.Sprint(n.RequestTCPSeq)]) != 2 || len(netResp[tuple+"/"+fmt.Sprint(n.ResponseTCPSeq)]) != 2 {
					reason = "ambiguous_identity_reuse"
				}
			} else {
				pidKey := fmt.Sprintf("%d/%d/", n.AgentID, associationPID(n))
				if len(sysReq[pidKey+n.RequestSyscallID]) != 2 || len(sysResp[pidKey+n.ResponseSyscallID]) != 2 {
					reason = "ambiguous_identity_reuse"
				} else if client[0].FlowID == server[0].FlowID {
					reason = "same_socket_not_handoff"
				}
			}
			evidence := associationEvidence(n, kind)
			if reason != "" {
				if reason == "ambiguous_identity_reuse" {
					var requestIDs, responseIDs []string
					if kind == "network_pair" {
						tuple := associationTuple(n)
						requestIDs, responseIDs = netReq[tuple+"/"+fmt.Sprint(n.RequestTCPSeq)], netResp[tuple+"/"+fmt.Sprint(n.ResponseTCPSeq)]
					} else {
						pidKey := fmt.Sprintf("%d/%d/", n.AgentID, associationPID(n))
						requestIDs, responseIDs = sysReq[pidKey+n.RequestSyscallID], sysResp[pidKey+n.ResponseSyscallID]
					}
					identities := make(map[string]bool)
					for _, id := range append(append(ids, requestIDs...), responseIDs...) {
						identities[id] = true
					}
					ids = []string{}
					for id := range identities {
						ids = append(ids, id)
					}
					sort.Strings(ids)
					evidence["request_identity_observations"], evidence["response_identity_observations"] = fmt.Sprint(len(requestIDs)), fmt.Sprint(len(responseIDs))
				}
				allCandidates = append(allCandidates, associationCandidate{kind, ids, reason, evidence})
				continue
			}
			from, to := client[0], server[0]
			if kind == "syscall_handoff" {
				from, to = server[0], client[0]
				evidence["upstream_flow_id"], evidence["downstream_flow_id"] = from.FlowID, to.FlowID
			}
			allEdges = append(allEdges, associationEdge{kind, from.ID, to.ID, evidence})
		}
	}
	if !out.Diagnostics.SeedFound {
		return out
	}
	component := map[string]bool{s.ID: true}
	for changed := true; changed; {
		changed = false
		for _, edge := range allEdges {
			if component[edge.FromID] != component[edge.ToID] {
				component[edge.FromID], component[edge.ToID], changed = true, true, true
			}
		}
	}
	included := make(map[string]bool)
	for id := range component {
		included[id] = true
	}
	for _, edge := range allEdges {
		if component[edge.FromID] && component[edge.ToID] {
			out.Edges = append(out.Edges, edge)
		}
	}
	for _, candidate := range allCandidates {
		relevant := false
		for _, id := range candidate.RecordIDs {
			relevant = relevant || component[id]
		}
		if relevant {
			out.Candidates = append(out.Candidates, candidate)
			if candidate.Reason == "ambiguous_identity_reuse" {
				out.Diagnostics.AmbiguousGroups++
			}
			for _, id := range candidate.RecordIDs {
				included[id] = true
			}
		}
	}
	for _, n := range nodes {
		if included[n.ID] {
			n.InSeedComponent = component[n.ID]
			out.Nodes = append(out.Nodes, n)
			if len(missing[n.ID]) > 0 {
				out.Diagnostics.MissingFields = append(out.Diagnostics.MissingFields, associationMissing{n.ID, missing[n.ID]})
			}
		}
	}
	out.Records = strconv.Itoa(len(out.Nodes))
	return out
}

func (c *console) associations(w http.ResponseWriter, r *http.Request) {
	scope, err := associationSelection(r.URL.RawQuery, time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	d, err := c.upstream(ctx, c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {associationQuery(scope)}}, true)
	if err == nil {
		var nodes []associationNode
		nodes, err = associationRows(d.Result, scope)
		if err == nil {
			writeJSON(w, 200, buildAssociations(nodes, scope))
			return
		}
	}
	if errors.Is(err, errAssociationLimit) {
		writeJSON(w, 413, map[string]string{"error": err.Error(), "code": "association_rows_exceeded"})
		return
	}
	writeJSON(w, 502, map[string]string{"error": err.Error()})
}
