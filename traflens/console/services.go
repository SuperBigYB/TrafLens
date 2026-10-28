package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const relationshipFields = "agent_id,signal_source,l3_epc_id_0,l3_epc_id_1,ip_0,ip_1,server_port,protocol,l7_protocol,observation_point"
const relationshipLimit = 100

var observationPoint = regexp.MustCompile(`^[a-z0-9-]{0,32}$`)

// Endpoint identity includes Agent/EPC and observation context. IP:port alone
// would combine different address spaces and client/server observations.
func relationshipFilter(k, value string) (string, error) {
	switch k {
	case "client_ip", "server_ip":
		ip, err := netip.ParseAddr(value)
		if err != nil || ip.Zone() != "" {
			return "", errors.New("endpoint must be a numeric IP without a zone")
		}
		column := "ip_0"
		if k == "server_ip" {
			column = "ip_1"
		}
		return column + " = '" + ip.Unmap().String() + "'", nil
	case "client_epc", "server_epc":
		n, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return "", errors.New("invalid endpoint EPC")
		}
		column := "l3_epc_id_0"
		if k == "server_epc" {
			column = "l3_epc_id_1"
		}
		return fmt.Sprintf("%s = %d", column, n), nil
	case "agent", "server_port", "transport":
		bits := 16
		column := k
		if k == "agent" {
			column = "agent_id"
		}
		if k == "transport" {
			column, bits = "protocol", 8
		}
		n, err := strconv.ParseUint(value, 10, bits)
		if err != nil {
			return "", errors.New("invalid Agent, service port or transport protocol")
		}
		return fmt.Sprintf("%s = %d", column, n), nil
	case "point":
		if !observationPoint.MatchString(value) {
			return "", errors.New("invalid observation point")
		}
		return "observation_point = '" + value + "'", nil
	}
	return "", errors.New("unknown relationship filter")
}

func isRelationshipFilter(k string) bool {
	switch k {
	case "client_ip", "server_ip", "client_epc", "server_epc", "agent", "server_port", "transport", "point":
		return true
	}
	return false
}

// Validate through the same builder as list/detail, so every drill-down has
// exactly the same predicates. Only the projection and grouping differ.
func selectionWhere(v url.Values, now int64) (string, error) {
	sql, err := selection(v, now)
	if err != nil {
		return "", err
	}
	where := strings.TrimPrefix(sql, "SELECT "+fields+" FROM l7_flow_log WHERE ")
	return where[:strings.LastIndex(where, " ORDER BY time DESC LIMIT ")], nil
}

func serviceSelection(v url.Values, now int64) (string, error) {
	if v.Has("id") || v.Has("limit") {
		return "", errors.New("services does not accept id or limit")
	}
	where, err := selectionWhere(v, now)
	if err != nil {
		return "", err
	}
	// One extra row is a truncation sentinel, never an invented exact total.
	order := strings.ReplaceAll(relationshipFields, ",", " ASC,") + " ASC"
	return "SELECT " + relationshipFields + ",Count(row) AS records FROM l7_flow_log WHERE " + where +
		" GROUP BY " + relationshipFields + " ORDER BY records DESC," + order +
		fmt.Sprintf(" LIMIT %d", relationshipLimit+1), nil
}

func normalizeRelationships(d *result) error {
	if len(d.Values) == 0 {
		d.Values = [][]json.RawMessage{}
		return nil
	}
	index := -1
	for i, column := range d.Columns {
		if column == "records" {
			index = i
		}
	}
	if index < 0 {
		return errors.New("missing relationship count")
	}
	for _, row := range d.Values {
		if len(row) != len(d.Columns) {
			return errors.New("invalid relationship row")
		}
		n, err := strconv.ParseUint(strings.Trim(string(row[index]), `"`), 10, 64)
		if err != nil {
			return errors.New("invalid relationship count")
		}
		// JSON strings retain UInt64 count precision in the browser.
		row[index], _ = json.Marshal(strconv.FormatUint(n, 10))
	}
	return nil
}

func (c *console) services(w http.ResponseWriter, r *http.Request) {
	sql, err := serviceSelection(r.URL.Query(), time.Now().Unix())
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	d, err := c.upstream(r.Context(), c.query+"/v1/query/", "POST", url.Values{"db": {"flow_log"}, "sql": {sql}}, false)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if d.Result == nil {
		d.Result = &result{Columns: []string{}}
	}
	if normalizeRelationships(d.Result) != nil {
		writeJSON(w, 502, map[string]string{"error": "invalid service relationship response"})
		return
	}
	truncated := len(d.Result.Values) > relationshipLimit
	if truncated {
		d.Result.Values = d.Result.Values[:relationshipLimit]
	}
	writeJSON(w, 200, map[string]any{"relations": d.Result, "truncated": truncated,
		"limit": relationshipLimit, "counting": "observation_records"})
}
