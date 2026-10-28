package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
)

const resourceLimit = 100

// These are current Controller registrations. The log's numeric agent_id alone
// cannot prove that historical records belong to the current LCUUID after reuse.
const resourceAssociation = "Current registrations in the fixed Controller organization; observations join by numeric agent_id only. Historical ID reuse may associate older records with a different LCUUID. No independent host/container identity or current health is inferred."

type agentResource struct {
	ID     int32  `json:"ID"`
	LCUUID string `json:"LCUUID"`
	Name   string `json:"NAME"`
	CtrlIP string `json:"CTRL_IP"`
	Type   int32  `json:"TYPE"`
	State  int32  `json:"STATE"`
	Enable int32  `json:"ENABLE"`
	TeamID int32  `json:"TEAM_ID"`
}

func resourceAgentFilter(raw string) (uint16, error) {
	v, err := url.ParseQuery(raw)
	if err != nil {
		return 0, errors.New("invalid resource query")
	}
	for key, values := range v {
		if key != "agent" || len(values) != 1 {
			return 0, errors.New("resources only accepts one exact agent filter")
		}
	}
	if !v.Has("agent") {
		return 0, nil
	}
	id, err := strconv.ParseUint(v.Get("agent"), 10, 16)
	if err != nil || id == 0 {
		return 0, errors.New("resource Agent ID must be 1..65535")
	}
	return uint16(id), nil
}

func normalizeResources(raw json.RawMessage) ([]agentResource, error) {
	// Explicit [] is a successful empty inventory. Missing/null DATA does not
	// establish an empty registration list and must not appear healthy.
	var input []struct {
		ID     *int32  `json:"ID"`
		LCUUID *string `json:"LCUUID"`
		Name   *string `json:"NAME"`
		CtrlIP *string `json:"CTRL_IP"`
		Type   *int32  `json:"TYPE"`
		State  *int32  `json:"STATE"`
		Enable *int32  `json:"ENABLE"`
		TeamID *int32  `json:"TEAM_ID"`
	}
	if err := json.Unmarshal(raw, &input); err != nil || input == nil {
		return nil, errors.New("invalid current resource inventory")
	}
	resources := make([]agentResource, 0, len(input))
	ids, identities := map[int32]bool{}, map[string]bool{}
	for _, row := range input {
		if row.ID == nil || row.LCUUID == nil || row.Name == nil || row.CtrlIP == nil || row.Type == nil || row.State == nil || row.Enable == nil || row.TeamID == nil {
			return nil, errors.New("missing current resource field")
		}
		if *row.ID < 1 || *row.ID > 65535 || *row.LCUUID == "" || ids[*row.ID] || identities[*row.LCUUID] || *row.Type < 0 || *row.State < 0 || (*row.Enable != 0 && *row.Enable != 1) || *row.TeamID < 0 {
			return nil, errors.New("invalid or duplicate current resource identity/state")
		}
		ids[*row.ID], identities[*row.LCUUID] = true, true
		resources = append(resources, agentResource{*row.ID, *row.LCUUID, *row.Name, *row.CtrlIP, *row.Type, *row.State, *row.Enable, *row.TeamID})
	}
	sort.Slice(resources, func(i, j int) bool { return resources[i].ID < resources[j].ID })
	return resources, nil
}

func (c *console) resources(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "resources is read-only"})
		return
	}
	agent, err := resourceAgentFilter(r.URL.RawQuery)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	d, err := c.upstream(r.Context(), c.controller+"/v1/vtaps/", "GET", nil, true)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	resources, err := normalizeResources(d.Data)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	if agent != 0 {
		selected := make([]agentResource, 0, 1)
		for _, resource := range resources {
			if resource.ID == int32(agent) {
				selected = append(selected, resource)
				break
			}
		}
		resources = selected
	}
	truncated := len(resources) > resourceLimit
	if truncated {
		resources = resources[:resourceLimit]
	}
	writeJSON(w, 200, map[string]any{"resources": resources, "limit": resourceLimit, "truncated": truncated,
		"scope": map[string]int{"org_id": 1, "user_id": 1}, "association": resourceAssociation})
}
