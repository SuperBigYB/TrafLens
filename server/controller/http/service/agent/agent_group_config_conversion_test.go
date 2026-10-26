// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"reflect"
	"testing"

	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/deepflowio/deepflow/server/controller/http/common/response"
	"gopkg.in/yaml.v3"
)

func configPortMap(value interface{}) map[string]interface{} {
	return map[string]interface{}{"processors": map[string]interface{}{"request_log": map[string]interface{}{"filters": map[string]interface{}{"port_number_prefilters": value}}}}
}
func TestGetStringYAMLDBFreePortForms(t *testing.T) {
	var receiver AgentGroupConfig
	want := configPortMap(map[string]interface{}{"HTTP": "18080,8000-8010", "HTTP2": "1-65535"})
	for name, input := range map[string]interface{}{"nested_json": configPortMap(map[string]interface{}{"HTTP": "18080,8000-8010", "HTTP2": "1-65535"}), "yaml_text_json": configPortMap("HTTP: 18080,8000-8010\nHTTP2: 1-65535\n")} {
		t.Run(name, func(t *testing.T) {
			got, err := receiver.getStringYaml(input, DataTypeJSON)
			if err != nil {
				t.Fatal(err)
			}
			var values map[string]interface{}
			if err := yaml.Unmarshal([]byte(got), &values); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(values, want) {
				t.Fatalf("configuration values changed: got %#v want %#v", values, want)
			}
		})
	}
}
func TestGetStringYAMLDBFreeRejectsInvalidTypes(t *testing.T) {
	var receiver AgentGroupConfig
	for _, tc := range []struct {
		name string
		data interface{}
		kind int
	}{
		{"json_scalar", 7, DataTypeJSON}, {"json_sequence", []interface{}{}, DataTypeJSON}, {"json_nil", nil, DataTypeJSON},
		{"yaml_wrong_container", "global: {}", DataTypeYAML}, {"yaml_nil", nil, DataTypeYAML}, {"yaml_scalar", []byte("7\n"), DataTypeYAML},
		{"invalid_dict_scalar", configPortMap(7), DataTypeJSON}, {"invalid_dict_text", configPortMap("not-a-map"), DataTypeJSON},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("DB-free config conversion panicked: %v", p)
				}
			}()
			out, err := receiver.getStringYaml(tc.data, tc.kind)
			if err == nil || out != "" {
				t.Fatalf("malformed input must fail without YAML output; err=%v", err)
			}
			typed, ok := response.IsServiceError(err)
			if !ok || typed.Status != common.INVALID_POST_DATA {
				t.Fatalf("user input error is not INVALID_POST_DATA: %v", err)
			}
		})
	}
}
func TestGetStringYAMLDBFreePreservesRawYAML(t *testing.T) {
	var receiver AgentGroupConfig
	input := []byte("# retained operator comment\nglobal:\n  limits:\n    max_millicpus: 1000\n")
	got, err := receiver.getStringYaml(input, DataTypeYAML)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(input) {
		t.Fatal("validated YAML was rewritten")
	}
}
