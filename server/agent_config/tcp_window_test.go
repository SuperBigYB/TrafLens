/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package agent_config

import (
	stdjson "encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func tcpWindowAt(t *testing.T, document map[string]interface{}, keys ...string) interface{} {
	t.Helper()
	var current interface{} = document
	for _, key := range keys {
		object, ok := current.(map[string]interface{})
		if !ok {
			t.Fatalf("expected configuration object before %q, got %T", key, current)
		}
		current, ok = object[key]
		if !ok {
			t.Fatalf("missing configuration key %q", key)
		}
	}
	return current
}

func tcpWindowPorts(t *testing.T, document map[string]interface{}) []string {
	t.Helper()
	value := tcpWindowAt(t, document, "inputs", "cbpf", "preprocess", "packet_segmentation_reassembly")
	items, ok := value.([]interface{})
	if !ok {
		t.Fatalf("expected a port list, got %T", value)
	}
	ports := make([]string, len(items))
	for index, item := range items {
		port, ok := item.(string)
		if !ok {
			t.Fatalf("port item %d must be a string for the Agent, got %T (%v)", index, item, item)
		}
		ports[index] = port
	}
	return ports
}

func TestTCPWindowTemplateMetadata(t *testing.T) {
	encoded, err := ConvertTemplateYAMLToJSON(nil)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := stdjson.Unmarshal(encoded, &document); err != nil {
		t.Fatal(err)
	}
	if got := tcpWindowPorts(t, document); len(got) != 0 {
		t.Fatalf("default must disable TCP windows, got %v", got)
	}
	comment := tcpWindowAt(t, document, "inputs", "cbpf", "preprocess", "packet_segmentation_reassembly_comment").(map[string]interface{})
	for key, want := range map[string]interface{}{
		"type": "string", "modification": "agent_restart", "ee_feature": false,
		"upgrade_from": "static_config.packet-segmentation-reassembly",
	} {
		if !reflect.DeepEqual(comment[key], want) {
			t.Errorf("metadata %s = %#v, want %#v", key, comment[key], want)
		}
	}
	description := tcpWindowAt(t, comment, "description", "en").(string)
	for _, required := range []string{"18080", "8000-8010", "Empty disables", "same-direction",
		"not general TCP stream or message reassembly", "Sequence gaps", "Original packets",
		"flow report tick", "64 KiB", "64 MiB", "passes packets through"} {
		if !strings.Contains(description, required) {
			t.Errorf("missing TCP window contract detail %q", required)
		}
	}
}

func TestTCPWindowConfigRoundTrip(t *testing.T) {
	for name, ports := range map[string][]string{"disabled": {}, "port_and_range": {"18080", "8000-8010"}} {
		t.Run(name, func(t *testing.T) {
			input, err := yaml.Marshal(map[string]interface{}{"inputs": map[string]interface{}{
				"cbpf": map[string]interface{}{"preprocess": map[string]interface{}{"packet_segmentation_reassembly": ports}},
			}})
			if err != nil {
				t.Fatal(err)
			}
			if err := ValidateYAML(input); err != nil {
				t.Fatal(err)
			}
			encoded, err := ConvertYAMLToJSON(input)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]interface{}
			if err := stdjson.Unmarshal(encoded, &document); err != nil {
				t.Fatal(err)
			}
			if got := tcpWindowPorts(t, document); !reflect.DeepEqual(got, ports) {
				t.Fatalf("YAML to JSON ports = %v, want %v", got, ports)
			}
			output, err := ConvertJSONToYAMLAndValidate(document)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip map[string]interface{}
			if err := yaml.Unmarshal(output, &roundTrip); err != nil {
				t.Fatal(err)
			}
			if got := tcpWindowPorts(t, roundTrip); !reflect.DeepEqual(got, ports) {
				t.Fatalf("JSON to YAML ports = %v, want %v", got, ports)
			}
		})
	}
	if err := ValidateYAML([]byte("inputs:\n  cbpf:\n    preprocess:\n      packet_segmentation_reassembly: '18080'\n")); err == nil {
		t.Fatal("a scalar must not replace the configured port list")
	}
}

func TestTCPWindowLegacyUpgrade(t *testing.T) {
	for name, ports := range map[string][]uint16{"single": {18080}, "multiple": {0, 8000, 18080, 65535}} {
		t.Run(name, func(t *testing.T) {
			legacyBytes, err := yaml.Marshal(map[string]interface{}{"packet-segmentation-reassembly": ports})
			if err != nil {
				t.Fatal(err)
			}
			legacy := string(legacyBytes)
			output, err := Upgrade(&AgentGroupConfigModel{YamlConfig: &legacy}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var document map[string]interface{}
			if err := yaml.Unmarshal(output, &document); err != nil {
				t.Fatal(err)
			}
			want := make([]string, len(ports))
			for index, port := range ports {
				want[index] = strconv.Itoa(int(port))
			}
			if got := tcpWindowPorts(t, document); !reflect.DeepEqual(got, want) {
				t.Fatalf("legacy numeric ports must migrate to Agent port strings: got %v, want %v", got, want)
			}
			if err := ValidateYAML(output); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTCPWindowLegacyEmptyAndMalformedValues(t *testing.T) {
	toolData, err := NewMigrationToolData(nil)
	if err != nil {
		t.Fatal(err)
	}
	upgrader := newUpgrader(toolData)
	output, err := upgrader.Upgrade([]byte("static_config:\n  packet-segmentation-reassembly: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]interface{}
	if err := yaml.Unmarshal(output, &document); err != nil {
		t.Fatal(err)
	}
	if got := tcpWindowPorts(t, document); len(got) != 0 {
		t.Fatalf("empty legacy list must remain disabled, got %v", got)
	}
	for _, invalid := range []interface{}{"18080", []interface{}{-1}, []interface{}{65536},
		[]interface{}{18080, true}, []interface{}{18080.5}} {
		if got := upgrader.fmtLowerVersionValue("static_config.packet-segmentation-reassembly", invalid); !reflect.DeepEqual(got, invalid) {
			t.Errorf("malformed legacy value unexpectedly coerced: %#v -> %#v", invalid, got)
		}
	}
	for _, legacy := range []string{"packet-segmentation-reassembly: [-1]", "packet-segmentation-reassembly: [65536]", "packet-segmentation-reassembly: [true]"} {
		var old StaticConfig
		if err := yaml.Unmarshal([]byte(legacy), &old); err == nil {
			t.Errorf("legacy []uint16 validation unexpectedly accepts %q", legacy)
		}
	}
}
