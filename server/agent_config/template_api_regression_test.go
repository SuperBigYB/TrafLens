// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	"fmt"
	"math"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func apiPortMap(value interface{}) map[string]interface{} {
	return map[string]interface{}{"processors": map[string]interface{}{"request_log": map[string]interface{}{"filters": map[string]interface{}{"port_number_prefilters": value}}}}
}
func TestPublicConfigPortNumberForms(t *testing.T) {
	for _, value := range []interface{}{map[string]interface{}{"HTTP": "18080", "DNS": "18053"}, "HTTP: \"18080\"\nDNS: \"18053\"\n"} {
		expected := apiPortMap(map[string]interface{}{"HTTP": "18080", "DNS": "18053"})
		wire, err := ConvertJSONToYAMLAndValidate(apiPortMap(value))
		if err != nil {
			t.Fatal(err)
		}
		var actual map[string]interface{}
		if err := yaml.Unmarshal(wire, &actual); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("native YAML shape changed: %#v", actual)
		}
		gui, err := ConvertYAMLToJSON(wire)
		if err != nil {
			t.Fatal(err)
		}
		var jsonMap map[string]interface{}
		if err := json.Unmarshal(gui, &jsonMap); err != nil {
			t.Fatal(err)
		}
		leaf := jsonMap["processors"].(map[string]interface{})["request_log"].(map[string]interface{})["filters"].(map[string]interface{})["port_number_prefilters"]
		text, ok := leaf.(string)
		if !ok {
			t.Fatalf("GUI dict leaf is not YAML text: %T", leaf)
		}
		var ports map[string]string
		if err := yaml.Unmarshal([]byte(text), &ports); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(ports, map[string]string{"HTTP": "18080", "DNS": "18053"}) {
			t.Fatalf("GUI ports changed: %#v", ports)
		}
		second, err := ConvertJSONToYAMLAndValidate(jsonMap)
		if err != nil {
			t.Fatal(err)
		}
		var repeated map[string]interface{}
		if err := yaml.Unmarshal(second, &repeated); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(repeated, expected) {
			t.Fatal("GUI round trip changed config")
		}
	}
}
func TestPublicConfigRejectsScalarDictionary(t *testing.T) {
	for _, value := range []interface{}{7, true, 1.5, "not-a-map"} {
		if _, err := ConvertJSONToYAMLAndValidate(apiPortMap(value)); err == nil {
			t.Fatalf("JSON scalar dict accepted: %T", value)
		}
	}
	for _, value := range []string{"7", "true", "1.5", "\"HTTP: 18080\\n\""} {
		if err := ValidateYAML([]byte("processors:\n  request_log:\n    filters:\n      port_number_prefilters: " + value + "\n")); err == nil {
			t.Fatalf("native YAML scalar dict accepted: %s", value)
		}
	}
}
func TestPublicConfigIntegerSources(t *testing.T) {
	if err := ValidateYAML([]byte("outputs:\n  flow_log:\n    filters:\n      l7_capture_network_types: [0.0]\n")); err == nil {
		t.Fatal("native YAML float sequence item accepted for integer sequence")
	}

	if err := ValidateYAML([]byte("global:\n  limits:\n    max_millicpus: 1000.0\n")); err == nil {
		t.Fatal("native YAML float accepted for integer field")
	}
	for _, value := range []float64{1000.5, math.Inf(1), math.Inf(-1), math.NaN(), math.Ldexp(1, 63)} {
		input := map[string]interface{}{"global": map[string]interface{}{"limits": map[string]interface{}{"max_millicpus": value}}}
		if _, err := ConvertJSONToYAMLAndValidate(input); err == nil {
			t.Fatalf("inexact JSON integer accepted: %v", value)
		}
	}
	input := map[string]interface{}{"global": map[string]interface{}{"limits": map[string]interface{}{"max_millicpus": float64(1000)}}}
	if _, err := ConvertJSONToYAMLAndValidate(input); err != nil {
		t.Fatalf("integral decoded JSON number rejected: %v", err)
	}
	for _, value := range []string{"1", "1.0", "1.5"} {
		if err := ValidateYAML([]byte("global:\n  circuit_breakers:\n    relative_sys_load:\n      trigger_threshold: " + value + "\n")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPublicConfigAliasIntegerCollections(t *testing.T) {
	shapes := map[string]string{
		"direct":         "outputs:\n  flow_log:\n    filters:\n      l7_capture_network_types: [*f]\n",
		"merged_filters": "outputs:\n  flow_log:\n    filters:\n      <<:\n        l7_capture_network_types: [*f]\n",
		"merged_parent":  "outputs:\n  flow_log:\n    <<:\n      filters:\n        l7_capture_network_types: [*f]\n",
	}
	for name, shape := range shapes {
		for _, floating := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_float_%v", name, floating), func(t *testing.T) {
				value := "0"
				if floating {
					value = "0.0"
				}
				source := "global:\n  circuit_breakers:\n    relative_sys_load:\n      trigger_threshold: &f " + value + "\n" + shape
				err := ValidateYAML([]byte(source))
				if (err != nil) != floating {
					t.Errorf("resolved alias/merge numeric type changed: float=%v err=%v", floating, err)
				}
			})
		}
	}
}
