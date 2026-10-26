// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func migrationResult(t *testing.T, migrator *Upgrader, source string) map[string]interface{} {
	t.Helper()
	raw, err := migrator.Upgrade([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	if err := yaml.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func migrationTool(t *testing.T) *Upgrader {
	t.Helper()
	data, err := NewMigrationToolData(nil)
	if err != nil {
		t.Fatal(err)
	}
	return newUpgrader(data)
}
func TestMigrationProfileMatchers(t *testing.T) {
	for _, existing := range []bool{false, true} {
		for _, tagged := range []bool{false, true} {
			t.Run(fmt.Sprintf("existing_%v_tagged_%v", existing, tagged), func(t *testing.T) {
				source := fmt.Sprintf("os-proc-sync-tagged-only: %v\nstatic_config:\n  ebpf:\n    on-cpu-profile:\n      regex: on-.*\n    off-cpu-profile:\n      regex: off-.*\n", tagged)
				want := []interface{}{}
				if existing {
					source += "  os-proc-regex:\n    - match-regex: keep-.*\n      action: drop\n"
					want = append(want, map[string]interface{}{"match_regex": "keep-.*", "ignore": true, "only_with_tag": tagged})
				}
				for _, feature := range []string{"on", "off"} {
					want = append(want, map[string]interface{}{"match_regex": feature + "-.*", "enabled_features": []interface{}{"ebpf.profile." + feature + "_cpu"}, "only_with_tag": tagged})
				}
				result := migrationResult(t, migrationTool(t), source)
				expected := map[string]interface{}{"inputs": map[string]interface{}{"proc": map[string]interface{}{"process_matcher": want}}}
				if !reflect.DeepEqual(result, expected) {
					t.Fatalf("profile matcher fields differ: got %#v want %#v", result, expected)
				}
			})
		}
	}
}
func TestMigrationSequentialUpgradeIsolated(t *testing.T) {
	m := migrationTool(t)
	migrationResult(t, m, "static_config:\n  ebpf:\n    uprobe-process-name-regexs:\n      golang-symbol: old-.*\n")
	if got := migrationResult(t, m, "{}\n"); len(got) != 0 {
		t.Fatalf("previous upgrade leaked into next result: %#v", got)
	}
}
func TestMigrationMalformedValues(t *testing.T) {
	for name, source := range map[string]string{
		"matcher_scalar": "static_config:\n  os-proc-regex: bad\n",
		"matcher_item":   "static_config:\n  os-proc-regex: [1]\n",
		"matcher_action": "static_config:\n  os-proc-regex:\n    - match-regex: test\n      action: [drop]\n",
		"on_cpu_regex":   "static_config:\n  ebpf:\n    on-cpu-profile:\n      regex: 123\n",
		"off_cpu_regex":  "static_config:\n  ebpf:\n    off-cpu-profile:\n      regex: [test]\n",
		"tagged_only":    "os-proc-sync-tagged-only: 1\n",
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("migration panicked: %v", r)
				}
			}()
			if _, err := migrationTool(t).Upgrade([]byte(source)); err == nil {
				t.Fatal("invalid typed legacy value accepted")
			}
		})
	}
}
func TestMigrationDomainIdentifiersRemainStrings(t *testing.T) {
	data, err := NewMigrationToolData(&DomainData{LcuuidToID: map[string]int{"known": 999}})
	if err != nil {
		t.Fatal(err)
	}
	for _, domains := range []string{"[]", "[\"0\"]", "[known, unknown]"} {
		result := migrationResult(t, newUpgrader(data), "domains: "+domains+"\n")
		var old map[string]interface{}
		if err := yaml.Unmarshal([]byte("domains: "+domains), &old); err != nil {
			t.Fatal(err)
		}
		got := result["inputs"].(map[string]interface{})["resources"].(map[string]interface{})["pull_resource_from_controller"].(map[string]interface{})["domain_filter"]
		if !reflect.DeepEqual(got, old["domains"]) {
			t.Fatalf("UUID/sentinel changed: got %#v want %#v", got, old["domains"])
		}
	}
}

func TestMigrationStaticTaggedOnly(t *testing.T) {
	legacy := "os-proc-sync-tagged-only: true\nos-proc-regex:\n  - match-regex: keep-.*\n"
	raw, err := Upgrade(&AgentGroupConfigModel{YamlConfig: &legacy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]interface{}
	if err := yaml.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	want := map[string]interface{}{"inputs": map[string]interface{}{"proc": map[string]interface{}{"process_matcher": []interface{}{map[string]interface{}{"match_regex": "keep-.*", "only_with_tag": true}}}}}
	if !reflect.DeepEqual(result, want) {
		t.Fatalf("typed DB static flag lost: got %#v want %#v", result, want)
	}
	for _, same := range []bool{true, false} {
		source := fmt.Sprintf("os-proc-sync-tagged-only: true\nstatic_config:\n  os-proc-sync-tagged-only: %v\n", same)
		_, err := migrationTool(t).Upgrade([]byte(source))
		if (err == nil) != same {
			t.Fatalf("conflicting aliases must fail; identical aliases must pass: same=%v err=%v", same, err)
		}
	}
}
func TestMigrationEmptyProfileRegexDoesNotMatchEverything(t *testing.T) {
	result := migrationResult(t, migrationTool(t), "static_config:\n  ebpf:\n    on-cpu-profile:\n      regex: \"\"\n    off-cpu-profile:\n      regex: \"\"\n")
	if len(result) != 0 {
		t.Fatalf("empty profiling regex generated a matcher: %#v", result)
	}
}
