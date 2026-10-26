/*
 * Copyright (c) 2024 Yunshan Networks
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy at http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by law or agreed in writing, software is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND.
 */
package agent_config

import (
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConvertDBToYAML(t *testing.T) {
	t.Run("TestConvertDBToYAML_01", func(t *testing.T) {
		source := &AgentGroupConfigModel{ID: 1, MaxCollectPps: legacyConvPtr(10000), L4LogTapTypes: legacyConvPtr("1,2,3"), YamlConfig: legacyConvPtr("ebpf:\n  on-cpu-profile:\n    disabled: true\nos-proc-sync-enabled: true\n")}
		got, err := convertDBToYAML(source)
		if err != nil {
			t.Fatal(err)
		}
		// Kpps belongs to max_collect_pps, not the unrelated Mbps NPB field.
		// Compare the entire YAML value tree, not serializer indentation.
		want := []byte(`max_collect_pps: 10
l4_log_tap_types: [1, 2, 3]
static_config:
  ebpf:
    on-cpu-profile:
      disabled: true
  os-proc-sync-enabled: true
`)
		var actual, expected any
		if err := yaml.Unmarshal(got, &actual); err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(want, &expected); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("complete YAML values differ: got=%#v want=%#v", actual, expected)
		}
	})
}

func TestYAMLToDB(t *testing.T) {
	t.Run("TestYAMLToDB_01", func(t *testing.T) {
		input := []byte(`max_collect_pps: 10
max_npb_bps: 20
max_tx_bandwidth: 30
max_cpus: 2
max_memory: 512
tap_interface_regex: eth0
npb_dedup_enabled: 1
l4_log_collect_nps_threshold: 100
l7_log_collect_nps_threshold: 200
capture_socket_type: 0
tap_mode: 2
decap_type: [1, 2]
external_agent_http_proxy_enabled: 0
l4_log_tap_types: [1, 2, 3]
domains: [synthetic-uuid]
static_config:
  ebpf:
    on-cpu-profile:
      disabled: true
  os-proc-sync-enabled: true
`)
		got := &AgentGroupConfigModel{ID: 17, VTapGroupLcuuid: legacyConvPtr("keep-group")}
		if err := convertYAMLToDB(input, got); err != nil {
			t.Fatal(err)
		}
		expected := &AgentGroupConfigModel{ID: 17, VTapGroupLcuuid: legacyConvPtr("keep-group"), MaxCollectPps: legacyConvPtr(10000), MaxNpbBps: legacyConvPtr(int64(20000000)), MaxTxBandwidth: legacyConvPtr(int64(30000000)), MaxCPUs: legacyConvPtr(2), MaxMemory: legacyConvPtr(512), TapInterfaceRegex: legacyConvPtr("eth0"), NpbDedupEnabled: legacyConvPtr(1), L4LogCollectNpsThreshold: legacyConvPtr(100), L7LogCollectNpsThreshold: legacyConvPtr(200), CaptureSocketType: legacyConvPtr(0), TapMode: legacyConvPtr(2), DecapType: legacyConvPtr("1,2"), ExternalAgentHTTPProxyEnabled: legacyConvPtr(0), L4LogTapTypes: legacyConvPtr("1,2,3"), Domains: legacyConvPtr("synthetic-uuid")}
		static := got.YamlConfig
		got.YamlConfig = nil
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("complete destination differs: got=%#v want=%#v", got, expected)
		}
		if static == nil {
			t.Fatal("nested static configuration was lost")
		}
		var actual, expectedStatic any
		if err := yaml.Unmarshal([]byte(*static), &actual); err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal([]byte("ebpf:\n  on-cpu-profile:\n    disabled: true\nos-proc-sync-enabled: true\n"), &expectedStatic); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expectedStatic) {
			t.Fatal("static configuration values/nesting differ")
		}
	})
}
