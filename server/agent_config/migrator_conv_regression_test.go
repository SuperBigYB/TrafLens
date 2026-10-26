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
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"
)

func legacyConvPtr[T any](value T) *T { return &value }

func TestLegacyDBConversionRejectsCorruption(t *testing.T) {
	cases := []struct {
		name  string
		model *AgentGroupConfigModel
	}{
		{"nil", nil},
		{"static_yaml", &AgentGroupConfigModel{YamlConfig: legacyConvPtr("ebpf: [")}},
		{"tap_types", &AgentGroupConfigModel{L4LogTapTypes: legacyConvPtr("1,bad")}},
		{"l4_sides", &AgentGroupConfigModel{L4LogIgnoreTapSides: legacyConvPtr("1,bad")}},
		{"l7_sides", &AgentGroupConfigModel{L7LogIgnoreTapSides: legacyConvPtr("1,bad")}},
		{"store_types", &AgentGroupConfigModel{L7LogStoreTapTypes: legacyConvPtr("1,bad")}},
		{"decap", &AgentGroupConfigModel{DecapType: legacyConvPtr("1,bad")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			var err error
			var panicValue any
			func() { defer func() { panicValue = recover() }(); data, err = convertDBToYAML(tc.model) }()
			if panicValue != nil || err == nil || data != nil {
				t.Fatalf("must fail without partial YAML: panic=%v err=%v bytes=%d", panicValue, err, len(data))
			}
		})
	}
}

func TestLegacyYAMLConversionRejectsOverflowWithoutMutation(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	max64 := int64(^uint64(0) >> 1)
	cases := []struct{ name, document string }{
		{"pps_positive", fmt.Sprintf("max_collect_pps: %d\n", maxInt/1000+1)},
		{"pps_negative", fmt.Sprintf("max_collect_pps: %d\n", (-maxInt-1)/1000-1)},
		{"npb", fmt.Sprintf("max_npb_bps: %d\n", max64/1000000+1)},
		{"tx", fmt.Sprintf("max_tx_bandwidth: %d\n", max64/1000000+1)},
		{"typed_list", "decap_type: 0\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := AgentGroupConfigModel{ID: 17, VTapGroupLcuuid: legacyConvPtr("synthetic-group"), LogLevel: legacyConvPtr("KEEP"), L4LogTapTypes: legacyConvPtr("7"), YamlConfig: legacyConvPtr("old: true\n")}
			got := original
			err := convertYAMLToDB([]byte(tc.document), &got)
			if err == nil {
				t.Fatal("invalid or overflowing value must return an error")
			}
			if !reflect.DeepEqual(got, original) {
				t.Fatal("failed conversion modified the destination")
			}
		})
	}
	var err error
	var panicValue any
	func() {
		defer func() { panicValue = recover() }()
		err = convertYAMLToDB([]byte("max_collect_pps: 1\n"), nil)
	}()
	if panicValue != nil || err == nil {
		t.Fatalf("nil destination must return error, panic=%v err=%v", panicValue, err)
	}
}

func TestLegacyRateUnitsAndZeroRoundTrip(t *testing.T) {
	for _, zero := range []bool{false, true} {
		t.Run(fmt.Sprint(zero), func(t *testing.T) {
			pps, npb, tx := 12000, int64(34000000), int64(56000000)
			if zero {
				pps, npb, tx = 0, 0, 0
			}
			source := &AgentGroupConfigModel{ID: 17, MaxCollectPps: &pps, MaxNpbBps: &npb, MaxTxBandwidth: &tx, L4LogTapTypes: legacyConvPtr("1,2,3"), DecapType: legacyConvPtr("1,2"), Domains: legacyConvPtr("uuid-a,uuid-b"), WasmPlugins: legacyConvPtr("one,two"), SoPlugins: legacyConvPtr("three"), YamlConfig: legacyConvPtr("ebpf:\n  on-cpu-profile:\n    disabled: true\nos-proc-sync-enabled: true\n")}
			wire, err := convertDBToYAML(source)
			if err != nil {
				t.Fatal(err)
			}
			var decoded AgentGroupConfig
			if err := yaml.Unmarshal(wire, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.MaxCollectPps == nil || *decoded.MaxCollectPps != pps/1000 || decoded.MaxNpbBps == nil || *decoded.MaxNpbBps != npb/1000000 || decoded.MaxTxBandwidth == nil || *decoded.MaxTxBandwidth != tx/1000000 {
				t.Fatal("legacy Kpps/Mbps units or explicit zero changed")
			}
			out := &AgentGroupConfigModel{ID: source.ID}
			if err := convertYAMLToDB(wire, out); err != nil {
				t.Fatal(err)
			}
			// Nested YAML formatting is not the storage contract; compare typed values.
			sourceYAML, outYAML := source.YamlConfig, out.YamlConfig
			source.YamlConfig = nil
			out.YamlConfig = nil
			if !reflect.DeepEqual(source, out) {
				t.Fatalf("round trip changed typed fields: got=%#v want=%#v", out, source)
			}
			var a, b any
			if err := yaml.Unmarshal([]byte(*sourceYAML), &a); err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal([]byte(*outYAML), &b); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(a, b) {
				t.Fatal("static config values or nesting changed")
			}
		})
	}
}
