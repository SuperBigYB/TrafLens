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
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var DeprecatedTapSideID = []int{48, 49, 50}

func convertDBToYAML(dbData *AgentGroupConfigModel) ([]byte, error) {
	if dbData == nil {
		return nil, fmt.Errorf("nil legacy DB configuration")
	}
	yamlData := &AgentGroupConfig{}
	ignoreName := []string{"ID", "VTapGroupLcuuid", "VTapGroupID", "Lcuuid", "YamlConfig",
		"L4LogTapTypes", "L4LogIgnoreTapSides", "L7LogIgnoreTapSides",
		"L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps", "MaxNpbBps", "MaxTxBandwidth",
		"WasmPlugins", "SoPlugins",
	}
	copyStruct(dbData, yamlData, ignoreName)
	if dbData.YamlConfig != nil {
		yamlConfig := &StaticConfig{}
		if err := yaml.Unmarshal([]byte(*dbData.YamlConfig), yamlConfig); err == nil {
			yamlData.YamlConfig = yamlConfig
		} else {
			return nil, fmt.Errorf("invalid legacy static_config: %w", err)
		}
	}

	if dbData.L4LogTapTypes != nil {
		cL4LogTapTypes, err := convertStrToIntList(*dbData.L4LogTapTypes)
		if err == nil {
			yamlData.L4LogTapTypes = append(yamlData.L4LogTapTypes, cL4LogTapTypes...)
		} else {
			return nil, fmt.Errorf("invalid legacy L4LogTapTypes: %w", err)
		}
	}
	if dbData.L4LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*dbData.L4LogIgnoreTapSides, DeprecatedTapSideID)
		if err == nil {
			yamlData.L4LogIgnoreTapSides = append(yamlData.L4LogIgnoreTapSides, tapSides...)
		} else {
			return nil, fmt.Errorf("invalid legacy L4LogIgnoreTapSides: %w", err)
		}
	}
	if dbData.L7LogIgnoreTapSides != nil {
		tapSides, err := ConvertStrToIntListWithIgnore(*dbData.L7LogIgnoreTapSides, DeprecatedTapSideID)
		if err == nil {
			yamlData.L7LogIgnoreTapSides = append(yamlData.L7LogIgnoreTapSides, tapSides...)
		} else {
			return nil, fmt.Errorf("invalid legacy L7LogIgnoreTapSides: %w", err)
		}
	}
	if dbData.L7LogStoreTapTypes != nil {
		cL7LogStoreTapTypes, err := convertStrToIntList(*dbData.L7LogStoreTapTypes)
		if err == nil {
			yamlData.L7LogStoreTapTypes = append(yamlData.L7LogStoreTapTypes, cL7LogStoreTapTypes...)
		} else {
			return nil, fmt.Errorf("invalid legacy L7LogStoreTapTypes: %w", err)
		}
	}
	if dbData.DecapType != nil {
		cDecapType, err := convertStrToIntList(*dbData.DecapType)
		if err == nil {
			yamlData.DecapType = append(yamlData.DecapType, cDecapType...)
		} else {
			return nil, fmt.Errorf("invalid legacy DecapType: %w", err)
		}
	}
	if dbData.Domains != nil {
		cDomains := strings.Split(*dbData.Domains, ",")
		for _, domain := range cDomains {
			if domain != "" {
				yamlData.Domains = append(yamlData.Domains, domain)
			}
		}
	}
	if dbData.MaxCollectPps != nil {
		cMaxCollectPps := *dbData.MaxCollectPps / 1000
		yamlData.MaxCollectPps = &cMaxCollectPps
	}
	if dbData.MaxNpbBps != nil {
		cMaxNpbBps := *dbData.MaxNpbBps / 1000000
		yamlData.MaxNpbBps = &cMaxNpbBps
	}
	if dbData.MaxTxBandwidth != nil {
		cMaxTxBandwidth := *dbData.MaxTxBandwidth / 1000000
		yamlData.MaxTxBandwidth = &cMaxTxBandwidth
	}

	if dbData.WasmPlugins != nil {
		cWasmPlugins := strings.Split(*dbData.WasmPlugins, ",")
		for _, wasmPlugin := range cWasmPlugins {
			if wasmPlugin != "" {
				yamlData.WasmPlugins = append(yamlData.WasmPlugins, wasmPlugin)
			}
		}
	}
	if dbData.SoPlugins != nil {
		cSoPlugins := strings.Split(*dbData.SoPlugins, ",")
		for _, soPlugin := range cSoPlugins {
			if soPlugin != "" {
				yamlData.SoPlugins = append(yamlData.SoPlugins, soPlugin)
			}
		}
	}

	return yaml.Marshal(yamlData)
}

// Conversion errors leave the caller's model unchanged. Do not log entire
// configuration documents: static configuration may contain sensitive values.
func convertYAMLToDB(yamlBytes []byte, dbData *AgentGroupConfigModel) error {
	if dbData == nil {
		return fmt.Errorf("nil legacy DB destination")
	}
	yamlData := &AgentGroupConfig{}
	if err := yaml.Unmarshal(yamlBytes, yamlData); err != nil {
		return fmt.Errorf("failed to unmarshal legacy YAML configuration: %w", err)
	}
	var staticConfig *string
	if yamlData.YamlConfig != nil {
		encoded, err := yaml.Marshal(yamlData.YamlConfig)
		if err != nil {
			return fmt.Errorf("failed to marshal legacy static_config: %w", err)
		}
		value := string(encoded)
		staticConfig = &value
	}
	converted := *dbData
	if err := convertToDb(yamlData, &converted); err != nil {
		return err
	}
	converted.YamlConfig = staticConfig
	*dbData = converted
	return nil
}

func validateLegacyRateUnits(data *AgentGroupConfig) error {
	maxInt := int64(^uint(0) >> 1)
	if data.MaxCollectPps != nil {
		value := int64(*data.MaxCollectPps)
		if value > maxInt/1000 || value < (-maxInt-1)/1000 {
			return fmt.Errorf("max_collect_pps overflows DB packet-per-second units")
		}
	}
	max64 := int64(^uint64(0) >> 1)
	for name, value := range map[string]*int64{
		"max_npb_bps":      data.MaxNpbBps,
		"max_tx_bandwidth": data.MaxTxBandwidth,
	} {
		if value != nil && (*value > max64/1000000 || *value < (-max64-1)/1000000) {
			return fmt.Errorf("%s overflows DB bit-per-second units", name)
		}
	}
	return nil
}

func convertToDb(sData *AgentGroupConfig, tData *AgentGroupConfigModel) error {
	if sData == nil || tData == nil {
		return fmt.Errorf("nil legacy conversion source or destination")
	}
	if err := validateLegacyRateUnits(sData); err != nil {
		return err
	}
	ignoreName := []string{"ID", "YamlConfig", "Lcuuid", "VTapGroupLcuuid", "VTapGroupID",
		"L4LogTapTypes", "L4LogIgnoreTapSides", "L7LogIgnoreTapSides",
		"L7LogStoreTapTypes", "DecapType", "Domains", "MaxCollectPps", "MaxNpbBps", "MaxTxBandwidth",
		"WasmPlugins", "SoPlugins",
	}
	copyStruct(sData, tData, ignoreName)
	if len(sData.L4LogTapTypes) > 0 {
		cL4LogTapTypes := convertIntSliceToString(sData.L4LogTapTypes)
		tData.L4LogTapTypes = &cL4LogTapTypes
	} else {
		tData.L4LogTapTypes = nil
	}
	if len(sData.L4LogIgnoreTapSides) > 0 {
		tapSides := convertIntSliceToString(sData.L4LogIgnoreTapSides)
		tData.L4LogIgnoreTapSides = &tapSides
	} else {
		tData.L4LogIgnoreTapSides = nil
	}
	if len(sData.L7LogIgnoreTapSides) > 0 {
		tapSides := convertIntSliceToString(sData.L7LogIgnoreTapSides)
		tData.L7LogIgnoreTapSides = &tapSides
	} else {
		tData.L7LogIgnoreTapSides = nil
	}
	if len(sData.L7LogStoreTapTypes) > 0 {
		cL7LogStoreTapTypes := convertIntSliceToString(sData.L7LogStoreTapTypes)
		tData.L7LogStoreTapTypes = &cL7LogStoreTapTypes
	} else {
		tData.L7LogStoreTapTypes = nil
	}
	if len(sData.DecapType) > 0 {
		cDecapType := convertIntSliceToString(sData.DecapType)
		tData.DecapType = &cDecapType
	} else {
		tData.DecapType = nil
	}
	if len(sData.Domains) > 0 {
		cDomains := strings.Join(sData.Domains, ",")
		tData.Domains = &cDomains
	} else {
		tData.Domains = nil
	}
	if sData.MaxCollectPps != nil {
		cMaxCollectPps := *sData.MaxCollectPps * 1000
		tData.MaxCollectPps = &cMaxCollectPps
	} else {
		tData.MaxCollectPps = nil
	}
	if sData.MaxNpbBps != nil {
		cMaxNpbBps := *sData.MaxNpbBps * 1000000
		tData.MaxNpbBps = &cMaxNpbBps
	} else {
		tData.MaxNpbBps = nil
	}
	if sData.MaxTxBandwidth != nil {
		cMaxTxBandwidth := *sData.MaxTxBandwidth * 1000000
		tData.MaxTxBandwidth = &cMaxTxBandwidth
	} else {
		tData.MaxTxBandwidth = nil
	}
	if len(sData.WasmPlugins) > 0 {
		cWasmPlugins := strings.Join(sData.WasmPlugins, ",")
		tData.WasmPlugins = &cWasmPlugins
	} else {
		tData.WasmPlugins = nil
	}
	if len(sData.SoPlugins) > 0 {
		cSoPlugins := strings.Join(sData.SoPlugins, ",")
		tData.SoPlugins = &cSoPlugins
	} else {
		tData.SoPlugins = nil
	}
	return nil
}
func copyStruct(from, to interface{}, ignoreName []string) {
	fromValue := reflect.ValueOf(from)
	toValue := reflect.ValueOf(to)
	if fromValue.Kind() != reflect.Ptr || toValue.Kind() != reflect.Ptr {
		return
	}
	if fromValue.IsNil() || toValue.IsNil() {
		return
	}
	fromElem := fromValue.Elem()
	toElem := toValue.Elem()
	for i := 0; i < toElem.NumField(); i++ {
		toField := toElem.Type().Field(i)
		if slices.Contains(ignoreName, toField.Name) {
			// set value to avoid return nil
			if toField.Type.Kind() == reflect.Slice {
				sliceType := reflect.SliceOf(toField.Type.Elem())
				emptySlice := reflect.MakeSlice(sliceType, 0, 0)
				toElem.Field(i).Set(emptySlice)
			}
			continue
		}
		fromFieldName, ok := fromElem.Type().FieldByName(toField.Name)
		if ok && fromFieldName.Type == toField.Type {
			toElem.Field(i).Set(fromElem.FieldByName(toField.Name))
		}
	}
}

func convertStrToIntList(convertStr string) ([]int, error) {
	if len(convertStr) == 0 {
		return []int{}, nil
	}
	splitStr := strings.Split(convertStr, ",")
	result := make([]int, len(splitStr))
	for index, src := range splitStr {
		target, err := strconv.Atoi(src)
		if err != nil {
			return []int{}, err
		} else {
			result[index] = target
		}
	}

	return result, nil
}

func ConvertStrToIntListWithIgnore(convertStr string, ignoreFields []int) ([]int, error) {
	if len(convertStr) == 0 {
		return []int{}, nil
	}
	splitStr := strings.Split(convertStr, ",")
	var result []int
	for _, src := range splitStr {
		target, err := strconv.Atoi(src)
		if err != nil {
			return []int{}, err
		}
		if slices.Contains(ignoreFields, target) {
			continue
		}
		result = append(result, target)
	}

	return result, nil
}

func convertIntSliceToString(intSlice []int) string {
	strSlice := make([]string, 0, len(intSlice))
	for _, ci := range intSlice {
		strSlice = append(strSlice, strconv.Itoa(ci))
	}

	return strings.Join(strSlice, ",")
}
