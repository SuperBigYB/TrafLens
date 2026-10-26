// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	stdjson "encoding/json"
	"fmt"
	"gopkg.in/yaml.v3"
	"math"
	"strconv"
)

// Scan decimal JSON exactly without powers, big integers, or exponent-sized
// allocation. Work is linear in token length; accumulation is at most int bits.
func exactJSONInteger(text string) (int, error) {
	invalid := func() (int, error) { return 0, fmt.Errorf("JSON number is not an exact representable integer") }
	maxInt := int(^uint(0) >> 1)
	if len(text) == 0 || len(text) > maxInt-32 {
		return invalid()
	}
	digit := func(c byte) bool { return c >= '0' && c <= '9' }
	i := 0
	negative := false
	if text[i] == '-' {
		negative = true
		i++
		if i == len(text) {
			return invalid()
		}
	}
	start := i
	if text[i] == '0' {
		i++
		if i < len(text) && digit(text[i]) {
			return invalid()
		}
	} else {
		if text[i] < '1' || text[i] > '9' {
			return invalid()
		}
		for i < len(text) && digit(text[i]) {
			i++
		}
	}
	integerDigits := i - start
	fractionDigits := 0
	if i < len(text) && text[i] == '.' {
		i++
		first := i
		for i < len(text) && digit(text[i]) {
			i++
		}
		fractionDigits = i - first
		if fractionDigits == 0 {
			return invalid()
		}
	}
	mantissaEnd := i
	exponent := 0
	if i < len(text) && (text[i] == 'e' || text[i] == 'E') {
		i++
		minus := false
		if i < len(text) && (text[i] == '+' || text[i] == '-') {
			minus = text[i] == '-'
			i++
		}
		first := i
		cap := len(text) + 32
		for i < len(text) && digit(text[i]) {
			d := int(text[i] - '0')
			if exponent > (cap-d)/10 {
				exponent = cap
			} else {
				exponent = exponent*10 + d
			}
			i++
		}
		if i == first {
			return invalid()
		}
		if minus {
			exponent = -exponent
		}
	}
	if i != len(text) {
		return invalid()
	}
	firstNonzero, lastNonzero, total := -1, -1, 0
	for j := start; j < mantissaEnd; j++ {
		if text[j] == '.' {
			continue
		}
		if text[j] != '0' {
			if firstNonzero < 0 {
				firstNonzero = total
			}
			lastNonzero = total
		}
		total++
	}
	if firstNonzero < 0 {
		return 0, nil
	}
	base := integerDigits - firstNonzero
	maxDigits := len(strconv.Itoa(maxInt))
	if exponent < 1-base || exponent > maxDigits-base {
		return invalid()
	}
	shift := exponent - fractionDigits
	if shift < 0 && total-1-lastNonzero < -shift {
		return invalid()
	}
	resultDigits := base + exponent
	limit := uint64(maxInt)
	if negative {
		limit++
	}
	var magnitude uint64
	logical, written := 0, 0
	for j := start; j < mantissaEnd && written < resultDigits; j++ {
		if text[j] == '.' {
			continue
		}
		if logical >= firstNonzero {
			d := uint64(text[j] - '0')
			if magnitude > (limit-d)/10 {
				return invalid()
			}
			magnitude = magnitude*10 + d
			written++
		}
		logical++
	}
	for written < resultDigits {
		if magnitude > limit/10 {
			return invalid()
		}
		magnitude *= 10
		written++
	}
	if negative {
		if magnitude == uint64(maxInt)+1 {
			return -maxInt - 1, nil
		}
		return -int(magnitude), nil
	}
	return int(magnitude), nil
}

func (f *DataFormatter) prepareJSONNumbers(data interface{}, path string) (interface{}, error) {
	switch value := data.(type) {
	case stdjson.Number:
		if f.isIntValue(f.keyToComment[path]) {
			number, err := exactJSONInteger(string(value))
			if err != nil {
				return nil, fmt.Errorf("%w, key: %s", err, path)
			}
			return number, nil
		}
		if !stdjson.Valid([]byte(value)) {
			return nil, fmt.Errorf("invalid JSON number, key: %s", path)
		}
		number, err := value.Float64()
		if err != nil || math.IsNaN(number) || math.IsInf(number, 0) {
			return nil, fmt.Errorf("JSON number is not finite, key: %s", path)
		}
		return number, nil
	case map[string]interface{}:
		result := make(map[string]interface{}, len(value))
		for key, child := range value {
			converted, err := f.prepareJSONNumbers(child, f.appendAncestor(path, key))
			if err != nil {
				return nil, err
			}
			result[key] = converted
		}
		return result, nil
	case []interface{}:
		result := make([]interface{}, len(value))
		for index, child := range value {
			converted, err := f.prepareJSONNumbers(child, path)
			if err != nil {
				return nil, err
			}
			result[index] = converted
		}
		return result, nil
	default:
		return data, nil
	}
}

// yaml.v3's implicit encoding can erase a whole float's tag. Preserve tags at
// corresponding map keys / sequence indexes, without undoing dict-to-text folds.
func preserveYAMLFloatTags(target, source *yaml.Node) {
	if target == nil || source == nil || target.Kind != source.Kind {
		return
	}
	switch target.Kind {
	case yaml.ScalarNode:
		if source.Tag == "!!float" && target.Tag == "!!int" {
			target.Tag = "!!float"
		}
	case yaml.MappingNode:
		old := make(map[string]*yaml.Node)
		for i := 0; i+1 < len(source.Content); i += 2 {
			old[source.Content[i].Value] = source.Content[i+1]
		}
		for i := 0; i+1 < len(target.Content); i += 2 {
			preserveYAMLFloatTags(target.Content[i+1], old[target.Content[i].Value])
		}
	default:
		for i := 0; i < len(target.Content) && i < len(source.Content); i++ {
			preserveYAMLFloatTags(target.Content[i], source.Content[i])
		}
	}
}
