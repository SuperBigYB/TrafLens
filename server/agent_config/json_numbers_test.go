// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	stdjson "encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"testing"
)

func TestExactJSONIntegerVectors(t *testing.T) {
	max := int(^uint(0) >> 1)
	cases := map[string]int{"0": 0, "-0": 0, "0e1000000000": 0, "1000.0": 1000, "1e3": 1000, "1000.000": 1000, "1000e-3": 1, "10.0e-1": 1, strconv.Itoa(max): max, strconv.Itoa(-max - 1): -max - 1}
	if strconv.IntSize == 64 {
		cases["9007199254740993"] = 9007199254740993
		cases["9.223372036854775807e18"] = 9223372036854775807
	}
	for text, want := range cases {
		got, err := exactJSONInteger(text)
		if err != nil || got != want {
			t.Errorf("%s: got %d err=%v want %d", text, got, err, want)
		}
	}
	for _, text := range []string{"", "-", "+1", "01", "1.", "1e", "1/2", "0x1", "NaN", "Inf", "1.00000000000000001", "1000.0000000000000001", "9223372036854775808", "-9223372036854775809", "1e1000000000", "1e-1000000000"} {
		if _, err := exactJSONInteger(text); err == nil {
			t.Errorf("invalid exact int accepted: %q", text)
		}
	}
}
func TestExactJSONIntegerIndependentOracle(t *testing.T) {
	for _, mantissa := range []string{"0", "1", "-1", "1200", "-1000001", "9007199254740993", "9223372036854775807", "-9223372036854775808"} {
		for _, exp := range []int{-20, -3, -1, 0, 1, 3, 20} {
			text := fmt.Sprintf("%se%d", mantissa, exp)
			rat, ok := new(big.Rat).SetString(text)
			if !ok {
				t.Fatal(text)
			}
			representable := rat.IsInt() && rat.Num().IsInt64()
			if representable && strconv.IntSize == 32 {
				v := rat.Num().Int64()
				representable = v >= -2147483648 && v <= 2147483647
			}
			got, err := exactJSONInteger(text)
			if (err == nil) != representable {
				t.Fatalf("oracle mismatch %s got=%d err=%v", text, got, err)
			}
			if representable && int64(got) != rat.Num().Int64() {
				t.Fatalf("wrong exact value for %s", text)
			}
		}
	}
}
func TestExactJSONIntegerLongCancellation(t *testing.T) {
	text := "1" + strings.Repeat("0", 100000) + "e-100000"
	got, err := exactJSONInteger(text)
	if err != nil || got != 1 {
		t.Fatalf("long exact cancellation failed: got=%d err=%v", got, err)
	}
}
func TestJSONNumberFloatAndSequenceSchemas(t *testing.T) {
	for _, text := range []string{`{"global":{"circuit_breakers":{"relative_sys_load":{"trigger_threshold":1.5}}}}`, `{"outputs":{"flow_log":{"filters":{"l7_capture_network_types":[0,1]}}}}`} {
		decoder := stdjson.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		var input map[string]interface{}
		if err := decoder.Decode(&input); err != nil {
			t.Fatal(err)
		}
		if _, err := ConvertJSONToYAMLAndValidate(input); err != nil {
			t.Fatalf("valid non-int-number path rejected: %v", err)
		}
	}
	for _, number := range []string{"0.00000000000000001", "0.0000000000000000000001e-1000"} {
		input := map[string]interface{}{"outputs": map[string]interface{}{"flow_log": map[string]interface{}{"filters": map[string]interface{}{"l7_capture_network_types": []interface{}{stdjson.Number(number)}}}}}
		if _, err := ConvertJSONToYAMLAndValidate(input); err == nil {
			t.Fatal("fractional numeric sequence item accepted")
		}
	}
}
