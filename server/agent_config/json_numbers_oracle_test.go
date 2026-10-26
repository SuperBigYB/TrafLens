// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	"fmt"
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// The production parser avoids arbitrary-precision allocation. This independent
// oracle uses only short tokens and bounded exponents to check exact arithmetic.
func TestJSONIntegerAgainstBoundedRationalOracle(t *testing.T) {
	rng := rand.New(rand.NewSource(20261027))
	for sample := 0; sample < 2048; sample++ {
		text := strconv.FormatUint(rng.Uint64(), 10)
		if rng.Intn(4) == 0 {
			text = "0"
		}
		if rng.Intn(2) == 0 {
			text = "-" + text
		}
		if rng.Intn(2) == 0 {
			var fraction strings.Builder
			for digits := 1 + rng.Intn(24); digits > 0; digits-- {
				fraction.WriteByte(byte('0' + rng.Intn(10)))
			}
			text += "." + fraction.String()
		}
		if rng.Intn(2) == 0 {
			text += fmt.Sprintf("e%+d", rng.Intn(81)-40)
		}
		oracle, ok := new(big.Rat).SetString(text)
		if !ok {
			t.Fatalf("invalid test vector %q", text)
		}
		wantOK := oracle.IsInt() && oracle.Num().IsInt64()
		if wantOK && strconv.IntSize == 32 {
			n := oracle.Num().Int64()
			wantOK = n >= -1<<31 && n <= 1<<31-1
		}
		got, err := exactJSONInteger(text)
		if (err == nil) != wantOK {
			t.Fatalf("%q: accepted=%v; rational=%s", text, err == nil, oracle.RatString())
		}
		if wantOK && int64(got) != oracle.Num().Int64() {
			t.Fatalf("%q: got %d; rational integer=%s", text, got, oracle.Num())
		}
	}
}
