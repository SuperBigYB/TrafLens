// Copyright 2026 TrafLens authors.
// SPDX-License-Identifier: Apache-2.0
package agent_config

import (
	stdjson "encoding/json"
	"gopkg.in/yaml.v3"
	"reflect"
	"testing"
)

func expectTemplateErrorWithoutPanic(t *testing.T, fn func() error) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("malformed metadata panicked: %v", value)
		}
	}()
	if err := fn(); err == nil {
		t.Error("malformed metadata must return an error")
	}
}

func TestTemplateMalformedCommentBoundaries(t *testing.T) {
	for name, input := range map[string]string{
		"orphan_metadata_at_eof": "# type: section",
		"orphan_todo_at_eof":     "# TODO unfinished",
		"missing_dict_default":   "# type: dict\n# ---\n# type: string\nitems: []",
		"dict_separator_at_eof":  "# type: dict\n# ---\n# type: string\n# ---",
		"scalar_metadata":        "# not-a-mapping\nitem: 1",
	} {
		t.Run(name, func(t *testing.T) {
			expectTemplateErrorWithoutPanic(t, func() error {
				_, err := NewTemplateFormatter([]byte(input)).GenerateKeyToComment()
				return err
			})
		})
	}
}

func TestTemplateDictSchemaRetainsDefaults(t *testing.T) {
	// HOWTO's independent schema + default YAML document contract.
	input := []byte("# type: dict\n# ---\n# type: string\n# ---\n# field: \"\"\nitems: []")
	got, err := NewTemplateFormatter(input).GenerateKeyToComment()
	if err != nil {
		t.Fatal(err)
	}
	expected := KeyToComment{
		"items": {
			"type": "dict",
			"value_comments": map[string]interface{}{
				"field":         "",
				"field_comment": map[string]interface{}{"type": "string"},
			},
		},
		"items.value_comments.field": {"type": "string"},
	}
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("schema/default metadata mismatch: got %#v", got)
	}
}

func TestTemplateInvalidIntegerReturnsError(t *testing.T) {
	node := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "not-an-integer"}
	_, err := NewTemplateFormatter(nil).fillingOrder(node)
	if err == nil {
		t.Fatal("invalid integer node returned nil error")
	}
}

func TestTemplateDictConversionErrorsPropagate(t *testing.T) {
	comments := KeyToComment{"outer.inner": {"type": "dict"}}
	for name, value := range map[string]interface{}{
		"nested_malformed_yaml": "[unterminated",
		"wrong_scalar_type":     7,
	} {
		t.Run(name, func(t *testing.T) {
			expectTemplateErrorWithoutPanic(t, func() error {
				data := map[string]interface{}{"outer": map[string]interface{}{"inner": value}}
				return NewDataFormatter().fmtVal("", data, comments, false)
			})
		})
	}
}

func TestTemplateStructuredDictConversionIsIdempotent(t *testing.T) {
	comments := KeyToComment{"outer.inner": {"type": "dict"}}
	data := map[string]interface{}{"outer": map[string]interface{}{"inner": map[string]interface{}{"field": "value"}}}
	expect := map[string]interface{}{"outer": map[string]interface{}{"inner": map[string]interface{}{"field": "value"}}}
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("already converted dict panicked: %v", value)
		}
	}()
	for i := 0; i < 2; i++ {
		if err := NewDataFormatter().fmtVal("", data, comments, false); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(data, expect) {
		t.Fatal("already structured dict changed")
	}
}

func TestTemplateJSONNormalizationPreservesEmbeddedLiterals(t *testing.T) {
	input := map[string]interface{}{"literal": "keep: null", "sentinel": "null", "empty": nil, "large": uint64(18446744073709551615)}
	encoded, err := NewDataFormatter().formatJson(input)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]stdjson.RawMessage
	if err := stdjson.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if string(got["literal"]) != `"keep: null"` {
		t.Fatalf("embedded literal was rewritten: %s", got["literal"])
	}
	if string(got["sentinel"]) != `""` || string(got["empty"]) != `[]` {
		t.Fatal("existing empty/sentinel JSON contract changed")
	}
	if string(got["large"]) != "18446744073709551615" {
		t.Fatal("large integer precision changed")
	}
}
