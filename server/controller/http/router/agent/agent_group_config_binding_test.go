// SPDX-License-Identifier: Apache-2.0
package agent

import (
	"encoding/json"
	"github.com/deepflowio/deepflow/server/agent_config"
	"gopkg.in/yaml.v3"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/gin-gonic/gin"
)

func TestAgentConfigJSONBindingRejectsBeforeDB(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, method := range []string{"POST", "PUT"} {
		for _, body := range []string{"", "{", "7", "[]", "null"} {
			t.Run(method+"_"+body, func(t *testing.T) {
				// Nil controller config makes reaching service/DB an immediate failure.
				router := gin.New()
				if method == "POST" {
					router.POST("/config/:group-lcuuid", postJsonAgentGroupConfig(nil))
				} else {
					router.PUT("/config/:group-lcuuid", putJsonAgentGroupConfig(nil))
				}
				request := httptest.NewRequest(method, "/config/synthetic-group", strings.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				recorder := httptest.NewRecorder()
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("invalid body reached service/DB: %v", p)
					}
				}()
				router.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusBadRequest {
					t.Fatalf("invalid JSON status=%d body=%s", recorder.Code, recorder.Body.String())
				}
				var result map[string]interface{}
				if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result["OPT_STATUS"] != common.INVALID_POST_DATA {
					t.Fatalf("wrong client error: %#v", result)
				}
			})
		}
	}
}

func TestAgentConfigLocalJSONNumberPrecision(t *testing.T) {
	for _, tc := range []struct {
		token, want string
		valid       bool
	}{
		{"9007199254740993", "9007199254740993", true}, {"1000.0", "1000", true}, {"1e3", "1000", true},
		{"9223372036854775807", "9223372036854775807", true}, {"-9223372036854775808", "-9223372036854775808", true},
		{"1.00000000000000001", "", false}, {"1000.0000000000000001", "", false}, {"9223372036854775808", "", false}, {"1e1000000000", "", false}, {"1e-1000000000", "", false},
	} {
		t.Run(tc.token, func(t *testing.T) {
			raw := `{"global":{"limits":{"max_millicpus":` + tc.token + `}}}`
			object, err := decodeAgentConfigJSON(strings.NewReader(raw))
			if err != nil {
				t.Fatal(err)
			}
			value := object["global"].(map[string]interface{})["limits"].(map[string]interface{})["max_millicpus"]
			number, ok := value.(json.Number)
			if !ok || number.String() != tc.token {
				t.Fatalf("raw numeric token was rounded: %T %v", value, value)
			}
			wire, err := agent_config.ConvertJSONToYAMLAndValidate(object)
			if strconv.IntSize == 32 && len(tc.want) > 10 {
				if err == nil {
					t.Fatal("out-of-native-int range accepted")
				}
				return
			}
			if (err == nil) != tc.valid {
				t.Fatalf("wrong exact integer acceptance: %v", err)
			}
			if !tc.valid {
				return
			}
			var values map[string]interface{}
			if err := yaml.Unmarshal(wire, &values); err != nil {
				t.Fatal(err)
			}
			got := values["global"].(map[string]interface{})["limits"].(map[string]interface{})["max_millicpus"]
			if strconv.FormatInt(int64(got.(int)), 10) != tc.want {
				t.Fatalf("stored integer rounded: %v", got)
			}
			gui, err := agent_config.ConvertYAMLToJSON(wire)
			if err != nil {
				t.Fatal(err)
			}
			decoder := json.NewDecoder(strings.NewReader(string(gui)))
			decoder.UseNumber()
			var readback map[string]interface{}
			if err := decoder.Decode(&readback); err != nil {
				t.Fatal(err)
			}
			actual := readback["global"].(map[string]interface{})["limits"].(map[string]interface{})["max_millicpus"].(json.Number)
			if actual.String() != tc.want {
				t.Fatalf("GET representation rounded: %s", actual)
			}
		})
	}
}
func TestAgentConfigDefaultBindingPrecisionControl(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Independent baseline: the default Gin binding rounds before any formatter.
	context, _ := gin.CreateTestContext(httptest.NewRecorder())
	context.Request = httptest.NewRequest("POST", "/", strings.NewReader(`{"n":9007199254740993}`))
	context.Request.Header.Set("Content-Type", "application/json")
	var old map[string]interface{}
	if err := context.ShouldBindJSON(&old); err != nil {
		t.Fatal(err)
	}
	if old["n"] != float64(9007199254740992) {
		t.Fatalf("default-binding control changed: %#v", old)
	}
	exact, err := decodeAgentConfigJSON(strings.NewReader(`{"n":9007199254740993}`))
	if err != nil {
		t.Fatal(err)
	}
	if exact["n"].(json.Number).String() != "9007199254740993" {
		t.Fatal("local decoder lost lexical precision")
	}
}
