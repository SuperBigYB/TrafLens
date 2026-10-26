// SPDX-License-Identifier: Apache-2.0
package response

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"unicode/utf8"

	httpcommon "github.com/deepflowio/deepflow/server/controller/http/common"
	"github.com/gin-gonic/gin"
)

func responseJSONRecorder(options ...ResponseSetter) *httptest.ResponseRecorder {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(recorder)
	JSON(context, options...)
	return recorder
}
func completeEnvelope(t *testing.T, recorder *httptest.ResponseRecorder) map[string]json.RawMessage {
	t.Helper()
	var envelope map[string]json.RawMessage
	// Unmarshal validates the entire body; a first-object decoder would miss double JSON.
	if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("response is not one complete JSON document: status=%d body=%q err=%v", recorder.Code, recorder.Body.String(), err)
	}
	return envelope
}
func TestJSONByteEnvelopeAndPagination(t *testing.T) {
	for name, data := range map[string][]byte{"typed_nil": nil, "empty": {}, "object": []byte(`{"n":9007199254740993,"ok":true}`), "array": []byte(`[1,"two"]`), "string": []byte(`"text"`), "null": []byte(`null`)} {
		for _, paged := range []bool{false, true} {
			t.Run(name+map[bool]string{false: "", true: "_page"}[paged], func(t *testing.T) {
				options := []ResponseSetter{SetData(data)}
				page := Page{Index: 2, Size: 3, Total: 4, TotalItem: 12}
				if paged {
					options = append(options, SetPage(page))
				}
				recorder := responseJSONRecorder(options...)
				if recorder.Code != http.StatusOK {
					t.Fatalf("status=%d", recorder.Code)
				}
				envelope := completeEnvelope(t, recorder)
				want := data
				if len(want) == 0 {
					want = []byte("null")
				}
				var actualValue, wantValue interface{}
				if err := json.Unmarshal(envelope["DATA"], &actualValue); err != nil {
					t.Fatal(err)
				}
				if err := json.Unmarshal(want, &wantValue); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(actualValue, wantValue) {
					t.Fatalf("DATA changed: %s", envelope["DATA"])
				}
				if name == "object" && string(envelope["DATA"]) != string(data) {
					t.Fatal("raw numeric representation changed")
				}
				if paged {
					var actual Page
					if err := json.Unmarshal(envelope["PAGE"], &actual); err != nil || actual != page {
						t.Fatalf("page changed: %+v %v", actual, err)
					}
				} else if _, ok := envelope["PAGE"]; ok {
					t.Fatal("unexpected page")
				}
			})
		}
	}
}
func TestJSONEscapesDescriptionsAndStatuses(t *testing.T) {
	message := "invalid \"quoted\" value\nnext\\line\tend"
	for _, paged := range []bool{false, true} {
		options := []ResponseSetter{SetData([]byte(nil)), SetError(ServiceError(httpcommon.INVALID_POST_DATA, message))}
		if paged {
			options = append(options, SetPage(Page{Index: 1, Size: 2}))
		}
		recorder := responseJSONRecorder(options...)
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("status=%d", recorder.Code)
		}
		envelope := completeEnvelope(t, recorder)
		var description, status string
		if err := json.Unmarshal(envelope["DESCRIPTION"], &description); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(envelope["OPT_STATUS"], &status); err != nil {
			t.Fatal(err)
		}
		if description != message || status != httpcommon.INVALID_POST_DATA || string(envelope["DATA"]) != "null" {
			t.Fatalf("typed400 content changed: %s", recorder.Body.String())
		}
	}
	status := "custom\"status\n"
	r := NewResponse(SetOptStatus(status), SetHTTPStatus(200), SetData([]byte(`[]`)))
	var decoded RawResponse
	if err := json.Unmarshal(r.JSONBytes(), &decoded); err != nil || decoded.OptStatus != status {
		t.Fatalf("status escaping failed: %+v %v", decoded, err)
	}
}
func TestJSONRejectsMalformedRawDataOnce(t *testing.T) {
	for _, data := range [][]byte{[]byte(`{`), []byte(`{"n":1}{"n":2}`), []byte(" \n")} {
		recorder := responseJSONRecorder(SetData(data), SetPage(Page{Index: 1, Size: 2}), SetHTTPStatus(200))
		if recorder.Code != http.StatusInternalServerError {
			t.Errorf("invalid raw JSON must override HTTP status to500: got=%d", recorder.Code)
		}
		envelope := completeEnvelope(t, recorder)
		if string(envelope["OPT_STATUS"]) != `"SERVER_ERROR"` || string(envelope["DESCRIPTION"]) != `"internal server error"` || string(envelope["DATA"]) != "null" {
			t.Fatal("generic error envelope mismatch")
		}
	}
}
func TestJSONOrdinaryMapListAndTypedError(t *testing.T) {
	for _, data := range []interface{}{nil, map[string]interface{}{"items": []string{"one", "two"}}, []interface{}{1, "two"}} {
		recorder := responseJSONRecorder(SetData(data))
		if recorder.Code != http.StatusOK {
			t.Fatal(recorder.Code)
		}
		envelope := completeEnvelope(t, recorder)
		expected, err := json.Marshal(data)
		if err != nil {
			t.Fatal(err)
		}
		if string(envelope["DATA"]) != string(expected) {
			t.Fatalf("ordinary JSON semantics changed: got=%s want=%s", envelope["DATA"], expected)
		}
	}
	recorder := responseJSONRecorder(SetData(map[string]int{"n": 1}), SetError(ServiceError(httpcommon.INVALID_POST_DATA, "bad \"input\"")))
	if recorder.Code != 400 {
		t.Fatal(recorder.Code)
	}
	completeEnvelope(t, recorder)
	recorder = responseJSONRecorder(SetError(errors.New("ordinary failure")))
	if recorder.Code != 500 {
		t.Fatal(recorder.Code)
	}
	completeEnvelope(t, recorder)
}
func TestJSONMarshalFailureIsGenericAndValid(t *testing.T) {
	for _, data := range []interface{}{map[string]interface{}{"bad": math.NaN()}, json.RawMessage(`{`)} {
		recorder := responseJSONRecorder(SetData(data))
		if recorder.Code != 500 {
			t.Errorf("marshal failure status=%d", recorder.Code)
		}
		envelope := completeEnvelope(t, recorder)
		if string(envelope["DESCRIPTION"]) != `"internal server error"` {
			t.Fatal("marshal failure exposed implementation details")
		}
	}
}

func TestResponseDirectByteHelpersAreSafe(t *testing.T) {
	for _, data := range [][]byte{nil, {}, []byte(`{"n":1}`), []byte(`{"bad":`)} {
		response := NewResponse(SetData(data), SetError(ServiceError(httpcommon.INVALID_POST_DATA, "bad \"input\"\nline")))
		for _, body := range [][]byte{response.JSONBytes(), []byte(response.JSONString())} {
			var decoded RawResponse
			if err := json.Unmarshal(body, &decoded); err != nil {
				t.Fatalf("direct helper produced invalid JSON: %v", err)
			}
			if len(data) > 0 && !json.Valid(data) {
				if decoded.OptStatus != httpcommon.SERVER_ERROR || decoded.Description != "internal server error" {
					t.Fatal("direct helper exposed invalid data")
				}
			} else if decoded.OptStatus != httpcommon.INVALID_POST_DATA {
				t.Fatal("direct helper changed valid typed status")
			}
		}
	}
}

func TestJSONRejectsInvalidUTF8RawData(t *testing.T) {
	for _, raw := range [][]byte{{34, 255, 34}, append(append([]byte(`{"value":"`), 255), []byte(`"}`)...)} {
		for _, data := range []interface{}{raw, json.RawMessage(raw)} {
			recorder := responseJSONRecorder(SetData(data))
			if recorder.Code != 500 {
				t.Errorf("non-UTF8 raw JSON must produce500, got%d", recorder.Code)
			}
			if !utf8.Valid(recorder.Body.Bytes()) {
				t.Error("response contains invalid UTF8")
			}
			envelope := completeEnvelope(t, recorder)
			if string(envelope["OPT_STATUS"]) != `"SERVER_ERROR"` || string(envelope["DESCRIPTION"]) != `"internal server error"` {
				t.Error("invalid UTF8 raw output was accepted")
			}
		}
	}
}
