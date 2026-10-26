// Copyright 2026 TrafLens authors.
// SPDX-License-Identifier: Apache-2.0

package querier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/router"
)

func singleQueryResponse(t *testing.T, recorder *httptest.ResponseRecorder) router.Response {
	t.Helper()
	decoder := json.NewDecoder(strings.NewReader(recorder.Body.String()))
	var response router.Response
	if err := decoder.Decode(&response); err != nil {
		t.Fatalf("invalid response JSON: %v; body=%q", err, recorder.Body.String())
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Errorf("response has trailing JSON/data: %v; body=%q", err, recorder.Body.String())
	}
	return response
}

func TestErrHandleWritesOneGenericServerErrorAndAborts(t *testing.T) {
	engine := gin.New()
	engine.Use(ErrHandle())
	after := false
	engine.POST("/v1/query/", func(c *gin.Context) { panic("private internal panic detail") }, func(c *gin.Context) { after = true })
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/query/", nil))
	if recorder.Code != http.StatusInternalServerError {
		t.Errorf("status=%d, want 500", recorder.Code)
	}
	response := singleQueryResponse(t, recorder)
	if response.OptStatus != common.SERVER_ERROR || response.Description == "" {
		t.Errorf("unexpected server error response: %+v", response)
	}
	if strings.Contains(recorder.Body.String(), "private internal panic detail") || strings.Contains(recorder.Body.String(), "goroutine") {
		t.Error("response disclosed internal panic information")
	}
	if after {
		t.Error("handler chain continued after recovery")
	}
}

func TestErrHandleKeepsWrittenResponseAndHeaders(t *testing.T) {
	engine := gin.New()
	engine.Use(ErrHandle())
	after := false
	const original = `{"message":"already complete"}`
	engine.POST("/v1/query/", func(c *gin.Context) {
		c.Header("X-Response-Marker", "preserved")
		c.Data(http.StatusAccepted, "application/json", []byte(original))
		panic("private internal panic detail")
	}, func(c *gin.Context) { after = true })
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/query/", nil))
	if recorder.Code != http.StatusAccepted || recorder.Body.String() != original || recorder.Header().Get("X-Response-Marker") != "preserved" || recorder.Header().Get("Content-Type") != "application/json" {
		t.Errorf("written response changed: code=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
	if after {
		t.Error("handler chain continued after written-response panic")
	}
}

func TestErrHandleLeavesNormalResponseUnchanged(t *testing.T) {
	engine := gin.New()
	engine.Use(ErrHandle())
	engine.POST("/v1/query/", func(c *gin.Context) {
		c.Header("X-Response-Marker", "normal")
		c.Data(http.StatusCreated, "application/json", []byte(`{"message":"normal"}`))
	})
	recorder := httptest.NewRecorder()
	engine.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/query/", nil))
	if recorder.Code != http.StatusCreated || recorder.Body.String() != `{"message":"normal"}` || recorder.Header().Get("X-Response-Marker") != "normal" {
		t.Errorf("normal response changed: code=%d headers=%v body=%q", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestQueryEndpointRejectsEmptyFunctionsWithoutDatabase(t *testing.T) {
	previousConfig, previousController := config.Cfg, config.ControllerCfg
	cfg := config.DefaultConfig()
	cfg.ControllerConfig.DFWebService.Enabled = false
	config.Cfg, config.ControllerCfg = &cfg.QuerierConfig, &cfg.ControllerConfig
	t.Cleanup(func() { config.Cfg, config.ControllerCfg = previousConfig, previousController })
	engine := gin.New()
	engine.Use(ErrHandle())
	router.QueryRouter(engine)
	for _, expression := range []string{"count()", "Count()", "UnrecognizedFunction()"} {
		for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json"} {
			t.Run(expression+"/"+contentType, func(t *testing.T) {
				sql := "SELECT " + expression + " FROM l7_flow_log"
				body := url.Values{"db": {"flow_log"}, "sql": {sql}}.Encode()
				if contentType == "application/json" {
					data, err := json.Marshal(map[string]string{"db": "flow_log", "sql": sql})
					if err != nil {
						t.Fatal(err)
					}
					body = string(data)
				}
				recorder := httptest.NewRecorder()
				request := httptest.NewRequest(http.MethodPost, "/v1/query/", strings.NewReader(body))
				request.Header.Set("Content-Type", contentType)
				engine.ServeHTTP(recorder, request)
				if recorder.Code != http.StatusBadRequest {
					t.Errorf("status=%d, want 400", recorder.Code)
				}
				response := singleQueryResponse(t, recorder)
				if response.OptStatus != common.INVALID_POST_DATA || !strings.Contains(response.Description, "argument") {
					t.Errorf("unexpected validation response: %+v", response)
				}
			})
		}
	}
}
