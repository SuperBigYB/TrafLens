package router

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/gin-gonic/gin"
)

func TestBoundedRouteRequiresExplicitIntegerBudget(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	cfg := &config.QuerierConfig{}
	cfg.Profile.FlameQueryLimit = 1000000
	ProfileRouter(engine, cfg)
	for _, budget := range []string{"", `,"max_rows":null`, `,"max_rows":0`, `,"max_rows":-1`, `,"max_rows":1.5`, `,"max_rows":true`, `,"max_rows":4097`, `,"max_rows":"2"`} {
		body := `{"app_service":"cpu-fixture","profile_event_type":"cpu","profile_language_type":"Golang","time_start":100,"time_end":110` + budget + `}`
		req := httptest.NewRequest("POST", "/v1/profile/ProfileTracingBounded", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		engine.ServeHTTP(rr, req)
		if rr.Code != 400 {
			t.Fatalf("bad budget reached native query: %s -> %d %s", budget, rr.Code, rr.Body.String())
		}
	}
}
func TestBoundedMetadataDoesNotChangeLegacyJSON(t *testing.T) {
	bytes, err := json.Marshal(model.ProfileTree{})
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"bounds_applied", "max_rows", "input_rows", "budgets"} {
		if strings.Contains(string(bytes), key) {
			t.Fatal("legacy tree gained bound metadata")
		}
	}
	var old model.Profile
	if err := json.Unmarshal([]byte(`{"app_service":"cpu-old"}`), &old); err != nil || old.MaxRows != nil {
		t.Fatal("legacy request changed")
	}
}
