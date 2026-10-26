// Copyright 2026 TrafLens authors.
// SPDX-License-Identifier: Apache-2.0

package clickhouse

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/parse"
)

func queryArgumentConfig(t *testing.T) {
	t.Helper()
	oldConfig, oldController := config.Cfg, config.ControllerCfg
	cfg := config.DefaultConfig()
	cfg.ControllerConfig.DFWebService.Enabled = false
	config.Cfg, config.ControllerCfg = &cfg.QuerierConfig, &cfg.ControllerConfig
	t.Cleanup(func() { config.Cfg, config.ControllerCfg = oldConfig, oldController })
}

func queryArgumentError(t *testing.T, run func() error) {
	t.Helper()
	defer func() {
		if value := recover(); value != nil {
			t.Errorf("empty argument list panicked: %v", value)
		}
	}()
	err := run()
	var serviceError *common.ServiceError
	if !errors.As(err, &serviceError) || serviceError.Status != common.INVALID_POST_DATA {
		t.Fatalf("got %v, want INVALID_POST_DATA validation error", err)
	}
	if !strings.Contains(serviceError.Message, "argument") {
		t.Fatalf("missing actionable argument error: %q", serviceError.Message)
	}
}

func TestEmptyAggregateArgumentsReturnValidationError(t *testing.T) {
	for _, name := range []string{"Count", "count", "UnrecognizedFunction", ""} {
		for _, empty := range [][]string{nil, {}} {
			t.Run(name+"/"+strings.Join(empty, ","), func(t *testing.T) {
				queryArgumentError(t, func() error {
					_, _, _, err := GetAggFunc(name, empty, "", nil, &CHEngine{DB: "flow_log"})
					return err
				})
			})
		}
	}
}

func TestEmptyFunctionSQLReturnsValidationError(t *testing.T) {
	queryArgumentConfig(t)
	for _, input := range []string{
		"SELECT count() FROM l7_flow_log",
		"SELECT Count() FROM l7_flow_log",
		"SELECT Count()+1 FROM l7_flow_log",
		"SELECT UnrecognizedFunction() FROM l7_flow_log",
	} {
		t.Run(input, func(t *testing.T) {
			e := CHEngine{DB: "flow_log", Context: context.Background()}
			e.Init()
			parser := parse.Parser{Engine: &e}
			queryArgumentError(t, func() error { return parser.ParseSQL(input) })
		})
	}
}

func TestCountRowSQLKeepsCanonicalTranslation(t *testing.T) {
	queryArgumentConfig(t)
	// Independent expected SQL from upstream count_1 and count_2 fixtures in
	// clickhouse_test.go. No ClickHouse, controller or monkey patch is used.
	for _, test := range []struct{ input, want string }{
		{"SELECT Count(row) AS a FROM l7_flow_log HAVING a > 0", "SELECT COUNT(1) AS `a` FROM flow_log.`l7_flow_log` HAVING a > 0 LIMIT 10000"},
		{"SELECT Count(row) FROM l7_flow_log HAVING Count(row) > 0", "SELECT COUNT(1) AS `Count(row)` FROM flow_log.`l7_flow_log` HAVING COUNT(1) > 0 LIMIT 10000"},
	} {
		t.Run(test.input, func(t *testing.T) {
			e := CHEngine{DB: "flow_log", Context: context.Background()}
			e.Init()
			parser := parse.Parser{Engine: &e}
			if err := parser.ParseSQL(test.input); err != nil {
				t.Fatal(err)
			}
			if got := e.ToSQLString(); got != test.want {
				t.Fatalf("Count(row) translation changed:\ngot  %s\nwant %s", got, test.want)
			}
		})
	}
}
