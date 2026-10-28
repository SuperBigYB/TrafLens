package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	queriercommon "github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/klauspost/compress/zstd"
)

func boundedArgs() (model.Profile, *config.QuerierConfig) {
	n := 2
	args := model.Profile{MaxRows: &n, AppService: "cpu-fixture", ProfileLanguageType: "Golang", ProfileEventType: "cpu", TimeStart: 100, TimeEnd: 110, Context: context.Background(), OrgID: "1", TagFilter: "agent_id=17 AND profile_value_unit='samples'"}
	cfg := &config.QuerierConfig{}
	cfg.Profile.FlameQueryLimit = 1000000
	return args, cfg
}
func compressBoundedTest(t *testing.T, s string) string {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	return string(encoder.EncodeAll([]byte(s), nil))
}
func boundedRows(rows ...[]interface{}) *queriercommon.Result {
	r := &queriercommon.Result{Columns: []interface{}{"profile_location_str", "profile_value"}}
	for _, row := range rows {
		r.Values = append(r.Values, row)
	}
	return r
}
func requireBoundedStatus(t *testing.T, err error, status string) {
	t.Helper()
	var typed *queriercommon.ServiceError
	if !errors.As(err, &typed) || typed.Status != status {
		t.Fatalf("wanted %s, got %v", status, err)
	}
}
func TestBoundedSQLAndValidationBeforeExecutor(t *testing.T) {
	args, cfg := boundedArgs()
	sql, n, err := boundedProfileSQL(args, cfg)
	if err != nil || n != 2 || !strings.HasSuffix(sql, "LIMIT 3") || !strings.Contains(sql, "agent_id=17 AND profile_value_unit='samples'") {
		t.Fatalf("query changed: %q %v", sql, err)
	}
	for _, tag := range []string{"", "profile_value_unit='samples'", "agent_id=65535 AND profile_value_unit='samples'"} {
		args.TagFilter = tag
		if _, _, err := boundedProfileSQL(args, cfg); err != nil {
			t.Fatal(err)
		}
	}
	for _, value := range []int{-1, 0, 4097, 1000000} {
		a, c := boundedArgs()
		a.MaxRows = &value
		_, err := generateBoundedProfile(a, c, func(context.Context, string, string) (*queriercommon.Result, error) {
			t.Fatal("invalid limit reached executor")
			return nil, nil
		})
		requireBoundedStatus(t, err, queriercommon.INVALID_POST_DATA)
	}
	for _, change := range []func(*model.Profile){func(a *model.Profile) { a.MaxRows = nil }, func(a *model.Profile) { a.AppService = "x' OR 1=1" }, func(a *model.Profile) { a.ProfileEventType = "inuse_space" }, func(a *model.Profile) { a.ProfileLanguageType = "eBPF" }, func(a *model.Profile) { a.TagFilter = "agent_id=65536 AND profile_value_unit='samples'" }, func(a *model.Profile) { a.TagFilter = "1=1 LIMIT 1000000" }, func(a *model.Profile) { a.TimeEnd = 99 }} {
		a, c := boundedArgs()
		change(&a)
		_, _, err := boundedProfileSQL(a, c)
		requireBoundedStatus(t, err, queriercommon.INVALID_POST_DATA)
	}
	args, cfg = boundedArgs()
	cfg.Profile.FlameQueryLimit = 3
	if _, _, err := boundedProfileSQL(args, cfg); err != nil {
		t.Fatal(err)
	}
	cfg.Profile.FlameQueryLimit = 2
	_, _, err = boundedProfileSQL(args, cfg)
	requireBoundedStatus(t, err, queriercommon.INVALID_POST_DATA)
}
func TestBoundedSentinelBeforeColumnsOrDecompression(t *testing.T) {
	args, cfg := boundedArgs()
	result := boundedRows([]interface{}{"not-zstd", int64(1)}, []interface{}{"not-zstd", int64(1)}, []interface{}{"not-zstd", int64(1)})
	result.Columns = nil
	tree, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return result, nil })
	requireBoundedStatus(t, err, queriercommon.RESOURCE_NUM_EXCEEDED)
	if tree.BoundsApplied || len(tree.Functions) > 0 {
		t.Fatal("sentinel returned partial tree")
	}
}
func TestBoundedRealStackWeightsAndMetadata(t *testing.T) {
	args, cfg := boundedArgs()
	r := boundedRows([]interface{}{compressBoundedTest(t, "main;hot"), int64(790)}, []interface{}{compressBoundedTest(t, "main;other"), int64(10)})
	tree, err := generateBoundedProfile(args, cfg, func(ctx context.Context, org, sql string) (*queriercommon.Result, error) {
		if org != "1" {
			t.Fatal("org changed")
		}
		return r, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tree.BoundsApplied || tree.MaxRows != 2 || tree.InputRows == nil || *tree.InputRows != 2 || tree.Budgets == nil || tree.Budgets.Nodes != 8192 || tree.Budgets.StackDepth != 512 {
		t.Fatalf("bounds absent: %+v", tree)
	}
	if tree.NodeValues.Values[0][3] != 800 {
		t.Fatal("root samples differ")
	}
	var hot int
	for i, name := range tree.Functions {
		if name == "hot" {
			hot = tree.FunctionValues.Values[i][0]
		}
	}
	if hot != 790 {
		t.Fatal("hot samples differ")
	}
	for i, node := range tree.NodeValues.Values {
		if i > 0 && (node[1] < 0 || node[1] >= i) {
			t.Fatal("invalid parent")
		}
	}
}
func TestBoundedEmptyAndMalformedUpstream(t *testing.T) {
	args, cfg := boundedArgs()
	tree, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return boundedRows(), nil })
	if err != nil || !tree.BoundsApplied || tree.InputRows == nil || *tree.InputRows != 0 || tree.Functions == nil || len(tree.Functions) != 0 || tree.NodeValues.Values == nil {
		t.Fatalf("empty shape: %+v %v", tree, err)
	}
	for _, r := range []*queriercommon.Result{nil, {Columns: []interface{}{"profile_location_str"}}, {Columns: []interface{}{"profile_value", "profile_value"}}, boundedRows([]interface{}{"x"}), boundedRows([]interface{}{3, int64(1)}), boundedRows([]interface{}{"x", float64(1)}), boundedRows([]interface{}{"x", int64(-1)})} {
		_, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return r, nil })
		requireBoundedStatus(t, err, queriercommon.SERVER_ERROR)
	}
}
func TestBoundedCorruptAndPerStackBudget(t *testing.T) {
	args, cfg := boundedArgs()
	for _, test := range []struct {
		stack  string
		status string
	}{
		{"bad-zstd", queriercommon.SERVER_ERROR},
		{compressBoundedTest(t, string([]byte{0xff, 0xfe})), queriercommon.SERVER_ERROR},
		{compressBoundedTest(t, "main\x00bad"), queriercommon.SERVER_ERROR},
		{compressBoundedTest(t, ""), queriercommon.SERVER_ERROR},
		{compressBoundedTest(t, strings.Repeat("x", (1<<20)+1)), queriercommon.RESOURCE_NUM_EXCEEDED},
		{compressBoundedTest(t, strings.Repeat("x;", 512)+"x"), queriercommon.RESOURCE_NUM_EXCEEDED},
	} {
		_, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) {
			return boundedRows([]interface{}{test.stack, int64(1)}), nil
		})
		requireBoundedStatus(t, err, test.status)
	}
}
func TestBoundedAggregateInputAndDecodedBudgets(t *testing.T) {
	args, cfg := boundedArgs()
	n := 9
	args.MaxRows = &n
	cases := []*queriercommon.Result{boundedRows([]interface{}{strings.Repeat("x", (2<<20)+1), int64(1)}, []interface{}{strings.Repeat("y", 2<<20), int64(1)})}
	total := boundedRows()
	stack := compressBoundedTest(t, strings.Repeat("x", 1<<20))
	for i := 0; i < 9; i++ {
		total.Values = append(total.Values, []interface{}{stack, int64(1)})
	}
	cases = append(cases, total)
	for _, r := range cases {
		_, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return r, nil })
		requireBoundedStatus(t, err, queriercommon.RESOURCE_NUM_EXCEEDED)
	}
}
func TestBoundedNodeBudgetAndSampleOverflow(t *testing.T) {
	args, cfg := boundedArgs()
	n := 17
	args.MaxRows = &n
	r := boundedRows()
	for i := 0; i < 17; i++ {
		frames := make([]string, 512)
		for j := range frames {
			frames[j] = fmt.Sprintf("r%df%d", i, j)
		}
		r.Values = append(r.Values, []interface{}{compressBoundedTest(t, strings.Join(frames, ";")), int64(1)})
	}
	_, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return r, nil })
	requireBoundedStatus(t, err, queriercommon.RESOURCE_NUM_EXCEEDED)
	args, cfg = boundedArgs()
	stack := compressBoundedTest(t, "f")
	r = boundedRows([]interface{}{stack, int64(^uint(0) >> 1)}, []interface{}{stack, int64(1)})
	_, err = generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) { return r, nil })
	requireBoundedStatus(t, err, queriercommon.RESOURCE_NUM_EXCEEDED)
}
func TestBoundedContextAndParallelQueries(t *testing.T) {
	args, cfg := boundedArgs()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	args.Context = ctx
	_, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) {
		t.Fatal("canceled request queried")
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	args.Context = context.Background()
	stack := compressBoundedTest(t, "main;hot")
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tree, err := generateBoundedProfile(args, cfg, func(context.Context, string, string) (*queriercommon.Result, error) {
				return boundedRows([]interface{}{stack, int64(800)}), nil
			})
			if err != nil || tree.NodeValues.Values[0][3] != 800 {
				t.Errorf("parallel formatter: %v", err)
			}
		}()
	}
	wg.Wait()
}
