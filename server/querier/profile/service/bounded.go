package service

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	queriercommon "github.com/deepflowio/deepflow/server/querier/common"
	"github.com/deepflowio/deepflow/server/querier/config"
	"github.com/deepflowio/deepflow/server/querier/engine/clickhouse"
	profilecommon "github.com/deepflowio/deepflow/server/querier/profile/common"
	"github.com/deepflowio/deepflow/server/querier/profile/model"
	"github.com/klauspost/compress/zstd"
)

const (
	boundedMaxRows           = 4096
	boundedCompressedBytes   = 4 << 20
	boundedDecodedStackBytes = 1 << 20
	boundedTotalDecodedBytes = 8 << 20
	boundedMaxNodes          = 8192
	boundedMaxDepth          = 512
)

var boundedApp = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
var boundedTag = regexp.MustCompile(`^agent_id=([0-9]{1,5}) AND profile_value_unit='samples'$`)

type boundedQueryExecutor func(context.Context, string, string) (*queriercommon.Result, error)

func boundedError(message string) error {
	return queriercommon.NewError(queriercommon.RESOURCE_NUM_EXCEEDED, message)
}
func boundedInvalid(message string) error {
	return queriercommon.NewError(queriercommon.INVALID_POST_DATA, message)
}
func boundedBadResult(message string) error {
	return queriercommon.NewError(queriercommon.SERVER_ERROR, message)
}

func boundedBudget() *model.ProfileBudgets {
	return &model.ProfileBudgets{CompressedBytes: boundedCompressedBytes, DecodedStackBytes: boundedDecodedStackBytes,
		TotalDecodedStackBytes: boundedTotalDecodedBytes, Nodes: boundedMaxNodes, StackDepth: boundedMaxDepth}
}

func boundedProfileSQL(args model.Profile, cfg *config.QuerierConfig) (string, int, error) {
	if args.MaxRows == nil {
		return "", 0, boundedInvalid("max_rows is required")
	}
	n := *args.MaxRows
	if cfg == nil || cfg.Profile.FlameQueryLimit <= 1 {
		return "", 0, boundedBadResult("bounded profile configuration unavailable")
	}
	if n < 1 || n > boundedMaxRows || n >= cfg.Profile.FlameQueryLimit {
		return "", 0, boundedInvalid("max_rows must be 1..min(4096, flame_query_limit-1)")
	}
	if args.ProfileEventType != "cpu" || args.ProfileLanguageType != "Golang" || !boundedApp.MatchString(args.AppService) {
		return "", 0, boundedInvalid("bounded profiles require an exact safe application, Golang and cpu")
	}
	if args.TimeStart <= 0 || args.TimeEnd < args.TimeStart || int64(args.TimeEnd)-int64(args.TimeStart) > 31*86400 {
		return "", 0, boundedInvalid("bounded profile time range must be ordered positive seconds within31days")
	}
	filter := "profile_value_unit='samples'"
	if args.TagFilter != "" && args.TagFilter != filter {
		match := boundedTag.FindStringSubmatch(args.TagFilter)
		if match == nil {
			return "", 0, boundedInvalid("bounded profile only accepts exact internal Agent/sample scope")
		}
		agent, err := strconv.ParseUint(match[1], 10, 16)
		if err != nil {
			return "", 0, boundedInvalid("invalid profile Agent ID")
		}
		filter = fmt.Sprintf("agent_id=%d AND profile_value_unit='samples'", agent)
	}
	return fmt.Sprintf("SELECT profile_location_str, profile_value FROM in_process WHERE time>=%d AND time<=%d AND app_service='%s' AND profile_language_type='Golang' AND profile_event_type='cpu' AND (%s) LIMIT %d", args.TimeStart, args.TimeEnd, args.AppService, filter, n+1), n, nil
}

func executeBoundedQuery(ctx context.Context, org, sql string) (*queriercommon.Result, error) {
	engine := &clickhouse.CHEngine{DB: profilecommon.DATABASE_PROFILE}
	engine.Init()
	result, _, err := engine.ExecuteQuery(&queriercommon.QuerierParams{DB: profilecommon.DATABASE_PROFILE, Sql: sql, Context: ctx, ORGID: org})
	return result, err
}

// The distinct route opts into these limits; the legacy formatter is untouched.
func BoundedProfile(args model.Profile, cfg *config.QuerierConfig) (model.ProfileTree, interface{}, error) {
	tree, err := generateBoundedProfile(args, cfg, executeBoundedQuery)
	return tree, nil, err
}

func generateBoundedProfile(args model.Profile, cfg *config.QuerierConfig, execute boundedQueryExecutor) (model.ProfileTree, error) {
	sql, n, err := boundedProfileSQL(args, cfg)
	if err != nil {
		return model.ProfileTree{}, err
	}
	ctx := args.Context
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return model.ProfileTree{}, err
	}
	result, err := execute(ctx, args.OrgID, sql)
	if err != nil {
		return model.ProfileTree{}, err
	}
	if result == nil {
		return model.ProfileTree{}, boundedBadResult("missing bounded profile result")
	}
	// Reject the sentinel before reading columns, decompressing any row or allocating a tree.
	if len(result.Values) > n {
		return model.ProfileTree{}, boundedError("profile input exceeds max_rows; narrow the scope")
	}
	return formatBoundedProfile(ctx, args.AppService, n, result)
}

func formatBoundedProfile(ctx context.Context, app string, n int, result *queriercommon.Result) (model.ProfileTree, error) {
	locationIndex, valueIndex := -1, -1
	if len(result.Columns) != 2 {
		return model.ProfileTree{}, boundedBadResult("invalid bounded profile columns")
	}
	for i, column := range result.Columns {
		switch column {
		case "profile_location_str":
			if locationIndex >= 0 {
				return model.ProfileTree{}, boundedBadResult("duplicate profile location column")
			}
			locationIndex = i
		case "profile_value":
			if valueIndex >= 0 {
				return model.ProfileTree{}, boundedBadResult("duplicate profile value column")
			}
			valueIndex = i
		default:
			return model.ProfileTree{}, boundedBadResult("unexpected bounded profile column")
		}
	}
	if locationIndex < 0 || valueIndex < 0 {
		return model.ProfileTree{}, boundedBadResult("missing bounded profile column")
	}
	rows := len(result.Values)
	tree := model.ProfileTree{Functions: []string{}, FunctionTypes: []string{}, BoundsApplied: true, MaxRows: n, InputRows: &rows, Budgets: boundedBudget(),
		FunctionValues: model.Value{Columns: []string{"self_value", "total_value"}, Values: [][]int{}},
		NodeValues:     model.Value{Columns: []string{"function_id", "parent_node_id", "self_value", "total_value"}, Values: [][]int{}}}
	if rows == 0 {
		return tree, nil
	}
	compressed := 0
	for _, raw := range result.Values {
		row, ok := raw.([]interface{})
		if !ok || len(row) != 2 {
			return model.ProfileTree{}, boundedBadResult("malformed bounded profile row")
		}
		stack, ok := row[locationIndex].(string)
		if !ok {
			return model.ProfileTree{}, boundedBadResult("invalid profile stack type")
		}
		weight, ok := row[valueIndex].(int64)
		if !ok || weight < 0 {
			return model.ProfileTree{}, boundedBadResult("invalid profile sample weight")
		}
		if len(stack) > boundedCompressedBytes-compressed {
			return model.ProfileTree{}, boundedError("profile compressed input exceeds4MiB")
		}
		compressed += len(stack)
	}
	decoder, err := zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderMaxMemory(boundedDecodedStackBytes), zstd.WithDecoderMaxWindow(boundedDecodedStackBytes))
	if err != nil {
		return model.ProfileTree{}, err
	}
	defer decoder.Close()
	type edge struct {
		parent int
		frame  string
	}
	edges := make(map[edge]int)
	functions := map[string]int{app: 0}
	tree.Functions = append(tree.Functions, app)
	tree.NodeValues.Values = append(tree.NodeValues.Values, []int{0, -1, 0, 0})
	decodedBytes := 0
	for _, raw := range result.Values {
		if err := ctx.Err(); err != nil {
			return model.ProfileTree{}, err
		}
		row := raw.([]interface{})
		stack := row[locationIndex].(string)
		weight := row[valueIndex].(int64)
		decoded, err := decoder.DecodeAll([]byte(stack), nil)
		if err != nil {
			if err == zstd.ErrDecoderSizeExceeded || err == zstd.ErrWindowSizeExceeded {
				return model.ProfileTree{}, boundedError("profile decoded stack/window exceeds1MiB")
			}
			return model.ProfileTree{}, boundedBadResult("invalid compressed profile stack")
		}
		if !utf8.Valid(decoded) || strings.IndexByte(string(decoded), 0) >= 0 {
			return model.ProfileTree{}, boundedBadResult("invalid profile stack text")
		}
		if len(decoded) == 0 {
			return model.ProfileTree{}, boundedBadResult("empty decoded profile stack")
		}
		if len(decoded) > boundedDecodedStackBytes {
			return model.ProfileTree{}, boundedError("profile decoded stack exceeds1MiB")
		}
		if len(decoded) > boundedTotalDecodedBytes-decodedBytes {
			return model.ProfileTree{}, boundedError("profile total decoded stacks exceed8MiB")
		}
		decodedBytes += len(decoded)
		frames := strings.Split(string(decoded), ";")
		if len(frames) > boundedMaxDepth {
			return model.ProfileTree{}, boundedError("profile stack depth exceeds512")
		}
		for _, frame := range frames {
			if frame == "" {
				return model.ProfileTree{}, boundedBadResult("empty profile stack frame")
			}
		}
		parent := 0
		if err := addBoundedWeight(&tree.NodeValues.Values[0][3], weight); err != nil {
			return model.ProfileTree{}, err
		}
		for _, frame := range frames {
			key := edge{parent, frame}
			node, ok := edges[key]
			if !ok {
				if len(tree.NodeValues.Values) >= boundedMaxNodes {
					return model.ProfileTree{}, boundedError("profile tree exceeds8192nodes")
				}
				function, exists := functions[frame]
				if !exists {
					function = len(tree.Functions)
					functions[frame] = function
					tree.Functions = append(tree.Functions, frame)
				}
				node = len(tree.NodeValues.Values)
				edges[key] = node
				tree.NodeValues.Values = append(tree.NodeValues.Values, []int{function, parent, 0, 0})
			}
			if err := addBoundedWeight(&tree.NodeValues.Values[node][3], weight); err != nil {
				return model.ProfileTree{}, err
			}
			parent = node
		}
		if err := addBoundedWeight(&tree.NodeValues.Values[parent][2], weight); err != nil {
			return model.ProfileTree{}, err
		}
	}
	tree.FunctionValues.Values = make([][]int, len(tree.Functions))
	for i := range tree.FunctionValues.Values {
		tree.FunctionValues.Values[i] = []int{0, 0}
	}
	for _, node := range tree.NodeValues.Values {
		for i := 0; i < 2; i++ {
			if err := addBoundedWeight(&tree.FunctionValues.Values[node[0]][i], int64(node[i+2])); err != nil {
				return model.ProfileTree{}, err
			}
		}
	}
	tree.FunctionTypes = GetLocationType(tree.Functions, tree.FunctionValues.Values, "cpu")
	return tree, nil
}

func addBoundedWeight(target *int, value int64) error {
	max := int64(^uint(0) >> 1)
	if value < 0 || value > max-int64(*target) {
		return boundedError("profile sample total exceeds integer capacity")
	}
	*target += int(value)
	return nil
}
