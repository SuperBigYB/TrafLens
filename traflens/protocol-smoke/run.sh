#!/usr/bin/env bash
set -euo pipefail

# Generate only in a disposable directory. Never run make vendor or go generate
# against the upstream source tree for this small compatibility check.
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=${TRAFLENS_ROOT:-$(git -C "$script_dir" rev-parse --show-toplevel)}
source_ref=8741e924ff0ae3964a135985c51e5a6ce6bde397
go_bin=${GO:-go}
protoc_bin=${PROTOC:-protoc}
export GOWORK=off
export GOTOOLCHAIN=local

command -v "$go_bin" >/dev/null || { echo "Go is required (set GO=/absolute/path/to/go)." >&2; exit 1; }
command -v "$protoc_bin" >/dev/null || { echo "protoc is required (set PROTOC=/absolute/path/to/protoc)." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required for safe copied-schema preparation." >&2; exit 1; }
git -C "$repo_root" cat-file -e "$source_ref^{commit}"

mkdir -p "$repo_root/.traflens/work"
build_dir=$(mktemp -d "$repo_root/.traflens/work/protocol-smoke.XXXXXXXX")
cleanup() {
  if [[ ${KEEP_WORK:-0} == 1 ]]; then
    echo "Retained scratch directory: $build_dir"
  else
    rm -rf -- "$build_dir"
  fi
}
trap cleanup EXIT
mkdir -p "$build_dir/flowpb" "$build_dir/statspb" "$build_dir/fixtures" "$build_dir/bin" "$build_dir/include/github.com/gogo"
mkdir -p "$build_dir/reference"
# Encode fixtures with the upstream baseline, independently of candidate schemas.
git -C "$repo_root" show "$source_ref:message/flow_log.proto" > "$build_dir/reference/flow_log.proto"
git -C "$repo_root" show "$source_ref:message/stats.proto" > "$build_dir/reference/stats.proto"
cp "$script_dir/go.mod" "$script_dir/go.sum" "$script_dir/protocol_test.go" "$build_dir/"
cp "$script_dir/fixtures/"*.textproto "$build_dir/fixtures/"
# Test the candidate working tree. The contract assertions and fixtures below
# are pinned to source_ref, so local schema changes cannot bypass validation.
cp "$repo_root/message/flow_log.proto" "$build_dir/flowpb/flow_log.proto"
cp "$repo_root/message/stats.proto" "$build_dir/statspb/stats.proto"

# Equivalent to upstream server/Makefile's sed on lines 6-10, but fail loudly
# if the pinned recipe does not match instead of stripping arbitrary lines.
python3 - "$build_dir/flowpb/flow_log.proto" "$build_dir/statspb/stats.proto" <<'PY'
from pathlib import Path
import sys
expected = [
    'import "github.com/gogo/protobuf/gogoproto/gogo.proto";',
    'option (gogoproto.unmarshaler_all) = true;',
    'option (gogoproto.marshaler_all) = true;',
    'option (gogoproto.sizer_all) = true;',
]
for name in sys.argv[1:]:
    path = Path(name)
    source = path.read_text(encoding="utf-8")
    for line in expected:
        original = "// " + line
        if source.count(original) != 1:
            raise SystemExit(f"Pinned schema preparation did not match: {name}: {line}")
        source = source.replace(original, line, 1)
    path.write_text(source, encoding="utf-8")
PY

cd "$build_dir"
"$go_bin" mod download github.com/gogo/protobuf
gogo_dir=$("$go_bin" list -mod=readonly -m -f '{{.Dir}}' github.com/gogo/protobuf)
ln -s "$gogo_dir" "$build_dir/include/github.com/gogo/protobuf"
"$go_bin" build -mod=readonly -o "$build_dir/bin/protoc-gen-gogo" github.com/gogo/protobuf/protoc-gen-gogo
export PATH="$build_dir/bin:$PATH"

for pair in flowpb/flow_log statspb/stats; do
  schema_dir="$build_dir/${pair%/*}"
  schema_file="${pair##*/}.proto"
  (
    cd "$schema_dir"
    "$protoc_bin" -I=. -I="$build_dir/include" -I="$gogo_dir/protobuf" --gogo_out=plugins=grpc:. "$schema_file"
  )
done

encode() {
  local schema_dir="$1" schema_file="$2" message_type="$3" fixture_name="$4"
  "$protoc_bin" -I="$schema_dir" -I="$build_dir/include" -I="$gogo_dir/protobuf" \
    --encode="$message_type" "$schema_file" \
    < "$build_dir/fixtures/$fixture_name.textproto" > "$build_dir/fixtures/$fixture_name.wire"
}
encode "$build_dir/reference" flow_log.proto flow_log.AppProtoLogsData http-session
encode "$build_dir/reference" flow_log.proto flow_log.TaggedFlow l4-flow
encode "$build_dir/reference" stats.proto stats.Stats stats

printf 'Compatibility reference: %s\n' "$source_ref"
printf 'Go: %s\n' "$("$go_bin" version)"
printf 'Protoc: %s\n' "$("$protoc_bin" --version)"
"$go_bin" test -mod=readonly -count=1 -v ./...
