#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'TrafLens build: %s\n' "$*" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || fail 'this build entry point requires Linux'
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"
tools="$repo_root/.traflens/tools"
download_tools="${TRAFLENS_DOWNLOAD_TOOLS:-0}"
[[ "$download_tools" == 0 || "$download_tools" == 1 ]] || fail 'TRAFLENS_DOWNLOAD_TOOLS must be 0 or 1'

for tool in awk git make patch protoc python3; do
    command -v "$tool" >/dev/null || fail "missing system prerequisite: $tool"
done
required_go="$(awk '$1 == "go" { print $2; exit }' "$repo_root/server/go.mod")"
[[ "$required_go" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'cannot determine exact Go version from server/go.mod'
bootstrap="$(command -v "${TRAFLENS_GO:-go}" || true)"
[[ -n "$bootstrap" && -x "$bootstrap" ]] || fail "set TRAFLENS_GO to an executable Go $required_go (or a bootstrap Go)"
bootstrap="$(readlink -f -- "$bootstrap")"

# Reuse the existing verified module cache, while isolating tool binaries/GOPATH.
export GOMODCACHE="${GOMODCACHE:-$("$bootstrap" env GOMODCACHE)}"
export GOPATH="$tools/gopath"
export GOBIN="$tools/bin"
export GOTOOLCHAIN=local
export GOSUMDB=sum.golang.org
if [[ "$download_tools" == 1 ]]; then
    export GOPROXY="${TRAFLENS_GOPROXY:-${GOPROXY:-https://proxy.golang.org,direct}}"
else
    export GOPROXY=off
fi
mkdir -p -- "$tools" "$GOBIN" "$GOPATH/src/github.com/gogo"

go_bin="$bootstrap"
if [[ "$("$go_bin" version | awk '{print $3}')" != "go$required_go" ]]; then
    case "$(uname -m)" in
        x86_64) go_arch=amd64 ;;
        aarch64) go_arch=arm64 ;;
        *) fail 'unsupported architecture; supply a verified exact TRAFLENS_GO executable' ;;
    esac
    module="golang.org/toolchain@v0.0.1-go${required_go}.linux-${go_arch}"
    case "$required_go:$go_arch" in
        1.26.2:amd64) expected_sum='h1:mCBp0gCL9gQVqXpC60jQ7R46JDxL73qeF8hv6SnV2ss=' ;;
        *) fail 'toolchain checksum is not pinned here; supply a verified exact TRAFLENS_GO executable' ;;
    esac
    if ! metadata="$(cd -- "$tools" && "$bootstrap" mod download -json "$module")"; then
        fail "Go $required_go unavailable in cache; opt in with TRAFLENS_DOWNLOAD_TOOLS=1 or set TRAFLENS_GO"
    fi
    toolchain_dir="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')"
    actual_sum="$(printf '%s' "$metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Sum"])')"
    [[ "$actual_sum" == "$expected_sum" ]] || fail 'Go toolchain module checksum does not match the pinned checksum'
    go_bin="$toolchain_dir/bin/go"
    # A bootstrap Go before automatic toolchains unpacks module files read-only.
    chmod u+x "$go_bin" "$toolchain_dir/bin/gofmt" "$toolchain_dir/pkg/tool/linux_${go_arch}/"*
fi
[[ "$("$go_bin" version | awk '{print $3}')" == "go$required_go" ]] || fail "Go executable must be exactly $required_go"
export PATH="$(dirname -- "$go_bin"):$GOBIN:$tools/pyenv/bin:$PATH"

ensure_go_tool() {
    local binary="$1" package="$2" module="$3" version="$4"
    if [[ -x "$GOBIN/$binary" ]] && "$go_bin" version -m "$GOBIN/$binary" | \
        awk -v module="$module" -v version="$version" '$1 == "mod" && $2 == module && $3 == version { found=1 } END { exit !found }'; then
        return
    fi
    [[ "$download_tools" == 1 ]] || fail "missing $binary@$version; opt in with TRAFLENS_DOWNLOAD_TOOLS=1"
    (cd -- "$tools" && "$go_bin" install "$package@$version")
}

# Versions are pinned in upstream server/Dockerfile.builder.
ensure_go_tool protoc-gen-gofast github.com/gogo/protobuf/protoc-gen-gofast github.com/gogo/protobuf v1.3.2
ensure_go_tool protoc-gen-gogo github.com/gogo/protobuf/protoc-gen-gogo github.com/gogo/protobuf v1.3.2
ensure_go_tool tmpl github.com/benbjohnson/tmpl github.com/benbjohnson/tmpl v1.1.0

# go generate uses legacy GOPATH include paths. Point at the complete module,
# never server/vendor, whose contents are replaced by the upstream Makefile.
if ! gogo_metadata="$(cd -- "$tools" && "$go_bin" mod download -json github.com/gogo/protobuf@v1.3.2)"; then
    fail 'gogo/protobuf v1.3.2 is not cached; opt in with TRAFLENS_DOWNLOAD_TOOLS=1'
fi
gogo_dir="$(printf '%s' "$gogo_metadata" | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')"
[[ -f "$gogo_dir/gogoproto/gogo.proto" && -d "$gogo_dir/protobuf/google/protobuf" ]] || fail 'full gogo protobuf include tree is missing'
gogo_link="$GOPATH/src/github.com/gogo/protobuf"
[[ ! -e "$gogo_link" || -L "$gogo_link" ]] || fail "refusing to replace an existing directory: $gogo_link"
if [[ "$(readlink -f -- "$gogo_link" || true)" != "$gogo_dir" ]]; then
    ln -sfn -- "$gogo_dir" "$gogo_link"
fi

# Upstream's Alpine package is unpinned; the TrafLens venv pins ujson explicitly.
venv_python="$tools/pyenv/bin/python3"
if [[ ! -x "$venv_python" ]]; then
    [[ "$download_tools" == 1 ]] || fail 'project Python venv missing; opt in with TRAFLENS_DOWNLOAD_TOOLS=1'
    python3 -m venv "$tools/pyenv"
fi
if [[ "$("$venv_python" -c 'import ujson; print(ujson.__version__)' 2>/dev/null || true)" != 5.10.0 ]]; then
    [[ "$download_tools" == 1 ]] || fail 'project ujson==5.10.0 missing; opt in with TRAFLENS_DOWNLOAD_TOOLS=1'
    "$venv_python" -m pip install --disable-pip-version-check ujson==5.10.0
fi

printf 'Building upstream server with %s\n' "$("$go_bin" version)"
exec make -C "$repo_root/server" server "$@"
