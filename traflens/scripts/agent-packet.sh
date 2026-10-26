#!/usr/bin/env bash
set -euo pipefail

fail() { printf 'TrafLens packet agent: %s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'USAGE'
Usage: bash traflens/scripts/agent-packet.sh [mode]
Modes: build (default), build-release, test-http, test-dns, test-mysql, test-labeler, test-time, test-plugin, test-tunnel, test-reassembly, test-direction, parser-test

Uses existing Rust/Cargo 1.97.1 and --locked --no-default-features.
This builds the packet agent without eBPF, syscall tracing or profiling.
The default dev build is for functional checks, not performance comparison.
USAGE
}

mode=${1:-build}
if [[ "$mode" == --help || "$mode" == -h ]]; then usage; exit 0; fi
[[ $# -le 1 ]] || { usage >&2; exit 2; }
case "$mode" in
  build|build-release|test-http|test-dns|test-mysql|test-labeler|test-time|test-plugin|test-tunnel|test-reassembly|test-direction|parser-test) ;;
  *) usage >&2; fail "unknown mode: $mode" ;;
esac

[[ "$(uname -s)" == Linux ]] || fail 'this entry point currently requires Linux'
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
required_rust=1.97.1
for tool in git protoc cc make pkg-config sha256sum; do
  command -v "$tool" >/dev/null || fail "missing system prerequisite: $tool"
done
pkg-config --exists libpcap || fail 'libpcap development files are missing (install libpcap-dev)'

case "$(uname -m)" in
  x86_64) rust_host=x86_64-unknown-linux-gnu ;;
  aarch64) rust_host=aarch64-unknown-linux-gnu ;;
  *) fail 'unsupported host architecture for this Linux build entry point' ;;
esac

rustc_bin=${TRAFLENS_RUSTC:-}
if [[ -z "$rustc_bin" ]]; then
  rustup_root=${RUSTUP_HOME:-"$HOME/.rustup"}
  for candidate in "$rustup_root/toolchains/$required_rust-$rust_host/bin/rustc" \
                   "$rustup_root/toolchains/stable-$rust_host/bin/rustc"; do
    if [[ -x "$candidate" ]]; then rustc_bin="$candidate"; break; fi
  done
fi
[[ -n "$rustc_bin" && -x "$rustc_bin" ]] || fail "set TRAFLENS_RUSTC to an existing Rust $required_rust executable; this script does not install toolchains"
rustc_bin=$(readlink -f -- "$rustc_bin")
rust_bin=$(dirname -- "$rustc_bin")
cargo_bin=${TRAFLENS_CARGO:-"$rust_bin/cargo"}
[[ -x "$cargo_bin" ]] || fail "cargo is missing beside the selected rustc; set TRAFLENS_CARGO explicitly"
cargo_bin=$(readlink -f -- "$cargo_bin")
[[ "$("$rustc_bin" --version | awk '{print $2}')" == "$required_rust" ]] || fail "rustc must be exactly $required_rust"
[[ "$("$cargo_bin" --version | awk '{print $2}')" == "$required_rust" ]] || fail "cargo must be exactly $required_rust"
[[ -x "$rust_bin/rustfmt" && -x "$rust_bin/cargo-fmt" ]] || fail 'the selected toolchain needs rustfmt and cargo-fmt for public protobuf generation'
export PATH="$(dirname -- "$cargo_bin"):$rust_bin:$PATH"
export RUSTC="$rustc_bin"
export RUSTFMT="$rust_bin/rustfmt"
export CARGO_NET_GIT_FETCH_WITH_CLI=true
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
export CARGO_BUILD_JOBS=${TRAFLENS_AGENT_JOBS:-4}
[[ "$CARGO_BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || fail 'TRAFLENS_AGENT_JOBS must be a positive integer'
# Reuse Cargo's normal agent/target cache unless the caller selects another.
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-"$repo_root/agent/target"}
case "$rust_host" in
  x86_64-unknown-linux-gnu) export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc ;;
  aarch64-unknown-linux-gnu) export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=cc ;;
esac

github_ssh=${TRAFLENS_GITHUB_SSH:-0}
[[ "$github_ssh" == 0 || "$github_ssh" == 1 ]] || fail 'TRAFLENS_GITHUB_SSH must be 0 or 1'
if [[ "$github_ssh" == 1 ]]; then
  config_count=${GIT_CONFIG_COUNT:-0}
  [[ "$config_count" =~ ^[0-9]+$ ]] || fail 'GIT_CONFIG_COUNT must be a nonnegative integer'
  export "GIT_CONFIG_KEY_${config_count}=url.git@github.com:.insteadOf"
  export "GIT_CONFIG_VALUE_${config_count}=https://github.com/"
  export GIT_CONFIG_COUNT=$((config_count + 1))
fi

otel_path=message/opentelemetry
otel_url=https://github.com/deepflowio/opentelemetry-proto.git
otel_pin=$(git -C "$repo_root" ls-tree HEAD -- "$otel_path" | awk '$1 == "160000" {print $3}')
[[ "$otel_pin" =~ ^[0-9a-f]{40}$ ]] || fail 'the checkout does not contain the expected OpenTelemetry gitlink'
otel_head=
if [[ -e "$repo_root/$otel_path/.git" ]]; then
  otel_head=$(git -C "$repo_root/$otel_path" rev-parse HEAD)
fi
if [[ "$otel_head" != "$otel_pin" ]]; then
  registered_url=$(git -C "$repo_root" config --local --get "submodule.$otel_path.url" || true)
  if [[ -n "$registered_url" ]]; then
    git -C "$repo_root" submodule update --init -- "$otel_path"
  else
    # Resolve the fork-relative URL explicitly, only when registration is absent.
    # The command-scoped override leaves .gitmodules and global config unchanged.
    git -C "$repo_root" -c "submodule.$otel_path.url=$otel_url" submodule update --init -- "$otel_path"
  fi
fi
[[ "$(git -C "$repo_root/$otel_path" rev-parse HEAD)" == "$otel_pin" ]] || fail 'OpenTelemetry submodule is not at the checkout gitlink revision'
[[ -f "$repo_root/$otel_path/opentelemetry/proto/trace/v1/trace.proto" ]] || fail 'OpenTelemetry trace.proto is missing after submodule initialization'

printf 'Source: %s\n' "$(git -C "$repo_root" rev-parse HEAD)"
printf 'Rust: %s\n' "$("$rustc_bin" --version)"
printf 'Cargo: %s\n' "$("$cargo_bin" --version)"
printf 'Lock SHA256: %s\n' "$(sha256sum "$repo_root/agent/Cargo.lock" | awk '{print $1}')"
printf 'OpenTelemetry reference: %s\n' "$otel_pin"
printf 'Scope: packet agent; --no-default-features; eBPF/syscall/profiling disabled\n'
printf 'Mode: %s; jobs: %s; dev/test debuginfo: 0; linker: cc\n' "$mode" "$CARGO_BUILD_JOBS"
printf 'Cargo target directory: %s\n' "$CARGO_TARGET_DIR"

cd -- "$repo_root/agent"
parser_test() {
  "$cargo_bin" test --locked --no-default-features --lib "$1" -- --test-threads=1
}
tunnel_test() {
  "$cargo_bin" test --locked --no-default-features --package tunnel --lib -- --test-threads=1
  parser_test common::decapsulate
}
reassembly_test() {
  "$cargo_bin" test --locked --no-default-features --package packet_segmentation_reassembly --lib -- --test-threads=1
  parser_test flow_generator::flow_node::tests::test_packet_segmentation_reassembly
  parser_test common::meta_packet::segment_regression
  parser_test flow_generator::flow_map::reassembly_tests
}
direction_test() {
  parser_test flow_generator::service_table::tests
  parser_test flow_generator::flow_map::tests::test_handshake_retrans
}
case "$mode" in
  build) exec "$cargo_bin" build --locked --no-default-features --bin deepflow-agent ;;
  build-release) exec "$cargo_bin" build --locked --no-default-features --release --bin deepflow-agent ;;
  test-http) parser_test flow_generator::protocol_logs::http::tests ;;
  test-dns) parser_test flow_generator::protocol_logs::dns::tests ;;
  test-mysql) parser_test flow_generator::protocol_logs::sql::mysql::tests ;;
  test-labeler) parser_test policy::labeler::tests ;;
  test-time) parser_test flow_generator::protocol_logs::tests ;;
  test-tunnel) tunnel_test ;;
  test-reassembly) reassembly_test ;;
  test-direction) direction_test ;;
  test-plugin)
    make -B -C resources/test/plugins
    parser_test plugin::c_ffi
    parser_test plugin::shared_obj::test
    ;;
  parser-test)
    parser_test flow_generator::protocol_logs::http::tests
    parser_test flow_generator::protocol_logs::dns::tests
    parser_test flow_generator::protocol_logs::sql::mysql::tests
    parser_test policy::labeler::tests
    parser_test flow_generator::protocol_logs::tests
    make -B -C resources/test/plugins
    parser_test plugin::c_ffi
    parser_test plugin::shared_obj::test
    tunnel_test
    reassembly_test
    direction_test
    ;;
esac
