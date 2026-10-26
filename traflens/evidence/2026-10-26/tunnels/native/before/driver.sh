#!/usr/bin/env bash
set -euo pipefail
base=/tmp/traflens-native-build-20261026
repo="$base/repo"
expected=4778380b292700a6e80cc493cae9e812172185ab
bundle="$base/incoming/tunnel-source-4778380b.bundle"
image=ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310
out="$base/artifacts/tunnel-4778380b"
test "$(readlink -f "$repo")" = "$repo"
test "$(git -C "$repo" rev-parse --show-toplevel)" = "$repo"
test "$(readlink -f "$(git -C "$repo" rev-parse --absolute-git-dir)")" = "$repo/.git"
test -z "$(git -C "$repo" status --porcelain)"
echo '1f2f82d155588a071b2e23626847ed4272da828352f73acb5caae0376e7810b8  '"$bundle" | sha256sum --check --status
git -C "$repo" bundle verify "$bundle"
git -C "$repo" fetch "$bundle" refs/heads/main
test "$(git -C "$repo" rev-parse FETCH_HEAD)" = "$expected"
git -C "$repo" checkout --detach "$expected"
test -z "$(git -C "$repo" status --porcelain)"
mkdir -p "$out"
date --iso-8601=seconds > "$out/start.txt"
docker run --rm --name traflens-native-tunnel-4778380b --network none \
  --cpus 4 --cpuset-cpus 0,1,2,3 --memory 8g --memory-swap 8g \
  --pids-limit 4096 --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$repo,target=/workspace/TrafLens" \
  --mount "type=bind,source=$base/cargo-registry,target=/usr/local/cargo/registry" \
  --mount "type=bind,source=$base/cargo-git,target=/usr/local/cargo/git" \
  --mount "type=bind,source=$base/target,target=/target" \
  --mount "type=bind,source=$out,target=/logs" \
  --mount "type=bind,source=$base/toolchains/stable-x86_64-unknown-linux-gnu,target=/opt/traflens-rust,readonly" \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=4 \
  -e CARGO_PROFILE_RELEASE_DEBUG=0 -e CARGO_NET_OFFLINE=true \
  -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  -e RUSTC=/opt/traflens-rust/bin/rustc \
  -e RUSTDOC=/opt/traflens-rust/bin/rustdoc \
  -e RUSTFMT=/opt/traflens-rust/bin/rustfmt \
  -w /workspace/TrafLens/agent "$image" bash -lc '
    set -euo pipefail
    export PATH=/opt/traflens-rust/bin:$PATH
    rustc --version
    cargo --version
    git rev-parse HEAD
    sha256sum Cargo.lock
    cargo build --release --locked --offline --bin deepflow-agent > /logs/build.log 2>&1
    echo native-release-build-passed
    cargo test --release --locked --offline --lib common::decapsulate -- --test-threads=1 > /logs/caller-tests.log 2>&1
    echo native-caller-tests-passed
    cargo test --release --locked --offline --package tunnel --lib -- --test-threads=1 > /logs/decoder-tests.log 2>&1
    echo native-decoder-tests-passed
    git status --short
  ' > "$out/container.log" 2>&1
date --iso-8601=seconds > "$out/end.txt"
test -z "$(git -C "$repo" status --porcelain)"
git -C "$repo" status --porcelain > "$out/source-status.txt"
artifact="$base/artifacts/deepflow-agent-native-linux-amd64-4778380b"
cp "$base/target/release/deepflow-agent" "$artifact"
"$artifact" -v > "$out/version.txt"
grep -q "CommitId: $expected" "$out/version.txt"
ldd "$artifact" > "$out/ldd.txt"
! grep -q 'not found' "$out/ldd.txt"
sha256sum "$artifact" > "$out/binary.sha256"
stat -c '%s' "$artifact" > "$out/binary-size.txt"
find "$repo/agent/src/ebpf" -name '*.o' -exec file {} \; > "$out/bpf-objects.txt"
find "$repo/agent/src/ebpf" -name 'libtrace.a' -exec stat -c '%s %n' {} \; > "$out/libtrace.txt"
cat "$out/container.log" "$out/version.txt" "$out/binary.sha256"
grep '^test result:' "$out/caller-tests.log" "$out/decoder-tests.log"
