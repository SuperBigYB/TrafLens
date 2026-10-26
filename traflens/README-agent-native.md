# Native Agent release build verified in the lab

The complete default-feature Agent, including libtrace, was built successfully
from committed source `6aec171bf820e5ce516349ed3677395050b8a384` on dev-240.
The build used the official native dependency image below with a separately
mounted, existing Rust/Cargo **1.97.1** toolchain. No dependency versions were
updated during the build.

This documents the prepared dev-79/dev-240 lab procedure, not a portable installer.
The image, compiler and dependency caches must exist before the offline build.

## Source and cold preparation

The primary checkout is dev-79:`/root/yb/git/TrafLens`. Build snapshots and caches
live only under dev-240:`/tmp/traflens-native-build-20261026`. Working-tree fixes
must be committed before making the source bundle; do not copy an actively edited
checkout. Full Git history is retained for the Agent's embedded revision metadata.

The final checkpoint bundle is
dev-79:`.traflens/work/native-prebuild/source-final-6aec171b.bundle`; its SHA256 is
`cc9a762b3ce8e9340d5c01ccf135c340bd03e2569332a262c7a00f7d4041cc51`.
The committed-source bundle was prepared with:

```sh
# Run on dev-79. For another checkpoint, choose and record its committed SHA.
repo=/root/yb/git/TrafLens
work="$repo/.traflens/work/native-prebuild"
source_ref=6aec171bf820e5ce516349ed3677395050b8a384
mkdir -p "$work"
test "$(git -C "$repo" rev-parse main)" = "$source_ref"
git -C "$repo" -c pack.threads=2 bundle create \
  "$work/source-final-6aec171b.bundle" main
git bundle list-heads "$work/source-final-6aec171b.bundle"
```

The two submodules were archived from their exact pinned commits, independently
of any uncommitted parent work:

- `message/opentelemetry`: `724e427879e3d2bae2edc0218fff06e37b9eb46e`, canonical
  source `https://github.com/deepflowio/opentelemetry-proto.git`.
- `agent/src/ebpf/libs/jattach`: `030d74328bd6b04114f804ba1b4de2ddfa031b55`, canonical
  source `https://github.com/deepflowio/jattach`.

```sh
git -C "$repo/message/opentelemetry" archive --format=tar \
  724e427879e3d2bae2edc0218fff06e37b9eb46e > "$work/opentelemetry.tar"
git -C "$repo/agent/src/ebpf/libs/jattach" archive --format=tar \
  030d74328bd6b04114f804ba1b4de2ddfa031b55 > "$work/jattach.tar"
tar -I 'gzip -1' -cf "$work/cargo-cache.tar.gz" -C /root/.cargo registry git
tar -I 'gzip -1' -cf "$work/rust1971-toolchain.tar.gz" \
  -C /root/.rustup/toolchains stable-x86_64-unknown-linux-gnu
```

The Cargo registry/Git caches had already been populated on dev-79 using the
locked dependency graph. An empty cache needs preparation with working network
access first; `--offline` must fail rather than resolve different dependencies.
Only `registry/`, `git/` and the compiler distribution were transferred: no
Cargo credentials/configuration, SSH keys, or account files were copied.
Archive checksums and sizes were recorded in manifests and checked after transfer.

The artifacts were relayed through the controlling computer with `scp -3`, for
example:

```sh
scp -3 dev-79:/root/yb/git/TrafLens/.traflens/work/native-prebuild/source-final-6aec171b.bundle \
  dev-240:/tmp/traflens-native-build-20261026/incoming/
```

On dev-240, clone the bundle into the owned `repo/` snapshot, extract the two
submodule archives into their recorded paths, and verify those pins with
`git ls-tree HEAD`. Extract the cache archive separately: strip its `registry/`
prefix into `cargo-registry/` and `git/` prefix into `cargo-git/`. Extract the
compiler archive under `toolchains/`. The final prepared layout is:

```text
/tmp/traflens-native-build-20261026/
  repo/                                  # full Git snapshot, HEAD 6aec171b
  cargo-registry/                        # registry cache only
  cargo-git/                             # Git dependency cache only
  toolchains/stable-x86_64-unknown-linux-gnu/
  target/                                # reusable Cargo build cache
  incoming/                              # source archives and manifests
  artifacts/                             # retained binaries and checksums
```

For an existing owned snapshot, verify its resolved absolute top-level and Git
directory remain inside this temporary build directory before discarding its
previous build changes. Fetch the new bundle and reset **only that snapshot**
to the recorded commit. The primary dev-79 checkout is never reset by this flow.
The final build used committed source with no source overlays; the earlier
`742d143a2` prebuild with a lockfile overlay is separate evidence.

## Offline build with the prepared caches

The following is the effective command used for the final build. CPU IDs 0–3
were available in this lab; check affinity before using a different host. Both
the CPU quota and affinity are restricted so upstream's `make -j$(nproc)` sees
four CPUs. The image was pulled before disabling container networking.

```sh
# Run on dev-240; the prepared paths above must already exist.
base=/tmp/traflens-native-build-20261026
image=ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310
docker run --rm --network none \
  --cpus 4 --cpuset-cpus 0,1,2,3 --memory 8g --memory-swap 8g \
  --pids-limit 4096 --cap-drop ALL --security-opt no-new-privileges \
  --mount "type=bind,source=$base/repo,target=/workspace/TrafLens" \
  --mount "type=bind,source=$base/cargo-registry,target=/usr/local/cargo/registry" \
  --mount "type=bind,source=$base/cargo-git,target=/usr/local/cargo/git" \
  --mount "type=bind,source=$base/target,target=/target" \
  --mount "type=bind,source=$base/toolchains/stable-x86_64-unknown-linux-gnu,target=/opt/traflens-rust,readonly" \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=4 \
  -e CARGO_PROFILE_RELEASE_DEBUG=0 -e CARGO_NET_OFFLINE=true \
  -e CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  -e RUSTC=/opt/traflens-rust/bin/rustc \
  -e RUSTDOC=/opt/traflens-rust/bin/rustdoc \
  -e RUSTFMT=/opt/traflens-rust/bin/rustfmt \
  -w /workspace/TrafLens/agent "$image" bash -lc '
    set -e
    export PATH=/opt/traflens-rust/bin:$PATH
    rustc --version
    cargo --version
    git rev-parse HEAD
    sha256sum Cargo.lock
    cargo build --release --locked --offline --bin deepflow-agent
  '
```

There is deliberately no `--no-default-features`. The image supplies GCC 11,
Clang 11, protoc 3.12 and the required static native libraries. Its own Rust 1.83
attempt could not resolve the transferred hpack cache offline; the verified
Rust 1.97.1 mount completed the build without dependency changes. Image tool
binaries are preserved: only the Cargo cache subdirectories are mounted.
No privileged mode, host networking, Docker socket or host device mounts are used.

## Verified artifact and limits

The cached final rebuild completed in **2m13s**, exit 0, without an OOM kill.
It produced a 45,057,166-byte `libtrace.a` and ten BPF ELF objects. The optimized
77,910,288-byte binary is retained on dev-240 at:

```text
/tmp/traflens-native-build-20261026/artifacts/deepflow-agent-native-linux-amd64-6aec171b
SHA256 04f3dabfd86c8d2ea6457aa4bd2d4309584c35fe07bcc04aa937c53fc734eaa4
```

Host dev-240 `-v` returned exactly
`CommitId: 6aec171bf820e5ce516349ed3677395050b8a384`; `ldd` resolved all libraries.
Git status was empty after the final build; generated build artifacts remain
ignored. Build logs, metadata, version, library/BPF proof and checksum records
were copied to dev-79:`.traflens/work/native-prebuild/results/` as
`native-release-6aec171b-*`. This SHA identifies that run's binary: embedded
compile time means a later build is not promised to be byte-identical.

A successful full native build does **not** prove live eBPF capture, syscall
tracing or profiling. The separate 20-request HTTP end-to-end check used the
packet Agent with eBPF disabled; it was not a runtime test of this native binary.


## Boundary-fix checkpoint: 4f0a7d96d

The same pinned image, Rust 1.97.1, offline cache and 4 CPU/8 GiB restrictions
validated exact source `4f0a7d96d833f770668dea304a5a6afaef2c0fbd` without source
overlays. The optimized default-feature Release builds in 2m10s; its version
matches this commit. Artifact on dev-240:
`/tmp/traflens-native-build-20261026/artifacts/deepflow-agent-native-linux-amd64-4f0a7d96`,
77,938,232 bytes, SHA256
`2f6bd8507bb50aeaa94af5a475b5d81466e23281a074c3ed1cef2eb8670dda53`.

The C fixture was force-built inside the native image before release tests.
All six `plugin::c_ffi::process_kname_tests` pass, including real libtrace
MetaPacket names, actual shared-object callbacks and 55 cross-language ABI
comparisons. First-time optimized test dependency compilation took 4m42s.
The response-time module also passes all 15 tests. The generated fixture ELF
was archived and restored to its committed bytes; final source status is clean.
This changes no Rust/C/header source and does not conceal a source overlay.

A further WASM feature-mode probe passes one of five tests and fails four
with real process names present. These remain unresolved; native support cannot
be inferred from packet-mode failure explanations. Full native suite and live
eBPF collection/profiling are separate pending gates. The exact commands,
state, logs, generated-fixture difference and result records accompany this
checkpoint under `evidence/2026-10-26/agent/`.
