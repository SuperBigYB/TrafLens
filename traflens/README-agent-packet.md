# Linux packet-agent build and parser tests

This entry point builds the community packet agent and runs real HTTP, DNS and
MySQL PCAP parser fixtures. Every Cargo invocation uses `--locked` and
`--no-default-features`. It does **not** enable libtrace/eBPF, syscall tracing,
uprobes or continuous profiling, and does not establish full Agent parity.

From the checkout root:

```sh
bash traflens/scripts/agent-packet.sh parser-test
bash traflens/scripts/agent-packet.sh build
```

Modes `test-http`, `test-dns` and `test-mysql` run one protocol suite. The tests
compare capture parsing with checked-in `.result` outputs and verify request,
response, error and RRT statistics. They execute serially because upstream
fixture failures can write a shared `agent/actual.txt` diagnostic file.

The default `build` mode uses Cargo's dev profile, with debug information disabled,
for functional checks and reuse of parser compilation artifacts. It retains
dev-profile optimization level 0: **do not use this binary for a throughput or
performance comparison**. The binary is `agent/target/debug/deepflow-agent` unless
`CARGO_TARGET_DIR` is set. Build an optimized packet agent explicitly before
performance work:

```sh
bash traflens/scripts/agent-packet.sh build-release
# Default output: agent/target/release/deepflow-agent
```

Even the release binary has the packet-only feature scope. Wire/link throughput,
parser correctness and end-to-end observability require separate measurements.

## Existing prerequisites

The wrapper requires Linux amd64 or arm64, existing Rust **1.97.1**, Cargo
**1.97.1**, rustfmt/cargo-fmt, Git, protoc, a C compiler (`cc`), make, pkg-config,
sha256sum and libpcap development files. On Debian/Ubuntu the native package
names include `build-essential protobuf-compiler pkg-config libpcap-dev`.
The wrapper does not install system packages or Rust toolchains.

`agent/rust-toolchain` is upstream's floating `stable`; this wrapper verifies
the actual compiler and Cargo versions before invoking either. It first checks
the existing versioned/stable toolchain directories under `RUSTUP_HOME` or
`~/.rustup`. To use a different installation location:

```sh
TRAFLENS_RUSTC=/path/to/rust-1.97.1/bin/rustc \
  bash traflens/scripts/agent-packet.sh test-http
```

`TRAFLENS_CARGO` can select Cargo from a separate location; it must also report
1.97.1. The selected rustc directory must contain rustfmt/cargo-fmt. All changes
to PATH, compiler/linker selection and Git transport apply only to the wrapper
process and its children; no global Cargo, Git or rustup settings are written.
The Linux GNU target linker is explicitly `cc`. Builds default to four jobs;
set `TRAFLENS_AGENT_JOBS` to another positive number when memory requires it.

## Locked sources and transport

`agent/Cargo.lock` pins dependency versions and the hpack/procfs Git revisions.
The wrapper refuses implicit lock updates. If manifests and lock data diverge,
investigate and review the minimal lock correction separately.

The public crate always generates OpenTelemetry protobuf bindings, including
without libtrace. The wrapper ensures `message/opentelemetry` is checked out at
the commit recorded by the repository's gitlink. An existing local submodule
URL registration is respected. For missing registration it supplies the
canonical `https://github.com/deepflowio/opentelemetry-proto.git` URL for that
command, avoiding relative URL resolution against the TrafLens fork; the
upstream `.gitmodules` is preserved. It does not initialize jattach because
that native libtrace dependency is outside this packet build.

Cargo uses the Git CLI. HTTPS is the default when no caller transport rewrite
is configured. In an environment with existing GitHub SSH access, opt into a
process-only HTTPS-to-SSH rewrite:

```sh
TRAFLENS_GITHUB_SSH=1 bash traflens/scripts/agent-packet.sh parser-test
```

This option appends a Git environment configuration entry and preserves any
entries the caller already supplied. It neither installs credentials nor changes
SSH configuration. Cargo can download the already-locked dependencies when
they are absent from its cache. Set `CARGO_NET_OFFLINE=true` after preparing
the complete cache to disable Cargo dependency network access. This Cargo option
does not prohibit Git from fetching a missing OpenTelemetry submodule.

The existing `agent/target` cache is reused by default; `CARGO_TARGET_DIR` is
honored. Each invocation prints the source revision, compiler/Cargo versions,
lockfile SHA256, OpenTelemetry commit and build scope to support captured logs.
Cargo build scripts generate protobuf source files in the locations required by
upstream; review any resulting source diff before committing.

`parser-test` also runs the CIDR labeler tests, including every valid IPv4 and
IPv6 prefix length. This guards the IPv6 `/0` boundary reached by a real packet
with no matching CIDR metadata. Use `test-labeler` to run that module alone.
The DNS test that reads an eBPF `.log` fixture is gated on `libtrace`; its PCAP
tests remain enabled here. Selected packet checks do not imply the full Agent
library or eBPF runtime suites pass.

## Time and C plugin contract gate

`parser-test` includes 15 response-time boundary tests, 5 packet-mode C
process-name/ABI tests and 2 real shared-object integrations. The protocol,
labeler, time and plugin groups retain their original 73 Agent tests.
Use `test-time` or `test-plugin` to run these groups alone. The
plugin gate forces a native `make -B -C agent/resources/test/plugins` rebuild
before loading the fixture, so it uses the current architecture and C header.
There are 55 independent C/Rust struct size/alignment/field-offset comparisons.
The additional libtrace process-name test belongs to the native feature gate.

## Tunnel contract gate

`test-tunnel` runs all 28 tunnel-crate wire tests, followed by the 26 Agent
`common::decapsulate` tests. These cover GPE/NSH, Tencent GRE, ERSPAN and TEB,
including checked-in PCAPs, header truncation, IPv4 options, snaplen capture,
and the caller's offsets, tunnel metadata and synthetic Ethernet headers:

```sh
bash traflens/scripts/agent-packet.sh test-tunnel
```

The parser, labeler, time, plugin and tunnel groups retain their original
127 checks: 99 Agent library tests and 28 tunnel-crate tests.

## Sliding-window and direction gates

`test-reassembly` runs 21 segmentation-window crate tests, the original Agent
segmentation PCAP test, 6 MetaPacket regressions and 5 FlowMap integration tests.
`test-direction` runs 7 service-table tests and the handshake/retransmission
regression. Run either group independently:

```sh
bash traflens/scripts/agent-packet.sh test-reassembly
bash traflens/scripts/agent-packet.sh test-direction
```

The feature is opt-in through
`inputs.cbpf.preprocess.packet_segmentation_reassembly`, a list of TCP ports or
port ranges that defaults to empty. It provides adjacent two-packet sliding
parsing windows: `p1,p2,p3` produces `p1+p2` and `p2+p3`, then flush returns the
original `p3`. Payload overlap between windows is intentional. These windows
improve L7 parsing across a packet boundary; they do not provide a complete
ordered TCP stream or determine application-message boundaries.

Each flow retains at most one original carrier per direction, each limited to
64 KiB of owned memory. Cached carriers share a process-wide 64 MiB retained-byte
budget. Parsing windows that have left the cache are outside that retained
budget. Oversized or budget-blocked inputs pass through with the previous
carrier intact. Gaps, overlaps, retransmissions and truncated captures are not
concatenated. Pure ACKs preserve the pending data window; SYN/FIN/RST packets
flush their direction and pass through. Original packets feed L4 metrics
individually; sliding windows and flushed tails feed L7 parsing.

`parser-test` now gates the complete packet Agent library (**382 tests**),
then both plugin crates (**28 tunnel + 21 window**), for **431 passes** with
zero failures or ignored tests. `test-library` runs the complete library alone;
all former focused commands remain available. The WASM integrity check precedes
tests, and the existing C plugin is built first. Locked dependency versions,
`--no-default-features` and serial test execution are retained.

The earlier TCP-window checkpoint's321 tests had9 known failures. Those cases
now pass after configuration, public fixture, Hessian and WASM contract repairs.
The separate default-feature optimized native library passes393 tests,
including the unchanged original2023 SDK integration; its two plugin crates
also pass49. See [the configuration and plugin guide](README-config-parity.md) and
[its aggregate evidence](evidence/2026-10-27/config-parity/summary.json) for current
scope, counts and qualifications.
Full library success in these modes is not live eBPF or performance parity.

CI runs the complete Server configuration race gate after the Server build:

```sh
cd server
go test -mod=vendor -race ./agent_config -timeout 120s -count=1
```

All 53 top-level tests and 163 total pass events succeed with no skips.
The latest API/precision and YAML alias controls are described in
[the API validation guide](README-api-validation.md). This includes the four TCP-window cases and repairs the inherited panic plus actual
template, migration and DB/YAML conversion defects. See
[the configuration and plugin guide](README-config-parity.md) for red controls,
input contracts and the separate malformed-plugin identity safeguards.


The ff05c646d checkpoint also validates ordinary, packed-ref and linked-worktree
Git metadata watching with three direct-production probes. Its packet binary
embeds the exact tested source commit. CI checks CommitId against HEAD, so a
cache artifact with stale source metadata fails the gate. These three watcher
probes are separate from the complete Cargo-library gate.
