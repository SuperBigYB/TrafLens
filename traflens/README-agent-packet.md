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

`parser-test` also includes this gate: **127 selected tests total**, comprising
99 Agent library tests and 28 tunnel-crate tests. Both Cargo invocations retain
`--locked --no-default-features` and execute tests serially.

The broader packet library now completes 307 tests, with 295 passing and 12
failures. The six original tunnel failures are fixed, thirteen caller
regressions were added, and the remaining failures match the prior inventory.
See `README-tunnels.md`, `STATE.md`, `evidence/2026-10-26/tunnels/` and the
earlier compatible upstream comparison in `evidence/2026-10-26/baseline/`. Selected
CI success must not be described as a complete library-suite pass.
