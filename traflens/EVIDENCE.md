# Validation evidence

`evidence/2026-10-26/` contains captured command output and raw measurements.
These files record a particular run and are not live health indicators.

- `raw-link-summary.json`, eight `link*-{client,server}.json` files and
  `network-dev-*.txt`: iperf3 3.9, two 10 GbE links, both directions, four TCP
  streams for ten seconds, scoped link-local IPv6, MTU 1500, TSO/GSO/GRO on.
  Receiver throughput was 9.166-9.277 Gbit/s. TCP retransmits were nonzero;
  NIC drop/error counters were zero. One run per case, shared hosts, simultaneous
  server compilation, no collector. This does not measure collection capacity.
- `server-build.log` and `server-version.txt`: successful upstream Makefile
  build and version entry point. Neither starts a complete observability stack.
- `go-toolchain-download.json`: Go module download provenance and checksums for
  the Go 1.26.2 Linux amd64 toolchain. Cache paths describe the build host.
- `preflight-dev-*.json`: read-only host snapshots. dev-240 has no TrafLens
  checkout, so its absent source revision/metadata is explicit, not a failure
  of the development checkout on dev-79. Go/Rust tool availability and memory
  shown here are snapshots, not guarantees for later runs.
- `preflight-tests.log`: distribution-tool tests on Linux.
- `protocol-smoke.log`: current schema decoder against pinned upstream wire
  fixtures, field-number/type checks and unknown-field behavior.
- `protocol-*-mutant.log`: intentionally failing negative controls. Renumbered
  `req_len` is rejected by field contracts; renumbered `domain`, outside the
  explicit descriptor list, is rejected by decoding pinned wire fixtures.
  These expected failures demonstrate coverage and are not outstanding defects.

The inherited flow-metrics tests initially failed to compile. Their repaired
API usage and subsequent behavioral failures must be distinguished: before-fix
and final test logs accompany any production fixes in this checkpoint. Only the
explicitly recorded packages have been tested; the full upstream suite and
end-to-end deployment are separate work.

`agent/` adds the second checkpoint: HTTP 20, DNS 4, MySQL 8 and labeler 19
selected tests pass. The broad-library failure inventory explicitly has no
baseline comparison. Full default-feature native release evidence pins source
`6aec171bf...`, the official dependency image, Rust 1.97.1, binary checksum,
successful host probes and ten compiled BPF objects. These builds do not prove
live eBPF tracing or profiling.

`runtime/http-e2e-acceptance.json` and the matching client/server/query JSON
prove twenty unique real HTTP requests over the direct IPv6 link became twenty
queried records, all GET/status 200. The runtime index and lab notes distinguish
the resolved IPv6 crash, the lab image's missing timezone archive, and the lab
ClickHouse resource-profile corrections. Selected functional acceptance does
not establish load capacity, all-protocol accuracy or complete product parity.


`baseline/` records the next checkpoint's directed comparison against the pinned
upstream plus its explicit build-only compatibility overlays. All18 remaining
packet-library failures were reproduced; the final candidate full-library run
finishes294 cases (276 pass/18 fail) without a signal. Time-input and plugin
process-name/C-layout regressions retain before/after evidence; selected73 pass.

`protocols/` retains exact expected requests and raw endpoints/query results for
MySQL20/20, DNS warm20/20 and no-warmup fresh-process DNS20/20. It also retains
the initial DNS19/20 failure and unresolved CKwriter-drop diagnosis. Packet and
sender-queue summaries include raw-file hashes. These low-rate synthetic checks
prove specific wire parsing/storage/query cases, not database execution, TLS,
loss-free restart recovery, sustained collection capacity or full product parity.


`agent/native-release-4f0a7d96-*` records a second exact-source native Release
and six default-feature CFFI regression passes. The native follow-up records
15 response-time passes and a WASM result of one pass/four failures. The latter
still needs diagnosis even with an eBPF process name present; it must not be
reported as a passed native WASM gate.
