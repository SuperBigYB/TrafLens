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
