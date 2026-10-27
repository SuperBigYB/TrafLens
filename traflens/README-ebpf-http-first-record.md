# Cold eBPF HTTP response inference

The HTTP/1 cold checker previously recognized request lines only. If a known
socket's first response arrived before its first request, a cold FlowLog omitted
that response. Twenty exchanges then produced 20 raw requests and 19 raw
responses before the Session queue. A warm protocol cache bypassed that checker,
and ordered cold input also worked. The regression preserves those positive
controls rather than warming up or discarding the first transaction.

Response inference now accepts a valid HTTP/1 status line only for syscall or
TLS eBPF input with a known client/server socket role and an established
server-to-client direction. Protocol and port filtering still precede this
check. Packet-mode inference remains request-only. Both required status-line
spaces are checked in addition to the existing version, ASCII and status-range
validation, so malformed lines cannot select HTTP merely by containing digits.

The owning tests run the real FlowLog parser with a restricted HTTP port. They
cover cold/warm and ordered/response-first input, role/direction/source gates,
non-TCP input, wrong ports, malformed/truncated status lines and all 20 raw
request/response pairs. With libtrace enabled, a further test feeds those real
parser outputs into SessionAggregator and requires 20 distinct complete HTTP
Sessions, including the first transaction. These tests do not attach kernel
programs or generate network traffic.

```sh
cd agent
cargo test --locked --no-default-features --lib \
  flow_generator::flow_map::first_record_tests -- --test-threads=1
# In the prepared native SDK environment:
cargo test --release --offline --locked --lib \
  flow_generator::flow_map::first_record_tests -- --test-threads=1
```

The old native implementation fails before Session aggregation with 39 raw
records. The corrected native test preserves all 40 raw records and produces
20 complete Sessions. This establishes the cold response-first defect and its
fix. The earlier retained managed-Agent 39/40 failure had no arrival transcript;
its historical cause cannot be proven from matching counts alone. Real managed
acceptance must still use the [strict dual-endpoint oracle](README-managed-ebpf-oracle.md)
without diagnostics, prewarming or a reduced expected count. General event
reordering, unknown-role inference, TCP stream recovery and performance parity
remain separate work.

## Initial rate-limit burst

Full-suite execution also exposed an independent initialization race in the
shared LeakyBucket. Its constructor returned with zero tokens and relied on a
background thread to provide the first configured burst. A first packet/log
could therefore be rejected solely because that thread had not run yet. The
initial burst is now available before construction returns. The refill worker
waits before its first refill instead of resetting the bucket on startup and
granting the same initial burst twice. Zero-rate unlimited behavior and later
rate updates retain their existing contract; refill arithmetic is bounded at
the full UInt64 range.

A no-sleep regression consumes the full first burst immediately after creation
at small, ordinary and UInt64-limit rates. It fails on the former constructor
and passes with synchronous initialization. Existing exhaustion/refill/update
coverage also passes. `agent-packet.sh parser-test` includes this shared-crate
suite, and `agent-packet.sh test-rate` runs it alone. The native Session test
requires all 40 raw heads, 20 merges and zero throttle drops as well as 20
complete output Sessions. Neither fix proves the arrival order or historical
cause of the retained managed-Agent failure.
