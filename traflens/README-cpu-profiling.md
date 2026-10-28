# CPU profiling checkpoint: real self samples, product gate still open

M9 is in progress. A finite owned Go process now produces a verified real CPU
profile. The first isolated native integration acknowledges upload, but the
whole-marker storage oracle still returns no rows. Ingestion, query/navigation
and the console gate are **not qualified** by this checkpoint. Retain the actual
artifact and failure evidence; do not generate or insert replacement samples.

## Why this sampling path

The existing native on-CPU profiler opens per-CPU perf events with `pid=-1`.
Process matching happens after kernel stack capture, and unmatched processes
can still be aggregated by command. Its regex therefore does not establish this
milestone's strict single-owned-process scope. The qualified scoped socket mode
also rejects continuous profiling/DWARF. No kernel or unrelated-process profiling
is enabled here.

Instead, the new [finite CPU workload](cpu-workload/README.md) uses the current
process's real Go `runtime/pprof` sampler. It has no network and attaches no host
profiler. This source is self/integration profiling, not eBPF on-CPU qualification.
The [official profiling integration guide](https://get.deepflow.io/docs/integration/input/profile/profile/)
describes the existing pprof ingestion route; actual store/query acceptance must
still be measured separately.

## Qualified finite artifact

Build and run through the module's public plan/execute flags with a fresh private
output and owned external resource limits. The2026-10-28 execution uses8 seconds,
one CPU,128MiB,32 PIDs, a read-only container root, no capabilities and no network.
The process exits0 and its owned container is removed. It records a799-byte real
gzip pprof file, SHA256 and an immutable execution receipt.

Independent `go tool pprof -raw`/`-top` decoding finds800 samples/count and
8000000000 CPU nanoseconds with a10000000ns period. The known
`main.traflensCPUHotLoop` is actually present in sampled stacks. These are the
actual artifact's two sample types and weights, not a promised future count or an
absolute CPU-utilization percentage. Receipt `sample_content_checked=false`
remains unchanged; a separate verification record establishes decoded content.
Three module race tests cover the offline default and input/private-output
boundaries. Existing HTTP/kernel/protocol matrices are not repeated.

## Native integration discovery and current failure

The existing Agent route is `POST /api/v1/profile/ingest` with pprof format,
gospy spy name, fresh application label and actual from/until times. Raw gzip
pprof must omit Content-Type; the current library treats a nonempty value as a
multipart form declaration. HTTP200 alone is insufficient: disabled input can
also return an empty200. The profile table has no L7 `signal_source` field, and
external pprof does not establish the stored process PID. Preserve actual
Golang/event/unit semantics rather than claiming a native process association.

The receiver has a wildcard listener and no bind-address setting. A dedicated
temporary Docker network/namespace with no published ports contains the native
Agent and the fixed-loopback uploader. Only profile integration is enabled;
packet/process/eBPF and other integrations are disabled. A separate owned
Controller registration/group avoids changing the existing packet test group.
The supported PROFILE_INT function11 is necessary; the historical packet
registration functions2/4/5 do not enable it. No feature-controller check or
permission is bypassed.

An initial wrong-function/readiness attempt fails before upload and restores all
owned resources. A fresh isolated attempt with actual listener readiness and
function11 returns200; Agent exits0, no OOM, and sender drain reports success.
The immutable profile is uploaded once in that successful HTTP attempt.
Nevertheless, the90-second exact whole-marker oracle repeatedly returns zero;
diagnostic same-Agent and unique-marker queries without a time predicate also
find zero. Do not widen a filter or repeat uploads to declare success. The next
task is to diagnose receiver/profile ingestion and effective routing/configuration,
then verify actual decoded samples, bounded queries and console navigation.

Both attempts remove only their owned Agent registrations/groups, containers
and networks, preserving the old identities, memberships, license settings,
YAML, management route and BPF identities. Detailed artifacts/addresses/run
labels remain private. Anonymous status is in
`evidence/2026-10-28/cpu-profiling/summary.json`. Public reusable integration
startup/stop and the complete product workflow remain M9 work, not completed
features in this partial checkpoint.
