# CPU profiling checkpoint: real stored samples, bounded query and console

The M9 finite functional gate is qualified. Real finite self CPU sampling and an isolated native
integration now pass actual storage and independent stack verification. Bounded
product queries, console navigation and the public integration/query lifecycle
now pass the real-data gate. The earlier zero-row failure is preserved and is not explained or
repaired merely by the later successful attempt.

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

## Integration history and actual storage acceptance

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
That first HTTP-success attempt's90-second exact whole-marker oracle still
returns zero; same-Agent and no-time diagnostics also find zero. The original
failure remains in the earlier `cpu-profiling/summary.json` checkpoint.

Read-only diagnosis in the actual Server network namespace proves receiver13
accepted the frame, the Go profile decoder parsed it into two rows, and generic
CKWriter dropped both before input. Its success/uncertain/retry/invalid-org counts
are zero;72h TTL and current ClickHouse time exclude the proposed expiry issue.
ProfileWriter's own write_err counter is not updated and cannot prove storage.
The concrete generic error is unavailable because its WARNING is masked by the
active ckwriter ERROR level. Offline parsing of the real artifact with the exact
native library independently produces two stacks totaling800 samples.

For one bounded diagnostic attempt, only that logger is temporarily opened to
WARNING, with exact Server identity and read-back/restore receipts. A fresh
application/transport identity reuses the unchanged actual799-byte artifact and
its original sample time; no CPU workload is rerun. This attempt actually writes
successfully, so it produces no new write-failure warning. The logger is restored
to ERROR. This observation is **not a code fix or explanation** for the previous
pre-input failure, which remains a reliability follow-up.

The new whole-marker oracle passes two complete same-ID/fingerprint reads:
two stored Golang/cpu/samples rows, total800, from the expected temporary Agent.
No Agent/event/unit/language predicate hides incorrect rows. The native readable
tree has9 functions/9 nodes, root/self-sum800; an independent collapse of the
original pprof matches both root-to-leaf stacks exactly. HotLoop self weight797,
cumulative800, and asyncPreempt self3 agree with the actual sample data. The tree
read is followed by another unchanged record fingerprint. These are sample
weights, not absolute CPU percentages or a database-proven OS PID association.

## Bounded native query and actual console

A distinct `POST /v1/profile/ProfileTracingBounded` requires an integer
`max_rows` from1 through `min(4096, FlameQueryLimit-1)`. It accepts a safe exact
application, Golang/cpu, inclusive positive time range up to31days and an exact
samples-unit filter with optional UInt16 Agent ID. The SQL selects only stack
and weight, uses `LIMIT max_rows+1`, and rejects the sentinel before any Zstd or
tree allocation. The legacy route without MaxRows retains its old behavior.
Old backends without the new route return404; the console never falls back to
the unbounded route.

The bounded formatter limits compressed input to4MiB, a decoded stack/window
to1MiB, total decoded stack bytes to8MiB, depth to512 and nodes to8192. Corrupt
stacks, invalid columns/UTF-8, negative/noninteger weights and aggregate overflow
fail without returning a partial tree. These limits govern returned rows and
subsequent decoding/tree construction. They do **not** cap ClickHouse scan work
or all driver allocation before rows are returned. Row limits alone are not a
complete database memory limit.

The console adds an independent CPU form and two fixed endpoints:

- `GET /api/profiles?from=<epoch>&to=<epoch>&agent=<id>&app=<exact-name>`
  lists Golang/cpu/samples application/Agent groups, at most100 plus a truncation
  sentinel. `agent` and `app` are optional for this directory.
- `GET /api/profile?from=<epoch>&to=<epoch>&agent=<id>&app=<exact-name>`
  requires the application and calls only the new native route, fixed256rows,
  a12s deadline and4MiB response ceiling. Unknown/duplicate filters fail.

Both routes remain loopback development tools using the existing fixed org/user1
scope, not a new public authorization mechanism. Counts/weights are decimal
strings. A successful empty query is distinct from unsupported backend501,
native budget413 and malformed/upstream502. The detail verifies native bounds
metadata and function/node/root weights before exposing data. The directory and
detail are separate reads, not an atomic snapshot.

Start the existing console entry with `-query <bounded-querier-base-url>`, open
the CPU form, select actual sample time and optional historical Agent/application,
and click Query. Open the stored application's hotspot detail and select a
function to inspect its actual ancestor paths. The aggregation root is labeled
as a summary node. This is a hotspot table with actual stack paths, not a claimed
full flamegraph. It exposes sample weights and unknown OS identity, not CPU
percentages, a process PID join or eBPF provenance inferred from language/name.

The2026-10-28 trial reuses the accepted stored two-row/800sample dataset, without
new sampling or uploads. Actual native max_rows1 returns400 RESOURCE_NUM_EXCEEDED;
max_rows2 returns the complete9function/9node tree. Missing/null/zero/fractional
limits fail, and a valid absent application returns explicit empty bounds.
Two candidate raw reads and one original-Server read exactly match the previous
whole-marker columns, IDs and values. Real Edge exercises the directory, detail,
HotLoop797self/800cumulative, asyncPreempt3self and actual ancestor navigation.
Wrong Agent, application and time are empty; a fake L7 source argument fails.
Ten native and40 complete console race tests, both builds and read-only review
pass. Earlier CPU fixture/tool matrices are retained, not repeated.

The existing Server has an image-embedded binary and read-only root. It was not
modified or restarted: the native test runs a separate finite Querier container
on the owned lab network with a credential-free allowlisted config, read-only
root and binary, no capabilities and loopback-only publication. The candidate
and console are stopped/removed afterwards; original Server identity/config and
stored rows remain unchanged. The historical private runtime is now superseded by the public
[prepare/start/verify/stop workflow](README-cpu-profile-runtime.md), exercised
with one necessary fresh application/transport identity and the unchanged original
profile/time. Both public stop entries and restoration pass.
Anonymous acceptance: `evidence/2026-10-28/cpu-profile-console/summary.json`.

All attempts remove only their owned Agent registrations/groups, containers
and networks, preserving the old identities, memberships, license settings,
YAML, management route and BPF identities. Detailed artifacts/addresses/run
labels remain private. Anonymous status is in
`evidence/2026-10-28/cpu-profile-ingestion/summary.json`, alongside the earlier
failed checkpoint. The new public lifecycle acceptance is recorded separately in
`evidence/2026-10-28/cpu-profile-runtime/summary.json`; it retains the original
failed-write history and does not claim an explanation or reliability fix.
