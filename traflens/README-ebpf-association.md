# Headerless eBPF observation association contract

M11 provides bounded evidence associations between real HTTP observations and a
public finite capture/verify/stop lifecycle. The accepted slice is not a complete
causal Span tree or a claim of full DeepFlow AutoTracing parity. SDK/OTel source4 and fabricated
Trace/Span IDs cannot substitute for the required native eBPF source3 records.

## Actual native execution path

The checked Go Querier registers `/v1/trace_map`, `/v1/trace_map/sync` and
`/v1/flow_map`, but its current `TraceMapAsync`, `TraceMapSync`, `FlowMap` and
generator `Start` implementations are stubs. A route name, HTTP200, configuration
defaults or an empty response does not establish a running tracing algorithm.
The Go Tempo adapter instead calls the separately configured DeepFlow-app
`/v1/stats/querier/L7FlowTracing` service. Its implementation is not present in
this checkout; deployment and functional availability must be checked separately.
Do not silently route the minimal lab feature to an absent external service.

Use the existing native `/v1/query/` path for fixed raw `flow_log.l7_flow_log`
projections. The engine's default10000-row LIMIT is a fallback, not a request
budget or proof of completeness. An association endpoint must impose a small
explicit row cap with an N+1 sentinel, reject excess input before linking,
retain exact Agent/time/source scope and constrain response bytes, execution
deadline and total queries. Count plus consecutive complete snapshots can
establish the finite test population; they do not make separate queries atomic.

Sources: [stub service](../server/querier/app/distributed_tracing/service/tracemap/tracemap.go),
[stub generator](../server/querier/app/distributed_tracing/service/tracemap/tracemap_generator.go),
[Tempo adapter](../server/querier/tempo/tempo.go),
[Query limit handling](../server/querier/engine/clickhouse/clickhouse.go).

## Current API contract

`GET /api/associations` requires exactly one each of `id`, `agent`, `from` and
`to`; other parameters and duplicates are rejected. ID is a nonzero UInt64,
Agent is1..65535, and the positive Epoch-second interval contains at most60
inclusive seconds (`to-from+1 <= 60`). The endpoint uses the console's fixed
organization1/user1 scope; it does not establish multi-tenant authorization.

One fixed native query selects the complete Agent/time window for
`signal_source=3`, HTTP `l7_protocol=20`, TCP `protocol=6` and Session `type=2`,
without filtering its population by URL or seed record. `LIMIT65` is a sentinel
for the64-observation input cap: an excess row is rejected before association.
The query has a12-second context deadline and the upstream response is bounded
to4MiB. These limits constrain returned rows, response bytes and request time;
they are not a ClickHouse scanned-row or scan-memory hard limit.

The response shows the seed's strong-evidence component plus its direct
candidates, with all identifier evidence retained. `window_records` counts the
bounded input window, not only returned component nodes. A missing seed is an
explicit successful empty component with `diagnostics.seed_found=false`.
Malformed scope is HTTP400, an over-cap window HTTP413, and a failed or malformed
upstream response HTTP502; none is converted into a successful empty graph.

Network pairs require the explicit tuple, EPC and both nonzero TCP sequence
identities. Handoffs require the local side PID, both nonzero phase syscall
identities and phase thread identities, with distinct nonzero local flow IDs;
single-phase reuse anywhere in the bounded window is retained as ambiguity.
Record generations and namespace leases are not stored in these L7 rows. The
historical API consequently reports matching kernel evidence rather than
asserting a verified process generation, SDK parentage or complete AutoTracing.

The finite real-data acceptance covers two complete identical window reads,
all eight seeds and their eight exact record-detail paths, and actual browser
component/detail navigation with negative scope controls. It establishes this
slice's API behavior. The public end-to-end lifecycle and its independent
acceptance now also pass; see the reproduction and acceptance sections below.

Source: [association API](console/associations.go) and
[console panel](console/index.html).

## Recorded fields and their scope

The current fixed API projection retains exact record ID, Agent ID, source,
type, TCP/HTTP protocol, observation point, client/server addresses and ports,
EPC scope, start/end microseconds, both TCP sequences, side-specific process IDs,
request/response syscall trace IDs, threads, capture sequences, local flow ID
and request resource. It does not project `response_duration` or coroutine
fields. Those native fields require a separate checked projection before future
use; their presence in storage is not an API implementation claim. Record, flow
and syscall UInt64 identifiers remain exact decimal strings throughout JSON and
browser handling. Missing or zero identifiers provide no positive association
evidence.

- `req_tcp_seq` and `resp_tcp_seq` are UInt32 first-L7-byte sequence positions.
  The parser adjusts TCP sequence by the protocol's offset. They belong to the
  corresponding TCP exchange, can wrap, and are not globally unique IDs.
- `process_id_0` describes the local client endpoint when observed there;
  `process_id_1` describes the local server endpoint. They are kernel TGIDs,
  require Agent and process-lifetime scope, and may be reused. A container PID,
  process name or unproven global-process inventory ID is not an equivalent
  identity. Coroutines are populated on the corresponding local endpoint side.
- `syscall_trace_id_request` and `_response` belong to the L7 request and
  response phases. `syscall_thread_0` is the request-phase thread;
  `syscall_thread_1` is the response-phase thread. Those suffixes must not be
  confused with the client/server suffixes of process IDs.
- The kernel tracking key contains TGID and either thread PID or Go goroutine
  ID. An ingress creates/remembers tracking information; a following egress
  can carry it to another socket and normally consumes it. Consecutive
  same-direction operations may reuse the previous trace ID, and some protocol
  paths explicitly retain tracking state. The value is consequently neither a
  globally unique business transaction ID nor an SDK Span ID.
- `syscall_cap_seq_0` is the captured request end sequence and `_1` the response
  start sequence. These are socket-local ordering evidence, reduced to UInt32
  on the L7 path; they are not cross-socket or cross-host parent identifiers.
  Native eBPF `flow_id` derives from the local socket identifier with source
  bits applied. L7 storage has no separate `socket_id` column. Neither an equal
  flow ID across Agents nor an equal capture sequence proves a shared socket.

The Query descriptors expose the concrete fields above. Convenience WHERE tags
`tcp_seq`, `syscall_trace_id` and `syscall_cap_seq` expand to OR predicates over
the paired fields; they are not new canonical scalar identities. Prefer the
explicit fields for projections and edge explanations. Runtime support for any
additional formatting expression must be checked before using it.

Sources: [L7 parser](../agent/src/flow_generator/protocol_logs/parser.rs),
[kernel tracking](../agent/src/ebpf/kernel/socket_trace.bpf.c),
[socket data contract](../agent/src/ebpf/user/socket.h),
[local flow identity](../agent/src/common/meta_packet.rs),
[storage columns](../server/ingester/flow_log/log_data/l7_flow_log.go),
[Query translations](../server/querier/engine/clickhouse/tag/translation.go).

## Minimal conservative association rules

Use a finite synchronous plain HTTP chain, explicit numeric addresses, one
in-flight request per owned service, fresh connections and an unrelated control
exchange. Do not send W3C/other tracing headers or use SDK instrumentation.
Keep independent workload receipts for actual requests, socket endpoints and
owned process lifetimes; URL markers select the test population, not its edges.

For a **network-exchange association**, require two actual opposite `c-p`/`s-p`
observations of the same normalized TCP five-tuple and compatible EPC/test
scope, with both nonzero request and response TCP sequences equal. Retain the
actual participating Agent identities. Do not compare local syscall trace IDs
across hosts, and do not infer such an edge when only one side was recorded.

For a **local handoff association**, require the incoming `s-p` observation's
nonzero `process_id_1` to equal the outgoing `c-p` observation's
`process_id_0` within the same Agent and verified collection/process lifetime.
Both nonzero request syscall trace IDs must match, and both nonzero response
syscall trace IDs must match. In the initial single-thread fixture, check the
recorded request threads against each other and response threads against each
other as well. These are two distinct observations and a labeled handoff
evidence edge; do not create synthetic SDK parent IDs.

Reject or explicitly report multiple candidates, duplicate observations, reused
identifiers and incomplete phases. This is a typed evidence graph: it does not
require an acyclic result. The current implementation does not separately
diagnose cycles or demote their edges. The accepted finite fixture is acyclic,
which does not generalize to a causal tree for arbitrary historical records.
Time bounds and URL equality cannot break an ambiguity or create a missing
edge. Partial or unmatched observations stay visible as such; they are not
proof that no request occurred.

## Capture and runtime preconditions

Reuse the qualified managed-HTTP eBPF path and its exact namespace lease/ABI,
finite Agent lifetime, BPF/map and outside-namespace controls. Select the normal
base feature functions `[2,4,5]` through the Controller and verify actual read-back;
TRACE_SYS5 enables the relevant socket path. Do not enable TRACE_APP6,
PROFILE_INT11 or a second integration to fill missing evidence. Keep process
discovery, all integrations, Agent self profiling, on-CPU sampling and DWARF
unwinding disabled, with the established resource and restoration guards.
Only use configuration keys accepted by the actual Controller template.

The qualified managed profile disables Go uprobes and uses
`golang.tracing_timeout="0ns"`. The checked kernel skips the tracking path for
recognized Go processes when that timeout is zero. A Go service with tracing headers removed
therefore cannot be assumed to supply a same-process handoff under this profile.
Prefer an ordinary single-thread synchronous C/Python fixture for this slice;
Go, asynchronous handoffs, multiplexing, NAT/proxies and broader protocol/kernel
matrices need separate evidence before extending the contract.

Source: [qualified managed profile](lab/managed-http-profile.json) and
[namespace scope reader](lab/managed_http_scope.py).

## Official reference and delivery boundary

DeepFlow's [official AutoTracing mechanism article](https://www.deepflow.io/blog/zh/018-the-practice-of-automatically-implementing-observability-based-on-ebpf/index.html)
explains same-thread ThreadID/SyscallTraceID association and TCP-sequence network
association without injecting TraceID/SpanID. It is a historical mechanism
explanation, not a current asynchronous compatibility matrix. The
[official repository feature scope](https://github.com/deepflowio/deepflow#key-features)
is substantially broader than this finite evidence graph.

The round17 two-host pipeline uses owned synchronous services in one isolated
source namespace, with the Agent sending to the other host's Server. It does
not qualify an application hop crossing physical hosts, NAT/proxy translation,
coroutine/asynchronous handoffs or a complete distributed causal tree.

The public coordinator [ebpf-association.py](lab/ebpf-association.py) performs
preparation inside its bounded run, then exact cleanup; plan/run/stop are the
operator actions. It reuses the silent namespace lease, normal kernel Controller
mode, bounded query/UI and strict independent verifier. Its original private
predecessor remains historical evidence, not a runtime dependency.

## Reproduce the finite public lifecycle

The following entry points default to an offline plan. Execute only against an
owned isolated lab whose Controller loopback publication and image/artifact
identities have been checked. Keep normal kernel functions2/4/5 and the qualified
native socket core; no trace/profile integration is used. The base native
artifact manifest and namespace/Agent requirements are documented in
[managed HTTP runtime](README-managed-http-runtime.md#prerequisites-and-configuration).
Reuse verified artifacts rather than rebuilding a kernel matrix.

Use canonical absolute paths under private mode0700 parents. CAPTURE and
BACKEND_WORK must be fresh, not existing run directories. BACKEND_CODE is an
already prepared private directory on BACKEND_HOST. Deploy the public helper
files there from this checkout: cpu-profile.py, cpu_profile_controller.py,
cpu_profile_common.py, configure-agent.py, lab.py, agent-smoke.json,
managed-http-profile.json and managed-http.py. The capture preflight compares
all eight source/peer file hashes before Controller mutation. SSH uses the
operator's existing authentication. Controller URLs must be credential-free
numeric loopback origins and match the owned Server's actual port publication.

Build the bounded fixture and inspect the offline entry first:

```sh
cc -static -O2 -Wall -Wextra -Werror -o "$WORKLOAD_BIN" \
  traflens/lab/no-header-http.c
WORKLOAD_SHA=$(sha256sum "$WORKLOAD_BIN" | cut -d' ' -f1)
python3 traflens/lab/ebpf-association.py
python3 traflens/lab/verify-ebpf-association.py
```

Run one finite capture:

```sh
python3 traflens/lab/ebpf-association.py run --execute \
  --work "$CAPTURE" --backend-host "$BACKEND_HOST" \
  --backend-root "$BACKEND_ROOT" --backend-work "$BACKEND_WORK" \
  --backend-code "$BACKEND_CODE" --server-container "$SERVER_NAME" \
  --controller-url "$CONTROLLER_LOOPBACK" \
  --controller-ip "$CONTROLLER_DATA_IP" --controller-port 20035 \
  --ingester-port 20033 --ctrl-ip "$HOST_CTRL_IP" --ctrl-mac "$HOST_CTRL_MAC" \
  --image "$IMAGE_ID" --artifacts "$RUNTIME/prepared.json" \
  --workload-bin "$WORKLOAD_BIN" --workload-sha256 "$WORKLOAD_SHA" \
  --forward-port 24017
```

The command prepares a dedicated temporary Controller group/Agent and a silent
namespace lease, verifies the actual scoped collector/policy/FD/map readiness,
then starts only the two owned synchronous services and the generator. It emits
two root requests, one main and one independent control, making four actual HTTP
exchanges. Worker runtime receipts retain actual inspect PID/network modes,
resource/capability envelope, exact identity, PID/startticks and namespaces;
application wire receipts retain independently observed execution/socket data.
The URL is a population marker and does not create an evidence edge.
The frontend is briefly paused only while recording the generator's actual
process identity, with a5second gate and unconditional unpause/cleanup. This
run is not a latency or throughput benchmark. Raw security options are retained;
Docker's additional label=disable is accepted only when both the actual daemon
SecurityOptions and absent host SELinux interfaces prove SELinux is inactive.
Unknown or repeated options remain rejected.

Capture execution/restoration success is separate from storage acceptance. Use
an independent bounded query/console runtime from
[the public query lifecycle](README-cpu-profile-runtime.md), with only the minimal
password-free connection configuration. Do not stop or replace the old Server.
Forward its published loopback query/console endpoints through SSH, then select
an explicit at-most60-inclusive-second interval covering the actual application
wire timestamps (started_unix_ns/finished_unix_ns). Do not rewrite those times.

```sh
python3 traflens/lab/verify-ebpf-association.py --execute \
  --capture-dir "$CAPTURE" --query-base "$QUERY_LOOPBACK" \
  --console-base "$CONSOLE_LOOPBACK" --from "$FROM" --to "$TO" \
  --output "$FRESH_ORACLE_DIR"
```

The verifier requires the scope/readiness receipts and original application
wire hashes. New capture-schema input also requires all three original runtime
inspect receipts; missing or partial receipts cannot fall back to the old
retrospective mode. It checks two complete whole-marker populations without hiding
Agent/time/source mismatches, all eight exact details and seed components,
main/control separation and three empty negative scopes. A zero kernel identifier
is retained; incomplete evidence does not create a handoff. HTTP ACK, exit0 or
an initial empty query-runtime readiness response is not this acceptance.
In the actual console's kernel-evidence form, use the same time/Agent plus a
real seed ID, inspect typed evidence and navigate to the original request. Repeat
with the independent control seed and wrong Agent/seed/time scopes.

Always stop/recover after success, interruption or failure:

```sh
python3 traflens/lab/ebpf-association.py stop --execute --work "$CAPTURE"
# Also stop the independent public query runtime and the exact owned SSH forwards.
```

Cleanup removes only exact owned workers, stops/removes the managed Agent and
checks BPF/tracefs restoration before releasing namespace pins, then unregisters
only its temporary group/Agent and ends its forward. A Docker inspect error is
not proof of disappearance. Preserve failed execution and separate restoration
receipts; successful stop cannot turn a failed workload into accepted data.
Do not delete a run directory before its stop/restoration proof is complete.

## Accepted public lifecycle (2026-10-28)

One fresh public run passed with real recorded Docker running-inspect receipts
for all three workers, original create-argv hashes, exact host PID/startticks,
namespace/held-FD and application wire identity. A short0.435second frontend
pause established the generator's real running identity; this was not a
performance measurement. All three workers and the Agent exited0 without OOM.
The public strict oracle took26requests and0.493seconds: two complete same-ID
whole-marker reads,8source3 Sessions, source0/4 zero, empty trace/span/parent,
all8seeds/exact details, separate main/control components and3negative scopes.
Each component has4nodes,2network pairs and1dual-phase syscall handoff. The
actual zero request syscall ID on one endpoint remains visible.

Actual Edge passed both components and both services'4exact detail navigations,
empty controls, over-wide-window failure and the default60-inclusive-second form
window, with0page errors. Both public stop interfaces pass, including an extra
idempotent capture stop. Old Server ID/config SHA, Controller identity/YAML,
BPF/tracefs, routes/interfaces and preexisting services remain; all owned
collector/worker/namespace/query/console/forward resources are removed.

The first public attempt failed before any worker execution because Docker added
label=disable to the host-PID worker's security options. It retained the owned
resources rather than assuming they were safe to remove. The narrow inactive-
SELinux normalization above resolved the actual mismatch; the original failed
result remains unchanged. Its first public stop encountered an acknowledgement
timeout while the lease was automatically cleaning up. A second unchanged stop
read the actual final pin/BPF/tracefs restoration proof and completed Controller
cleanup. That recovery does not turn the failed capture into accepted data.
A new directory and fresh identity then produced the accepted population.

23targeted lifecycle/verifier tests and a final independent read-only review pass.
The earlier56console race tests and59tool checks are historical baselines, not
repeated by this lifecycle-only change. Remote CI was not checked. Anonymous
acceptance evidence is in
[evidence/2026-10-28/ebpf-association-runtime/summary.json](evidence/2026-10-28/ebpf-association-runtime/summary.json).
