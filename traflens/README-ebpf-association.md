# Headerless eBPF observation association contract

M11 starts with bounded evidence associations between real HTTP observations.
This source contract is not an acceptance result, a complete causal Span tree,
or a claim of full DeepFlow AutoTracing parity. SDK/OTel source4 and fabricated
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
slice's API behavior. Public end-to-end orchestration and its recovery workflow
remain a separate M11-05 delivery; no such completion is claimed here.

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

Public pieces now include the default-offline C fixture, silent namespace lease,
normal kernel Controller mode, bounded query/UI and strict independent verifier.
The coordinator that assembled the accepted capture is still a private lab
script. M11-05 remains open until a public prepare/run/stop orchestrator is
executed and verified once with exact recovery. Do not present the private
capture script or this document as that missing entry point.
