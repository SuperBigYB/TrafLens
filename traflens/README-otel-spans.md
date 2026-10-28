# OpenTelemetry Span integration contract

M10 now passes a finite real SDK -> native integration -> stored observations
-> explicit parent graph -> exact console detail gate. The acceptance below is
separate from source inspection; it does not establish headerless AutoTracing,
general distributed tracing coverage or DeepFlow performance parity.

## Native HTTP receiver

The Agent accepts `POST /api/v1/otel/trace` on its configured integration port.
Use an OTLP trace protobuf body and `Content-Type: application/x-protobuf`;
the current receiver decodes `TracesData` directly and does not select a JSON
decoder from the content type. The standard OTLP trace export request has the
corresponding `resource_spans` wire layout. An SDK exporter must explicitly use
this path: the default `/v1/traces`, a gRPC endpoint or a JSON export is not an
equivalent route. The finite lab sender uses uncompressed requests. The native
decoder also recognizes an exact `Content-Encoding: gzip` value.

The receiver binds an unspecified IPv4/IPv6 address. Put it in a new owned
network namespace with no published ports and allow only the finite owned SDK
workload to send to it. Check the actual listener and applied configuration
before sending. A disabled trace integration also returns an empty HTTP200;
an acknowledgement therefore does not prove that spans were accepted or stored.

Source: [Agent integration receiver](../agent/src/integration_collector.rs).

## Normal feature license and isolated configuration

The normal feature is `AGENT_LICENSE_FUNCTION_TRACE_APP = 6`.
There is no separate `TRACE_INT` constant in this version. The Controller forces
`trace_integration_disabled=true` without TRACE_APP. PROFILE_INT11 is for CPU
profile integration and must not be used to authorize traces.

The shared Controller lease accepts `integration_mode="otel_trace"` only with
a fresh `span-` followed by24 lowercase hexadecimal characters. Its
`trace_only_profile(controller_ip, controller_port, ingester_port)` builds the
exact permitted configuration; the Controller grants only `[6]` through normal
feature management and verifies read-back. The configuration enables the trace
integration while disabling profile, metric and log integrations, process
discovery and the global eBPF input, including its profiling paths; the supported
on-CPU and DWARF switches are explicitly disabled. Agent self profiling, packet
request capture and flow-metric output are disabled as well. The live Controller
template does not accept `inputs.ebpf.profile.off_cpu` or `.memory` dictionaries;
this profile does not add those keys or infer support from newer source defaults. The packet interface
regex matches no physical interface. Trace/profile transport compression is
explicitly disabled for this initial slice. This does not claim that the native
OTel handler creates no internal L7 statistics.

The existing implicit CPU-profile mode keeps its `cpu-` prefix and license11.
The trace lifecycle must retain the same owned Server port binding check,
fresh output directory, intent/receipt recovery, exact temporary group/Agent
identities, stopped-collector proof and baseline YAML hashes. Stop the owned
Agent before deleting its registration, then delete only its empty temporary
group. Do not alter a default group, reuse another Agent, publish the listener
or enable a second input to make a test pass.

Sources: [license constants](../server/controller/common/const.go),
[feature enforcement](../server/controller/trisolaris/vtap/vtap_cache.go),
[shared lease](lab/cpu_profile_controller.py).

## Stored Span semantics and query projection

The native OTel importer writes one `flow_log.l7_flow_log` observation per Span,
with `signal_source=4` and Session `type=2`. These are application-instrumented
observations, not packet/eBPF observations or deduplicated business requests.

- Trace/Span/parent IDs are lowercase hexadecimal encodings of the recorded
  protobuf bytes. An absent parent is an empty string. SpanKind is retained:
  CLIENT3 and PRODUCER4 map to `c-app`; SERVER2 and CONSUMER5 map to `s-app`;
  INTERNAL1 and other kinds map to `app`.
- `start_time` and `end_time` are nanoseconds truncated to integer microseconds;
  storage uses DateTime64 microsecond columns. `response_duration` is the
  positive difference in microseconds. `time` is the Span end Epoch second.
  Do not silently interpret formatted timestamps in the browser's local zone.
- Resource `service.name` and `service.instance.id` populate `app_service` and
  `app_instance`. Span name populates `endpoint`. Missing strings remain empty;
  these fields do not prove a host, container, Kubernetes or OS process identity.
  If `app.host.ip` is absent, the Agent inserts the HTTP peer IP; a loopback
  exporter consequently does not establish a physical host address.
- For this pinned importer, use compatible Span attributes `http.method`,
  `http.target` (or `http.url`), `http.status_code`, `http.flavor` and
  `http.scheme`. Newer keys such as `http.request.method` alone do not populate
  the corresponding core request columns. Nonzero HTTP status takes priority
  over Span status; otherwise ERROR maps to server error, OK to success and
  UNSET to unknown. A server-app observation without a populated server port
  receives the native sentinel65535; do not present that as an observed port.

The checked Query descriptors include `agent_id`, `signal_source`, `type`,
`time`, `start_time`, `end_time`, `response_duration`, `app_service`,
`app_instance`, `endpoint`, `trace_id`, `span_id`, `parent_span_id`, `span_kind`,
`tap_side`, `request_type`, `request_resource`, `response_code` and
`response_status`. A bounded fixed projection should retain exact record IDs,
scope by actual Agent/source/time and explicit Trace ID, and reject excessive
rows rather than silently construct a partial tree. The actual fixed projection and serialization pass the running-Server gate below.

Only display parent relationships recorded by the SDK and present in the
queried set. Missing parents, another Trace and incomplete exports must remain
explicit. Shared Trace ID or time order alone does not prove a causal tree.
Acceptance must compare the SDK's independently retained Span IDs, parents,
timestamps, attributes and Span count with complete stored rows and browser
navigation, including an unrelated Trace control.

Sources: [OTel importer](../server/ingester/flow_log/log_data/otel_import.go),
[L7 storage columns](../server/ingester/flow_log/log_data/l7_flow_log.go),
[signal source enum](../server/libs/datatype/flow.go),
[Query tag descriptors](../server/querier/db_descriptions/clickhouse/tag/flow_log/l7_flow_log).

## Public finite lifecycle

Build the actual SDK fixture in its existing server module/vendor tree; no new
module dependencies or generated/vendor edits are needed:

```sh
(cd server && GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=0 "$GO" build \
  -mod=vendor -trimpath -o "$PRIVATE_BINARY" ./cmd/traflens-span-workload)
```

The workload defaults to an offline plan. `serve --execute --role frontend|backend`
starts one owned process, and `generate --execute` makes real HTTP requests.
The lifecycle below runs them as separate restricted containers sharing one
private namespace on the sampling host. The Agent forwards OTLP to the second
host's existing Server/storage. This is a two-host ingestion product gate, not
an inter-host application-throughput measurement.

Deploy the public Controller helper files listed in the
[finite integration preparation](README-cpu-profile-runtime.md#prepare-binaries-and-private-inputs)
to a private backend code directory. Reuse the existing running owned lab and a
preloaded compatible Agent image/binary/libraries. On the sampling host:

```sh
python3 traflens/lab/otel-spans.py --execute \
  --backend-host "$BACKEND_SSH_ALIAS" --backend-root "$OWNED_LAB_ROOT" \
  --backend-code "$BACKEND_CODE" --backend-output "$NEW_CONTROLLER_WORK" \
  --controller-ip "$CONTROLLER_IP" --controller-port 20035 --ingester-port 20033 \
  --image "$PRELOADED_AGENT_IMAGE_ID" \
  --agent "$AGENT_BINARY" --agent-sha256 "$AGENT_SHA256" --libs "$AGENT_LIBS" \
  --workload "$SDK_BINARY" --workload-sha256 "$SDK_SHA256" \
  --output "$NEW_PRIVATE_WORK" --requests 2 --seconds 90
```

Remove `--execute` to inspect the no-side-effect plan. Output parents must be
canonical, owned and private0700; every execution directory must be fresh. The
entry grants only its temporary group/Agent function6, checks actual namespace
listener readiness, then serves frontend18081/backend18082 and generates one
main and one unrelated control request. Each real request creates four SDK
Spans: frontend server -> frontend client -> backend server -> backend internal.
The W3C context is propagated over the actual HTTP call. The SDK chooses IDs,
records real time and exports through its official OTLP conversion; no fake
Span JSON, SQL insertion or client-invented Span IDs qualify this path.

Each service retains actual `ReadOnlySpan` JSONL, canonical protobuf files,
wire SHA/HTTP acknowledgement and an execution receipt. The generator records
actual request outcomes. HTTP acknowledgement and exit0 alone do not qualify
storage; incomplete service receipts remain failed even if orderly shutdown is0.
The public strict oracle currently qualifies the two-request/eight-Span slice,
not every possible workload option.

Reuse the [independent finite Querier/console entry](README-cpu-profile-runtime.md#start-the-independent-bounded-query-runtime)
with the new console binary. Its initial empty profile-protocol readiness is
only component readiness; the following OTel oracle establishes actual Span
functionality. The original Server stays running and its binary/config is not
replaced. Start owned loopback SSH forwarding on the sampling host for the query
and console endpoints when the backend is on the other host:

```sh
ssh -N -L 127.0.0.1:20819:127.0.0.1:20818 \
  -L 127.0.0.1:20820:127.0.0.1:20880 "$BACKEND_SSH_ALIAS"
python3 traflens/lab/verify-otel-spans.py --execute --work "$ACTUAL_WORK" \
  --query-base http://127.0.0.1:20819 --console-base http://127.0.0.1:20820 \
  --output "$NEW_PRIVATE_ORACLE_WORK"
```

The verifier checks actual SDK/HTTP/wire receipts, two full-marker ID/metadata/
measured-time populations without hiding wrong source/Agent/time, source4 versus
source0/3 controls, both exact parent graphs, empty scopes and all eight exact
record details. It compares nanoseconds floored to microseconds and their actual
differences, not application sleep time. It allows64 native rows,16 SDK Spans,
32 requests,12s per request and60s total, and saves failures instead of retrying
with a different expression or wider predicates.

## Fixed bounded graph and actual UI

`GET /api/spans?trace=<32lowerhex>&from=<epoch>&to=<epoch>&agent=<optional-id>`
selects only source4/Session2 and the exact Trace, positive inclusive time up to
31days and optional historical Agent. SQL fetches257 for a256-observation cap;
excess is413 rather than a partial tree. The handler uses the console's response
budget and12s deadline. These are returned-row/time/response constraints, not an
absolute database-scan or all-driver-memory cap.

Each observation retains its own exact string record ID, Span/parent IDs,
application/instance, kind, endpoint, microsecond start/end/duration and Agent.
Only a unique recorded parent creates an edge. Duplicate Span observations stay
separate; conflicts, missing/ambiguous parents, cycles and invalid IDs have
explicit diagnostics and affected edges are withheld. Missing schema/upstream
errors return502; valid empty results remain200 with empty arrays. The fixed
scope remains development org/user1 and loopback, not public multi-user auth.

The independent Span form renders only those proven edges and exposes diagnostics.
Select a node to open the exact actual record with pinned Trace/time/Agent/source4.
The request selector, labels and shared overview/RED/relationships now accept
OpenTelemetry4 alongside packet0/eBPF3. App/host mappings and the sentinel port
remain native recorded fields, not a discovered physical endpoint or health.

Stop only this run's resources through its receipt:

```sh
python3 traflens/lab/otel-spans.py stop --execute --output "$ACTUAL_WORK"
python3 "$BACKEND_CODE/profile-query-runtime.py" stop --execute --work "$QUERY_WORK"
```

The SDK services finish/flush before Agent drain; only exact owned process/
container/Controller/network identities are removed. Stop the two owned SSH
forwards too. Keep failed attempts and do not override an ownership failure.

## Actual acceptance (2026-10-28)

The first public preparation fails on unsupported off_cpu config before a
collector or workload starts; its profile is corrected to the actual supported
global eBPF/onCPU/DWARF disable gates. A second preparation fails serializing a
Path mount intent, also before any Agent/workload upload; it restores its temporary
registration and network. Both immutable failed directories remain. The direct
serialization fix has a Path-specific recovery regression test. A fresh third
execution is the qualified dataset; old markers and timestamps are not reused.

Two real HTTP requests create eight SDK Span observations across two services,
four per Trace with three recorded parent edges. Agent and both service processes
exit0/noOOM and retain complete receipts. The public oracle passes two complete
same-ID/value reads, exact SDK IDs/parents/resource fields/ns-to-us time/duration,
source4=8 with source0/3=0, both four-node/three-edge graphs, empty Agent/time/Trace
controls and all eight matching record details. Real Edge independently visits
both Trace graphs and both services' details, keeps Trace populations separate,
selects source4 and exercises empty controls with zero page errors.

Both public stop entries pass. Old Server identity/config SHA, old Controller
identities/license/YAML hashes, management route and BPF baseline are preserved.
All owned containers/registrations/networks/forwards stop; only the eight retained
real observations remain. Public anonymous evidence:
`evidence/2026-10-28/otel-spans/summary.json`. The local plan closes M10 after both
repository main refs match this delivery.

References: [DeepFlow OpenTelemetry input](https://get.deepflow.io/docs/integration/input/tracing/opentelemetry/),
[OpenTelemetry Span API/context](https://opentelemetry.io/docs/specs/otel/trace/api/).
The pinned native code and actual qualified receipts determine this slice's
supported behavior; current upstream documentation alone is not test evidence.
