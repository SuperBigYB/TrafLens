# TrafLens development checkpoint - 2026-10-27

The objective remains ongoing: validate and extend DeepFlow functionality and
performance. Read this file, `git status --short --branch`, and the latest evidence
before each half-hourly iteration. Source presence, a successful build and a healthy
process are separate from successful collection and product parity.

## User priority: mainline product first (2026-10-28)

Follow [ROADMAP.md](ROADMAP.md) before historical next-step suggestions. The next
priority is a reproducible product entry point and minimal real-data console
(Agent status, overview, request list/detail), then managed eBPF ingestion,
topology/tracing and metrics/profiling. Defer nonblocking edge cases and detailed
performance work. Review priorities after each milestone or three half-hourly runs.

## M15-03a bounded ordering code/replay gate (2026-10-29)

The no-op Reorder now holds missing capture sequences by full socket UID/source
and emits only contiguous ranges, including CLOSE. Default native preprocess
selects MySQL; explicit [] still opts out, while the Controller template and
capture/license scope remain unchanged. Fixed item/state/accounted-byte/time
bounds, drop reasons, ordinary idle checkpoints and reconfiguration/stop handling
are implemented. Segmentation no longer uses the masked FlowID as its identity.

Forty-three distinct tests pass:7 library+11 independent42-header replay,7 native
MetaPacket/config/dispatcher helper/admission checks,1 merged-range regression
and17 additional existing config/scope checks (18 in that run,1 overlap).
The actual default-libtrace native test build rebuilt C and linked the full Rust
test executable under a limited offline, unprivileged, networknone container.
No collector, new L7 capture, parser/store/API/browser or performance gate ran.
Both original failed R22 captures remain failed and the old qualified3dec Agent
bytes are unchanged. No deployment Agent ELF has been qualified.

Next is M15-03b: produce a real release Agent from the new committed source,
prove version/artifact/image/library identity and actual ABI/FD/map/noAF_PACKET
qualification; then a fresh complete fast18Session/API/Edge gate with an explicit
unpaced receipt/oracle contract. Do not present the existing paced oracle as
fast qualification or use the unit-test executable as a deployment Agent.
See [source/test evidence](evidence/2026-10-29/mysql-ordering/README.md) and
[the native contract](../agent/plugins/reorder/README.md). M15 remains active.

## M15 fast MySQL ordering diagnosis (2026-10-29, active)

A separate default-offline unpaced diagnostic entry adds nonce-bound before/after
observer gates and bounded metadata parsing without changing DNS/paced defaults
or native3dec20af5. One actual fresh scenario reproduced incompleteness:18rows
are17Sessions plus a control/client Login Request; marker12/query6/QUIT6 and
outside0 are retained by two full same-ID/field reads. All36actual data IO and
6CLOSE callbacks match existing same-run wire. One socket arrives2,3,4,5,6close,
0,1 in the single C worker; exact socket/flow/tuple/PID/time binds that orphan.
This proves the observed pre-callback disorder, not an exclusive explanation
for R21 or a native repair. Sampled counters show42input/enqueue/dequeue;
period loss zeros cannot prove lifetime zero loss. Worker-index NULL and
missing post/trailing counters remain explicit.

The first runtime failed before wire at socket binding; the second passed the
exact native-root/run SO_PEERCRED gate and then its live observer wrongly
rejected legal cap_seq0. Original failures remain failed. The parser correction
and50combined targeted tests pass;42headers were recovered only offline from
the original owned console. No recapture, native build, UI/matrix rerun or
remote-CI verification was used. M15-03 should address bounded per-socket
cap-sequence ordering, initial gaps, timeout/memory and CLOSE, then qualify
a new artifact and perform the necessary complete fast gate.

Both original failed results remain unchanged; final exact owned resource,
BPF/tracefs, Controller/YAML, physical hardware/routes and old Server restoration
checks pass. No unknown program was detached.

See [diagnostic entry](README-ebpf-mysql-diagnostic.md) and
[anonymous evidence](evidence/2026-10-29/fast-mysql/README.md).

## M14 paced eBPF MySQL wire functional gate (2026-10-29)

The explicit100ms-paced finite protocol fixture passes. Typed immutable
contracts reuse namespaceFD/map/no-AF_PACKET and four actual limited workers;
MySQL-only18080/normal kernel2/4/5 and a strict managed-MySQL manifest retain
HTTP/DNS default contracts. Native core3dec20af5 is unchanged. The self comm
mysqld is only its inference direction hint, bound to real PID/exe/ns, not SQL
database identity. No SQL executes and no existing database is a workload.

Three positive conversations produce18source3 Sessions:6Login/6Query/6QUIT.
Two full Agent/time reads include empty QUIT without hidden filters; whole
marker12/query subset6 and all18 precise API details match actual complete
classic wire/PID/TID/Docker/FD-map proof and21real100ms waits per worker.
Negative namespace3conversations yields0; marked source0/4=0. Normal codes
are NULL; ERR1064 has native status3. Actual Edge shows18/12/6 and all18details,
error/NULL/empty controls with no page errors.100targeted checks and independent
review pass; console64 is unchanged historical and remote CI was not checked.

The unpaced first sample remains a genuine failed completeness gate:17records,
16Sessions plus1orphan QueryRequest, missing server mainQUIT and client control
response. Sender drain succeeded but no final numeric lost/drop counters exist.
Reorder is a no-op; perCPU/close/parser ordering are hypotheses, not a proved
cause. Pacing is not a native fix or a throughput/reliability qualification.
The exact original workload source is archived in public evidence; its original
raw result/wire/artifacts remain private and unchanged.

Public/idempotent stop restores all owned resources, BPF/tracefs/pins and original
Controller0/1/YAML; old Server identity/network/historical M9 configSHA, physical
device/interface/routes remain, temporary query/console/forwards are gone.
See [workflow](README-ebpf-mysql.md) and
[paced and failed evidence](evidence/2026-10-29/ebpf-mysql/README.md).

After both refs match, close this explicitly paced M14 slice and activate M15:
bounded fast-MySQL completeness and event-order/loss diagnosis. Obtain actual
input/kernel/queue/parse/session/writer counter evidence on the finite owned
scope, localize the unpaced loss and implement a supported direct fix before
claiming the original18-observation path or expanding protocols further.

## M13 scoped eBPF DNS/TCP product gate complete (2026-10-29)

Public managed-DNS preparation, normal kernel2/4/5 Controller mode and an explicit
strict DNS branch in the shared launcher pass a fresh finite lifecycle. Existing
namespace FD/inode/map/no-AF_PACKET scope and native3dec20af5 are reused. Four
owned limited C workers execute three DNS/TCP queries in each of two namespaces
on the same18080 port. The positive scope yields6 source3 Sessions (4 successes,
2 NXDOMAIN/RCODE3/native ClientError4); negative marker has0, source0/4 have0.
This is3positive business queries observed at client/server, not6queries.

Independent framed-wire/SHA/tuple/PID/TID/Docker/map proof, two complete whole-
marker original-ID/field populations and6 precise API details pass in20requests.
RRT is native microseconds checked against actual per-observer calls, not the
identity pause. Real Edge6details/protocol/source/error/empty controls pass with
no page errors. Existing generic DNS UI is reused; native DNS transaction IDs
are not newly displayed or treated as globally unique causal identities.

The first run failed before DNS client execution because a generic artifact
path helper rejected intentional /proc/PID/exe. The dedicated bounded stable-
PID/executable SHA fix keeps generic symlink rejection intact; original failed
result is unchanged and a fresh second run passes.74 targeted tests (31DNS and
43shared regressions), static C build and independent review pass. Console64
is an unchanged historical baseline; no old matrices or remote CI were repeated.

Agent/workers exit0, public/idempotent stop and exact BPF/tracefs/pins/Controller
0/1/YAML restore pass; old Server identity/network and historical M9 config SHA,
physical device/interface/route remain. Query/console/owned forwards are gone.
See [public workflow](README-ebpf-dns.md) and
[anonymous evidence](evidence/2026-10-29/ebpf-dns/README.md).
This small TCP/single-frame slice does not qualify UDP/DoT/DoH, arbitrary stream
segmentation, recursive DNS, general AutoTracing or physical10G performance.

After both main refs match, close M13 and select M14: a finite managed eBPF
MySQL request/error product loop. First inspect actual parser, handshake/state,
normal permissions and the same strict scope; reuse the existing packet wire
fixture only as protocol knowledge, never as evidence of source3 qualification.

## M12 finite TCP connection product gate complete (2026-10-29)

The public finite packet lifecycle, strict independent oracle and real Edge
pass three owned socket outcomes: normal HTTP, actual server abort/reset and
bound-but-not-listening refusal. Three source0 L4 reports have native close
codes1/2/15; three outside-filter sockets produce zero rows. Two complete
Agent/time populations preserve all records without hiding source/protocol/
tuple/port/close-code filters. Native counters/units and API values match;
all three exact L4 details and one exact same-native-flow HTTP record pass.

The kernel proof retains actual AF_PACKET bind0 plus the complete installed
address/port prefix and IFINDEX control-flow guard accepting only lo; it does
not call bind0 a physical lo bind. Native time=floor(end_time), deletion
deadlines2/5/35s, packet duration and minute-aligned periodic reports are distinct.
The public50s natural drain and immutable actual FinishedAt+60s report bound
avoid truncating them. Raw periodic reports are retained and period counters
conserve final lifetime totals; report count is not business connection count.

The first template/bind/log gates, short-drain/restoration failure, overly strict
native UInt64 oracle and actual HTTP-link502 are preserved separately. The last
two fixes parse exact raw integer bytes without float conversion and reuse the
same real capture; they do not replay traffic or edit stored rows/times. Native
Agent exits0, public and idempotent stop restore actual BPF/tracefs/lo/Controller
identity/membership/YAML. Old Server ID/image/network and historical M9 round14
config SHA match; physical device/interface/routes are unchanged. All owned
query/console/forwards are removed.64 full console race tests/build,49 targeted
TCP tool tests and independent review pass; remote CI was not checked.

See [public workflow](README-tcp-connections.md) and
[anonymous evidence](evidence/2026-10-29/tcp-connections/README.md).
This is a finite loopback packet-to-peer-Server product slice, not physical10G
performance, loss-free capture, health/root-cause proof, generic host connection
inventory or interchangeability with eBPF flow IDs. Row/byte/deadline bounds do
not cap all database scanning or driver memory.

After both main refs match this delivery, close M12 in the local plan and select
M13: finite managed eBPF DNS query/error navigation. First inspect actual parser,
transport and strict scope support; do not presume UDP or full protocol coverage.
Keep CPU/DWARF/process/profile/OTLP inputs off and normal kernel permissions.
Completed HTTP/OTLP/profile/packet-protocol/performance matrices stay historical.

## M11 public headerless association lifecycle functional gate complete (2026-10-28)

The public plan/run/stop capture coordinator and strict independent verifier now
pass a fresh two-host pipeline. Preparation uses only its normal temporary
kernel2/4/5 group/Agent, silent namespace lease and qualified socket core. Three
actual running-inspect receipts bind complete Docker intent, resource limits,
host PID/startticks/namespaces and original C wire execution; old retrospective
capture evidence cannot substitute for these receipts in the new schema.

Two root requests generate4HTTP exchanges and8real source3 Sessions. The public
oracle verifies two whole-marker identical complete populations, every8seed and
exact detail,3negative scopes, empty trace context and separate main/control
components (each4nodes/2network pairs/1dual-phase handoff). One endpoint's zero
request syscall ID remains visible. Real Edge verifies both services'4details,
negative scopes, over-budget failure and default60-inclusive-second window.

The first attempt failed before worker execution because Docker appended an
inactive SELinux label option. The narrow fix accepts it only with actual daemon
and host evidence that SELinux is absent, retaining raw options. Original failure
is unchanged. An initial release-ack timeout during automatic cleanup is retained;
unchanged public stop resumed from concrete final restoration proof. Fresh second
run and idempotent stop both pass; Agent/workers exit0 without OOM. The0.435second
identity gate is not a performance benchmark.23targeted lifecycle/verifier checks
and final independent review pass; existing56console/59tool baselines were not
repeated, remote CI was not checked.

All owned groups/Agents/workers/collector/namespace/query/console/forwards are
removed; old Server ID/config SHA/network, Controller baseline0Agents/1default
group/YAML, BPF/tracefs, actual interfaces/routes and preexisting services remain.
This is a finite synchronous evidence graph, not complete AutoTracing, generic
PID-generation proof, acyclic SDK parentage or physical cross-host application
correlation. See README-ebpf-association.md and the new ebpf-association-runtime
evidence. Earlier partial-slice evidence below remains historical.

After both main refs match this delivery, the local plan closes M11 and activates
M12: TCP connection observation and network-problem navigation. Inspect actual
L4 flow/metric input, schema, units and safe minimal owned scope before choosing
a supported bounded path; do not presume packet and eBPF IDs are interchangeable
or broaden collection to the management network. Do not repeat completed matrices.

## Earlier M11 partial slice (round17; historical)

M11-01..04 pass one actual finite source3 capture, a bounded evidence API and the
real Edge path. Two plain synchronous C services and a generator send no tracing
or custom headers and no SDK Spans. Two independent root requests generate4HTTP
exchanges and8Session observations. Actual app wire hashes, process/thread and
socket records match two complete whole-marker same-ID/all-column reads; source3
is8, source0/4 are0 and all trace/span/parent IDs are empty. One actual root-end
request syscall ID is zero and remains visible; both frontend handoffs have the
complete nonzero request/response syscall/thread evidence.

The fixed /api/associations query accepts an exact seed, historical Agent and at
most60inclusive seconds, forces source3/Session2/HTTP20/TCP6, uses65sentinel rows
for a64row cap,12s and4MiB. Each of8seeds returns its4node component with2network
pairs and1same-process syscall handoff. Main/control are disjoint,8exact details
and3empty negative scopes pass. URL/time never create an edge. UInt64 identifiers
remain strings. The typed evidence graph is not an SDK parent tree and currently
does not separately diagnose cycles or generic PID-generation reuse.

Actual Edge verifies both components, both services'4exact detail navigations,
empty scopes and over-budget errors with0page errors.56full console race tests,
59focused Python checks, C static build and console build pass. Review corrected
the default window to59seconds difference (60inclusive seconds) and narrowed
source/documentation claims. The first mixed-case group UUID preparation failure
occurred before collection and is retained; exact case validation now passes.

All owned workers/collector/Controller group+Agent/namespace/query/console and
forwards stop; BPF/tracefs baseline and old Server/network are preserved, without
physical interface/route changes. No previous profile/OTLP/protocol/kernel/perf
matrices were rerun. Remote CI was not checked.

M11 remains the only active milestone: M11-05 must publish the still-private
capture coordinator as a bounded prepare/run/verify/stop lifecycle and execute it
once before closure. Reuse public silent scope lease, normal kernel license2/4/5,
qualified native core, strict verifier and query runtime; do not mistake these
pieces for a completed public full lifecycle. See README-ebpf-association.md and
evidence/2026-10-28/ebpf-association/summary.json.

## M10 explicit real SDK Span functional gate complete (2026-10-28)

Two owned SDK HTTP service processes and one finite generator run through a
public isolated trace-only lifecycle with normal TRACE_APP6 and no packet,
process/eBPF/profile/metric/log input. One main and one unrelated control request
produce8real source4/Session2 observations. Independent original SDK/wire receipts,
two complete whole-marker same-ID/value reads, exact parents/resource/kind/ns-to-us
measurements and all8details pass. Each Trace has4nodes/3recorded edges; missing,
duplicate, conflict and cycle semantics remain explicit. New fixed /api/spans
and actual Edge graph/details/source4/empty controls pass with no page errors.

The initial unsupported-template and Path-intent preparation failures are retained;
no collector/SDK upload happened then, and all owned resources restored. A fresh
third execution qualifies the actual population. Both public stop commands pass,
old Server/config/registration/license/YAML/route/BPF identities remain and all
owned forwarding/query/collector/workload resources exit. See README-otel-spans.md
and dated otel-spans evidence. This is explicit SDK/W3C propagation, not headerless
AutoTracing, discovered OS/container assets or performance parity.

After both repository main refs match the delivery, the local plan closes M10
and activates M11: one finite no-trace-header eBPF HTTP association product slice.
First inspect the existing native tracing engine/fields and strict scope; require
actual kernel/request identifiers and an independent app oracle, not time or URL
alone. Do not rerun completed CPU/OTLP/protocol/kernel/performance matrices.

## M9 public finite CPU profile functional gate complete (2026-10-28)

The public profile-only lifecycle, independent query/console runtime and strict
verifier now pass one complete real two-host trial. A fresh application/Agent
reuses the original799-byte self profile and its original sampling time, without
rerunning CPU capture. Actual namespace LISTEN/readiness, HTTP acknowledgement,
Agent exit0/drain and exact Controller/container/network restoration pass. The
public bounded oracle independently reruns Go raw decoding and verifies two
complete same-ID/metadata/weight reads, two stored rows/800samples, N-1 refusal,
N-complete9function/9node tree, exact collapsed stack weights and empty controls.
The real Edge form/detail/function-to-ancestor-stack navigation passes with no
page errors; HotLoop797self/800cumulative and asyncPreempt3 remain exact.

Both public stop commands pass. The old running Server binary/configuration,
network, old registration/license/YAML identities, management route and BPF
baseline remain unchanged, and temporary query/console/tunnel endpoints close.
Public code writes only a minimal password-free Querier config; existing group
YAML is hashed, not copied. Inspection failure cannot prove a collector absent.
This is a finite Go self/integration profile gate, not eBPF CPU, OS PID/container
correlation, multi-language continuous profiling or performance parity. The first
generic-writer failure remains unexplained. See README-cpu-profile-runtime.md
and dated cpu-profile-runtime evidence.

The local plan closes M9 only after both main refs match this delivery, then
activates M10: real explicit cross-service Span causality and bounded navigation.
First verify actual OTLP/Span receiver, stored source/IDs/parent semantics and an
isolated supported path. Header Trace correlation alone is not a causal tree.
No more profile/kernel/protocol/performance matrices are needed for that task.

## M9 bounded profile queries and real console accepted (2026-10-28)

M9-03a/b/c and M9-04 now pass on the accepted two-row/800sample dataset, without
new capture or uploads. A separate native bounded route requires MaxRows, SQL
N+1 rejection before decompression and explicit stack/byte/depth/node budgets.
The fixed console API and actual Edge form/detail navigate9functions/9nodes and
real ancestor stacks; HotLoop797self/800cumulative and asyncPreempt3 match the
independent original pprof. Wrong app/Agent/time are empty and unknown source
fails. Two complete candidate raw reads and an original-Server read match all
previous row IDs/columns/values.10native and40console race tests/builds pass.

The original image-embedded read-only Server stays running and unchanged. A
finite independent native Querier with credential-free allowlisted config proves
the new route; temporary query/console containers/processes/forwarding exit and
the original Server/config/network persist. Bounds constrain returned rows and
subsequent decoding, not ClickHouse scan work or all pre-return driver memory.

M9 remains the sole active milestone. Next M9-05 must turn the existing private
profile-only preparation/integration and new query runtime into a public reusable
prepare/start/verify/stop workflow, then do one necessary replay through that
entry. Do not repeat old CPU/kernel/protocol matrices. The first ingestion writer
failure remains unexplained and is not repaired by successful later data reads.
See README-cpu-profiling.md and dated cpu-profile-console evidence. No M10 yet.

## M9 real profile ingestion accepted; bounded product API next (2026-10-28)

The original zero-row path is now located after PROFILE receiver and Go decode:
actual counters prove two generic writer pre-input failures, not merely a pending
queue or72h TTL. Current library offline decoding of the same799-byte artifact
independently returns two stacks/800samples. A single diagnostic transport identity
reuses that original profile under a reversible ckwriter warning lease, and this
attempt actually stores two rows. No code fix or cause for the original failure
is claimed; it remains an explicit reliability follow-up with all failed evidence.

M9-02c passes two whole-marker complete same-ID/fingerprint/Count+Sum reads, actual
Agent/Golang/cpu/samples semantics and exact raw-profile collapsed-stack weights.
The readable tree has9functions/9nodes, root/self total800, HotLoop self797/cum800
and asyncPreempt self3; post-tree fingerprint is unchanged. The logger restores
ERROR, and only owned temporary registration/group/container/network resources
are removed; old configuration/identities/routes/BPF remain. No CPU recapture,
synthetic database rows or unrelated workload sampling is performed.

M9 remains the sole active milestone. Next M9-03 needs a genuinely bounded native
profile route, then the console/public lifecycle and actual browser gate. Existing
ProfileTracing has no request-level limit; preflight Count alone is not a hard
query bound. Prefer a separate strict bounded route so old servers404 instead of
silently ignoring an added JSON field. Preserve old behavior for existing clients.
See README-cpu-profiling.md and dated cpu-profile-ingestion evidence. Do not rerun
the old packet/kernel/CPU artifact qualification or erase the first-write failure.

## M9 CPU profiling partial checkpoint (2026-10-28)

M9 remains the sole active milestone. Native on-CPU capture is system-wide before
user-space matching, so this strict single-process slice uses real Go runtime
self sampling. A new public finite fixture, tested under1CPU/128MiB/32PIDs with
no capabilities/network, exits0 and yields a799-byte gzip profile. Independent
pprof decoding verifies800 samples/count,8e9 CPU nanoseconds,10ms period and the
actual known hot function.3 new-module race tests pass; no kernel profiler runs.

A separate registration/group and no-published-port network namespace isolate
native profile-only integration. Correct supported PROFILE_INT11 and an actual
listener gate fix the first pre-upload failure without changing old resources.
The following HTTP200/Agent-exit0/drain-success still does not establish storage:
90s exact whole-marker queries, same-Agent and no-time diagnostics return0 rows.
No rows are synthesized, filters widened for acceptance, or uploads repeated to
hide the failure. All owned registrations/groups, containers and networks restore;
existing management route/BPF/identities/configuration remain. Next M9-02c is the
actual profile receiver/decoder/routing diagnosis, followed by strict stored-sample
oracle, bounded API/console and public reusable lifecycle. Do not rerun CPU sampling
or the old packet/eBPF/HTTP matrix just to recreate the retained valid artifact.
See README-cpu-profiling.md and dated cpu-profiling evidence. M9 is not closed.

## M8 observation time trends functional acceptance (2026-10-28)

The console adds a fixed two-query Session trend API and actual chart/table
interval navigation. Steps60/300/900/3600/14400 are bounded to240 aligned buckets,
with native integer-Epoch alignment verified on the qualified UTC+8 backend.
Time is end_time floored to seconds; inclusive clipped intervals and one-second
ranges retain exact request/RED scope. Rates use actual covered seconds. Counts
and maxima retain UInt64 strings; no positive samples means null latency.
Missing result/schema is502; complete-schema empty values may fill zero counts.
Two reads are non-atomic and contradictory snapshots never become partial health.

No new capture is needed:24 M4/M5 two-host HTTP Sessions produce two12-record
periods on a36-bucket60s grid, with53/50-second clipped edges and34 empty buckets.
All fields match independent raw recomputation, including4 client/2 server errors,
positive means1113.8333333333333/64101.5us and maxima3330/503264us. Actual Edge
verifies both interval->exact-detail paths, shared Agent/protocol/source/resource
scope, explicit Session selection and restore, empty/source3 controls and bounded
resolution rejection. Page errors0;32 full module race tests/build pass. Review
corrected missing-result zero fill and implicit all-record drill-down before the
successful browser gate. Owned console exits; profiles/network/BPF/services stay
unchanged. See README-service-trends.md and dated service-trends evidence.
Complete both remote synchronizations before recording M8 closure.

The sole planned next milestone is M9: one owned process's real CPU profiling
signal through ingestion/query to console inspection. First examine existing
native profiling, profile schemas/query APIs and qualified lab paths. Prefer a
supported native on-CPU path; an existing profiling integration must be labeled
with its actual source. Use one bounded owned workload and exact process/cgroup
scope, keep unrelated workloads out, verify actual stack/sample units and known
hot function, and restore all owned collector state. Do not insert synthetic
profile rows or infer CPU percentage from request latency. Broader profiling,
full identity discovery, AutoTracing and maximum performance remain later work.

## M7 current Agent resources functional acceptance (2026-10-28)

The new bounded resource API projects8 real current-registration fields in the
fixed organization1/user1 lab scope. Numeric-ID ordering/truncation is explicit;
exact-ID lookup precedes truncation. Unknown ID, genuine empty, invalid input and
upstream/malformed inventory stay distinct. TEAM_ID is an attribute, not a new
multi-tenant authorization implementation. L7 has only numeric Agent ID, without
registration UUID/generation, so no historical host/container identity is inferred.

The directory selects visible Agent scope shared by overview, relationships, RED
and request/detail. Manual Agent changes clear a previous relationship; clearing
Agent/relationship restores other filters. Actual Edge compares the directory to
an independent Controller response and navigates current registration ->2 service
relationships/RED ->8 historical M6 protocol observations -> exact detail. Two
complete same-ID reads pass; unknown Agent and source3 controls are empty. Current
registration state0(disconnected)/enable1 is preserved while historical data exists.
24 console race tests, build and independent review pass; page errors0. No capture,
profile, network or backend service change is needed; owned console exits and
source/peer configuration, BPF identity and existing services are verified unchanged.
See README-resource-directory.md and dated resource-directory evidence. Complete
both remote synchronizations before recording M7 closure.

The sole planned next milestone is M8: service observation time trends and interval
drill-down. First verify actual bounded time-bucket query support/units, then expose
record/error/positive-latency trends sharing resource/service scope and navigate
an actual selected interval to requests/details. Preserve partial bucket/empty/
failed-query semantics; do not label observation rates as deduplicated throughput.
Use existing qualified records or one necessary finite scenario, without repeating
old protocol/kernel/performance matrices. Full profiling, identity discovery and
AutoTracing remain subsequent milestones.

## M6 DNS/MySQL functional acceptance (2026-10-28)

The console names DNS/MySQL consistently and exposes real domain/answer/exception
fields with protocol-specific response-code guidance. Reused finite fixtures send
4 DNS A and4 MySQL read-only wire-protocol queries over the two hosts;2 more of
each protocol on excluded ports complete but produce no marked storage rows.
MySQL uses a protocol fixture, not the Controller database or SQL execution.
The new independent whole-marker oracle verifies8 unique source0 Sessions twice,
without protocol/source/status filters concealing mismatches. Actual Edge passes
protocol selection, overview/relationship scope, exact ID details, DNS answer and
MySQL null-code interpretation, excluded-marker/source3 controls; page errors0.
19 console race tests and249 lab tests pass. Native core is unchanged.

Agent exit0, exact YAML, test interface/management route, BPF/tracefs, fixture
processes and owned console restore; pre-existing services remain. Preparation
and browser-fixture failures are retained, followed by the qualified fresh
attempt. See README-protocol-product.md and dated protocol-product evidence.
Complete both remote synchronizations before recording M6 closure.

The sole planned next milestone is M7: host/Agent resource directory linked to
actual service observations and request details. Start by checking real Controller
inventory fields and tenant/scope semantics, then implement a bounded exact-ID
resource-to-services/RED/requests navigation slice. Do not invent container or
Kubernetes associations from an Agent name; full AutoTracing, profiling and
maximum-performance work remain subsequent slices.

## M5 service RED functional acceptance (2026-10-28)

The console now shows Session observation volume/window rate, client/server
errors and positive latency, with shared service/Trace scope and error/slow
request navigation. Live probes and source definitions verify us units, server3/
client4 statuses and native mean exclusion of zero durations. A positive-sample
count makes that exclusion explicit. Empty means/maxima/error ratio stay null;
UInt64 counters/maxima remain strings. Two supported bounded queries replace an
unsupported conditional-Sum probe (HTTP500); failed/missing/contradictory second
aggregates do not become partial healthy metrics. Queries are not atomic.

An opt-in real two-host HTTP scenario yields12 Sessions:4 client errors,2 server
errors,6 successes, mean64101.5us, maximum503264us and2 records >=100ms. The unchanged
native Agent plus extended independent whole-marker oracle pass two exact reads.
Actual Edge recomputes from records and verifies service-scoped3-error navigation,
exact detail/full Trace,2 slow records, successful unrelated control and null
empty states; no page errors.19 module race tests/build and245 lab tests pass.

Agent exit0, fixture processes, exact YAML, source test link/management route,
BPF/tracefs and owned console restore; existing services remain. No native/kernel
or throughput matrix is repeated. See README-service-red.md and dated service-red
evidence. Complete both remote synchronizations before recording M5 closure.

The sole next milestone is M6: DNS/MySQL requests from real capture to console.
Reuse existing protocol sources, fixtures and evidence before selecting one
necessary bounded two-host acceptance; expose real protocol names/fields and
shared filters/details. Do not turn source presence into runtime qualification
or mix full AutoTracing/performance goals into that protocol product slice.

## M4 exact HTTP Trace functional acceptance (2026-10-28)

A new public finite HTTP fixture sends client -> frontend -> backend across the
two hosts with explicit W3C context propagation and an unrelated-Trace control.
The unchanged qualified native parser stores all12 HTTP Session records:10 target
Trace observations across two endpoints and2 control records. A new independent
whole-marker oracle recomputes the wire contract and requires two exact reads;
source/protocol/Trace/status mismatches cannot hide behind query predicates.

The console adds exact Trace filtering and a bounded cross-endpoint Trace dialog.
A relationship's Trace jump retains time/source and removes narrow endpoint,
resource/protocol restrictions for that view. Exact ID details retain Trace scope;
Span/ParentSpan fields remain raw. Real Edge verifies10 linked records,5 under
one relationship,2 for the control, zero missing/wrong-source, exact detail and
error/empty distinction; no page errors. ParentSpan is empty, not inferred.

14 module race tests/build and243 lab tests pass. Agent exit0, original YAML,
link/route/BPF/tracefs and owned fixture processes restore. Initial workstation
console-stop fails; a follow-up via the authorized host confirms actual owned
console exit. No kernel/native rebuild or repeated M2 matrix is needed. See
README-http-trace.md and dated http-trace evidence.

M4 functional acceptance is complete; synchronize both remotes before recording
closure. The sole next milestone is M5: service RED metrics and error/slow-record
navigation. Confirm actual duration units, error definitions and supported
aggregations first, then expose real metrics with observation semantics and a
controlled error/delay scenario. Full AutoTracing/causal Span assembly remains
future work, separate from this verified header-based correlation slice.

## M3 service relationship functional acceptance (2026-10-28)

The console aggregates real L7 records into scoped client -> service endpoint
relationships. Exact Agent/EPC/IP/port/transport/protocol/source/observation
filters are shared by relationships, list, overview and details. Top100 plus a
sentinel exposes truncation; UInt64 counts stay strings. Unknown values and
observation counts are not reinterpreted as universal service names or spans.

A fresh two-host, two-port trial completes200 requests per endpoint. All400 rows
pass exact scans twice per endpoint. Real Edge verifies two groups/total400,
relationship navigation to100 latest rows/total200, all scope predicates,
exact detail, protocol drill-down, clear selection, empty/error and zero page
errors. Existing eBPF data splits40 records into20c-p/20s-p groups without a
new capture run.10 module race tests and build pass. Agent exit0, exact YAML,
link/route/BPF/tracefs, owned console/forwarding and existing services restore.

The initial shortened readiness wait yields121/200 on the first endpoint and
200/200 on the second. Retained failure evidence leads to an actual dispatcher
and three-listener readiness gate; a fresh sample then passes all400. Earlier
private coordinator path/directory failures do not start an Agent. See
README-service-relations.md and dated service-relations evidence.

M3 functional acceptance is complete; close it after both remote synchronizations.
The sole next milestone is M4: Trace ID correlation across real service requests.
Confirm stored trace/span fields and propagation first, then provide a bounded
multi-service fixture and safe trace navigation. Do not invent causal spans
from an aggregate relationship. Full AutoTracing/parity remains future work.

## M2 portable runtime functional acceptance (2026-10-28)

The public bounded runtime in `lab/managed-http-agent.py` and
`lab/managed_http_workload.py` replaces private startup/stop preparation. Explicit
prepared configuration and artifact hashes, live Controller group/profile
readback, exact held namespace FD and a finite lifetime are required. Readiness
checks actual collector/policy, Agent pin, zero AF_PACKET sockets and the owned
scope ARRAY before allowing phases. Stop verifies exact resource identity and
restoration; no unknown BPF program is detached. See README-managed-http-runtime.md.

A fresh trial through these entries passes20 positive roundtrips ->40 Sessions
(source3,20client+20server),40 negative roundtrips ->zero records and two strict
whole-marker reads. Real Edge sees the new40 records, exact details and protocol
aggregation; same-marker packet source is empty. Agent exit0, worker/pin cleanup,
BPF/tracefs, exact Controller YAML, existing lab services and owned console/SSH
forward cleanup pass.236 lab tests pass, including eight new runtime guards.
Initial coordinator-path and input-mode failures remain private; neither started
an Agent, and the second restored the temporarily applied profile and workers.

M2 functional acceptance is complete; synchronize this delivery to both remotes
before recording milestone closure. The sole next milestone is M3: real service
relationships in the console, with shared filters and request drill-down. Start
by checking available real query fields, then deliver the API/UI and a bounded
multi-service acceptance. Do not expand protocol/kernel/performance matrices
inside this product milestone. Full DeepFlow parity remains unproven.

## M2 preparation checkpoint (historical, 2026-10-28)

`lab/managed-http.py` and its identity-free profile template provide public
profile/bootstrap preparation. Literal endpoints, ports and group are explicit;
output is a fresh private directory with hashed files. The default is a read-only
plan and no command starts capture or changes Controller.228 lab tests pass.
Generated output equals the previously qualified managed HTTP profile and
passes a live community template check without writes or another capture run.

At that checkpoint only M2-05a was complete; startup/stop and its runtime
verification were pending. Those remaining gates are delivered above. File
generation by itself did not close M2.

## M2 collection-to-console slice (2026-10-28)

Native `3dec20af5` passes the existing namespace-scoped managed eBPF HTTP oracle:
20 exchanges yield40 Sessions (20c-p+20s-p), two passing reads, source3 with
correct socket/process identity, and zero negative rows for40 out-of-scope
exchanges. Actual collector readiness, scope map/FD and no AF_PACKET socket are
verified; no diagnostics or prewarming. Worker/Agent/BPF/tracefs/YAML cleanup pass.

The console now filters and labels packet/eBPF source consistently in lists and
overview. Real Edge sees40 new source3 rows, correct detail and zero source0
rows for the same marker. Module race/build checks pass. M2-01 through M2-04
functional gates pass; M2-05 is delivered by the public runtime entry above. See README-ebpf-console.md and dated
ebpf-console evidence. This section records the earlier collection/UI checkpoint; the runtime delivery above completes its remaining gate.

## M1 functional acceptance: real-data console (2026-10-28)

The minimal console now includes real request list/detail, time/resource and
protocol filters, exact total/protocol overview with drill-down, and Controller
Agent inventory. `scripts/console.sh` builds/starts the embedded single binary;
`console/README.md` integrates existing lab startup, SSH access and stopping.

A fresh two-host2000-request workload passes exact storage scans twice. Actual
headless Edge interactions verify100 rows, total2000, matching detail ID, protocol
drill-down and empty/error states. Module race tests/build/startup build pass.
Visual review and failed attempts remain private. Owned workers/console/forwarding
stop; YAML, persistent service identities and link/route/BPF checks pass.
Independent background-job changes are recorded. See the dated console-product
evidence. M1 code `4c16f7cce` is synchronized to both repositories. The active milestone
is now M2: managed eBPF HTTP capture-to-query-to-console. The local plan holds
task decomposition, exact synchronization and subsequent milestone transitions.
This is a minimal local product, not a public authenticated deployment or full
DeepFlow parity. Earlier narrow validation records below remain historical.

## M1 first slice: minimal real-data console (2026-10-28)

M1-01 reuse decision: keep the working Server/Agent/lab and reuse query/Controller
APIs; this checkout has no shipped frontend application. `console/` adds an
independent standard-library Go module and embedded HTML with a loopback-only
entry point. Requests can be filtered by time/resource and loaded by exact
string ID; a reduced Agent inventory is exposed. Module race tests/build pass.
A temporary peer process queries5 real historical rows, verifies exact detail
ID and reads inventory, then stops cleanly. No backend service restart occurs.

M1-02 remains partial: browser interactions and new workload/UI acceptance are
not yet qualified. M1-03 overview and M1-04 unified deployment remain pending.
Next: verify the UI against actual data, then add the overview and reproducible
product launch workflow. M1 is not complete. See `console/README.md`.

## Current checkpoint: stable packet profile (2026-10-28)

Community license allocation periodically restores all functions; the former
packet profile relied on the restricted license mask to set fine-grained input
switches. Its stored YAML stayed unchanged while effective defaults changed
and triggered exit3. Explicit packet-only switches repair this test configuration.
All220 lab tests pass; the new regression fails on the old profile. No production
Controller or Agent source changes are needed for this profile correction.

Native `3dec20af5` now completes both two-machine controls across observed license
restoration: healthy2000/2000 exact rows (two scans), exit0; unbound data port
with healthy control channel,2000 completed exchanges, two zero counts, exit1.
Both use2CPU/1GiB,200RPS10s,70s pre-load stability dwell and40s stop grace.
Healthy stop13.000s; fault stop11.607s. All owned runtime workers are removed;
Controller YAML/link/route/BPF and existing service identities restore exactly.
The original zero-row diagnostic failure and its independent count-only follow-up
are retained. See `README-agent-shutdown.md` and the dated evidence JSON.
The older pre-signal disable/absent-registration cause remains unproven.
Next work follows the mainline roadmap above. These results are not a
maximum-throughput or full-parity claim.

## Checkout and source

- Primary: `dev-79:/root/yb/git/TrafLens`, branch `main`, tracking `github/main`.
- Upstream pin: `8741e924ff0ae3964a135985c51e5a6ce6bde397`,
  `v7.2.3-1-g8741e924f`; original history, notices and package paths retained.
- GitLab `origin`: `git@192.168.1.50:yb/TrafLens.git`.
- GitHub `github`: `git@github.com:SuperBigYB/TrafLens.git`.
- Reference `upstream`: `git@github.com:deepflowio/deepflow.git`, push disabled.
- GitLab SSH currently rejects this host key. Use the provided token only through
  the ephemeral SSH-stdin helper in ignored `.traflens/work/` when needed; never
  store it in a URL, config, source, evidence or credential file. GitLab has no
  HTTPS listener. Push both remotes without force and verify exact branch SHAs.

## Validated service foundation

- Complete community server builds via `make -C traflens server`: Go 1.26.2,
  official vendor patches, protobuf generation and private tool dependencies.
- Queue, LRU and flow-metrics package tests pass; 18 Python tooling tests and
  five top-level protobuf compatibility tests plus subtests pass. Negative schema
  renumbering controls are correctly rejected.
- Initial production fix `4922b11ff560b64412bee6b1092f605e4dbda0a0` repairs IPv6
  tag clone independence, anomaly/OOO merges, metric separators and lexical tags.
- `742d143a242bbb053705f4241241c58dcdc3abea` isolates 24 upstream-only jobs and
  adds native TrafLens CI. Its server CI passed, with binary artifact, in run
  <https://github.com/SuperBigYB/TrafLens/actions/runs/40297869105>.
- Both Server and packet Agent jobs passed for `6944472ea` in run
  <https://github.com/SuperBigYB/TrafLens/actions/runs/40314728930>.
  The next checkpoint expands the selected Agent gate to time and plugin ABI
  regressions. Check the new commit's actual run before claiming its remote gate.

## Agent correctness and builds

- `035a19064d171ed690422c5521ab25f12e66bb80` fixes the stale pcap lock edge,
  libtrace feature gating, asynchronous workspace-wide formatter side effects,
  and stale embedded Git revision metadata. No dependency versions were upgraded.
- `6aec171bf820e5ce516349ed3677395050b8a384` fixes blacklist accounting, request/
  response ordering, fragment/flow-end double counting and timeout retirement,
  and the IPv6 `/0` shift overflow reproduced by real traffic.
- The `6aec171bf` checkpoint passes HTTP 20, DNS 4, MySQL 8 and policy-labeler
  19 tests (51 total). The one DNS test reading an eBPF `.log` fixture requires
  `libtrace`; native builds retain it. It is not silently ignored in that mode.
- Full default-feature, optimized native Agent release build passed on dev-240
  from exact committed source `6aec171bf...`, with no source overlays. It built
  `libtrace.a` and 10 BPF ELF objects. Source tree was clean after the build;
  host version/ldd probes passed and embedded CommitId matches the source.
- Binary: `/tmp/traflens-native-build-20261026/artifacts/deepflow-agent-native-linux-amd64-6aec171b`
  on dev-240, 77,910,288 bytes, SHA256
  `04f3dabfd86c8d2ea6457aa4bd2d4309584c35fe07bcc04aa937c53fc734eaa4`.
- Native build uses official image digest recorded in evidence plus existing
  Rust 1.97.1, offline dependency caches, 4 CPUs/8 GiB and no container network or
  privileged mode. Image Rust 1.83 could not reuse the newer offline Git cache;
  the toolchain fallback changed no dependency versions.

## Isolated runtime and actual traffic

- dev-240 has owned `traflens-lab-{mysql,clickhouse,server}` resources, private
  bridge/volumes, pinned images and generated private credentials. Existing
  multimeter and gitlab-runner containers were preserved.
- CPU/RAM caps: MySQL 1 core/1 GiB, ClickHouse 2/4 GiB, Server 2/4 GiB.
  Metadata schema has 161 tables/version 7.1.0.40; ClickHouse schemas, controller
  health and a real `Count(row)` query succeed.
- Controller/data: `192.168.1.240:20035/20033`; APIs only loopback 20417/20416.
  Scripts and exact bring-up constraints are in `lab/README.md`.
- Physical Agent ID 1 is registered through public APIs, with NPM/request-log
  features, bounded supervisor, 2 cores/1024 MiB, interface `enp1s0f0`, TCP port
  18080 and HTTP only. eBPF/integrations/proc discovery remain disabled in this
  functional smoke configuration. Full native build is not eBPF runtime proof.
- HTTP is generated over scoped IPv6 on the first 10G link. First 20-request run
  returned HTTP 200 but crashed the Agent at the IPv6 `/0` boundary; regression
  and runtime logs directly identified the defect now fixed.
- A later instrumented 20-request run produced 40 raw app records, 40 tagged
  flows and 20 complete HTTP Sessions with exact request paths/status 200 in the
  Agent's final protolog sender queue. Observers copied data and did not consume
  the primary queues.
- The initial minimal Ubuntu runtime omitted the IANA timezone database. Receiver
  and decoder counters proved 20 HTTP records arrived and decoded with zero
  decoder drops; CKWriter then failed on `DateTime('Asia/Shanghai')` timezone
  inference. The lab package now includes Go 1.26.2's `zoneinfo.zip`, sets
  `ZONEINFO`, and includes runtime assets/recipe in its image cache key. Only the
  owned Server container was replaced; both databases and volumes were retained.
- Final marker `smoke-20261026105159-timezone-fixed` PASSED: 20 client requests,
  20 server responses and 20 unique queried rows; every resource path matches
  exactly, with method GET and response code 200. Acceptance JSON and raw inputs
  are retained. This proves low-rate packet-mode IPv6 HTTP collection, transport,
  persistence and querying, not broad protocol/eBPF/performance parity.
- Absence of a separate L7 TCP connection log is normal: senders share
  `GLOBAL_CONNECTION` by default. Queue observers copied records without consuming
  the application queues and were bounded/disabled after diagnosis.
- Subsequent verification exposed an undersized ClickHouse thread pool in the
  lab configuration. After restarting only the owned ClickHouse container with
  its data volume retained, five fresh query-API reads each returned the exact
  same twenty GET/200 rows (4.7-17.4 ms). This measures these low-rate queries,
  not ingestion throughput or performance parity. CPU/RAM caps stayed unchanged.
- All 11 lab regression tests pass, including supervisor PID/start-time/repo
  ownership, existing-container image provenance and clean content-addressed
  runtime extraction. The private-password scan of complete Server logs found
  no match. The Agent supervisor is stopped; three owned lab containers remain.

## Protocol acceptance and boundary repairs - next checkpoint

- `4f0a7d96d833f770668dea304a5a6afaef2c0fbd` repairs future/cross-hour
  response-time inference, rejects non-ASCII/invalid minute-second inputs before
  slicing, and enforces the 120-second limit at microsecond precision.
- The same commit repairs the C plugin's dangling empty-string pointer and
  safely retains a NUL-terminated process name, including a full 15-byte comm,
  across each callback. It also aligns the public C header with the existing
  Rust response/check-result ABI and rebuilds the test shared object through a
  new Makefile. Fifty-five C/Rust size/alignment/offset comparisons pass.
- Default-feature native Release from exact `4f0a7d96d` also passes, with
  ten BPF objects, no source overlays and clean source after archiving/restoring
  the generated test ELF. Six native CFFI tests pass, including the libtrace
  MetaPacket process-name case; the native response-time module passes 15/15.
  Binary SHA256 is
  `2f6bd8507bb50aeaa94af5a475b5d81466e23281a074c3ed1cef2eb8670dda53`.
  Follow-up native WASM tests pass one of five and fail four despite a valid
  process name. Those four need further diagnosis; missing packet-mode process
  context does not explain all WASM failures. Live eBPF tracing is still untested.
- Final packet selected gate passes 73 tests: HTTP 20, DNS 4, MySQL 8, labeler
  19, response-time 15, process-name/ABI 5 and shared-object integration 2.
  The 46 lab tests cover independent DNS/MySQL wire vectors, deadlines, malformed
  responses, group ownership and exact query multisets. DNS acceptance requires
  the exact answer address/TTL; duplicate rows cannot hide missing requests.
- A complete packet library run now finishes without SIGSEGV: 294 cases,
  276 passed and 18 failed. All eighteen failures were reproduced individually
  against the compatible pinned upstream baseline. Its pristine locked build
  cannot run; the explicit minimal build-only overlays and exact evidence are in
  `evidence/2026-10-26/baseline/`. This is not a full upstream-suite pass.
- The three-protocol profile preserves all original resource/interface limits,
  adding only UDP 18053/DNS and TCP 18060/MySQL to HTTP 18080. Updating a populated
  group requires an explicit flag and the sole exact registered dev-79 identity;
  the operator must stop the owned Agent before applying restart-tagged settings.
- Real cross-host MySQL wire acceptance passed: complete greeting/login,
  20 unique COM_QUERY SQL strings and verified one-row results, then exact
  20-row query-API readback of SQL/type/success status twice. This is a bounded
  protocol fixture, not execution against a real database engine or TLS proof.
- DNS first batch `dns-20261026-ingest1` failed strict acceptance at 19/20.
  q0 had one request/one response in L4, DNS parsed successfully, but no L7 row.
  A contemporaneous CKwriter broken-pipe warning explicitly dropped one L7 item;
  correspondence to q0 is a strong inference because the warning has no flow ID.
  No reliability fix is included and the failed evidence is preserved.
- The next warm DNS batch and a new-process, no-warmup cold DNS batch each passed
  exact 20/20 domain/type/rcode/status/A-address/TTL query readback twice. Each
  observed batch independently captured 40 packets with zero kernel capture
  drops, 40 app records and 20 complete sender Sessions. The later passes do not
  erase or establish a fix for the first loss. Both bounded Agent runs stopped;
  queue observers are off, and only the three owned lab containers remain.

## ClickHouse write recovery checkpoint

- `f89e5647c58e1ff02b1fbd7f53b4aada07789350` adds a real ch-go native-protocol
  input gate. It retains serialized rows across only provably pre-supply network
  failures, replaces broken clients, and resets/counts a logical batch once.
  No vendor, table engine, deduplication or external API signature was changed.
- `4b2799823516bc49ff2f3c840a782cd57361f28f` extends recovery to at most 13
  attempts under a shared ten-second context, with 100ms exponential backoff
  capped at one second. A 550ms refusal regression fails the initial 200ms policy
  and passes the new one. Driver cancellation may add about one second cleanup.
- Thirteen top-level Go tests plus real-protocol subcases pass, including race
  checks. They cover stale idle sockets, failure before metadata, lost reply
  after data, exception preservation, empty metadata, DateTime inference, one
  EOF block, bounded dialing and single final accounting. CI now includes the
  owning package with `-race`. All 65 lab helper tests also pass.
- Actual candidate Server on dev-240 embeds exact source `4b2799823`, binary
  SHA256 `b820516ca626e213f71a4955e68e6fccda09b57603b0bd6234d2a4855a8447aa`;
  runtime archive SHA256
  `5c1690d76be3c12699a43a23e80a19488f321884438b1965627008d6e89484e0`.
  Only the owned Server container was replaced before the candidate experiment;
  databases/data volumes were retained and unrelated containers were preserved.
- Baseline Server `4922b11ff` and candidate use the same `6aec171bf` packet Agent
  and exact protocol config. After an offline inventory
  entry was found absent, the same owned dev-79 identity was safely re-registered as Agent ID2.
  Re-run `register-agent.py` before capture rather than assuming ID1 persists.
- Baseline `f20261026b2` failed BEFORE fault injection at HTTP20/MySQL20/DNS19;
  its guard correctly prevented a restart. This loss is preserved separately.
  The initial `b1` preparation was abandoned without traffic or mutation when
  the helper's after-failure recovery checks were corrected.
- Controlled warm baseline `f20261026b3` and candidate `f20261026c1` each record
  one explicit DNS preconditioning exchange outside measured requests. Each
  then sends twenty HTTP/DNS/MySQL requests in each of before/during/after,
  with one owned ClickHouse restart overlapping all three protocols. Baseline
  gives 60/60, 59/60, 60/60 and final FAIL; candidate gives 60/60 in every phase,
  all nine exact multisets match twice again at finalization, and final PASS.
  Thus this controlled case improves 179/180 to 180/180 with no duplicate rows.
  All phase overlap uses dev-240 server timestamps, not cross-host clocks.
- Persisted candidate L7-writer intervals show six retries, five failed retry
  attempts, zero failed/uncertain rows, and successful writes. These are sampled
  interval increments, not a cumulative gauge; the initial 61 seconds before
  the first stored point are unobserved. The total includes warmup and
  fixture connection messages beyond the 180 marked requests.
- A failed INSERT after input supply remains an uncertain outcome and is never
  blindly replayed. This does not provide durable buffering, general exactly-once
  delivery, unbounded outage coverage or retries of independent DDL paths.
  The controlled pass does not erase the unfaulted first-DNS-loss evidence or
  establish unrestricted load/performance parity. The bounded Agent is stopped.

## Tunnel decoder checkpoint

- The four public tunnel plugin stubs are replaced with independent ERSPAN
  I/II/III, TEB, Tencent keyed GRE and IPv4 VXLAN-GPE/NSH decoders. Public Rust
  signatures and tunnel enums are unchanged; no dependency/vendor update or
  private implementation is imported. Standard wire formats and the existing
  Go pseudo-MAC contract guide the implementation.
- The Agent caller now validates header bounds and IPv4 options, respects IHL,
  checks UDP and inner-IP logical lengths, returns IPv6 Geneve offset 56,
  snapshots Tencent outer addresses before synthetic Ethernet mutation, rejects
  excessive tiers/unrepresentable IPIP offsets transactionally, and accepts
  minimal IPIP and consistent snaplen-truncated captures.
- All 28 decoder tests and 26 Agent decapsulation tests pass. The complete
  selected packet CI gate passes 127 cases (99 Agent plus 28 tunnel crate).
  The full packet library finishes 307 cases: 295 pass and 12 fail. All six
  previous tunnel failures now pass; the twelve remaining names match the
  previous eighteen-case inventory. They remain unresolved, not ignored.
- Thirteen new caller regressions cover independent wire vectors, every prefix,
  invalid L2/tier values, declared-length padding, IPv4 options, snaplen, nested
  identity and packet/metadata transactionality. An explicit hybrid negative
  control using the old 52fa57a8b caller with the new decoders fails ten of these
  thirteen, including two panics, the incorrect Geneve offset and address
  corruption. This is not a pristine upstream suite comparison.
- Independent review found three additional length-validation gaps; the final
  candidate includes focused rejection and valid-snaplen controls for each.
  See `README-tunnels.md` and `evidence/2026-10-26/tunnels/` for raw results.
- Outer-IPv6 GRE/GPE, extension chains, outer fragment reassembly, ERSPAN raw-IP
  frame types/custom C/K extensions and IPIP layouts with IP header no larger
  than L2 remain unsupported. No new live tunnel traffic or throughput claim
  follows from these parser tests.
- Exact source `ff05c646d` passes the complete default-feature native Release,
  all 54 native tunnel tests, host version/ldd and clean-source checks. Binary
  SHA256 `14f60cbf02ebce613732b2f9b45bdeb3197e37a2ed90f0a6693fd3c7205ffe90`; ten BPF ELF files and libtrace are built. The first
  4778380b2 build failed version acceptance despite passing tests; legacy Git
  cache invalidation is repaired and its failed evidence retained. Three real
  repository-layout probes pass; CI now checks embedded CommitId against HEAD.
  Both current lab Agent binaries embed ff05c646d; the bounded Agent remains
  stopped. Full native suite/live tracing and actual tunneled traffic remain
  separate pending gates.

## Actual tunnel-wire checkpoint - 2026-10-27

- New bounded link/traffic/capture/acceptance helpers validate eleven supported
  tunnel layouts with IPv4/IPv6 inner HTTP and DNS on the first direct link.
  The final tn20261026w3 case sends 260 frames at 20 pps: 20 HTTP and 20 DNS
  synthetic conversations, not a real HTTP service or DNS resolver workload.
- Actual receiver PCAP contains all 260 frames in identical byte order to the
  generated frames, with zero kernel capture drops. The Agent observes 80 app
  records and sends 40 complete Sessions. Both exact protocol multisets match
  twice, including DNS answer address and TTL60. All 40 L7 records also match
  inner endpoints/types and their persisted L4 tunnel metadata/closure twice.
- ERSPAN/TEB intentionally trim metadata (L7 tunnel_type zero); Tencent GRE
  retains type3 and GPE/NSH type5, tier1, full key/VNI and the original outer
  transport addresses. Both inner directions are mirrored 240-to-79; the outer
  response addresses must not be reversed. L7 has no tunnel ID/outer-IP fields.
- Retained failures remain explicit: w1 Local mode splits retained-tunnel
  request/response flows; its capture expired before emission and is not loss
  evidence. w2 Mirror merges these but only gives HTTP18/20 and DNS18/20 because
  default NPB BPF excludes ERSPANIII before decoding. Final lab-only mode1 with
  skip_npb_bpf=true fixes the configuration, retaining strict full BPF/MAC/IP
  scope and all CPU/memory/output limits. No Rust production default is changed.
- Both 240-second link leases clean their exact bench-only /32 addresses and
  peer routes in all three cases; final cleanup succeeds with no unknown state.
  The bounded Agent and observers are stopped. Only the three owned lab
  containers remain; unrelated containers and management routes are preserved.
- Runtime packet source ff05c646d and Server4b2799823 are verified by version
  and binary hashes. All119 lab helper tests pass, including real offline BPF,
  independent wire/checksum/TCP/DNS vectors and strict metadata counterexamples.
  CI installs tcpdump so the offline BPF gate cannot be skipped for its absence.
  Sources, raw PCAPs/queries, failures and exact hashes are under
  evidence/2026-10-27/tunnel-wire/. See README-tunnel-wire.md for commands.

## Adjacent TCP-window checkpoint - 2026-10-27

- Source `155c5ff79ce19d31efd6cf1522c5b40a2b150d31` replaces the community
  segmentation stub with opt-in adjacent two-packet sliding parse windows.
  Original packets feed L4 once; windows/tails feed L7. Tests cover TCP sequence
  wrap/gaps/truncation/control boundaries, metadata ownership, byte budget,
  interleaved ACK/retransmission metrics, report-tail drain and direction changes.
- The controller exposes the disabled-by-default port-list setting. Four focused
  Go tests cover template metadata, round trips and numeric legacy-list upgrade.
  Configured service scores and reverse cache updates are repaired; the stale
  handshake fixture follows the existing first-ACK completion algorithm.
- All168 selected Rust and124 lab Python tests pass. Full packet-library result
  is321=312PASS/9FAIL, no ignored tests. Full agent_config retains the same
  observed5 top-level and7 subcase failure names/panic as isolated parent395f;
  cases after the panic remain unverified. Focused success is not a full pass.
- Actual case sw20261027a1 passes300 ordered byte-identical received frames,
  zero kernel capture drops, exact HTTP20/DNS20 multisets twice, and all40
  associated tunnel metadata/flow closures twice. Both HTTP directions split
  after two bytes. Profile segmentation retains strict Mirror capture scope,
  Agent2CPU/1024MiB,20pps, bounded100s capture/90s observers/240s link leases.
  Both temporary network leases clean completely; Agent and observers stop.
  Only owned Server is recreated; both databases retain identity/start times.
- Live packet Agent and Server embed155c5ff79. Separate default-feature optimized
  native Release passes41 selected tests, exact version/ldd/libtrace and10BPF
  ELF checks. Primary repository is clean; archived jattach dependency has one
  pre-existing Makefile static-library build patch. All10 non-Makefile files,
  including5 C sources, and26 OTel files match pins. Patch/hashes and the BPF
  proof-glob correction are retained; dependency build metadata is qualified.
- Core CI40371413194 passes both jobs, including168 Cargo/124 lab/focusedGo and
  embedded CommitId gates. Public result summary and guide: README-tcp-window.md and
  evidence/2026-10-27/tcp-window/summary.json. Full raw evidence stays ignored
  locally. No general TCP stream, live eBPF, sustained
  performance or complete DeepFlow parity is claimed.

## Complete Agent-library checkpoint - 2026-10-27

- Core source `913231d6a7918edadd8db48a4e5d38ec9b76601d` closes the earlier9 packet-library failures. Complete
  packet library371/371, default-feature native library382/382,
  tunnel28/28 and window21/21 pass with no ignored tests. CI now runs the full
  packet library instead of the prior168-case subset. Python124 and focusedGo4
  still pass; both local binaries build from committed source.
- Configuration restores Lua defaults/capture4 naming and aligns existing
  Triple/Dameng filter maps without enabling those protocols. RocketMQ golden
  changes retain all prior fields; the existing public memcached PCAP changes
  only four global-header bytes, retaining every one of20421 packet records.
- Hessian complete ASCII/chunk bounds fix EOF/truncation defects and preserve
  Java/Hessian separation. Legacy SDK2023/current layouts and merge-cache end
  flags are repaired. Guest memory/context errors fail safely, modern WASI
  imports remain within an empty capability context, and only typed exit0 is
  accepted during initialization. HTTP metadata uses already captured headers.
- Two reproducible Go guests use a pinned compiler/SDK and an explicit IsEnd
  fixture patch. The unchanged2023 guest passes native integration. Native
  source is clean, with the disclosed pre-existing jattach Makefile build patch.
  The first GCC4.8 link failure and first legacy-fixture failure are retained;
  restoring image login-shell GCC11 resolves the environment issue.
- Public aggregates: evidence/2026-10-27/agent-protocols/summary.json; detailed
  logs and environment evidence remain ignored. Guide: README-agent-protocols.md.
  Live eBPF, sustained workloads and complete DeepFlow parity remain pending.

## Configuration and plugin checkpoint - 2026-10-27

- Core `62429a607627051c3f242247ff646c67fee80e3e` closes the inherited full Go configuration suite:
 44 top-level/129 total pass events (85 subtests) under `-race`, no failures or skips. CI now
 gates the entire package. Template bounds/types/recursive errors, embedded JSON
 string preservation, legacy profiling/tagged-only migration, reusable upgrader
 state, DB/YAML error propagation and atomic unit-overflow rejection are repaired.
- Missing plugin merge IDs and mixed active/batch merge modes fail before shared
 cache/performance mutation. Read-only peek preserves LRU order; C retains its
 per-item rejection contract. Conservative same-key batch mode changes are
 rejected. Shared timeout algorithms remain unchanged; RTT threshold is not TTL.
- Complete packet382+28+21=431 and native393+28+21=442 pass,
 no failures/ignored tests. Scoped56 plugin cases include real host-import guests,
 C collision and12 direct unchanged-algorithm baseline controls. Python124+18 pass.
 Exact-source Server/packet/native binaries build; native original2023 keeper,
 version/ldd/libtrace/tenBPF checks pass. Existing jattach build overlay is qualified.
- Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40395398781. Guide: README-config-parity.md.
 Aggregate evidence: evidence/2026-10-27/config-parity/summary.json. Raw logs and
 environment/configuration evidence remain ignored. No new runtime deployment or
 traffic acceptance was performed; earlier wire results remain separate.

## API and eBPF runtime checkpoint - 2026-10-27

- Final Server source `c91b1a3c5ee61654d3f5ba89b00d689b21f56614` fixes empty-function query panics and
 malformed controller error JSON. Empty arguments return one typed400; recovery
 writes generic500 only before a response is written, otherwise aborting without
 appending. Nil byte data is null; descriptions and
 pages are encoded safely, and invalid raw JSON/UTF8 fails before headers.
- Local UseNumber preserves JSON integer tokens. A bounded linear scanner
 accepts exact whole decimal/exponent values within Go-int bounds; native YAML
 float/alias/merge values cannot masquerade as integers. Four inherited test
 selectors are removed. Generic dict/null and operational range limits remain.
- Six relevant Go packages pass race:91 top-level/292 total test-pass events.
 The 2048 bounded rational-oracle vectors are included in one config test.
 Local lab tools134 pass. Source CI includes config and five API package gates.
- Actual candidate HTTP13/13 passes: three empty functions, native Count(row)
 equivalence, nested-map and GUI-text persistence, invalid-update atomicity,
 exact raw integers/whole decimals/exponents, and empty-group cleanup. Original
 configurations and inventory are preserved; both database container/start/volume
 identities survive Server-only replacement. First f980 malformed DATA failure
 and later observer null-list failure are retained privately.
- Independent libtrace runtime gate links source624 artifacts:81 loaded program
 sections and30 attachment wrappers, RUNNING then STOP,20 synthetic TCP roundtrips,
 zero callbacks. Full port bypass and disabled protocol maps are read back;
 all owned programs disappear and host BPF/tracefs inventories are restored.
 This is system-wide-hook lifecycle/rejection proof, not full Agent payload or
 ingestion/profiling/performance acceptance. The prior jattach build overlay stays
 qualified. Guides: README-api-validation.md and README-ebpf-runtime.md.
- Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40405314725. Public aggregates:
 evidence/2026-10-27/api-ebpf/summary.json. Raw HTTP, configs, identifiers,
 process/container metadata and logs stay ignored locally.

## Socket namespace and native verifier checkpoint - 2026-10-27

- Core `a0cb0fb9c111cb7b34168d459fd3e188b07826e6` adds a disabled-by-default current-task netns socket fence,
  immutable local managed-Agent bootstrap with a process-lifetime namespace FD,
  and preflight rejection of unsafe capture/profiling/controller candidates.
  It is not a socket-owner or kernel PID ACL; host hooks and some metadata
  access remain global. Full managed-Agent payload ingestion remains pending.
- Native stack pressure, leaked output-buffer references, outlined fork helpers
  rejected by the map-only loader, and an uninitialized PID/thread bitfield are
  repaired. All failed candidates/verifier/harness observations stay private.
  Nine C tests run364 assertions, including actual-function/poisoned-stack cases;
  the offline ELF checker rejects the real seven-object bad build and accepts
  all ten corrected objects. Published tool/lab suites pass31/154.
- Exact native403+28+21=452 and packet392+28+21=441 pass, no failed/ignored tests.
  The unchanged original2023 keeper passes. Native binary SHA256 is
  `7e3ecc60f8c0199e7f66ec1c64508e1f7eb13cef545944ff39783e94287630ae`. The inherited jattach Makefile build-only overlay
  remains qualified. Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40423638878 (both jobs passed; owning7 Go race packages
  and CKwriter race also pass). Later helper/docs HEAD CI is checked separately.
- Actual standalone libtrace runs pass all three modes: default all-bypass and
  wrong-owned-netns controls each deliver0 callbacks; selected netns delivers
  80 exact data+2 close callbacks. Each mode completes20 positive+40 negative
  same-port/equal-length HTTP roundtrips (180 total). All81 loaded programs and
  30 attachment wrappers stop/clean; full BPF/tracefs inventories and preexisting
  containers are preserved. No Agent/Server ingestion or performance claim.
- Server `-f` reparsing is repaired. Runtime Server source121bdbe26f starts with
  explicit `-f /etc/server.yaml` and passes real HTTP13/13; database and unrelated
  container/start/mount identities are retained. Current Agent inventory is0.
- Guide: README-ebpf-netns-scope.md; aggregates:
  evidence/2026-10-27/ebpf-scope/{summary,runtime}.json. Raw configuration,
  namespace/process/container IDs and logs stay ignored. Runtime191-file private
  manifest fingerprint: `afae099b0ca69584d54c1fac3f30c136d76aa780d8dd158f7999caba48883e32`.

## Remaining validation and priorities

1. Design persistence/server-side idempotency for ambiguous commits and longer
   outages before replaying supplied blocks. Extend recovery coverage to DDL,
   queue pressure and process restart, and investigate unfaulted cold/idle DNS
   first-record loss independently of the passed warm restart experiment.
2. Extend tunnel acceptance to malformed/lost/reordered traffic, real services
   and sustained workloads; extend protocol
   acceptance to a real MySQL database, DNS error/truncation/TCP,
   reconnects, TLS, loss, agent/server restart and sustained workloads.
3. Extend Hessian Unicode/map coverage and general TCP streams; keep current
   ASCII and adjacent-window limits explicit. The complete configuration race,
   packet/default-native library and guarded plugin-identity gates now pass.
4. Extend the passed standalone exclusive-netns payload gate to full managed
   Agent collection, transport, persistence and exact queries, then TLS/profiling
   and trace application/GUI. Respect the initial restricted profile and pin FD
   lifetime; private-PID Agent readiness and end-to-end ingestion remain pending.
5. Extend remaining API shape/range cases (the startup-flag issue is resolved) in
   `lab/KNOWN_LIMITATIONS.md`; compare pinned candidate/reference workloads with
   loss, CPU/RSS, flow/span rates and visibility delay before parity claims.

Both direct links were enabled at runtime only; no management routes/persistent
network/offload settings were changed. Initial iperf3 4-stream/10-second receiver
rates were 9.166-9.277 Gbit/s, with nonzero TCP retransmits and zero NIC drop/error
counters. These are preliminary raw-link measurements on shared hosts.

Use `lab.py stop` for only owned containers; preserve their data volumes. Agent
supervisors expire after 15 minutes or three exits, and stop only their own child
process group. Runtime secrets/logs stay ignored; sanitize evidence before commit.
Keep the hourly task active: full feature/performance parity is not achieved.

Latest completed source CI: both jobs passed for
`a0cb0fb9c111cb7b34168d459fd3e188b07826e6` in <https://github.com/SuperBigYB/TrafLens/actions/runs/40423638878>.
The final helper/documentation head's actual CI is verified separately. Exact
native/runtime source and Server runtime source are distinct as recorded above.
Full feature/performance parity remains ongoing.

## Controlled HTTP load checkpoint - 2026-10-27

The bounded Go workload and its live scope are documented in README-http-load.md
and evidence/2026-10-27/http-load/summary.json. Both no-Agent controls and native
packet-Agent loads completed200/500 requests at40/100RPS for5seconds. Each Agent
load passed two strict request reads and two post-stop whole-marker reads, with
exact single-endpoint Session counts. Native source95f5e10df is unchanged.
The first no-traffic readiness failure and one invalid supplemental query remain
private alongside successful corrected runs. Exact Controller YAML and BPF/tracefs
were restored, owned workers removed, existing containers/databases retained.
Maximum/sustained throughput, true Agent CPU/RSS/queue curves, eBPF load and
matched pinned-reference comparison remain pending; see the guide for limits.

## Pinned native reference and resource observation checkpoint - 2026-10-27

Read README-reference-compare.md and evidence/2026-10-27/reference-compare/summary.json.
Pinned upstream8741e924f builds natively with only disclosed lock/protobuf-format
build compatibility changes; no L7/eBPF candidate fixes were transplanted. Native
candidate95f5e10df is unchanged. Under identical2CPU/1GiB packet profiles, each
version completes three500-request loads at100RPS with exact full-marker readback.
CPU/RSS medians are close at this light load; no capacity or speedup claim follows.
Resource sampling now verifies the readiness socket owner, distinguishes watchdog
CPU from work-process RSS, and preserves unavailable memory.peak as null. Early
invalid sampling attempts and one immediate BPF inventory mismatch are retained;
final BPF/tracefs baseline was verified twice, without program detachment. After
hardware changed on recovery, direct ports were reidentified and all temporary
link-UP changes restored to their original DOWN state. Management routes unchanged.
Broader sustained/ramp, packet/queue-loss, eBPF/GUI and full performance parity
remain ongoing. Current physical identity must be re-read before any future run.


## Paginated HTTP acceptance checkpoint - 2026-10-27

The previous1000-row single-result oracle remains unchanged. New
`lab/verify-http-pages.py` removes that retrieval barrier with bounded keyset
pagination, validated lookahead rows, exact sequence/metadata checks, whole-marker
counts before/after each of two full scans and strict offline archive replay.
Linux execution has private exclusive outputs, no proxy/redirects, bounded API
bodies/calls and a wall-clock deadline. Default execution is an offline plan.
All219 lab tests pass, including15 new cases and a synthetic2000-request pair.
Six existing native candidate/reference500-request samples pass live API rechecks:
96 data pages and24 count requests,3000 earlier Sessions checked twice. This
adds no new traffic/rate or CPU/RSS measurement. See README-http-load.md and
`evidence/2026-10-27/http-pagination/summary.json`. Next: real above1000-request
acceptance and repeated matched higher-rate ramps with pinned native binaries,
current hardware identity, resource sampling and exact cleanup. Full parity and
capacity limits remain unproven; two scans are not a transactional snapshot.


A follow-up CI exposed an existing due-timer/cancellation selection race in the
HTTP client. Pre-fix reproduction fails; explicit cancellation checks before/after
the timer and in the worker fix it. All9 top-level/18 Go subtests pass with race;
600 pre-cancelled stress workloads/6,000,000 slots yield zero attempts. Failed CI
and before/after inputs remain private, with a separate cancellation seal. New
binary builds; it has not replaced the earlier live benchmark binary. Exact final
commit CI must pass before declaring this checkpoint remotely validated.


## Real2000-request native workload checkpoint - 2026-10-27

Read README-http-ramp.md and evidence/2026-10-27/http-ramp/summary.json. At200RPS
for10s, the same pinned native candidate95f5e10df and reference8741e924f each
complete three2000-request trials under the unchanged2CPU/1GiB packet profile.
All12000 qualified Sessions pass two exact whole-marker scans before stopping
and two fresh scans after stopping, including complete metadata and report-byte
identity checks. Twelve archives replay offline. Generator source d18bf64b0
includes the cancellation fix and identical binary bits are used at both ends.

The first reference attempt stopped before verifying ingestion and failed at
1894/2000 resources, missing the final106 sequences despite successful client/
server exchanges and exit0. It remains a failed attempt, with diagnostic evidence.
Both pinned stop paths call a one-second sleep then process exit; the exact
pending pipeline stage is unproven. Pre-stop drain coordination avoids this loss
in the qualified matrix but does not fix shutdown reliability. Prioritize bounded
pipeline drain and immediate-stop regression next. Resource windows exclude the
subsequent ingestion drain, so do not claim full per-request CPU cost. No maximum
or sustained capacity, complete packet/queue-drop curves or full parity is proven.

All seven owned Agent/workload lifecycles restored exact Controller YAML and BPF/
tracefs snapshots. Both link leases restored the original source-portDOWN state;
management routes and existing container IDs were retained. Combined1289-entry
private evidence is sealed and backed up on the peer. Publish only aggregates,
source/software hashes and manifest fingerprint; raw identities, markers, SQL,
reports and configuration remain private. Hourly development continues.


## Bounded queued packet-log shutdown checkpoint - 2026-10-27

Core938890898b2d4d502251409f25409f3acb7a74fd replaces the immediate successful
exit with a30s bounded control-thread shutdown. Partial FlowMap batches flush on
exit; the L7 aggregator and senders drain queued batches, and final TCP/file
buffers flush. Zero writes, uncertain partial-frame failures, persistent stalls,
join timeout/panic and known terminal failures cannot silently count as completed drain. Uncertain frames are
not replayed. The existing receive wait remains bounded; see README-agent-shutdown.md
for the precise write/connect/loop bounds and required supervisor grace.

Twelve new regressions pass; exact committed source passes native422+tunnel28+
window21=471 with no failures/ignored tests. Optimized native release, embedded
938 revision, ldd/minimal-runtime probe,10BPF ELF headers and source-clean checks
pass. Existing jattach static Makefile overlay is retained; no Rust source overlay.
Core CI40519977157 passes both jobs, packet459+2rate and219lab/fullServer gates.

At the same200RPS/10s and2CPU/1GiB profile, three old-candidate immediate-stop
controls complete2000 requests but lose389/382/282 tail rows. Three fixed runs
complete all6000 Sessions, post-stop exact scans twice each and byte-bound offline
replay. No ingestion query/wait precedes stop. Both versions use40s termination
grace; fixed clean stops take11.2-12.4s, so10s grace is insufficient. This is not
faster shutdown or full-pipeline CPU cost. Fixed native SHA256 is
`e3f50224010982b7cc5e7cc9bb077ec93e058fabad074aee3176ba7bef4aa50f`.

All controls/failures and raw evidence are private and sealed; anonymous summary:
`evidence/2026-10-27/agent-shutdown/summary.json`. Controller YAML, container IDs/
start times/images/mounts, source link state, management route and BPF/tracefs
baselines are restored. Next: active/incomplete flow and kernel-ring termination,
eBPF/TLS/outage cases, full-pipeline resource windows and sustained higher rates.
This closes the reproduced generated-log tail case; durable ACK/exactly-once,
general shutdown reliability and full DeepFlow feature/performance parity remain open.
