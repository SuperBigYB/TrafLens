# TrafLens mainline roadmap

Priority set by the user on 2026-10-28: build the usable product backbone first;
defer nonblocking details and progressively optimize the recurring work plan.
This roadmap takes precedence over next-step suggestions in historical evidence.

## Current foundation

Native Agent and community Server build; the owned two-machine lab validates
packet HTTP collection, storage and exact queries. The latest stable profile
passes a healthy2000-request trial and an unavailable-data-port failure control.
M1 and the finite scoped HTTP slice of M2 now provide a working product
foundation; M6 adds the finite packet DNS/MySQL product gate; full DeepFlow parity is not validated. Retain the recorded evidence without repeatedly
requalifying it when unrelated work changes.

## Milestones in priority order

1. **Usable minimum product (completed functional gate, 2026-10-28).** Provide a reproducible deployment/start
   entry point and a minimal real-data console: Agent status, traffic/service
   overview, request list and request detail. Reuse the existing APIs and lab.
   Acceptance: a fresh bounded workload on the two hosts is visible through the
   product entry point, with usable filtering and a drill-down to real records;
   document how to start and access it. Do not substitute mock data for this gate.
2. **Core eBPF ingestion (HTTP, finite TCP DNS M13, MySQL M14/M15 and single-peer UDP DNS M16 slices complete).** Complete managed eBPF capture through ingestion and
   query for the core HTTP/DNS/database scenarios, then extend TLS coverage.
   Acceptance: known real requests appear with the correct protocol and source
   metadata under a repeatable setup. Carry blocking collection fixes here.
3. **Topology and request tracing (M3 relationships complete; M4 Trace ID correlation and M10 explicit SDK Span gate complete; M11 finite no-Header evidence lifecycle gate complete).** Connect resource/service identities to
   service relationships and per-request paths, exposed in the console.
   Acceptance: a small multi-service scenario can be followed from a service
   dependency to its requests and associated spans/records.
4. **Metrics, profiles and resource correlation (M5 service RED slice complete; M7 current Agent resource slice complete; M8 time trends complete; M9 finite self-profile lifecycle/query/console functional gate complete).** Add useful metric views,
   continuous-profile entry points and host/container/Kubernetes associations.
   Acceptance: each implemented signal can be queried and navigated from the
   relevant service or resource in an actual scenario.
5. **TCP/network observations (M12 finite functional gate complete).** Provide bounded native packet L4 reports, actual close-code/counter/RTT semantics and exact same-flow HTTP navigation. Three real owned socket outcomes and outside-filter controls pass the public lifecycle, independent raw comparison and actual browser. This does not establish physical10G performance, loss-free capture or eBPF/packet identity interchangeability.
6. **Sustained performance and parity gaps.** With the main workflow usable,
   compare pinned implementations under matched resources and representative
   sustained workloads; improve the measured bottlenecks and remaining features.
   Retain correctness and loss measurements alongside throughput/resource cost.

Dependencies may change this order, but each iteration should deliver a vertical
product slice or remove a direct blocker to the active milestone. Existing
upstream source alone is not completion. Keep source/build/runtime/benchmark
qualification distinct. Preserve upstream licensing and attribution.

## Active M17: one UDP DNS server socket, two-client transaction isolation

M16 is closed and M17 is the sole active milestone. **M17-01 is next.** The
same-server-FD peer/key concern is still source-derived; no real multi-peer failure
or repair has been established. First obtain the smallest actual reproduction.

Use one owned UDP DNS server socket and two real client ports in the existing
strict namespace. First send one exchange from each port with different TXIDs;
then interleave one from each with the same TXID. Four fresh exchanges with
controlled success/error replies exercise peer and transaction isolation. All
wire and actual peer/tuple/PID/TID/socket-generation identities remain independent
oracles; qnames, neighboring timestamps or a16bit TXID alone cannot create an
association. An initial conflict, missing response or orphan stays a failure.

1. **M17-01 - actual identity and minimum plan.** Inspect current native input,
   flow/session/log keys, real peer/direction fields and TXID scope; define the
   smallest safe fixture and exact whole-population contract. No fix is preselected.
2. **M17-02 - real reproduction (depends on01).** Run four fresh positive exchanges
   and a bounded outside-scope control. Retain every actual wire/tuple/process
   receipt and complete population, including tuple conflicts, orphans and excess
   records. Separate original input facts from later flow/session/store behavior.
3. **M17-03 - evidence-led direct repair (depends on02).** Localize any observed
   identity/transaction failure and change only its blocking layer with meaningful
   bounded regressions. If no failure reproduces, document the finite positive
   result rather than inventing a patch. A necessary new native build must have
   real committed source, a production release ELF/version/hash and minimum actual
   scope ABI/FD/map qualification; a test ELF or old artifact is not a substitute.
4. **M17-04 - product acceptance (depends on03).** Read two complete unchanged raw
   populations and prove the expected eight source3 observations for four real
   exchanges, exact per-peer/TXID identities, bounded API/details and actual
   restricted Edge navigation. Keep controlled error, outside-scope and source
   controls explicit; no filter may conceal tuple conflicts or orphan records.
5. **M17-05 - repeatable delivery (depends on04).** Provide default-offline public
   prepare/run/verify/stop, exact owned-resource/config/network/BPF restoration,
   anonymous evidence and independent verification of both repository pushes.
   Only after this gate closes select one further milestone.

Keep normal kernel licensing, DNS-only18080 and the exact owned namespace scope;
AF_PACKET/proc/onCPU/DWARF/profile/OTLP stay closed. Preserve unrelated services and
all historical failures. Do not expand asset discovery, performance searches,
protocols or unrelated kernel/HTTP/MySQL/OTLP matrices. Follow the local
file-driven, mainline-first half-hour plan.

## Closed M16: finite single-peer UDP DNS

The finite single-peer UDP DNS raw/API and actual console gates now pass. R31's
specific authorization allowed the retained R25 acceptance result to be reviewed
without new capture: six source3 Session observations, UDP17/L7 DNS120, three
positive/three outside exchanges, outside0, source0/4zero, two whole-marker and
two unfiltered Agent/time populations, wire/host PID/TID/tuple checks and six
exact API details in25data requests.

Restricted actual Edge navigation passes six details, four normal/two NXDOMAIN
observations and source0/4 empty controls with page errors0. Its29data requests
stay in scope; seven initialization API calls are blocked, with no out-of-scope
or fabricated requests. Full metadata is not persisted on the workstation.
The earlier pre-query oracle declaration failure, its source and the explicit
planned-source archive repair bridge remain history; no failed result is relabeled.

The prior74targeted/offline checks, public typed entry, real C fixture and original
execution/stop evidence remain recorded. Final recovery/resource checks pass:
all temporary Query/forward resources are stopped and original Server/config/
Controller baselines are unchanged. Qualification delivery commit
`bd5c659e8886a352f8430c670d652969323e5af4` was verified on both repository main refs.
M16 is closed. Its single-peer limit remains; this does not establish multi-peer
correctness, general UDP compatibility or performance. See
[the finite qualification](evidence/2026-10-29/udp-dns-qualified/README.md).

## Historical M15 completion and selection of M16

The real new Agent e1daf16b1/0544bd9c passes actual scope/merged configuration,
public unpaced lifecycle, independent complete18Session/marker12/query6/QUIT6/
outside0 raw/API and actual headless Edge details. The bounded native repair is
supported by R22 disorder and R23 native replay; the R24 live input itself was
ordered, so it is not live evidence of disorder correction or loss-free generality.
All earlier failures remain unchanged and all temporary resources were restored.
See [the finite qualification](evidence/2026-10-29/fast-mysql-qualified/README.md).

After M15 synchronization, M16 was selected for **managed eBPF UDP DNS query/error
navigation**. M13 had established TCP-only DNS; ordinary UDP collection was still
unproven at that selection. The following gates describe M16's finite scope:

- M16-01 passes native/source and minimum single-peer scenario checks: actual UDP
  syscall/input/inference/parser, fields/units, profile/license and strict FD/map
  readiness. No new native change/rebuild is required for this slice.
- M16-02 passes real bounded UDP success/error and outside-scope capture with
  independent wire/process/tuple identities and the complete source3 population.
  TCP, packet source0, synthetic ingestion and ACKs are not substituted.
- M16-03 passes reused bounded protocol/source/error/detail APIs and console;
  counts/transactions/time and flow-scoped16bit TXID semantics stay explicit.
- M16-04 passes independent two-host raw/API positive-negative and actual restricted
  browser checks without filters hiding unsupported or orphan observations.
- M16-05 passes public prepare/run/verify/stop, final resource/restoration checks
  and dual-repository qualification delivery at
  `bd5c659e8886a352f8430c670d652969323e5af4`. M16 is closed.

The e1daf artifact was built and qualified for M15's finite MySQL path/scope;
M16 adds this finite single-peer UDP gate without rebuilding it. Older protocol
gates remain historical. Do not rerun unrelated HTTP/OTLP/profile/L4/performance
matrices. Keep onCPU/DWARF/proc/profile/OTLP disabled and normal kernel licensing;
never widen to management traffic/unrelated processes or use the Controller DB
as a workload. The local file is the execution authority.

## Recurring execution policy

- Run every30 minutes in the existing task; inspect current repository state before work.
- Select one concrete unfinished acceptance point from the active milestone.
  Implement, perform checks proportionate to the change, commit and sync both
  repositories. Avoid multiple unrelated microtasks in one iteration.
- Fix data correctness, permission boundaries and failures that prevent the
  core demonstration. Record other edge cases as deferred work and move on.
- Do not repeatedly run the same microbenchmark, archive regeneration, rare
  shutdown scenario or formatting cleanup after sufficient checks have passed.
- After a milestone or three iterations, review actual progress, dependencies
  and the next acceptance point. Update this roadmap and STATE; adjust the
  existing automation instructions when the phase changes, without creating
  duplicate tasks or silently changing hosts, remotes or cadence.
- Report a meaningful milestone, blocker or required human action. Ordinary
  unchanged heartbeat results remain quiet. Never claim full parity from a
  narrow functional sample.

## Deferred unless they block the active milestone

Broader incomplete-flow shutdown and unread-kernel-ring cases; rare teardown
failures; deeper explanations of historical invalid samples; repeated archive
sealing; fine-grained CPU/RSS tuning and maximum-rate searches. Preserve existing
failure records and revisit these systematically during reliability/performance
work rather than letting them displace the product backbone.

## Historical selection after M10: M11 finite no-header eBPF HTTP association

M1-M10 now cover real request exploration, scoped eBPF HTTP, service relationships,
explicit W3C Trace lookup and SDK Span parents, RED, packet DNS/MySQL, current
Agent resources, trends and a finite self-profile lifecycle. After both main refs
match M10, the local plan activates only M11. The next core gap is correlation
without application Trace headers; this does not require redoing the completed
OTLP or profiling gates.

M11 first inspects the native AutoTracing/query implementation, actual eBPF L7
kernel/request/socket identifiers, supported bounded scope and API limits. Choose
one finite owned synchronous HTTP chain without traceparent/tracestate/SDK export,
with an independent app execution oracle and unrelated traffic control. Reuse the
qualified native scoped HTTP runtime; keep onCPU/DWARF disabled and do not broaden
capture to unrelated processes. Display only the associations supported by actual
identifiers, with evidence/ambiguity/missing observations explicit. Equal URL,
shared time or a made-up Span ID cannot prove causal association.

M11-01 actual identifiers/native engine/scope -> M11-02 finite no-header real
capture and full source3 population -> M11-03 bounded association API/evidence ->
M11-04 actual console/independent two-host positive-negative acceptance -> M11-05
public lifecycle/restoration/dual sync. Qualification is this finite slice, not
all-language asynchronous AutoTracing or full causal coverage. Larger protocol,
asset, language, reliability and matched performance work remain future work.
The unexplained early profile writer failure remains an explicit reliability
follow-up. Keep the one-active-milestone/file-first half-hour workflow.

## Next single milestone after M11 dual-sync: M12

M11's public finite source3 headerless capture/verify/stop gate is complete. The
next product backbone slice is TCP connection observation and network-problem
navigation, using actual L4 flow/metric records and known units/counting scope.
First verify existing native input/schema/safe collection and choose one bounded
owned scenario. Then implement fixed bounded connection/API/detail views and
only supported request links; prove normal/failing cases against independent
socket/application evidence in the two-host pipeline, actual browser and public
recovery. Missing records, unsupported metrics and upstream failure stay distinct.

No unproven L4/source/flow-ID equivalence or broad management-interface collection
is authorized by a field name. Reuse qualified inputs where supported, keep one
active milestone and defer old protocol/kernel/performance matrices. The local
file becomes M12-active only after both repository refs match M11's delivery.

## Next single milestone after paced M14 synchronization

M14 qualifies only the100ms-paced finite MySQL wire product loop. The original
unpaced17-versus18 failure remains open and has priority over protocol expansion.
M15 will collect bounded actual kernel/input/queue/parse/session/writer evidence
for the same owned three-conversation case, localize missing or misordered
events, implement the direct bounded fix and verify unpaced complete populations,
negative scope, exact details and actual browser before delivery. Do not claim
that waits or a no-op reorder configuration solve native reliability. Preserve
all original failures and stop/restoration boundaries; no host-wide tracing,
profile/stack collection or unrelated benchmark matrix is needed for this task.
