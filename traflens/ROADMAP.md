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
2. **Core eBPF ingestion (HTTP and finite TCP DNS M13 gates complete; further protocols deferred).** Complete managed eBPF capture through ingestion and
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

## Next single milestone after M13 synchronization

M13 completes the finite managed eBPF DNS/TCP product slice with strict raw,
actual-browser and public-restoration gates; UDP/encrypted/general DNS remain
unqualified. M14 selects managed eBPF MySQL request/error navigation: inspect
actual native parser/handshake/cache/port support and exact scope first, then
finite real owned wire execution with independent oracle, complete source3
population, existing API/detail/error navigation, public stop and both refs.
Do not treat M6's packet MySQL fixture or source availability as eBPF acceptance.
No Controller database or unrelated service is a workload target. Preserve one
active milestone and defer nonblocking compatibility/performance matrices.
