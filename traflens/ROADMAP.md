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
2. **Core eBPF ingestion (HTTP gate complete; protocol expansion deferred).** Complete managed eBPF capture through ingestion and
   query for the core HTTP/DNS/database scenarios, then extend TLS coverage.
   Acceptance: known real requests appear with the correct protocol and source
   metadata under a repeatable setup. Carry blocking collection fixes here.
3. **Topology and request tracing (M3 relationships complete; M4 Trace ID correlation complete).** Connect resource/service identities to
   service relationships and per-request paths, exposed in the console.
   Acceptance: a small multi-service scenario can be followed from a service
   dependency to its requests and associated spans/records.
4. **Metrics, profiles and resource correlation (M5 service RED slice complete; M7 current Agent resource slice complete; M8 time trends complete; M9 finite self-profile lifecycle/query/console functional gate complete).** Add useful metric views,
   continuous-profile entry points and host/container/Kubernetes associations.
   Acceptance: each implemented signal can be queried and navigated from the
   relevant service or resource in an actual scenario.
5. **Sustained performance and parity gaps.** With the main workflow usable,
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

## Next after M9 delivery: M10 explicit cross-service Span causality

M1-M9 now cover real request exploration, scoped eBPF HTTP, service relationships,
explicit W3C Trace correlation, RED, packet DNS/MySQL, current Agent resources,
trends and a finite Go self-profile product lifecycle. M9 is closed only after
both repositories match the accepted delivery; the authoritative local plan then
activates only M10. First inspect the existing OTLP/Span receiver/decoder and
actual stored source, trace/span/parent fields; choose one small strictly owned
supported path rather than assuming source presence means product support.

M10 should connect actual instrumented requests across two owned services into
recorded explicit parent/child Span relationships and a bounded console view.
Use finite real HTTP work and real measured Span boundaries, with independent
expected IDs/parents and an unrelated Trace control. Expose only proven edges,
including missing parents, duplicate observations and inconsistency states; time
order or equal Trace ID does not establish causality. Do not relabel this as
headerless AutoTracing. Keep receiver exposure isolated, restore temporary
registrations/processes/configuration, and deliver public reproduction/stop and
actual two-host/API/browser evidence before closing the milestone.

M10-01 actual schema/source/scope -> M10-02 bounded real instrumented Span
population -> M10-03 exact query and explicit graph -> M10-04 actual console
navigation/positive-negative acceptance -> M10-05 public restoration/dual sync.
More eBPF protocols, independent assets, all-language profiles, headerless tracing,
matched peak performance and the unexplained early profile writer failure remain
later work unless they directly block this slice. Do not rerun completed matrices.
