# TrafLens mainline roadmap

Priority set by the user on 2026-10-28: build the usable product backbone first;
defer nonblocking details and progressively optimize the recurring work plan.
This roadmap takes precedence over next-step suggestions in historical evidence.

## Current foundation

Native Agent and community Server build; the owned two-machine lab validates
packet HTTP collection, storage and exact queries. The latest stable profile
passes a healthy2000-request trial and an unavailable-data-port failure control.
M1 and the finite scoped HTTP slice of M2 now provide a working product
foundation; full DeepFlow parity is not validated. Retain the recorded evidence without repeatedly
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
3. **Topology and request tracing (M3 service relationship slice next).** Connect resource/service identities to
   service relationships and per-request paths, exposed in the console.
   Acceptance: a small multi-service scenario can be followed from a service
   dependency to its requests and associated spans/records.
4. **Metrics, profiles and resource correlation.** Add useful metric views,
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

## Next milestone after M2 delivery: M3 service relationships

M1 and M2 functional gates pass: real-data console plus publicly repeatable,
bounded namespace-scoped eBPF HTTP startup/readiness/ingestion/UI/cleanup. See
README-managed-http-runtime.md and the dated managed-runtime evidence. Complete
both remote synchronizations before closing M2 in the authoritative local plan.

Then activate only M3: real service relationships and request drill-down. Reuse
stored L7 data and the console. First confirm available client/server/resource
fields and counting semantics; provide a fixed aggregate API and service view;
click a real service relationship to open requests with the same filters and
exact-ID details. Verify a small two-host scenario with at least two identifiable
service endpoints. Clearly label observation records; do not infer unrecorded
spans or claim complete distributed tracing from a topology view.

DNS/database/TLS eBPF expansion and sustained performance remain subsequent
work. Do not reopen completed milestones for styling or repeat their full
kernel/benchmark matrices. The local execution file controls task breakdown.
