# API and libtrace runtime evidence — 2026-10-27

The verified core source is `c91b1a3c5ee61654d3f5ba89b00d689b21f56614`.
The rebuilt Server passes all 13 actual HTTP acceptance cases. Both exact-core
[CI jobs](https://github.com/SuperBigYB/TrafLens/actions/runs/40405314725) pass.

Go gates pass 91 top-level tests and 292 total test-pass events, including nested
subtests. Configuration contributes 53/163, its service 11/36, its router 3/23,
two query packages 17/51, and shared HTTP responses 7/19. All recorded owning
gates use the race detector and default vet, with no failures or skips. The 2048
exact-number oracle vectors are included in the configuration gate. The final
local lab helper suite passes 134 tests. Its last observer cleanup control was
added after the core commit; exact-core CI passes 133 lab tests from its own
committed snapshot. CI also passes the complete packet library and both plugin
crates: 382+28+21=431, with no failures or ignored tests and an exact embedded
source revision. Those Rust counts are separate from the Go pass events.

The earlier Server baseline produced three malformed query responses containing
multiple JSON documents. Its valid aggregate result and independent native
protocol query both counted 40. The first candidate, `f9802bfef`, passed six
cases before the seventh exposed a malformed typed-error JSON envelope with a
missing DATA value. That attempt stopped early and cleaned its temporary
resources. The failed control is retained; it led to the shared response repair.

The first final-candidate observer completed 12 business checks, then failed by
iterating a missing empty-group result. This was an observer defect. The narrow
observer correction accepts an absent empty result while continuing to reject
malformed inventory types. The subsequent complete run passes all 13 cases.
Both database instances retain their lifecycle identities and data mounts.
Temporary configuration/group cleanup, unchanged default configuration and Agent
inventory are verified. Final health shows 161 schema tables, zero registered
Agents, a successful query and no test credential found in Server logs. Only the owned
Server was replaced for candidate acceptance; no Agent collection workload was
introduced by these API tests.

The independent C experiment uses verified native libtrace from source
`62429a607`; it does not run the complete Agent. It loads 81 BPF programs,
attaches 30 links and completes 20 synthetic loopback TCP exchanges. Hooks are
system wide. Map readbacks confirm all ports bypassed, all protocols disabled
and an empty allow bitmap. Payload callbacks remain zero, and the callback does
not dereference payload. Stop removes all links and restores the program
inventory without changing tracefs. This establishes bounded library load,
attach and detach behavior with payload bypass. It does not establish a process
filter, payload collection, Agent ingestion or sustained performance.

Only aggregate counts and code/artifact hashes are public. Detailed failed and
successful controls, raw HTTP, configuration, identities and environment records
remain ignored locally. No new captured traffic is published. See the
[API guide](../../../README-api-validation.md) and
[libtrace guide](../../../README-ebpf-runtime.md) for operator scope. Full feature
and performance parity with DeepFlow remains unfinished.
