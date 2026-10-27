# Repeated real HTTP loads above the single-query limit

The native candidate and pinned DeepFlow reference each complete three2000-request
loads at200 requests/sec for10 seconds. All12000 qualified Sessions pass exact
whole-marker scans twice before Agent stop and twice afterwards. This advances
the earlier500-request comparison to a real workload above the old1000-row
retrieval bound. It does not establish a capacity ceiling or full parity.

Anonymous samples, bounds and hashes are in
[evidence/2026-10-27/http-ramp/summary.json](evidence/2026-10-27/http-ramp/summary.json).
Raw requests, SQL/responses, hardware/process/container identities, configuration
backups and all unsuccessful attempts remain private and sealed.

## Fixed inputs and scope

The native candidate remains source `95f5e10dfe63c4b5920c8d7932b683fb896a1479`,
binary SHA256 `cbee7383430743230af341a3d28118e4a78bb71f47124e1332509ddd5030ce23`.
The reference remains source `8741e924ff0ae3964a135985c51e5a6ce6bde397`, binary
SHA256 `4bc3b1525ccc444a378552ee11f21d4156646e34f866014d2dd60e7b23e65d80`.
Its two build-only compatibility overlays are disclosed in
[README-reference-compare.md](README-reference-compare.md); no candidate protocol
or eBPF behavior was copied into the reference. Neither native binary was rebuilt
for this experiment.

The fixed Go generator is rebuilt from committed source
`d18bf64b07a70c86f39bbba38877b37663d61f53`, incorporating the pre-cancelled slot
repair. Binary SHA256 is
`69e0fdc43d47c88c2dc6b9f59c3aa32805bb14bf17103b7b268364f3a3aea822`;
identical bits run on both hosts. The dependency-free Go1.26.2 static build uses
`-trimpath`, cached tools and no downloads. Each request opens a fresh TCP
connection;16 requests may be in flight, with1000ms per-request timeout. Paired
reports independently validate every response and scheduled sequence, including
failure/skip counts and recomputed latency percentiles.

Both native versions retain the same packet profile:2CPU quota and affinity,
1GiB,384 PIDs, one explicitly scoped10G direct interface, MTU1500 and an IPv6/TCP
HTTP filter. The same minimal runtime/libraries, read-only root and limited
capabilities apply. eBPF/process input/integrations/profiling/debug remain disabled.
This does not establish complete host metadata isolation. Telemetry still crosses
the management transport, with10Mbit/sec export,1000L7 logs/sec throttle and4096
concurrent-flow limit. No queue/flow/export setting was increased for a pass.
The [upstream tuning guide](https://get.deepflow.io/docs/best-practice/agent-performance-tuning/)
explains that smaller queues reduce burst buffering; matching these limits is
part of the experiment, not proof of production-scale capacity.

Each trial starts a new native process and requires its own readiness listener
and dispatcher startup, followed by12 seconds of warmup. The predeclared order
is reference, candidate, candidate, reference, reference, candidate. All six
trials in this sequence qualify; samples were not selected by favorable latency
or CPU values. There is no new no-Agent control at this rate, so these data do
not isolate the Agent's overhead on application latency.

## Two-phase ingestion gate

1. Stop the finite producer after its2000 verified exchanges. While the owned
   Agent is still running, execute `lab/verify-http-pages.py` into a new private
   preliminary archive. Wait within its90s budget for the full count, then require
   two exact scans. This coordinates drain; it is not stopped-system acceptance.
2. Stop/remove only the receipted Agent, verify its lifecycle/Controller restore,
   then collect a second new archive. Both complete scans must again contain
   exactly the same2000 canonical resources and expected ten-column metadata.
3. Replay both archives offline against the exact paired report-byte hashes,
   expected Agent identity and page size. Missing/extra queries, changed inputs,
   wrong metadata, duplicates, truncated pages or unstable counts fail.

The collector uses the documented
[SQL API](https://get.deepflow.io/docs/integration/output/query/sql/), with sorted
canonical resource keysets and256 consumed rows plus one validated lookahead per
page. Whole-marker counts have no protocol, Agent or observation-point filter.
The expected cardinality is one captured endpoint per request: HTTP20/TCP6,
GET/200/success, Session2, packet signal0 and client observation point. Twenty-four
complete scans use192 data-page requests and88 count requests, including initial
underfilled-count polling. All twelve archives replay successfully offline.
Stable reads do not provide a transactional snapshot or prove future writes
can never arrive.

## Retained immediate-stop failure

Before this sequence, one reference trial completed2000 client/server exchanges
and stopped the Agent without first checking ingestion. Its post-stop count stayed
at1894 through the90s bound. Independent pagination found exactly resources0-1893;
sequences1894-1999 remained absent. NIC error/drop counters did not rise and the
Agent exited0. This failed trial is retained and excluded from the qualified
matrix. It is not evidence that the candidate fixes this behavior: the candidate
was not tested with that immediate-stop procedure.

Both pinned source stop paths call a helper which sleeps one second and exits
the process, without a coordinated pipeline drain at that call site. The exact
stage holding the missing tail is unproven. The two-phase procedure prevents
stopping before the observed records are persisted, but does **not** repair
shutdown delivery. A bounded producer-to-consumer drain, explicit unfinished-
delivery outcome and immediate-stop regression are the next reliability work.
See [KNOWN_LIMITATIONS.md](lab/KNOWN_LIMITATIONS.md).

## Resource observations and limits

Median observed container CPU is0.186364 core-seconds for reference and0.184020
for candidate. Median sampled actual-Agent RSS maximum is122.390625MiB and
122.917969MiB. Client service-P99 medians are1.430289ms and1.448969ms; scheduled-
latency P99 medians are2.451147ms and2.431939ms. Ranges overlap and the three samples
per version do not support an improvement claim.

The CPU window spans client endpoint setup, the10s offered load and endpoint
cleanup (about10.5-10.7s). It excludes startup, warmup and subsequent ingestion
waiting/drain. Flush work outside that window is unmeasured: these are not full
pipeline CPU costs or per-request efficiency numbers. CPU includes the container's
Agent/watchdog/timeout processes; RSS belongs to the verified readiness listener
owner and is sampled100ms. The kernel's missing cgroup memory peak remains null;
sampled RSS/cgroup memory are not exact lifetime peaks. Host IRQ/global CPU are
excluded. HTTP response latency is not telemetry visibility latency.

All twelve qualified endpoint windows have zero NIC error/drop deltas. Exact
Session preservation does not replace full AF_PACKET/kernel and queue-drop
accounting. Sustained ramps, higher rates, loss/reordering, eBPF/TLS/profiling/GUI
behavior, full-pipeline resource costs and complete DeepFlow parity remain open.

Both bounded link leases restore the original source-portDOWN state. All seven
owned Agent/workload lifecycles restore exact Controller YAML and BPF/tracefs
baselines; management routes and existing container IDs are preserved. No unknown
BPF program was detached. The combined1289-entry private manifest includes the
failed attempt and all qualified trials; its archive checksum matches on both
machines. Future runs must re-read current hardware and inventory rather than
reuse historical addresses, interface names or logical registrations.
