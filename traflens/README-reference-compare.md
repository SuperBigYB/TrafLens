# Pinned native reference and matched low-load observations

This checkpoint compares a pinned upstream community Agent with the TrafLens
candidate under the same finite packet-mode HTTP profile. It qualifies the
reference build, exact collection and resource measurement method. It does not
establish maximum throughput or complete DeepFlow parity.

## Reference provenance

- Upstream source: `8741e924ff0ae3964a135985c51e5a6ce6bde397`.
- Candidate native source: `95f5e10dfe63c4b5920c8d7932b683fb896a1479`.
- Both use Rust1.97.1 and GCC11.2.1 in the fixed DeepFlow SDK image
  `ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310`.
- Reference binary SHA256:
  `4bc3b1525ccc444a378552ee11f21d4156646e34f866014d2dd60e7b23e65d80`.
- Candidate binary SHA256:
  `cbee7383430743230af341a3d28118e4a78bb71f47124e1332509ddd5030ce23`.

The pristine upstream `--offline --locked` build fails because its lock is
inconsistent with declared dependencies. The published
`evidence/2026-10-27/reference-compare/native-build-compat.patch` changes only
`agent/Cargo.lock` and `agent/crates/public/build.rs`: lock synchronization with
the already-declared pcap-sys dependency, and synchronous formatting limited to
generated protobuf files. It does not transplant HTTP, session, eBPF or other
candidate runtime fixes. The earlier packet-only app_table cfg overlay is not
applied. This is a pinned upstream **with disclosed build compatibility changes**,
not an unmodified official binary.

The reference source and3.3GiB compilation cache were copied into independent
directories. Candidate source/cache and sealed artifacts were not changed.
Dependencies and toolchains were mounted read-only; the build had no network,
all capabilities dropped, a read-only root,2 CPUs,8GiB and512 PIDs, and a1800s
hard timeout with10s grace. The successful native build embeds the exact upstream
revision. Both binaries passed version/ldd checks with the same minimal runtime
image and shared libraries, without starting collection. An existing linker
warning about a C source archive member is retained in the private build log.
See the [upstream build guide](https://github.com/deepflowio/deepflow/blob/main/agent/build.md)
for the native prerequisites; the pinned SDK digest and bounded execution above
are the qualified environment for this checkpoint.

## Placement, load and acceptance

After the source machine recovered, hardware/interface identities differed from
the earlier run. Four initially down, unaddressed standalone high-speed ports
were temporarily enabled for identification. Two paired10G links were proven
with scoped IPv6 replies; unused ports were restored immediately. The benchmark
uses one reidentified link, MTU1500. The prior hardware's network-capacity result
is not reused as a capacity measurement of this hardware. All four ports were
restored to their original administrative DOWN state after trials, with management
IPv4 routes unchanged. Raw device identities and pairing receipts remain private.

Both versions run on the same source host, CPU affinity0,1, quota2 CPUs,1GiB and
384 PIDs. They use the same native libraries, host network, private PID namespace,
read-only root, NET_RAW/SYS_RESOURCE only,240s lifetime plus10s grace, and identical
Controller YAML. eBPF, integrations, profiling/debug and process input are disabled;
complete host-metadata isolation is not established. The existing packet smoke
queue/flow limits,1000/s request-log throttle and10Mbit/s export limit are retained.
HTTP load travels over the10G direct link; telemetry retains its management-network
transport. These settings do not qualify10G ingestion/export throughput.

The [bounded workload](README-http-load.md) offers100 requests/sec for5seconds,
500 distinct fresh-connection GET requests, concurrency16 and1s request timeout.
Each version has three independent Agent processes, ordered reference/candidate/
candidate/reference/reference/candidate. No cache flush or frequency/governor
change was made. Each pair validates all client responses and server counts.
The ordinary strict request oracle reads the exact rows twice. After collection
stops, two additional whole-marker queries, without protocol/Agent/source filters,
require the exact500 paths, GET/200/success, HTTP20/TCP6, Session type2, packet
source0, client observation point and the expected logical Agent. All six final
loads pass with no skipped/failed client slots or missing/duplicate query rows.
This does not imply every packet/queue counter is loss-free.

The two hosts' wall clocks differ by about180s. Workload/resource intervals use
single-host monotonic time. Fresh source-stop proofs bind a new control-host
timestamp/nonce, rather than relaxing the freshness bound or changing host clocks.
Cross-host telemetry delivery latency is not measured.

## Resource tools and observed scope

`lab/sample-agent-resources.py` defaults to an offline plan. Explicit execution
requires an exact benchmark-container ID, a private new report path and1–30s.
It checks the purpose label, resource limits, cgroup membership path and Agent
process tree. The actual readiness-listener owner identifies the business Agent;
tree position alone is insufficient because this version's watchdog is a child.
PID/parent/start-time identities and listener ownership must remain stable.

```sh
python3 traflens/lab/sample-agent-resources.py  # offline plan
python3 traflens/lab/sample-agent-resources.py --execute \
  --container-id "$OWNED_BENCHMARK_CONTAINER" --seconds 6 --output "$NEW_PRIVATE_RAW"
python3 traflens/lab/verify-agent-resources.py \
  --sample "$NEW_PRIVATE_RAW" --output "$NEW_ANONYMOUS_METRICS"
```

Cgroup-v2 CPU includes the Agent, watchdog and timeout process. It excludes
unattributed host IRQ/other-host CPU costs. VmRSS is sampled every100ms from the
verified business process, excluding the watchdog. The measurement window starts
before client endpoint setup and ends after its cleanup, so it is slightly wider
than the5s offered load. CPU seconds are not pure per-request attribution.
The verifier recomputes units, rates and sampled maxima; rejects identity failures,
wrong scope, nonfinite/coerced numbers, time gaps and CPU-accounting inconsistencies.

This kernel does not expose cgroup `memory.peak`; it is explicitly unavailable/null.
Sampled process RSS and sampled cgroup memory maximum are separate quantities and
are not substituted for an exact lifetime peak. Shared-page charging means cgroup
memory can differ from process RSS.

For these three samples per version, median CPU observation is0.055028 core-seconds
for reference and0.056417 for candidate; median sampled Agent RSS peak is115.7305MiB
and115.7344MiB respectively. Client service P99 medians are1.5931ms and1.6004ms.
The small differences and overlapping ranges do not support a speedup claim.
The workload is far below a demonstrated capacity ceiling. Higher repeated ramps,
matched export/queue limits, sustained traffic, full packet/queue-loss accounting,
eBPF/application/GUI behavior and query scaling remain separate gates.

## Retained failures and cleanup

Six initial attempts emitted no HTTP because sampling incorrectly required one
Agent PID. Six subsequent loads passed request acceptance but their resource
reports failed: optional `memory.peak` was absent and RSS had been selected by
tree position. Those records are preserved and not used as qualified resource
samples. The final six loads use listener ownership and explicit unavailable
counter handling; all metrics pass independent verification. All18 attempts are
retained, with selection based on these stated validity checks, not speed.

One final reference trial's immediate post-removal BPF inventory differed by one
ID. The original failed snapshot and first unsuccessful later recheck remain.
Two subsequent global reads exactly matched the original BPF/tracefs baseline,
without detaching a program. The transient ID's attribution is unproven; immediate
per-trial cleanup is not described as uniformly passing. All owned Agent/workload
containers are removed, exact Controller YAML restored, existing databases and
other containers preserved. The public summary contains anonymous samples,
source/software/patch hashes and a private-manifest fingerprint. Raw programs,
PIDs, namespaces, hardware/network identities, run markers and API responses stay
in private sealed evidence.
