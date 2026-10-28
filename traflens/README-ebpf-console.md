# Managed eBPF HTTP to console

The current mainline slice reuses native `3dec20af5` and the existing controlled
C syscall HTTP fixture. It is a real kernel-to-Agent-to-Server-to-browser path;
packet dispatch is disabled. Existing scope/HTTP inference foundations are in
[managed oracle](README-managed-ebpf-oracle.md) and
[cold first-record inference](README-ebpf-http-first-record.md).

The pinned positive namespace is distinct from the negative namespace. Before
traffic, the coordinator checks the Agent-owned namespace FD, reads only the
new owned tracer scope configuration, verifies the namespace match, waits for
actual collector/policy readiness and confirms absence of Agent AF_PACKET
sockets. No stdout datadump, prewarming or skipped first exchange is used.

Twenty positive exchanges require40 Sessions: one client and one server process
observation per resource. Forty negative exchanges across10/20/10 phases must
produce zero marked rows. The whole-marker oracle has no source/Agent/status
filter hiding mismatches, preserves UInt64 identity and requires two passing
reads. The qualified trial meets the full contract with the current native
binary. Its hard lifetime is180s plus40s kill grace, total at most220s, within
the existing worker lease. Config/worker/Agent cleanup and BPF/tracefs restoration
pass. No physical test-interface change is needed for this scoped loopback case.

The console source selector exposes the actual source metadata. After selecting
a time range and resource marker, choose eBPF to inspect its40 rows and total;
open details to confirm source3 and process observation. Choosing packet source
for that same marker shows zero. This full UI interaction is checked with real
headless Edge; source filters also apply to protocol drill-down. Counts are
observation records and are not deduplicated transaction counts.

[Anonymous evidence](evidence/2026-10-28/ebpf-console/summary.json) records the
finite result. Raw markers, process IDs, namespace identities, maps and queries
stay private. This does not qualify arbitrary processes, TLS, profiling, other
kernels or maximum performance.

## Portable profile/bootstrap preparation

`lab/managed-http.py` now replaces the private configuration-generation step.
It has no Controller write, Docker, namespace or BPF action. With no arguments
it prints a read-only plan. Preparation takes explicit literal IPs and a
Controller group SHORT_UUID; it does not embed a development-machine identity
or reuse a historical registration receipt.

```sh
python3 traflens/lab/managed-http.py
install -d -m 700 .traflens/work/managed-http
python3 traflens/lab/managed-http.py prepare \
  --output "$(pwd)/.traflens/work/managed-http/prepared" \
  --controller-ip "$CONTROLLER_IP" --controller-port "$CONTROLLER_PORT" \
  --ingester-ip "$INGESTER_IP" --ingester-port "$INGESTER_PORT" \
  --group-id "$GROUP_SHORT_UUID" --http-port 18080
```

The POSIX output parent must be private and owned. The new output directory
is mode0700; its files are mode0600 and are never overwritten:

- `group-profile.json`: HTTP-only inference; AF_PACKET interface empty; eBPF
  socket kprobe enabled; process collection, Go/TLS uprobes, IO events, profiling
  and integration disabled. Integration leaves remain explicit across license
  allocation. Resource/queue settings match the previously qualified trial.
- `bootstrap.yaml`: JSON-valid YAML with chosen Controller/group, bounded worker
  count, fixed container log/state paths and mandatory namespace scope target
  `/run/traflens/target.netns`. It contains no host-specific namespace path.
- `manifest.json`: hashes/lengths and outstanding startup requirements. Its
  `runtime_qualified` flag is false; preparation never means capture is running.

Default Controller/data ports are30035/30033; supply the actual environment's
ports. Omitted ingester IP follows the Controller IP. A custom HTTP port updates
both the inference prefilter and otherwise-disabled packet filter. IPv6 literal
serialization is tested; it is not a new IPv6 runtime qualification. Files are
JSON-encoded, so address/group values cannot add YAML directives.

The full lab suite passes228 tests (eight new preparation cases). Actual
prepared output equals the profile of the qualified managed trial and passes
the running community Controller's template check without modifying it. No
Agent, workload or backend was restarted for this preparation-only validation.
See [preparation evidence](evidence/2026-10-28/managed-preparation/summary.json).

## Portable runtime delivery

M2-05b/c now provide the public [bounded runtime entry](README-managed-http-runtime.md):
explicit artifacts and Controller readback, a held namespace lease, start,
actual collector/FD/map readiness, finite HTTP phases and exact stop/release.
No historical private startup script or namespace-probe receipt is required.

One necessary fresh two-host trial through these public tools passes the same
20-positive/40-negative contract:40 source3 Sessions, two strict whole-marker
reads, no negative rows, real Edge list/overview/details and no packet-source
rows. The Agent exits0; namespace pins release only after Agent/BPF restoration,
Controller YAML restores exactly, and console/forwarding stop.236 lab tests pass.
See [runtime evidence](evidence/2026-10-28/managed-runtime/summary.json).

This closes the finite scoped HTTP product delivery gate. DNS/database/TLS,
other kernels and performance parity remain future work. The next product
milestone is real service relationships and request drill-down, as described
in [ROADMAP.md](ROADMAP.md).
