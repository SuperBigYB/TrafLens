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

## Remaining M2 delivery gate

The established coordinator is still a private prepared workflow. M2 is not
closed by this runtime success alone. The next step is a reusable scoped
managed-Agent startup/stop entry point and complete reproduction instructions,
reusing the current contracts instead of constructing another kernel test
matrix. Then verify that entry point, record delivery and close M2.
