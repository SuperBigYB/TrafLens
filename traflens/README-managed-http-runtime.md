# Bounded managed HTTP runtime

This is the public startup, readiness and stop interface for the managed eBPF
HTTP slice. It reuses the reviewed namespace supervisor and scope-map proof,
with explicit paths and immutable runtime artifacts. No historical development
directory, machine address, registration receipt or namespace-probe file is
required. Every executable defaults to a read-only plan; mutations require
`--execute`. These tools never write Controller configuration or pull images.

## Prerequisites and configuration

Use the existing isolated Server deployment and a dedicated group with exactly
one explicitly registered, enabled, stopped Agent. Registration and group
configuration use the normal Controller API/UI. Keep unrelated groups/services
unchanged. Agent licenses must include functions2/4/5; disable integration in
the profile rather than relying on a temporary license omission. The launcher
reads the actual group, membership, Agent ID and profile before starting and
again before approving traffic. An absent/mismatched registration fails closed.

The qualified environment is Linux x86_64 with Docker, bpftool, Python3, BTF and
mounted debugfs/tracefs; the measured kernel is5.15. Use a native build containing
the scoped socket collector, cold first-record inference and bounded shutdown
changes. The measured binary is native `3dec20af5`, SHA256
`8dd5ec668a09dcdac10068727fb47f282cf8091a93a11fb71cbbc33db3853763`.
Other builds/kernels need their own qualification. No Rust rebuild is needed
when reusing that verified artifact.

First run [profile preparation](README-ebpf-console.md#portable-profilebootstrap-preparation).
Use HTTP port18080 for this finite fixture. Save the dedicated group's original
YAML **byte for byte**. With its Agent stopped and identity checked, apply the
generated `group-profile.json` using the Controller's
`PUT /v1/agent-group-configuration/{group-lcuuid}/yaml` endpoint (JSON is valid
YAML). Check `OPT_STATUS=SUCCESS` and GET that endpoint back; its decoded content
must equal the prepared profile. Retain the original, applied and read-back
documents privately. Do not use the older machine-specific packet helper to
configure this workflow. After stopping, compare the current profile with the
applied document before restoring the saved original; then GET and compare the
original YAML bytes. A mismatch requires investigation before further writes.

The read-only Controller API argument is a loopback origin such as
`http://127.0.0.1:24017`. For a remote Controller use an explicitly bound SSH
forward to its loopback API. No proxy or redirect is followed. API headers use
the existing isolated lab's organization/user1 contract; this is not a public
multi-tenant deployment or an authentication provisioner.

Place the following in a private runtime directory, with regular root-owned
artifacts that cannot be written by other users:

```text
runtime/
  prepared.json             # mode0600, explicit artifact manifest
  deepflow-agent
  libs/libz.so.1
  libs/libstdc++.so.6
  libs/libgcc_s.so.1
```

`prepared.json` must contain `source` (full40-hex commit), `binary_sha256`,
`image_id` (cached immutable `sha256:...` ID), and `libraries` keyed by exactly
those three filenames, each with its `sha256`. Obtain hashes from the verified
build/package, not from an untrusted download. The image supplies compatible
glibc and `/usr/bin/timeout`; the Agent/libraries are read-only bind mounts.
The tools validate actual bytes and exact cached image identity. This manifest
binds inputs; it does not itself prove a new binary's runtime correctness.

## Prepare a held namespace lease

Build the synthetic C traffic executable using the commands in
[namespace runtime](README-ebpf-netns-scope.md#reproducing-the-bounded-gate), including
`GATE_TRAFFIC_ONLY`; its reviewed SHA256 is
`1882c6fa3b5c3a18afb4b32c401044f86e750cb671870a2d81f472e8306c212f`.
The supervisor rejects an artifact with another hash. Reuse a verified binary
when available. Set all variables below to canonical absolute private paths;
`WORK` is a new mode0700 directory for this run. `IMAGE_ID` is the same cached
compatible image used by the runtime manifest. No host network port is changed.

```sh
python3 traflens/lab/managed-http-agent.py
python3 traflens/lab/managed_http_workload.py
install -d -m 700 "$WORK" "$WORK/runs"
python3 traflens/lab/managed_http_workload.py prepare --execute \
  --work "$WORK/runs" --traffic-bin "$TRAFFIC_BIN" --image "$IMAGE_ID"
```

Run the last command in a dedicated terminal/session and retain its output. It
creates two owned private network namespaces and emits a ready message naming
the new `LEASE` directory. It sends **no HTTP**. Inspect `LEASE/lease.json`:
status must be `ready_waiting_root_commands`; record the positive pin and inode.
The root supervisor holds both namespace FDs through the Agent lifetime. The
lease is360s with a60s cleanup allowance; worker hard alarms are240s. The Agent
must start while more than240s of lease remain. Do not recycle a lease or detach
its supervisor. Expiry alone is not successful cleanup.

## Start, prove readiness and send finite traffic

```sh
python3 traflens/lab/managed-http-agent.py start --execute \
  --work "$WORK" --prepared "$PREPARED" --artifacts "$RUNTIME/prepared.json" \
  --lease "$LEASE" --controller-api "$CONTROLLER_API" --agent-id "$AGENT_ID"
python3 traflens/lab/managed-http-agent.py ready --execute --work "$WORK"

for phase in before mixed after; do
  python3 traflens/lab/managed_http_workload.py phase --execute \
    --lease "$LEASE" --phase "$phase"
done
```

`start` binds the exact held network namespace read-only, verifies its type and
inode, rejects the host namespace and another active tracer, and registers the
exact Agent container with the lease. It uses2CPU/1GiB/384PIDs, host NET/PID,
cap-dropALL plus SYS_ADMIN/SYS_RESOURCE/BPF/PERFMON/SYS_PTRACE, no-new-privileges
and AppArmor unconfined. These privileges are explicit requirements of this
qualified path. It is not a privileged container. Native lifetime is180s with
40s kill grace; restart is disabled. The receipt is `WORK/agent/current.json`.

`ready` waits for actual collector and three-listener policy readiness, rechecks
the live restricted Controller profile, proves an Agent-owned namespace FD and
zero Agent AF_PACKET sockets, then reads only the new owned scope ARRAY and
validates its ABI/inode. The lease accepts phases only after this independent
proof. Neither start nor ready emits traffic. Failure does not authorize traffic;
always execute the stop/release/config-restore sequence below. Diagnostic
datadump, prewarming and skipped initial requests are absent.

The phases emit10 negative, then20 positive+20 negative, then10 negative HTTP
roundtrips. Use the ready lease marker and private positive/negative receipts
with [the strict public oracle](README-managed-ebpf-oracle.md). Expected storage
is40 Sessions (20client +20server), source3 and correct process/socket metadata;
all40 negative exchanges require zero rows. Require two passing reads with the
whole-marker query; do not add a source/Agent filter that hides mismatches.
Use [the console](console/README.md) to inspect eBPF source, request list,
overview and exact-ID details. Observation counts are not transaction counts.

## Stop and restore

Stop while the namespace supervisor is still alive, including on any failure:

```sh
python3 traflens/lab/managed-http-agent.py stop --execute --work "$WORK"
python3 traflens/lab/managed_http_workload.py release --execute --lease "$LEASE"
```

The stop operation checks the exact container ID/name/image/command/labels,
resource/capability envelope, hostname and bind mounts before acting. It records
logs and exit state, allows40s graceful stop, removes only that container and
checks BPF/tracefs restoration. It never detaches an unknown program. The lease
refuses release until its registered Agent is gone and the pre-Agent inventory
has restored (its owned worker cgroup metadata may disappear during cleanup).
Wait for the supervisor's final result, require no cleanup errors and verify
the original host BPF/tracefs inventory and preexisting services. A failed
workload may have `pass=false` even when cleanup succeeds; preserve both facts.

Restore and read back the original Controller YAML as described above, then stop
the owned console/SSH forward. Retain all private receipts, including failures.
These tools don't delete registrations or stop other services. Timeout, source
presence or a running process alone does not satisfy the end-to-end milestone.
