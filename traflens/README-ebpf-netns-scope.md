# Optional socket-tracer network namespace scope

TrafLens adds an opt-in current-task network namespace fence to the native socket
tracer. The existing default remains unscoped. The fence is intended for bounded
collection experiments whose tasks and namespace lifetime the operator controls.
It is an extension to the pinned community source, not a claim of complete
DeepFlow functionality or performance parity.

## Scope contract

The C API is `set_socket_tracer_netns_scope(uint64_t inode)`. Call it before
initialization/attachment, keep an open namespace FD through detach, and check its
return value. Zero preserves legacy behavior. Nonzero scope requires a valid
32-bit namespace inode and validated kernel BTF offsets. Missing maps, invalid
offsets, null pointers and failed namespace reads reject collection. Configuration
is frozen once tracer startup begins; changing it requires a process restart.

The comparison uses the **current task's** network namespace. It does not identify
the namespace that owns a socket. Do not transfer a socket FD across namespaces
or change a task's namespace while using its sockets in this experiment. TLS,
Go HTTP/2, socket-record and file-record entry paths have payload fences, but
profilers have their own collection paths and are excluded from this mode.

Hooks remain system-wide. Syscall argument pointers/lengths and socket metadata
can still be read outside the selected namespace. Rejected tasks must not reach
socket payload inference/copy/submission. Offset adaptation deliberately uses its
existing task identity and metadata before the payload fence, so the loader can
run outside the selected namespace. Periodic buffer flushing retains each
record's earlier decision; it does not compare the flushing worker's namespace.

Namespace pointer reads use a per-CPU scratch value rather than adding stack
objects to each inlined probe. An atomic depth contribution admits only one
cursor user on that CPU; nested or preempting contenders fail closed and release
their own contribution. The decision is copied to a scalar before release.
Unused-return XADD operations retain the project's legacy BPF instruction
contract. Scope-denied output takes the shared buffer-reference cleanup path.
These source properties and mock regressions do not establish runtime support
on every kernel or measure disabled/enabled-mode overhead.

## Managed Agent bootstrap

Linux native builds accept this local bootstrap key:

```yaml
ebpf-socket-netns-scope: /absolute/path/to/pinned-netns
```

This snippet is only the scope setting, not a complete Agent configuration. The
Agent opens a real FD, checks `NS_GET_NSTYPE == CLONE_NEWNET`, derives its inode
with `fstat`, and retains it for the process lifetime. The inode cannot be supplied
through deserialized configuration. Relative paths, ordinary files, other
namespace types, zero/out-of-range inodes and repeated initialization fail.
Packet-only builds reject a requested scope instead of falling back to unscoped
tracing.

The controller profile must use Local mode and enable the eBPF dispatcher. All
packet/alternate packet inputs, integration/vector inputs, profilers, DWARF,
socket-ops, NIC optimization, file-I/O collection, and TLS/Go/DPDK uprobes must be disabled for
this first managed experiment. In particular, the AF_PACKET interface expression
must be empty; setting a separate disabled flag is insufficient. The complete
validation lives in `Config::validate_socket_tracer_scope` and
`Ebpf::validate_socket_tracer_scope`. Unsafe controller candidates are
rejected before static/runtime configuration or callbacks change. With scope
enabled, failure to create the native eBPF dispatcher is fatal. Unscoped startup
keeps its existing behavior.

A port/protocol map is not a namespace ACL. Keep unrelated protocols disabled,
use owned traffic, and verify the namespace configuration before allowing any
payload in a standalone experiment. Managed Agent collection, transport,
persistence and query acceptance require their own evidence after this gate.

## Validation records

Compilation, the userspace loader, and the kernel verifier enforce different
contracts. Native artifacts are checked offline with:

```sh
python3 traflens/scripts/check-bpf-loader.py \
  'agent/src/ebpf/kernel/build/**/*.bpf.elf' --expect-count 10
```

This structural check rejects BPF subprogram calls and executable function
relocations, checks legacy map relocations and their bounds, and leaves
non-executable BTF/debug relocations alone. It is a partial structural gate,
not a complete ELF loader or a kernel verifier. Thirteen independent small ELF
vectors include valid map/helper calls, the actual outlined-call failure pattern,
truncation and malformed table boundaries. It rejected all seven socket objects
from the affected earlier native build while accepting its three profiler
objects. The corrected build's ten objects pass.

The added fence enlarged an existing fork helper enough for LLVM to outline it.
The current userspace loader accepts map relocations only, so that helper now
requires forced inlining. A separate kernel verifier failure exposed an
uninitialized process-event storage word shared by the 31-bit PID and thread
flag. All three event constructors now initialize their complete 24-byte object.
The regression extracts the real exit/exec/clone functions, requires a compiler
with poisoned automatic storage, and checks 90 assertions. The earlier successful
native artifact remains a valid observation; changed stack allocation exposed
this latent source defect.

Exact source revisions, test totals and runtime outcomes are recorded in the
accompanying aggregate summary and the current development checkpoint. Keep
source compilation, kernel verifier acceptance, callback contents, Agent
ingestion and performance results separate. Preserve failed probes; neither a
passing packet build nor a stale native binary validates a new kernel change.

Raw namespace/process/container identifiers, configurations and runtime logs stay
in ignored private evidence. Published evidence contains software hashes, counts,
qualifications and a private-manifest fingerprint only.


## Actual standalone acceptance

Exact native core `a0cb0fb9c111cb7b34168d459fd3e188b07826e6` passes 403 native
library +28 tunnel +21 window tests (452 total, no failures/ignored), ten ELF
loader-contract checks, and the unchanged original 2023 SDK keeper. Packet CI
passes 392+28+21=441. Nine C tests execute 364 assertions; the published tooling
and lab suites pass 31 and 154 tests. The inherited jattach Makefile build-only
overlay remains qualified; pinned C/dependency sources were not upgraded.

The fixed Linux 5.15 x86_64 runtime uses a host-PID loader in its own private
network namespace, plus separately owned private-PID/private-network fixtures.
Private-PID managed Agent readiness is not established by this run. Each mode
completes 20 positive and 40 same-port/equal-length negative HTTP roundtrips:

- Legacy control bypasses all 65,536 ports and enables zero protocols: zero
  callbacks. This is a rejection/lifecycle control, not unscoped payload proof.
- An owned quiet third namespace is selected: zero callbacks from both fixtures.
- The positive namespace is selected: exactly 80 data callbacks, with both
  copies of each of 20 requests/responses matching generated bytes and indices;
  two zero-length close records are counted separately (82 callbacks total).

Ordinary syscall records carry `MSG_COMMON`. The gate derives request/response
from the verified client/server role and ingress/egress direction; it rejects
unexpected message hints, roles, directions, source, protocol or length before
reading payload. The callback first checks the owned positive host TGID. This
userspace defense is separate from the kernel current-task namespace fence; no
kernel PID ACL is claimed. Negative-only phases before and after the concurrent
phase, positive drain, and final quiet windows all pass.

All three modes reach RUNNING with configuration maps read back, 81 loaded
program sections and 30 libtrace attachment wrappers. Stop leaves zero wrappers;
after exit all owned program IDs disappear, full BPF/tracefs inventories are
restored and preexisting containers remain running. Wrappers can contain perf
FDs; this is not a claim of 30 kernel BPF_LINK objects. Observed kernel/user queue
loss and allocation failures are zero for this bounded experiment.

The fixtures are real OS TCP endpoints carrying generated HTTP. They are not
a browser/application-service or sustained load benchmark. The complete Agent
was not launched, and these records were not sent to the Server or database.
Runtime aggregates and evidence fingerprints are in
[the checkpoint](evidence/2026-10-27/ebpf-scope/summary.json) and
[the three-mode result](evidence/2026-10-27/ebpf-scope/runtime.json).

## Reproducing the bounded gate

[runtime-netns.py](lab/runtime-netns.py) defaults to an offline plan. It requires
explicit execution, prepared immutable binaries, a fresh root-owned mode-700
work directory, no existing socket tracer, and JIT already enabled. It creates
only randomly named labeled resources, checks exact identities on cleanup,
holds namespace pins through tracer termination, and never changes host network
configuration. The tracer has 2 CPUs/2 GiB/256 PIDs and only SYS_ADMIN,
SYS_RESOURCE, BPF and PERFMON capabilities; BTF/tracefs mounts stay read-only.
Workers have 0.25 CPU/64 MiB/8 PIDs. This is a privileged kernel experiment with
bounded resources, not an unprivileged collection test.

Build [the C source](lab/ebpf-netns-gate.c) inside the pinned image below using
`bash -lc` to select GCC 11.2.1. Mount the verified native source read-only at
`/source`, matching trace-utils archive read-only at `/trace-utils.a`, and a fresh
private output directory at `/evidence` containing the C source. From
`/source/agent/src/ebpf`:

```sh
cc -std=gnu11 -O2 -g -rdynamic -Wall -Wextra -Werror \
  -Wno-unused-parameter -Wno-sign-compare -Wno-old-style-declaration \
  -Wno-missing-field-initializers -I. -I../../crates/trace-utils/src \
  /evidence/ebpf-netns-gate.c -o /evidence/gate \
  -Wl,--wrap=_ebpf_log -Wl,--start-group libtrace.a /trace-utils.a \
  -L/usr/lib64 -L/usr/lib -L/usr/local/lib64 -L/usr/local/lib \
  -Wl,-Bstatic -lGoReSym -lbddisasm -ldwarf -lbcc_bpf -lbcc -lelf -lpcap \
  -Wl,-Bdynamic -Wl,--end-group -lz -lstdc++ -lpthread -ldl -lrt -lm -lresolv
cc -DGATE_TRAFFIC_ONLY -std=gnu11 -O2 -Wall -Wextra -Werror \
  /evidence/ebpf-netns-gate.c -pthread -o /evidence/gate-traffic
/evidence/gate self-test
/evidence/gate-traffic self-test
```

Image: `ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310`.
Verify `ldd` has no missing dependencies and bind execution to the software
hashes in the aggregate. The traffic-only binary does not link libtrace and
rejects tracing. The full gate uses real SDK headers and preserves private SDK
diagnostics through the logging wrapper; it does not persist raw payloads.

```sh
python3 traflens/lab/runtime-netns.py
python3 traflens/lab/runtime-netns.py --execute \
  --work /tmp/fresh-private-gate-run \
  --tracer-bin /path/to/verified/gate \
  --traffic-bin /path/to/verified/gate-traffic --mode all --port 18089
```

`--port 18080` is also accepted for later managed-Agent preparation. Each actual
run must get a new private work directory. The driver refuses unknown ownership,
records failures rather than deleting unrelated resources, and requires complete
cleanup/inventory restoration to pass. Raw outputs remain private.

## Managed Agent checkpoint

The [strict managed oracle](README-managed-ebpf-oracle.md) now covers the complete Agent-to-ClickHouse path for this finite dual-endpoint HTTP workload. [Aggregate evidence](evidence/2026-10-27/managed-ebpf/summary.json) retains a 39/40 non-diagnostic failure and a subsequent 40/40 diagnostic pass. The first server-session loss is still unresolved; the successful diagnostic window does not establish repeatability or full feature/performance parity.
