# eBPF no-payload runtime gate

The [C gate](lab/ebpf-no-payload-gate.c) verifies that the native libtrace
implementation can load, attach, reach its running state, and detach while
kernel socket-payload collection is bypassed. It runs independently of the
controller, Server and database.

The verified native source is commit
`62429a607627051c3f242247ff646c67fee80e3e`. The gate C source SHA256 is
`c59a224a5865ef59b0e85ebdeae4dbc0243f34d22b51fab2e152e33a2b7cce45`.
It includes that tree's C headers without redefining ABI structures. The complete
Agent binary was not started.

## Verified result and scope

On Linux `5.15.0-198-generic` with readable BTF and syscall tracepoints:

- libtrace initialization and loading returned zero, and the tracer reached
  `TRACER_RUNNING`.
- The gate identified **81 loaded BPF program sections** and **30 attached
  libtrace probe/tracepoint/kfunc wrappers**.
- Both complete port maps and all 200 protocol-filter entries were read back:
  every one of the 65,536 ports was bypassed, the allow map was empty, and every
  protocol was disabled.
- A new synthetic process completed **20 TCP roundtrips** over its private
  loopback interface. The payload callback count was **zero**; it never
  dereferences the callback's data pointer.
- Stop returned zero and reached `TRACER_STOP`, with the 30 attachment wrappers
  reduced to zero. After process/container exit, all owned program IDs were gone,
  the host BPF program inventory and tracefs definitions matched their preflight
  snapshots, and preexisting service containers remained running.

The attachment count is derived from libtrace's non-null internal `link`
pointers. These can wrap perf-event FDs and are **not** a claim that 30 kernel
`BPF_LINK` objects were created. Likewise, the **ten compiled BPF ELF files**
from the [native build](README-agent-native.md) are a different unit from the
81 program sections loaded here.

This is a system-wide hook experiment with kernel payload bypass enabled.
It does not prove PID-filtered collection, Agent payload capture, pipeline
ingestion, database rows or performance parity. The synthetic TCP checks verify
the owned sockets directly; they are not eBPF-captured requests.

## Why the gate bypasses all payload

The pinned kernel implementation returns when either socket port matches the
bypass map, before protocol inference and payload submission. The allow map
instead forces `PROTO_CUSTOM`; it is not an exclusive whitelist. A zero
`set_data_limit_max` value selects the default 4096-byte limit, rather than
disabling capture. Process matching must not be treated as a syscall PID
allowlist.

The gate therefore sets every bypass bit, leaves the allow bitmap empty, and
enables no protocols. It explicitly disables file/virtual I/O collection and
never enables profiling, uprobes or datadump. Full map readback is required
before the synthetic TCP check. The callback counts any unexpected delivery
without reading its metadata or payload, and a nonzero count fails the gate.

These source files are byte-identical between the native source commit above
and upstream `8741e924ff0ae3964a135985c51e5a6ce6bde397`:
`user/socket.c`, `kernel/socket_trace.bpf.c`, `user/tracer.c` and `user/probe.c`.
The fixed-source references are:

- [Kernel bypass and allow-map behavior](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/agent/src/ebpf/kernel/socket_trace.bpf.c#L1890-L1913).
- [Data-limit zero selects the default](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/agent/src/ebpf/user/socket.c#L2386-L2397).
- [Tracer initialization side effects](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/agent/src/ebpf/user/tracer.c#L2310-L2415).
- [Probe attachment implementation](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/agent/src/ebpf/user/probe.c).
- [Upstream process-selection discussion](https://github.com/deepflowio/deepflow/issues/10222).

## Prepared build prerequisites

Use the exact native source and its verified `libtrace.a` plus a compatible
existing `trace-utils` static archive. The experiment used the prepared dependency
image:

```text
ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310
```

A login shell selects its GCC **11.2.1**. The image contains libGoReSym,
bddisasm, libdwarf, bcc_bpf, bcc, libelf and libpcap static libraries. Empty-cache
native compilation is a separate preparation step; this gate is not an
installer. The native build's preexisting jattach Makefile static-build patch
remains disclosed, with all five pinned jattach C sources unchanged and no new
dependency changes for this runtime experiment.

The verified `libtrace.a` SHA256 is
`cc283bfa1d536007bf57396005a2bb510cddf84bbeb1bcf913e90f0a00da81c2`.
The standalone gate binary SHA256 is
`8678864d37637500210027f00cb298258b7dd51a08261e230018c193ba865d05`.

Mount the native source read-only at `/source`, the compatible trace-utils
archive read-only at `/trace-utils.a`, this C file read-only at `/gate-source.c`,
and a fresh private output directory at `/evidence`. The compile command inside
the image, from `/source/agent/src/ebpf`, is:

```sh
cc -std=gnu11 -O2 -Wall -Wextra -Werror \
  -Wno-unused-parameter -Wno-sign-compare -Wno-old-style-declaration \
  -Wno-missing-field-initializers -I. -I../../crates/trace-utils/src \
  /gate-source.c -o /evidence/gate \
  -Wl,--start-group libtrace.a /trace-utils.a \
  -L/usr/lib64 -L/usr/lib -L/usr/local/lib64 -L/usr/local/lib \
  -Wl,-Bstatic -lGoReSym -lbddisasm -ldwarf -lbcc_bpf -lbcc -lelf -lpcap \
  -Wl,-Bdynamic -Wl,--end-group -lz -lstdc++ -lpthread -ldl -lrt -lm -lresolv
```

## Runtime ownership and cleanup requirements

Use a supervisor that first rejects active DeepFlow/socket tracers and existing
`_deepflow_` tracefs events. JIT must already be enabled. libtrace initialization
otherwise attempts residual-probe cleanup and installs a control tool/socket;
those filesystem effects must stay inside the temporary container root.

The verified runtime used one uniquely labeled owned container with private
PID and network namespaces, `network=none`, 2 CPU, 2 GiB, and a PID limit of 256.
It retained default seccomp and `no-new-privileges`, dropped all capabilities,
then added `SYS_ADMIN`, `SYS_RESOURCE`, `BPF` and `PERFMON`. This is not an
unprivileged kernel test.

Mount host BTF read-only, and host `/sys/kernel/debug` and
`/sys/kernel/tracing` read-only. No writable tracefs, host PID/network namespace,
host `/proc/root`, Docker socket, credentials or database/config volume is
required. The first OCI attempt failed before libtrace execution because it
could not create a nested tracefs mount target on read-only sysfs. Mounting the
existing parent debug directory read-only resolved it without adding write
access; both attempts are retained separately.

Run `gate --execute-no-payload` with an inner 110-second and outer 120-second
deadline. The supervisor must verify the exact container identity and labels,
stop/remove only that container on every outcome, and compare pre/post tracefs
definitions and BPF program IDs. Successful stop state and zero attachment
wrappers are required in addition to process exit.

`gate.json` contains transient kernel IDs for cleanup verification and must
remain private. Publish only the aggregate result, without raw logs, process or
container identifiers, internal configuration or environment dumps. The runtime
supervisor used in this experiment depends on prepared lab cache paths; this
guide documents its required behavior rather than providing a general-purpose
host tracing launcher.
