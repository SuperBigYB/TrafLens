# Fast MySQL collection diagnosis

This is the M15 diagnosis entry, separate from the qualified100ms-paced M14
fixture. It does not execute SQL, change the native Agent, repair ordering, or
qualify unpaced completeness merely because its process or observer succeeds.
The archived unpaced source and binary SHA are fixed by
`lab/ebpf-mysql-diagnostic.py`. The existing paced and DNS defaults are unchanged.

The default invocation is an offline plan. `run --execute` requires the same
explicit owned lab, normal kernel2/4/5 license, exact namespace FD/inode/map,
no-AF_PACKET and four limited workers as the prior public protocol lifecycle.
It adds two bounded, nonce-bound observer gates: before any worker/wire and
after every finite worker and the ordinary sender drain. No arbitrary shell
hook is accepted. Gates fail closed and retain the original run and cleanup
receipts. Observer timeouts are5–45seconds and cannot extend the180second Agent
limit. `stop --execute --work <same-private-directory>` resumes exact cleanup.

At each gate, the private `observer/<stage>/request.json` binds the actual
immutable Agent container, native PID/start ticks, native artifact/core, held
namespace and Controller identity. An observer must preserve that binding and
write1–8 bounded same-directory artifacts plus `manifest.json`, then invoke:

```sh
python3 traflens/lab/ebpf-mysql-diagnostic.py ack --execute \
  --work <same-private-directory> --stage before-first-wire
```

Use `after-final-wire` for the second gate. The public acknowledgement verifies
the nonce, hashes, permissions, budgets, deadline and still-live scope binding.
It never treats arbitrary supplied evidence as proof of zero loss or storage
completeness. Manifests contain no credentials or copied server configuration.

`lab/native-mysql-observer.py` is a default-offline command planner and a
streaming metadata parser. It never executes its planned native commands.
Its executing mode reads only an already scope-verified exact Agent stdout
pipe, retains bounded validated callback headers/hashes, discards payload and
addresses, and binds the two real positive workers' existing Docker/process
receipts. It explicitly accepts the two fixed product/diagnostic schemas and
purposes; unknown contracts fail. Unknown zero-UID CLOSE events are anonymous
counts, including events before a workload roster exists.

Capture sequence starts at zero. The parser accepts a real first `cap_seq=0`,
retains exact decimal socket/sequence values, and rejects negative values or a
gap/reset in the serialized print sequence. It does not assume cap-sequence
arrival is monotonic: detecting a backtrack is part of the diagnosis.

The stock control client must independently be available and artifact/ABI
verified; its illustrative `/usr/bin` path in the offline plan is not proof
that a chosen image contains it. Never expand the Agent mounts or capture
scope to obtain a client. The tested approach uses a verified static control
client in the existing private writable log mount. Resolve the fixed Unix
endpoint under the actual native task root. For the verified image,
`/var/run` is an absolute symlink to `/run`; require that exact link and use
`/proc/<actual-native-PID>/root/run/deepflow_bpf_ctrl`. Following the absolute
link through a caller-root path can otherwise reach the host filesystem.
Verify `SO_PEERCRED` against that exact native PID/generation before any call.

The stock client can print `Failed.` while returning exit0. Require the exact
requested parameter acknowledgement and one `Success.`, and explicitly turn
off the owned observer in `finally`; never rely solely on its coarse timeout.
Datadump output is the Agent stdout, not the `docker exec` stdout. Start the
bounded metadata pipe before enabling it, turn it off before the post snapshot,
then close the log follower so the parser receives EOF. No port/protocol filter
may silently drop CLOSE, whose tuple/port/protocol can be zero; the exact quiet
namespace, owned processes and fixed MySQL-only profile provide the boundary.

Counter meanings matter. The native MySQL protocol count is cumulative only
within the same tracer generation and is measured before C enqueue; it includes
all converted protocol events, not business queries or stored Sessions. Most
loss/enqueue/allocation snapshots are concurrently read and reset by the Agent's
periodic statistics. Pre/post subtraction and two zero snapshots cannot prove
zero loss. Actual execution CPU and Rust queue-acceptance order are not present
in these headers; the socket ID high bits identify its creation CPU. Serialized
print sequence is not successful downstream enqueue or collector order.

Numeric periodic telemetry, if present, must be queried under the exact fresh
hostname bound to that Agent, with bounded time and projections. Missing/null
metrics and unregistered senders are unavailable, never implicit zero. Preserve
each interval; distinguish delta counters, gauges, maxima, frames and rows.
No existing numeric metric covers every parser omission. An apparently clean
counter set therefore still requires the independent wire/whole-population
oracle; empty QUIT and orphan Request records must remain visible.

R22 produced one actual fresh unpaced wire scenario after a preceding
before-wire path failure. The live parser incorrectly rejected legal first
sequence0 and failed; both failures and their cleanup results remain unchanged.
The parser correction and15 tests were completed afterward. Only the existing
same-run private console headers were recovered offline: no wire or marker was
replayed, no live EOF/post-counter or lifecycle success was invented.

All36 actual data IOs uniquely match36 callbacks and all6 CLOSE records match
their owned sockets. Five sockets arrive0..6; the control client socket arrives
`2,3,4,5,6(CLOSE),0,1`. Its Auth is printed before Greeting/Login, and CLOSE
before those earlier syscalls. The actual native tracer has one C worker;
the synchronous print→callback source chain establishes callback invocation
order here. Per-event Rust queue acceptance and MySQL state transitions remain
uninstrumented. Execution CPU is unavailable and must not be inferred from the
socket ID. The native core and binary were not changed.

Two same-ID/full-field storage reads contain18 rows:17 Sessions and one
control/client Login Request without a response. All6 QUIT records, including
empty resources, remain. Whole marker12/query6, negative namespace0 and marker
source0/4=0 were checked without hiding orphan rows. This is another failed
unpaced completeness gate, distinct from the historical Query/QUIT failure.

The actual returned collector interval has42 input/enqueue/dequeue events and
zero sampled kernel/user enqueue loss, token failure and push conflict;
`time_backtrack_max` is6936700ns. These are observed interval samples, not
whole-lifetime zero-loss proof. Session/queue numeric metrics are retained but
their worker index is NULL, so no per-worker grouping is qualified. An observed
sender period has17items while final storage has18; tail coverage is missing
and those numbers must not be declared a lost row. No final native post
snapshot/protocol-counter delta exists.

Fifty targeted public tests cover the diagnostic gates, corrected metadata
parser and unchanged DNS/paced contracts. No HTTP/profile/OTLP/kernel/performance
matrix or unchanged console suite was repeated; remote CI was not checked.
The next M15 task is an evidence-directed bounded socket/cap-sequence ordering
repair with initial gaps, missing events, CLOSE, timeout and memory limits,
followed by a newly qualified native artifact and one necessary fast gate.
This round does not close M15 or establish an exclusive cause for the earlier
R21 sample. See the anonymous evidence under `evidence/2026-10-29/fast-mysql/`.

The original fast failure and paced success remain immutable; a successful
observer is not a native fix or a maximum-performance result.

