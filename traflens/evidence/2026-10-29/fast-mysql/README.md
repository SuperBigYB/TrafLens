# M15 fast-MySQL diagnosis, 2026-10-29

The native Agent is unchanged and M15 remains active. One fresh unpaced wire
scenario completed with three owned positive and three outside-namespace
conversations. All36 data IO and6 CLOSE headers were recovered from the same
existing private Agent console and matched independently; no scenario/marker
was replayed. The live observer failed on legal cap_seq0 and remains failed.
The public parser correction passes15 tests;50 combined public tests pass.

The control client socket callback order is2,3,4,5,6(CLOSE),0,1. The actual
C-worker count is1 and its synchronous print/callback chain confirms this
invocation order. Exact socket/flowID/tuple/process/timestamps bind the
stored orphan to the control client Login. Two complete same-ID/field reads
show18rows,17Sessions and1Request, not18complete Sessions. QUIT6, marker12,
query6, outside0 and marker source0/4=0 remain visible.

Actual interval statistics contain42input/enqueue/dequeue events and zero
sampled kernel/user enqueue loss; maximum time backtrack is6936700ns. They
do not prove lifetime zero loss. Worker-index projections are NULL; session
and queue metrics are retained without per-worker grouping. The sampled
sender period17 and final18rows do not establish a lost record. No final
tracer snapshot/protocol delta exists.

The first runtime stopped at the before-wire target-root socket proof with
no worker. The verified image uses absolute /var/run -> /run; the second
uses the exact native task's root/run and checks SO_PEERCRED. It passed the
before gate, then its live parser rejected legal first sequence0. These
failures are retained, not relabeled by the later offline recovery. Normal
Controller leases, exact scope, private artifacts and explicit off/public
stop protect recovery; see the final restoration summary separately.

Implement a bounded ordering repair next. Do not infer that the Reorder stub
is the sole cause of every earlier failure, or claim a native fix before a
new qualified artifact and the fast complete-session gate pass. This is not
a maximum-throughput or DeepFlow-parity result. No old matrix was rerun and
remote CI was not checked.

See [workflow](../../../README-ebpf-mysql-diagnostic.md) and [anonymous
evidence](summary.json). Full scoped wire, counters, original failed results,
hashes, exact-ID comparison and identity/restore receipts remain private on
the two authorized hosts. No credentials, payload or IP/MAC metadata are
published.

Final read-only restoration passed. Both Agents and all four executed workers
exited0/noOOM; holders, pins, exact recorded processes and forwards are gone.
Controller0Agents/1default/YAML, original Server ID/Image/network/config hash,
physical interface/device/routes and final BPF/tracefs match their original
receipts. Loopback is compared explicitly to a historical R19 baseline, not an
invented R22 pre-state. A transient additional cgroup-device program was seen,
then returned explicit ENOENT and was absent in the final exact inventory; its
owner/cause is unknown and no unknown program was detached or type-exempted.
Restoration passing does not change either failed capture/observer result.
