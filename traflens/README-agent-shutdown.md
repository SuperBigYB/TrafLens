# Bounded native Agent shutdown

`Trident::stop` now requests termination of the control thread and waits up to30
seconds for its component shutdown. It exits nonzero if the control thread panics,
misses that deadline, or reports a known sender frame failure in that component run. The final PID-file
cleanup/exit helper adds about one second; termination grace must exceed31 seconds.
The controlled runtime validation uses40 seconds. No controller configuration
field or network/resource limit is raised by this change.

The packet dispatcher joins before its SessionAggregator. FlowMap buffered senders
flush partial final batches on drop. The aggregator drains its remaining queue
before its existing session-cache flush. eBPF/metrics integration producers stop
before the shared L4/L7/metrics senders are notified. Senders consume final queued
batches and flush the encoder/file writer. Their active drain loop has a5-second
budget after observing stop; an existing receive wait can take up to3 seconds.
Each TCP frame has a3-second total write deadline. Numeric TCP connect has its
own3-second bound; the overall control-thread deadline covers locks, hostname resolution and
other component waits. Zero writes and persistent WouldBlock/TimedOut are failures.
An uncertain partial write is not replayed on another connection.

A nonblocking termination notification avoids waiting on the configuration mutex;
its existing bounded condition-variable wait remains a fallback. Shutdown errors
survive periodic counter resets. Network-frame failures during normal operation
are sticky too: clearing an encoder after a failed send must not let an empty
final flush conceal the earlier loss. This includes frames discarded during
reconnect backoff or configured throughput limiting. A later successful frame
does not recover the lost frame or clear the failure; only a new component run
resets it. Supervisors can therefore see a nonzero normal-stop result after an
earlier transient failure even if the destination has since recovered. L7 aggregation worker failures propagate instead
of silently becoming a successful join. Each sender's failure state resets only
when that component starts a new run.

Twelve new regressions cover an incomplete dispatcher batch, multi-batch session
and TCP queues, actual loopback frame bytes, refused final connections, partial/
zero/interrupted/stalled writes, blocked and panicking joins and configuration-lock
contention. The complete default-feature native library422, tunnel28 and window21
tests pass with no ignored tests in the isolated SDK. Build uses cached, pinned
protobuf/jattach sources; the existing jattach static Makefile overlay is retained.

This is a drain of already generated/queued records, not a durable acknowledgement
from ClickHouse. Other historical runtime drops (including producer/queue losses), overwrite
pressure, incomplete flow/
stream state, unread kernel capture data and broad eBPF/runtime behavior need
separate validation. File flush is not fsync durability. No ambiguous frame replay
or general exactly-once claim is added. The earlier failed immediate-stop reference
sample and its missing106 resources remain in README-http-ramp.md; the prior
pre-stop query workaround is not treated as a product fix. New committed-source
native binary and immediate-stop before/after evidence are recorded separately.


## Committed binary and real immediate-stop comparison

The fixed native binary is exact source
`938890898b2d4d502251409f25409f3acb7a74fd`, SHA256
`e3f50224010982b7cc5e7cc9bb077ec93e058fabad074aee3176ba7bef4aa50f`
(79,321,968 bytes). Offline optimized release builds with pinned SDK/Rust1.97.1/
GCC11.2.1,2CPU/8GiB and no network/added capabilities. The embedded commit, SDK ldd,
minimal-runtime version probe and clean source checks pass. Ten BPF ELF headers
are checked as build artifacts; no BPF kernel-load claim follows. Exact committed
source also passes the complete native422+28+21 suite. Core CI40519977157 passes
both jobs: packet410+28+21 plus2rate, and219lab/fullServer/race/API/writer/wire gates.

Three old-candidate and three fixed-candidate trials each generate2000 fresh-TCP
HTTP requests at200RPS for10 seconds. Order is old, fixed, fixed, old, old, fixed.
Both receive the same profile, runtime libraries,2CPU/1GiB/384PIDs and40-second
termination grace. Both endpoints use identical generator bits fromd18bf64b0,
with16 connections and1000ms timeout. Every client/server pair completes all2000
responses, with zero failed/skipped generation slots. No ingestion query, drain
wait or arbitrary sleep precedes SIGTERM: it follows workload-wrapper cleanup.

The old native95f5e10df binary exits0 in about1.2 seconds yet stores only
1611/1618/1718 rows, missing the final389/382/282 resource sequences. Each failed
strict query archive is retained, followed by independent bounded full-row
metadata diagnostics and stable counts. Its post-stop observation budget is20s;
this does not claim no future late write can ever arrive. The original upstream
reference's106-tail failure remains separate historical evidence.

The new binary exits0 with an explicit successful drain record in all three
trials. Its2000/2000 rows per trial pass two whole-marker exact scans after process
removal, including complete method/status/protocol/source/observation-point/Agent
metadata. All three archives replay offline against paired report-byte hashes.
Total6000 fixed Sessions pass48 data-page and12 count queries. The fixed oracle
budget is90s, but all initial counts are already2000; no post-stop count polling
was required. Client latency and CPU snapshots are not used to claim performance
improvement or full shutdown CPU cost.

Measured Docker stop waits are11.245/12.376/11.545 seconds versus the old binary's
1.219/1.187/1.162 seconds. The new work waits for component teardown and buffered
output; it is not a faster-stop result. The40-second grace is material, not an
undisclosed increase to the2CPU/1GiB or export/queue limits. A default10-second
supervisor grace is insufficient for these measured clean stops.

Anonymous samples and hashes are in
[evidence/2026-10-27/agent-shutdown/summary.json](evidence/2026-10-27/agent-shutdown/summary.json).
Raw logs, all preparation failures, before/after controls, configuration, queries
and identities stay in private sealed evidence with a matching peer archive.
Existing container IDs/start times/images/mounts, exact Controller YAML, management
route and BPF/tracefs baselines are preserved. All owned runtime workers/Agents
are removed and the bench link returns to its original DOWN state.

Refused connections, partial/stalled writes and blocked/panicking joins have
unit/loopback negative controls. This iteration does not inject a real-ingester
outage. Broader active/incomplete flows, unread kernel ring data, eBPF/TLS and
historical runtime losses remain separate gates. Successful TCP writes are not
storage acknowledgements, and this result does not establish complete shutdown
reliability, maximum throughput or full DeepFlow parity.

Forced SIGKILL, host failures and other direct fatal-exit paths bypass this normal
termination coordinator and remain outside the demonstrated contract.


## Sender failure history regression

A loopback refusal while the sender is still running used to clear its frame
without setting the sticky failure flag. After periodic counters reset, a stop
with no queued items and an empty encoder could incorrectly appear successful.
The regression verifies an actual refused connection, zero transmitted frames,
cleared encoder, a nonzero drop counter followed by its reset to zero, then
terminal processing. It fails on the previous implementation and passes when
all failed network-frame flushes set the per-run failure flag.

This follow-up changes failure reporting; it does not add retransmission,
server acknowledgements, recovery of lost data, or an actual-ingester outage
qualification. The earlier immediate-stop binary and traffic results above
remain evidence for their named revision, not for a newly built runtime binary.

The fixed source passes the complete default-feature native library423, tunnel28
and window21 tests (472 total), with zero failures or ignored tests. The added
regression fails on the previous implementation (five existing sender tests pass,
one new test fails). SDK rustfmt leaves the tested source unchanged. The known
libtrace archive member linker warning remains; it does not fail this build.
Anonymous results and raw-log hashes are in
[evidence/2026-10-27/sender-failure-history/summary.json](evidence/2026-10-27/sender-failure-history/summary.json).
