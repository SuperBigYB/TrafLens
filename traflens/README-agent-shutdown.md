# Bounded native Agent shutdown

`Trident::stop` now requests termination of the control thread and waits up to30
seconds for its component shutdown. It exits nonzero if the control thread panics,
misses that deadline, or reports a known final sender failure. The final PID-file
cleanup/exit helper adds about one second; termination grace must exceed31 seconds.
The controlled runtime validation uses40 seconds. No controller configuration
field or network/resource limit is raised by this change.

The packet dispatcher joins before its SessionAggregator. FlowMap buffered senders
flush partial final batches on drop. The aggregator drains its remaining queue
before its existing session-cache flush. eBPF/metrics integration producers stop
before the shared L4/L7/metrics senders are notified. Senders consume final queued
batches and flush the encoder/file writer, with a5-second local drain budget and
a3-second total deadline per TCP frame. Numeric TCP connect also has a3-second
bound; the overall control-thread deadline covers locks, hostname resolution and
other component waits. Zero writes and persistent WouldBlock/TimedOut are failures.
An uncertain partial write is not replayed on another connection.

A nonblocking termination notification avoids waiting on the configuration mutex;
its existing bounded condition-variable wait remains a fallback. Shutdown errors
survive periodic counter resets. L7 aggregation worker failures propagate instead
of silently becoming a successful join. Each sender's failure state resets only
when that component starts a new run.

Twelve new regressions cover an incomplete dispatcher batch, multi-batch session
and TCP queues, actual loopback frame bytes, refused final connections, partial/
zero/interrupted/stalled writes, blocked and panicking joins and configuration-lock
contention. The complete default-feature native library422, tunnel28 and window21
tests pass with no ignored tests in the isolated SDK. Build uses cached, pinned
protobuf/jattach sources; the existing jattach static Makefile overlay is retained.

This is a drain of already generated/queued records, not a durable acknowledgement
from ClickHouse. Historical runtime drops, overwrite pressure, incomplete flow/
stream state, unread kernel capture data and broad eBPF/runtime behavior need
separate validation. File flush is not fsync durability. No ambiguous frame replay
or general exactly-once claim is added. The earlier failed immediate-stop reference
sample and its missing106 resources remain in README-http-ramp.md; the prior
pre-stop query workaround is not treated as a product fix. New committed-source
native binary and immediate-stop before/after evidence are recorded separately.
