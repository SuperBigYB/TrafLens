# trident-rs

trident in rust

# X86 Dynamic Libraries

This project requires the following dynamic libraries:

1. **linux-vdso.so.1**
2. **libpthread.so.0**
3. **libz.so.1**
4. **libstdc++.so.6**
5. **libgcc_s.so.1**
6. **librt.so.1**
7. **libm.so.6**
8. **libdl.so.2**
9. **libc.so.6**
10. **ld-linux-x86-64.so.2**

# ARM Dynamic Libraries

This project requires the following dynamic libraries:

1. **linux-vdso.so.1**
2. **libpthread.so.0**
3. **libz.so.1**
4. **libstdc++.so.6**
5. **libgcc_s.so.1**
6. **librt.so.1**
7. **libm.so.6**
8. **libdl.so.2**
9. **libc.so.6**
10. **ld-linux-aarch64.so.1**
11. **libibverbs.so.1**
12. **libnl-route-3.so.200**
13. **libnl-3.so.200**


## TrafLens termination behavior

The TrafLens fork coordinates queued-record shutdown with a30-second control-thread
deadline and nonzero incomplete-shutdown outcome. Container/service termination
grace must exceed31 seconds; the lab uses40. See
[the shutdown guide](../traflens/README-agent-shutdown.md) for scope and validation.


## TrafLens native MySQL capture ordering

The native eBPF preprocess default now selects MySQL for bounded ordering before
stateful L7 parsing. This changes post-processing of already captured records;
it does not enable another protocol, process, interface, profiling input or
license function. Explicit native runtime configuration with an empty protocol
list still disables ordering. The existing Controller template is unchanged;
no new Controller UI/profile field is assumed to exist.

The ordering key preserves the full kernel socket UID and source domain. A first
capture2 waits for0/1, and CLOSE cannot pass an unresolved sequence gap. Empty
checkpoints survive ordinary long connection idle; budgets and failure counters
remain explicit. Existing reported FlowID formatting is unchanged and is not a
global or historical process-identity guarantee. For limits, counters, timeout,
unknown CLOSE and eviction behavior, see [the ordering crate](plugins/reorder/README.md).

The dispatcher reconfigures ordering when its native preprocess settings change,
uses a bounded idle ticker, and closes socket-callback admission before draining
at most the fixed Rust ingress capacity. It then releases buffered ownership
without sending CLOSE across a gap. These guarantees cover admitted Rust records;
the C-side stop operation remains asynchronous and is not a proof of complete
kernel/perf/C-queue drain. A new native artifact must pass the scoped FD/map and
real fast-MySQL storage/API/browser gates before it replaces the qualified lab
Agent. A unit replay or successful compilation alone is not that qualification.
