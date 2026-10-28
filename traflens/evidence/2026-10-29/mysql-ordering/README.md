# M15-03a bounded MySQL ordering, 2026-10-29

The native no-op ordering module is replaced with bounded socket/capture
sequence ordering. Full kernel UID and source remain separate; reported
FlowID formatting is unchanged. The real prior42-header arrival order
replays into contiguous0..6 for every socket; the problem control client
2,3,4,5,6(CLOSE),0,1 no longer sends Auth/Close ahead of Greeting/Login in
this code/replay gate. Original event time is not rewritten.

The native default selects MySQL; explicit native empty protocol lists still
opt out. No Controller template, normal license or capture scope changed.
Unknown CLOSE only follows an already tracked key; untracked/disabled/zero-ID
records bypass with counters. Gaps, duplicates, ranges, timeout, memory/items,
state pressure and terminal states are handled explicitly. Open connections
retain checkpoints through normal idle. See [the exact bounded
contract](../../../../agent/plugins/reorder/README.md).

Forty-three distinct checks pass:7 library,11 independent anonymous replay,
7 actual native MetaPacket/config/dispatcher helper/admission tests,1 existing
merged-range regression and17 additional existing configuration/scope checks.
The final configuration run has18 passes, including1 already counted test. The final test used the cached native
image, default libtrace, actual clean C rebuild, offline locked dependencies
and full native Rust test linkage; it did not bypass build.rs or substitute
C stubs. The build was limited to2CPUs/12GiB/512PIDs, networknone, capdropALL
and a read-only root filesystem. It exited0/noOOM and was removed; original
Server identity/image/running state and qualified Agent bytes are preserved.

The first host test lacked the repository's devtoolset11 linker. A subsequent
native snapshot mistakenly omitted the tracked config.h symlink; restoring
exact Git source topology fixed that build prerequisite without editing C
macros. A configuration run also exposed a missing Git-tracked public template
fixture; supplying that source schema fixed the environment, without copying
live Server configuration. Old failed logs/results remain. Jattach inputs were copied as bounded
public source with individual hashes; its current tree is not independently
proved to have the historical claimed upstream Git pin. An ignored non-object
archive member warning remains recorded, not expanded into another matrix.

This is source/replay/native-unit validation, not deployment qualification.
The tests do not start a collector or prove actual FlowMap/parser/session/store
results. A real Agent ELF from the new commit, exact version/artifact/library
binding, actual namespaceFD/map/noAF_PACKET and the fast18 complete-Session
API/browser gate remain M15-03b/c and04/05 work. Original incomplete rows
and observer failures are not relabeled. No wire sleeps, reuploads, new
scenarios, old matrix repeats, remote-CI check or performance claims were used.

[Anonymous evidence](summary.json) records source and result hashes. Full build
logs/limited container intents and fixed-source/ABI handoff remain private
in the authorized round23 directories. M15 remains the only active milestone.
