# Agent targeted baseline attribution, 2026-10-26

Compared pinned upstream `8741e924ff0ae3964a135985c51e5a6ce6bde397` with TrafLens `6944472eab429dc52eaabf1fb98e768431c2dfc8`. This is a directed failure inventory, not a completed full-library gate.

## Reproduction and provenance

- `metadata.json` records sources, environment, retained binary SHA256s, final time-fix source SHA256, and limits.
- Each `current-tests/` and `upstream-tests/` log records the exact executable command and working directory. `comparison.json` pairs all 16 results and panic details.
- Both builds used Rust1.97.1, libpcap1.10.1, `cargo test --offline --locked --no-default-features --lib --no-run`. `run-env.json` contains only whitelisted build settings, no credentials/environment dump.
- The clean upstream locked build fails before tests (`upstream-pristine-build.log`). The upstream comparison therefore uses exactly `upstream-build-compat.patch`: minimal lock synchronization, app_table libtrace cfg, and synchronized protobuf-only rustfmt. It does not include the L7/HTTP/DNS/labeler behavioral fixes.
- The copied cache initially skipped protobuf generation into the new upstream source. `upstream-build.log` preserves that failed build; touching only isolated public/root build.rs timestamps and rebuilding generated it successfully (`upstream-build-generated.log`).
- The OpenTelemetry proto tree was copied at verified gitlink `724e427879e3d2bae2edc0218fff06e37b9eb46e` into each isolated source. The copied .git indirection was removed; no submodule registration or primary source change was made.
- The isolated current source was later used for the first 9-test time-fix verification. Its exact post-comparison diff is `current-final-isolated-source.patch`; the original comparison binaries remain unchanged and preserved.

## Paired results and actual categories

Before the time fix, all 14 assertion failures selected in current also failed in the compatible upstream baseline. The original DNS eBPF fixture failed on upstream, while current selects zero tests due to its precise libtrace gate. Both plugin check tests exited signal11.

- Six tunnel failures (`decapsulate_all`, ERSPAN I/II/III, TEB, VXLAN-NSH): real missing functionality. `agent/plugins/tunnel/src/lib.rs` returns `None` for the relevant public plugin entry points in both revisions. Expected nonzero offsets/ERSPAN bitmap cannot be produced. Fixtures exist. These are not missing-tool failures.
- `flow_node::test_packet_segmentation_reassembly`: public `PacketSegmentationReassembly::inject` and flush return `None`, and does_support returns false. Both revisions produce zero outputs versus expected2. This is another feature gap, not a fixture load failure.
- `config::check_defaults`: the YAML template includes a Lua/LuaJIT ProcessMatcher (`rewrite_name: "$5"`), while UserConfig::default does not. Both revisions have exactly this mismatch; snippets are in `*-config-diff.json`. Treat as a defaults-contract drift until the intended default is decided.
- `flow_map::test_handshake_retrans`: RTT client max1255 versus1567 in both revisions. The fixture loads and real assertion fails. Root cause remains unresolved; no assertion was relaxed.
- DNS `perf_with_blacklist`: upstream no-default rejects existing `udp-from-same-socket.log` as unsupported. Current correctly omits this libtrace-specific fixture from packet-mode. Default-feature behavior was not retested here.
- RocketMQ `check`: first heartbeat PCAP parses, but checked-in Debug-string snapshot lacks newly present fields (`is_async`, `is_reversed`, attributes and biz fields). `*-rocketmq.diff` shows equal core values/RRT for this first fixture. The test stops here, so later fixtures remain unverified.
- Hessian2 `decode_trace_id`: zero IDs versus one. The test encodes string tag0x74; the Hessian2 decoder supports S/R/compact tags and returns None for this tag. Same unchanged implementation and assertion fail on both revisions. Decoder/fixture dialect compatibility needs review; do not call it a missing fixture or fix by changing the expectation blindly.
- Memcached `check`: normal PCAP is accepted, but existing `memcached-userdata.pcap` has little-endian magic `d4c3b2a1` followed by version bytes `00020004` (interpreted as512.1024). libpcap rejects the malformed global header before protocol parsing. Both source revisions contain identical fixture bytes.
- `service_table::port_map`: actual253 versus expected0 after the final PSH scoring step in both revisions. A real scoring assertion remains unresolved; source/tests were not changed.
- Plugin `test_check`: SIGSEGV on both binaries. Rust `ParseCtx` passes `"".as_ptr()` as a C string; the C fixture prints it via `%s`. The std-only upstream probe prints the empty Rust str pointer as0x1. With the same .so, a NUL-terminated empty string returns proto1, while0x1 crashes immediately before the proc print (`plugin-c-abi-*.log`). This confirms a C-string boundary defect. Root assigned the repair separately; no plugin production change belongs to this report.

## Scoped time-function repair

`estimate_rrt_us_by_beijing_mmss` first added3600 for every negative difference, making its subsequent future-clamp branch unreachable. The upstream existing future-clamp test returned None and panicked. The function now chooses the nearest hour before clamping; past120s and cross-hour behavior retain their assertions.

Input checks now reject anything except four ASCII digits before slicing, and require minute/second<60. `upstream-time-input-probe.log` records the original Unicode slicing panic and acceptance of0060/6000/-110.

Only `agent/src/flow_generator/protocol_logs.rs` was changed by this task. Existing seven time tests plus seven additional cross-hour/input/fraction cases passed14/14 in the real crate (`current-time-inputs-final.log`). A first new valid0000 regression accidentally used epoch0; `current-time-inputs-after.log` preserves that test failure. The corrected test uses a nonzero whole hour and separately asserts that epoch0 remains rejected.

The final bound compares microseconds, so120s+1us is now rejected. `time-fraction-before.log` records the old Some(120000001) result. The added limit regression verifies exact120s accepted,120s+1us rejected, and119s+999999us preserved. To avoid contention with the plugin worker's Cargo target, the final verbatim pure function plus complete test module was compiled with std-only `rustc --test`; all15 pass in `time-module-final-standalone.log`. This does not substitute for the final real-crate integration gate: root must run filter `flow_generator::protocol_logs::tests` with the final combined changes.

## Resource and validation boundary

The independent copied target was5.1GB and triggered the host90% disk guard. After all paired builds and the initial time tests, its resolved absolute path was verified and only `.traflens/work/agent-baseline-20261026/target` was deleted. `cache-cleanup.json` records deletion and artifact hashes; df recovered17GB free/87%. Final input tests reused the existing main target sequentially with the plugin agent; no further target copy was made.

No Agent process, lab container, capture config, network interface, or repository commit/push was changed by this task. Other concurrent lab/source edits belong to their owners. No full-suite pass, default-feature pass, cross-toolchain invariance, or proof of unaffected later RocketMQ fixtures is claimed.
