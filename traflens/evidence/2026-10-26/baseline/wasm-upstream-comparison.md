# WASM failure comparison (2026-10-26)

Executed only the five newly visible WASM cases using the retained compatible upstream test binary, from the isolated upstream agent directory. No Cargo/build, target, source or fixture changes were made.

All five exit 101 with the same panic location and message as the current full-library log; all print the empty process-name mismatch before failing. Both the test source and compressed WASM fixture have identical SHA256 hashes between the checkouts.

The packet-only test build omits ebpf_param under cfg(libtrace), so the WASM fixture receives an empty process name although it expects test_wasm. This is a feature-scope fixture incompatibility reproduced on pinned upstream, not evidence of a new C-plugin regression.

Cases:
- plugin::wasm::test::test_check_payload: src/plugin/wasm/test.rs:280:5; identical panic.
- plugin::wasm::test::test_wasm_http_req: src/plugin/wasm/test.rs:175:18; identical panic.
- plugin::wasm::test::test_wasm_http_resp: src/plugin/wasm/test.rs:233:18; identical panic.
- plugin::wasm::test::test_wasm_parse_payload_req: src/plugin/wasm/test.rs:305:10; identical panic.
- plugin::wasm::test::test_wasm_parse_payload_resp: src/plugin/wasm/test.rs:380:10; identical panic.

Inputs and full commands are recorded in wasm-upstream-comparison.json; raw logs are in upstream-wasm-tests/. The current comparison log is ../protocols-20261026/agent-full-lib-final.log.

No default-feature WASM behavior or complete upstream library pass is claimed. These failures remain deferred; no test expectations were weakened.
