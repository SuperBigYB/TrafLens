# WASM parser regression fixtures

These guests exercise the Agent host ABI with strict HTTP and custom-protocol
context, payload and output assertions. `packet` expects an empty process name;
`native` expects `test_wasm`. Both use HTTP protocol 20, custom protocol 1, and
current SDK check-payload direction encoding. The original 2023
`../wasm_test.wasm.gz` remains a separate legacy compatibility fixture.

The source is adapted from the Apache-2.0 Go fixture formerly embedded in
`agent/src/plugin/wasm/test.rs`. `decode.go` implements only the two documented
fixture input protobuf messages; output messages use the pinned SDK protobuf
serializer. Its tests cover known vectors, malformed messages and unknown fields.
The HTTP guest checks the exact response headers/body and parses its JSON without
network calls. Request attributes include `a`, `b`, `c` and the empty value.

## Verify checked-in fixtures

```sh
python3 agent/resources/test/plugins/wasm-fixture/verify.py
```

This offline check validates every committed source/dependency/build input hash,
gzip header timestamp, decompressed WASM hash and output length. A changed input
requires regenerating both fixtures and the manifest. It does not execute the
WASM or replace the owning Rust host tests.

## Rebuild

Requires Python 3, Docker, and access to public dependency downloads. Run:

```sh
python3 agent/resources/test/plugins/wasm-fixture/build.py
# Or choose a fresh retained build directory:
python3 agent/resources/test/plugins/wasm-fixture/build.py --work /tmp/traflens-wasm-fixture-rebuild
```

The script creates a new owned directory and mounts only it in the official image
`ghcr.io/tinygo-org/tinygo@sha256:52907162ca3ba807c3c0914e07daffc1fe0c50ce91445ec43a0428337dc1b901`
(TinyGo 0.42.0, Go 1.27.0, LLVM 22.1.4). It uses 4 CPUs, 8 GiB, 4096 PIDs,
drops all capabilities and enables no-new-privileges. Public dependency preparation
uses private Go module/build caches. Compilation is offline. No host credential or
Docker socket is mounted inside the build container. The directory is retained
for diagnosis; caches and raw logs are not committed.

SDK base commit:
`3ac5fba17db6cc03ae6ed82254e2a0a9f39a5e9d` in
[deepflow-wasm-go-sdk](https://github.com/deepflowio/deepflow-wasm-go-sdk/tree/3ac5fba17db6cc03ae6ed82254e2a0a9f39a5e9d).
The public archive, original serializer, patch and patched serializer hashes are in
`sdk-provenance.json`. The SDK is extracted with link/path checks, and all hashes
must match before the patch is applied. `go.mod`/`go.sum` pin dependencies; the
isolated build adds a local replacement for that verified SDK tree.

**Disclosed SDK patch:** the pinned SDK exposes `ProtocolMerge` and `IsEnd`, but
its current protobuf serializer omits `AppInfo.is_end` (field 21).
`sdk-is-end.patch` sets that existing optional field only when `ProtocolMerge` is
true. This fixture uses the patched SDK; it does not prove the unmodified SDK
correctly emits merge/end flags. `IsAsync` is not changed. No production ABI or
SDK protobuf definition is changed.

The build uses `-target=wasi -scheduler=asyncify -panic=trap -no-debug -opt=z`.
Go 1.27's timer implementation requires scheduler support even without guest
networking. Each flavor is compiled twice with identical inputs and compared
byte for byte. Each gzip is then generated with level 9 and timestamp zero and
compared again. `build-manifest.json` records input hashes and both compressed
and decompressed output hashes. The two build tags differ only in the expected
process-name constant. Host integration results are recorded separately by the
owning Rust test gate.
