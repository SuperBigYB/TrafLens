# Agent protocol and plugin contract gate

`bash traflens/scripts/agent-packet.sh parser-test` now runs the complete packet
Agent library and both tunnel/window plugin crates. `test-library` runs only
the Agent library. Both modes first verify the checked-in WASM fixture inputs
and outputs, and build the existing C plugin fixture. Individual protocol,
direction and segmentation commands remain available for diagnosis.

The committed source checkpoint is `913231d6a7918edadd8db48a4e5d38ec9b76601d`. Complete packet
library: **371/371**; default-feature native library:
**382/382**; tunnel/window crates: **28+21**.
All have zero failures and ignored tests. Lab helpers124 and focused Go4 pass;
full Server configuration-package success is not claimed.

## Configuration and protocol fixtures

The Rust default process matchers now include the Lua matcher already documented
in the controller template. Lua/LuaJIT script names use capture four; capture five
does not exist in that expression. Omitted, standalone, explicit and controller
template paths are checked without weakening the original whole-config equality
test. Triple and Dameng port/tag filter defaults are synchronized with their
existing Rust defaults. This neither enables those protocols nor removes their
existing feature gates.

RocketMQ's ten public PCAP fixtures retain exactly the same old output fields.
Their golden Debug strings now include seven new default metadata fields.
Independent JSON/binary remoting vectors also cover serialization type, flags,
unsigned opaque identifiers and malformed/truncated headers. Production
RocketMQ decoding is unchanged.

The existing public `memcached-userdata.pcap` mixed little-endian magic and
packet records with big-endian global version bytes. Only offsets 4–7 are
corrected to little-endian version 2.4. The complete packet-record region stays
byte-identical: SHA256
`f78dccea332db603ad6b648d4bdba4c46279a54ba952f365abc293a6077ead2d`.
All 20,421 record boundaries and both original parser goldens are checked.
Additional text-protocol vectors cover declared byte lengths, binary values,
embedded CRLF/commands and truncated capture. This changes an already public
test fixture; no new captured traffic is published.

Hessian tests now use valid Hessian strings rather than Java ObjectStream's
`TC_STRING`. A complete ASCII string/chunk envelope is checked before calling
the shared decoder, preventing EOF panics, truncated-header success and
unfinished chunks. Valid Java data remains a negative Hessian control. This is
still a best-effort ASCII attachment lookup, not a complete Hessian map or
Unicode/CESU-8 decoder.

## WASM interoperability and bounds

The verified 2023 result layout omits both the protocol-name slot and the
later business-type trailer. The current layout is tried first, followed by
one complete old-layout parse. The 2023 fallback requires exact EOF; it does
not accept intermediate historical variants with an extra business trailer.
The one-byte trailer is optional, complete attribute pairs are required, and
truncated response fields return errors instead of indexing beyond the buffer.
In the current layout a lone final byte is interpreted as business type; this versionless legacy
format cannot distinguish it from the first byte of a truncated next length.
Unknown longer trailers are rejected. This unversioned format can be ambiguous
between complete supported layouts; current layout wins. The protobuf path
remains separate.

Custom request/response merge flags now populate the performance cache's merge
state. Incomplete chunks do not count as complete requests/responses; end flags,
RRT, cache retirement, reversed direction and async behavior have independent
regressions. The production performance assertions remain enabled.

Guest memory is validated in the host's checked address domain before reads,
writes or log access. Missing memory/context and invalid ranges fail safely.
Request, response and custom serializer failures retain their context so a
subsequent valid call can succeed. Real WAT guests exercise those boundaries
and compare valid ABI bytes. Production serializer layouts are unchanged.

Modern TinyGo guests require three additional standard WASI imports:
`poll_oneoff`, `sock_recv` and `random_get`. The context still inherits no
environment, preopened directory or socket. Invalid socket descriptors return
BADF and empty polling returns INVAL. Initialization accepts a normal return or
typed WASI exit status zero; nonzero exits and other traps remain failures.
Required export checks and hook registration remain in force.

The HTTP SDK adapter preserves explicit legacy User-Agent/Referer values, then
falls back to the latest matching already captured attributes. It does not
rescan raw headers, enable default capture or add persisted legacy fields.
The HTTP integration test opts those headers in and checks the exact captured
and plugin-generated attribute set, trace IDs, rewritten fields and status.

## Reproducible guests and scope

`agent/resources/test/plugins/wasm-fixture/` contains ordinary Go source, pinned
module checksums, the exact TinyGo image digest and a rebuild command. Packet
and native guests enforce their corresponding process-name context. Each guest
was built twice with identical WASM and deterministic gzip bytes. Offline
verification rejects changed inputs, unexpected source files or corrupted
outputs. The original 2023 guest is unchanged and has a separate native legacy
compatibility regression.

The pinned Go SDK omits serialization of its existing merge/end flag. The
fixture build applies a reviewable, checksum-guarded patch for protobuf field
21; it does not substitute the unrelated async flag. This patched fixture tests
the host's merge/end contract and is not proof that an unmodified SDK emits it.
Build instructions, hashes, source attribution and this qualification are kept
with the fixture. Regular CI verifies the committed guests without Docker or
downloading TinyGo.

Public results are aggregate summaries. Detailed test logs and working artifacts
remain in ignored local storage. Passing library and native build gates does
not establish live eBPF tracing, sustained throughput, storage robustness,
arbitrary TCP stream reconstruction or complete DeepFlow parity. The inherited
full Server configuration-package failures remain a separate task; its focused
TCP-window configuration tests are checked independently.

Valid stable-ID merge streams are covered; malformed or changing merge identities
remain a separate validation task.
