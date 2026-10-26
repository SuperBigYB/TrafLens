# Configuration conversion and plugin session guards

This checkpoint uses core source `62429a607627051c3f242247ff646c67fee80e3e`. It closes the inherited full
`server/agent_config` panic/failures and adds validation before untrusted plugin
merge metadata reaches shared performance state. Source contracts come from the
pinned DeepFlow template, its HOWTO and history: metadata/default changes in
`57e7371292bd352ae352b6e58cd7a211b12fbf42` and domain UUID preservation in
`41a2b2b4baf3f5ff2d74c3363c77075090c4d037`.

## Configuration behavior

Template comment conversion now checks EOF and malformed metadata, requires
valid dict defaults, propagates recursive conversion errors and avoids unsafe
type assertions. JSON normalization works on typed values, preserving embedded
strings such as `keep: null`, array semantics and full integer precision.
Existing null normalization remains unchanged. JSON normalization does not mutate
its input; conversion of already structured dict values is idempotent. Old inline test expectations were aligned to the established
`value_comments` and schema-default contract instead of removing assertions.

Legacy migration now appends the correct on/off-CPU feature to process matchers,
preserves matcher order and applies the canonical static tagged-only setting.
The historical root alias remains accepted; conflicting aliases return an error.
Recognized malformed matcher/scalar inputs fail before assertions. Reusing one
upgrader resets the per-call manual fields. Domain UUIDs retain the established
upstream contract; the numeric TCP-window migration is unchanged.

DB/YAML conversion returns errors for malformed static YAML and CSV fields.
YAML-to-DB conversion checks rate-unit multiplication before committing a copied
model, so parse errors and overflow leave the destination intact. Existing valid
units, explicit zeros, identifiers, domains and plugin lists have independent
roundtrip assertions. Entire configuration documents are no longer logged on
parse failures. These checks cover recognized fields, not a complete new legacy
schema validator or a changed policy for representable signed values.

Test outputs use temporary directories. The old developer-file print test is
now self-contained with valid-JSON assertions. Earlier generated artifacts were
preserved privately; regular tests no longer recreate `test_tmp`.

## Plugin session behavior

Malformed plugin metadata could request multi-message merging without a request ID and reach a shared performance assertion. Reusing an active session key with a different merge mode could also mix incompatible cache representations and panic. The C ABI emits plain results, but its flow ID, session ID, and reversal flag can collide with a merged WASM entry.

The decoder now rejects missing merge identities after completing legacy or Protobuf layout selection; an explicit ID of zero remains valid. Before updating statistics or the session cache, the WASM wrapper checks the entire batch against existing entries and a batch-local key-to-mode map. A conflict rejects the whole batch at that boundary, preserving cached requests and accounting. This deliberately conservative contract also rejects different modes for one key within a batch that might otherwise be interpreted as completing and reusing a session. The C wrapper applies the same compatibility check with its existing per-item rejection behavior.

The new `RrtCache::peek` does not refresh LRU order. Async results bypass mode checks because they do not enter session aggregation, while missing required IDs remain invalid. Reversed results use their separate key. Normal completion, flow removal, and existing capacity eviction allow later mode changes.

Real WASM guests exercise the host metadata import and parser wrapper: the five initial regressions went from one pass/four failures to passing. The final scoped plugin suite passed 56 tests, with zero failures or ignored tests. Coverage includes atomic rejection, correct response closure after rejection, driven LRU eviction, async/reversed controls, and timeout boundaries. Actual C `ParseInfo` conversion proves the cross-plugin collision and safe rejection/closure; existing C callback tests also pass.

`rrt_timeout` limits RTT accounting; it is not a cache TTL. An incompatible mode remains rejected while the entry exists. Shared assertions and timeout algorithms are unchanged. A separate direct control, calling no new decoder, wrapper, guard, or `peek`, verifies 12 cases against production bodies proven byte-identical to the baseline. At RTT 999 or 1000 microseconds with threshold 1000, both modes and arrival orders count one RTT sample. At 1001, request-first accounting yields plain timeout=1 and multi-message timeout=0; response-first yields timeout=1 for either mode. Response-first arrival preserves original capture timestamps. These are existing behaviors, not an endorsement of the policy or a claim that arrival orders are equivalent.

## Validation and reproduction

```sh
make -C traflens server
cd server
go test -mod=vendor -race ./agent_config -timeout 120s -count=1
cd ..
bash traflens/scripts/agent-packet.sh parser-test
bash traflens/scripts/agent-packet.sh build
python3 -m unittest discover -s traflens/lab/tests -p 'test_*.py'
```

The complete configuration race gate passes **44 top-level tests /129 total
test-pass events (85 subtests)**, with no failures or skips. CI runs this whole package.
The complete packet gate passes **382+28+21=431**; default-feature native release
passes **393+28+21=442**, all with zero failures or ignored tests.
The unchanged original2023 SDK keeper passes in native mode. All124 lab and18
distribution Python tests pass. Server and packet binaries embed exact source
`62429a607`; native version, ldd, libtrace and ten BPF compilation artifacts pass.
Native uses the pinned official image, Rust1.97.1 and image login-shell GCC11.2.1,
offline with4CPU/8GiB; the pre-existing jattach Makefile build overlay remains
explicitly qualified.

[Core CI](https://github.com/SuperBigYB/TrafLens/actions/runs/40395398781) checks Server and packet jobs. The
[aggregate evidence](evidence/2026-10-27/config-parity/summary.json) includes
checksums and a private-manifest fingerprint. Detailed logs stay ignored.
Live eBPF, broader services, storage ambiguity, API robustness and sustained
candidate/reference performance still require validation; full parity is ongoing.
