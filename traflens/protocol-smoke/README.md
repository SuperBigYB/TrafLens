# Pinned protobuf compatibility smoke checks

Run from the TrafLens checkout on Linux:

```sh
bash traflens/protocol-smoke/run.sh
```

Requires Git, Bash, Go 1.18 or later, protoc and Python 3. The first run downloads
only the pinned `github.com/gogo/protobuf v1.3.2` module; its hashes are checked by
Go. Set `GO=/absolute/path/to/go` or `PROTOC=/absolute/path/to/protoc` if needed.
`GOWORK=off` and `GOTOOLCHAIN=local` keep generation independent of the server's
large module/workspace. `KEEP_WORK=1` retains generated scratch files for diagnosis.

The compatibility reference is upstream DeepFlow commit
`8741e924ff0ae3964a135985c51e5a6ce6bde397`. The script reads `flow_log.proto` and
`stats.proto` from the candidate working tree, copies them into `.traflens/work/`, enables exactly
the four commented gogo import/options used by upstream `server/Makefile`, and
generates with the official datatype/stats `--gogo_out=plugins=grpc` recipe.
Source schemas, vendored code and generated files in the checkout are untouched.
The script separately reads the original schemas from the pinned commit with
`git show` and uses those unmodified reference schemas for `protoc --encode`.
Generated candidate Go code decodes this baseline wire data, so a change to any
populated fixture field cannot be hidden by changing both encoder and decoder.
Explicit field-number/type contracts additionally cover the listed fields.
The temporary directory is removed when the command exits unless retained.

Tests cover:

- HTTP L7 request and response fields, session discriminators, trace metadata,
  request/response lengths and TCP sequence numbers, including large unsigned IDs.
- Bidirectional L4 counters beyond 32 bits, negative EPC IDs, TCP performance
  counters and repeated packed identifiers.
- Agent statistics with paired labels and floating metrics.
- Pinned-baseline `protoc --encode` text fixtures decoded by candidate Go code,
  generated encode/decode equality and encoded-size consistency.
- Added unknown varint, bytes, fixed32 and fixed64 fields surviving remarshal
  without changing known values; truncated input must be rejected.
- Explicit field-number and protobuf-type contracts, so a self-consistent
  encoder/decoder schema mistake cannot silently pass a roundtrip check.

Protocol discriminator values are taken from the pinned
`agent/crates/public/src/l7_protocol.rs` (`Http1=20`, request=0, response=1,
session=2); response statuses are checked against the pinned public enum tests
(`Ok=0`, `ServerError=3`). Synthetic fields 65000-65003 are compatibility probes,
not claims about an existing upstream extension.

This is a schema/wire smoke test. It does not validate packet parsing, framing of
the agent's transport stream, controller registration, ingestion, queries, tracing
accuracy, UI compatibility or feature/performance parity.
