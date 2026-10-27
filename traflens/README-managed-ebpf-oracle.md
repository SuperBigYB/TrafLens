# Managed eBPF HTTP oracle

`traflens/lab/verify-managed-ebpf.py` is a read-only acceptance tool for the bounded loopback workload in `ebpf-netns-gate.c`. It queries an existing owned isolated lab after traffic has finished. It never starts Agent, hooks, containers or traffic, and never changes a controller profile or database.

## Why 20 requests require 40 Sessions

The positive worker owns both the client socket and a separately accepted server socket in one process and target network namespace. It reuses this connection pair for 20 unique HTTP exchanges. Each exchange has two process observation points: `c-p` (client) and `s-p` (server), as documented in [DeepFlow AutoMetrics](https://www.deepflow.io/docs/features/universal-map/auto-metrics/).

Native socket state is keyed by host TGID and FD and assigns a separate socket UID to each endpoint. `MetaPacket::generate_ebpf_flow_id()` retains that socket identity. The eBPF [FlowMap key](https://github.com/deepflowio/deepflow/blob/a2cd9553ff22c80561cf14e8938aea91c83ea6ed/agent/src/flow_generator/flow_node.rs#L91-L97) uses the generated flow ID, and the [L7 session key](https://github.com/deepflowio/deepflow/blob/a2cd9553ff22c80561cf14e8938aea91c83ea6ed/agent/src/flow_generator/protocol_logs/parser.rs#L223-L275) keeps its full 64 bits together with protocol and capture sequence/session ID. Equal PID, reversed five-tuple or request resource does not merge the two socket observations.

The [signal-source enum](https://github.com/deepflowio/deepflow/blob/a2cd9553ff22c80561cf14e8938aea91c83ea6ed/server/libs/datatype/flow.go#L101-L109) assigns `signal_source=3` to eBPF; the [point mapping](https://github.com/deepflowio/deepflow/blob/a2cd9553ff22c80561cf14e8938aea91c83ea6ed/server/libs/flow-metrics/tag.go#L224-L225) stores `c-p`/`s-p`. Current Server persists a completed Session as `type=2`. Source review and a private source-extracted arithmetic probe confirmed 40 matching request/response keys across two distinct socket flow IDs (85 assertions). That probe does not establish parser, kernel or ingestion success.

## Strict contract

- Exactly 40 complete successful HTTP Sessions: resources `/traflens-ebpf/<marker>/positive/01` through `/20`, each once at each process observation point. GET/200, `response_status=0`, HTTP (`l7_protocol=20`), TCP (`protocol=6`), `signal_source=3`, expected Agent ID, domain and server port must match.
- Exactly two distinct full-precision UInt64 flow IDs: one with 20 Sessions per point. All rows share one ephemeral client port. The worker's **host TGID** occupies `process_id_0` on `c-p` and `process_id_1` on `s-p`; the other process field remains zero.
- Both verified C receipts are required: positive 20 and negative 40 exchanges, with the same fresh marker. The negative phases are 10/20/10. Failed receipts or duplicate resources fail validation.
- The main query selects the whole marker family without source, Agent, protocol, status or observation-point filters. A separate negative-prefix query also has no source filter. Both must succeed on two successive reads; negative rows must be zero.
- Unsupported columns, API errors, malformed/multiple JSON bodies, duplicated JSON keys and wrong shapes fail. Floats and booleans cannot become integer identities. Duplicates cannot compensate for missing requests.

The existing API was independently checked using an 18-column `LIMIT 0` query and native schema inspection. Raw `observation_point` is a string and `flow_id` is UInt64. The helper uses `observation_point` directly, avoiding display-name Enum conversion. A nonexistent-column negative control returned an API failure rather than a successful empty result.

## Invocation

The operator must first establish the exact binary/config/namespace scope, bounded Agent lifetime, successful capture readiness and completed workload receipts. Keep AF_PACKET and unsupported collection paths disabled according to the scope contract. Both process observation points must remain enabled. Align the C worker port with the managed HTTP inference port; the oracle requires an explicit port.

Run on the existing isolated lab host, with a fresh output directory strictly under its canonical owned root:

```sh
python3 traflens/lab/verify-managed-ebpf.py \
  --root "$LAB_ROOT" --marker "$FRESH_MARKER" \
  --agent-id "$REGISTERED_AGENT_ID" --worker-host-pid "$POSITIVE_HOST_TGID" \
  --server-port "$HTTP_PORT" \
  --positive-receipt "$POSITIVE_RECEIPT_JSON" \
  --negative-receipt "$NEGATIVE_RECEIPT_JSON" \
  --output "$LAB_ROOT/$FRESH_MARKER/oracle" --timeout 150
```

The helper checks the lab owner receipt, exact container ownership and fixed loopback query binding, and compares Server/MySQL/ClickHouse identities before and after. Responses and results are written mode0600 in the private output directory. Preserve failed markers; a new run uses a new marker and output directory. Raw evidence and deployment receipts remain private.

## Validation and current qualification

The standalone stdlib suite has 17 tests, including missing-versus-duplicate rows, observation/process identity, two-flow separation, UInt64 precision, malformed/error responses, SQL marker validation and wrong ownership/binding. Run it with:

```sh
python3 -m unittest discover -s traflens/lab/tests -p test_managed_ebpf.py
```

A retained controlled trial produced 39/40 complete Sessions (`c-p=20`, `s-p=19`), missing the first server-side observation. All 74 negative reads were empty, but the strict 150-second oracle correctly failed. This is an unresolved observed loss, not a passing managed-Agent ingestion result. No prewarming or relaxed expectation substitutes for the missing Session.

This tool qualifies only this finite dual-endpoint syscall HTTP workload. It does not prove global process-metadata isolation, profiling/TLS/file-IO coverage, arbitrary-kernel support or DeepFlow feature/performance parity. A topology with only one endpoint in scope has a different 20-Session contract and must use a separately justified oracle.

A malformed SUCCESS response that omits the `values` field is rejected. Explicit `values:null` and `values:[]` retain the Server's empty-result semantics. The regression failed against the earlier helper and passes after this narrow fix; all 152 retained trial responses explicitly contain `values`, so their recorded outcomes are unaffected.

A subsequent run of the same native core passed the unchanged oracle: 40 complete Sessions (`c-p=20`, `s-p=20`) on two consecutive reads, with zero negative rows. That run enabled a short stdout diagnostic restricted to the positive synthetic process, HTTP1 and worker port. Its first server request and response arrived in order. The earlier non-diagnostic loss remains unexplained; the diagnostic changes timing and is not a production fix. Both results are retained in the [managed checkpoint](evidence/2026-10-27/managed-ebpf/summary.json).
