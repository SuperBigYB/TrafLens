# UDP DNS multi-peer checkpoint (M17)

M17 remains active and unqualified. Only the source audit and an offline-tested
finite wire fixture are delivered here. No multi-peer capture, storage, API or
browser acceptance has run; no native fix is justified by this checkpoint alone.

## Actual source scope

The eBPF flow node key uses `generate_ebpf_flow_id()` rather than peer tuple
(`agent/src/flow_generator/flow_node.rs:91`). Matching derives direction from the
initial client IP/port (:206); logged tuple fields come from flow peer metrics
(`protocol_logs/parser.rs:115`). The reported ID replaces socket-UID bits48..55
with input source (`common/meta_packet.rs:1037`). DNS exposes its 16-bit TXID as
session ID (`protocol_logs/dns.rs:142`). This is a source-derived risk, not proof
that the complete live pipeline misassociates two peers. Preserve all observations
and localize any actual discrepancy before changing native code.

## Finite fixture

`python3 traflens/lab/dns-udp-multipeer-fixture.py` is offline by default. It opens
no socket, creates no output and starts no Agent. The explicit execution form is:

```sh
python3 traflens/lab/dns-udp-multipeer-fixture.py --execute \
  --run udpmp-<24-lowercase-hex> --output <fresh-private-directory> \
  --require-netns-inode <actual-owned-namespace-inode>
```

Execute only inside a deliberately owned isolated namespace after its identity,
process scope and restoration contract have been proved; do not run against an
existing DNS service or substitute the management namespace. All addresses are
fixed loopback, port18080, without reuse flags. Three separately spawned workers
own one server UDP socket and two bound client ports. The first two exchanges
have distinct TXIDs. The second pair has the same TXID, both questions arrive
before either response, and responses are sent in reverse arrival order. There
are exactly four real exchanges, two success and two NXDOMAIN outcomes, with
small unprefixed datagrams and no fabricated ingestion. Each worker has bounded
socket/control waits; the parent joins/terminates/kills only its own children.

Private receipt keeps each actual syscall byte string/SHA, endpoint tuple,
PID/TID/startticks/netns and socket FD; never print it wholesale or publish it.
The CLI does not print runtime test data. `native_source3_verified` is always
false: wire execution alone cannot prove eBPF collection or database acceptance.
The six targeted tests verify message identities, errors, repeated-ID questions,
invalid inputs, default-offline behavior and required execute identity. They do
not execute the socket path or qualify the actual fixture runtime.

## Next direct step

Add a separate multi-peer preparation/worker/receipt and independent verifier
contract before a scoped capture. Existing single-peer C runtime/verifier schemas
explicitly require one peer and three distinct transactions; do not weaken them
or fabricate their receipts to run this scenario. First prove the isolated wire
fixture, then one necessary fresh scoped capture with an outside-namespace
control. Expected eight source3 observations must match actual tuple/TXID/wire
and process identity, with complete repeated reads, exact API details and scoped
browser checks. Unknown, orphan, missing and tuple-conflicting records stay in the
population. Any native change requires a real release artifact and necessary
scope qualification. M17-02..05 and production functionality are still open.
