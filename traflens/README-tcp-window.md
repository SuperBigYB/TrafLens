# Adjacent TCP parsing windows

The `155c5ff79ce19d31efd6cf1522c5b40a2b150d31` source checkpoint implements
the adjacent two-packet aggregation described by the [pinned Agent configuration](https://github.com/deepflowio/deepflow/blob/8741e924ff0ae3964a135985c51e5a6ce6bde397/server/agent_config/example.yaml).
The former community plugin was a stub. This implementation retains package paths,
licensing and the original inject/flush/reverse entry-point signatures, with
updated MetaPacket/FlowMap integration and an extended Segment trait.

Enable it explicitly with TCP port strings or ranges:

```yaml
inputs:
  cbpf:
    preprocess:
      packet_segmentation_reassembly: ["18080"]
```

The public controller template defaults to an empty list. The setting requires
an Agent restart. The legacy `static_config.packet-segmentation-reassembly`
numeric uint16 list migrates to decimal port strings; its existing invalid-input
boundary is preserved. Template metadata, round trips and the public upgrade
path have a separate four-test Go gate in CI.

For contiguous payloads `p1,p2,p3`, the parser receives `p1+p2`, `p2+p3`, then
the original `p3` at flush. The overlap is intentional. Exact wrapping TCP
sequence adjacency and complete captured payloads are required. Gaps, overlaps,
retransmissions and snaplen truncation do not produce concatenated windows.
Pure ACKs leave the pending carrier intact; SYN/FIN/RST flush their direction.
Flow close and forced reporting flush pending tails before metric reset.

Original packets feed transport metrics exactly once and in their arrival
order. Derived windows feed only application parsing. A flow-direction change
reverses pending carriers and their buckets, and delayed parsing aligns each
carrier with the current flow tuple. Regression tests cover original TCP
metrics with interleaved ACK/retransmission, split HTTP, sequence gaps, complete
HTTP uniqueness, keepalive tails and direction correction after reporting.

Each direction retains at most one carrier, limited to 64 KiB of owned memory.
All cached carriers share a 64 MiB process-wide retained-memory budget. Failed
admission passes inputs through without losing the prior carrier. Vec capacities
and owned metadata count toward the limit; windows already emitted for parsing
are outside this budget. This is not a bound on total Agent RSS. The owned
snapshot path can make an additional transient copy and needs performance
measurement before optimization claims.

The same checkpoint fixes configured service-port score retention, priority
against strong SYN-ACK/L7 evidence, and reverse-direction cache updates. The
historical handshake test now reflects the existing first-ACK completion rule
and verifies that a later duplicate ACK does not alter its latency metrics.
The production handshake algorithm was not changed.

## Validation

```sh
bash traflens/scripts/agent-packet.sh parser-test
python3 -m unittest discover -s traflens/lab/tests -p 'test_*.py' -v
cd server
go test -mod=vendor ./agent_config -run '^TestTCPWindow' -timeout 120s -count=1
```

The selected packet-mode gate passes 168 tests: 119 Agent-library tests and
49 plugin-crate tests. All 124 lab-helper tests and the four focused Go tests
pass. The broader packet Agent library completes 321 tests: 312 pass and nine
known failures remain in defaults, RocketMQ, Hessian2, memcached and five WASM
cases. Full `agent_config` still has the same inherited five top-level and seven
subcase failure names and the same panic as isolated parent `395f155d`; cases
after that panic are unverified. Selected CI success does not imply either full
suite passes. Evidence retains both failed controls and final successful gates.

## Bounded direct-link check

The lab's `segmentation` profile derives from its strict tunnel Mirror profile
and enables only TCP port 18080 for this feature. It retains the lab's 2-core,
1024 MiB Agent and interface/MAC/benchmark-address filters. Packet BPF remains
enabled; the explicit lab NPB exclusion override is needed to admit ERSPAN III.

Generate an offline plan before any bounded run; replace the lowercase marker with a fresh value for each run:

```sh
python3 traflens/lab/tunnel-traffic.py plan --marker sw20261027new \
  --flavors all --count 1 --http-split-at 2 --pps 20 --timeout 30 \
  --output-dir .traflens/work/sw20261027new-plan
```

The split fixture carries 20 HTTP and 20 DNS conversations through eleven
tunnel layouts with both inner address families. Each HTTP request and
response start with a two-byte TCP fragment, followed by the remaining bytes;
DNS packets are unchanged. This yields 300 frames, including handshakes and
FIN closure. The default unsplit fixture remains byte-identical to its prior
260-frame form.

For emission, use the lease, capture-readiness and exact query checks described
in `README-tunnel-wire.md`, with `--http-split-at 2`. Start the finite receiver
capture and debug-copy observers before emission; an open stats port alone does
not establish capture readiness. Record version/hash proof for both binaries,
exact queried multisets twice, persisted flow metadata/closure, received frame
bytes/order, and cleanup of both link leases and the Agent supervisor.

## Accepted checkpoint

Marker `sw20261027a1` passes on the physical two-host link with matching
Server and packet Agent revision `155c5ff79`. All 300 received Ethernet frames
match the generated bytes and order; kernel capture drops are zero. The query
API returns exactly HTTP20 and DNS20 twice, including the first DNS record.
All 40 associated flows pass the strict tunnel metadata and complete closure
checks twice. The 100-second capture and 90-second debug observers exit cleanly;
both 240-second network leases remove their exact temporary addresses/routes,
and the owned Agent supervisor is stopped. Both database containers retain their
original identities/start times while only the owned Server was replaced.

The packet functional binary SHA256 is
`b729693df8aae3bb06d8be8aaffa759b3f737fc2a2ddd2f33b20ae0860fcb138`.
The separate default-feature optimized native Release build passes all 41 selected
native tests and embeds the same source commit. Its 77,902,304-byte binary SHA256
is `ed4e9600686744d2e25ef32f4946f2fc986c9fdd446cc3423166055844a26862`.
`ldd` reports no missing libraries; libtrace and ten BPF ELF objects are present,
with ELF type/machine/checksum validation. These are build and test results;
the accepted live traffic uses the packet functional binary.

The native primary Git checkout is clean. Its archive-populated jattach
submodule retains one pre-existing Makefile patch to build the static library;
all ten non-Makefile archive files, including all five C sources, match the dependency pin.
The OTel archive files also match their pin. Evidence retains the patch and
upstream/actual hashes; a clean primary checkout does not imply an unmodified
jattach build file. The initial post-build proof used an incorrect `*.o` glob;
the retained correction checks the actual `*.bpf.elf` objects without rebuilding
or rerunning the already successful tests.

[Core CI run 40371413194](https://github.com/SuperBigYB/TrafLens/actions/runs/40371413194)
passes both jobs, including 168 selected Cargo tests, all 124 lab tests, the new
configuration gate and the exact embedded CommitId check. The published aggregate summary is
`evidence/2026-10-27/tcp-window/summary.json`. Complete test logs, raw queries,
PCAPs, failed controls and detailed environment/cleanup evidence are retained
only in ignored local files, excluded from the published repository.

This checkpoint supplies two-packet parse windows, not a complete TCP stream.
Arbitrary multi-segment messages, out-of-order buffering, loss recovery, live
eBPF, sustained performance and full DeepFlow parity remain separate work.
