# Managed single-peer eBPF UDP DNS

This is a separate UDP entry; the old DNS/TCP and MySQL defaults remain unchanged.
The finite scope is one connected client UDP socket, one bound server UDP socket,
three distinct TXIDs and three actual DNS exchanges. Both sockets explicitly bind;
client connects to the single peer while the server uses recvfrom/sendto. Each
process records six complete datagram IO, flags0 and at most512DNS bytes. There is
no TCP length prefix, EOF or per-query wait. A short external identity gate is
not a latency/performance measurement.

## Current qualification checkpoint

The new C fixture passes static build and targeted offline/isolated wire checks.
The retained R25 two-host capture passes actual namespace/FD/map/noAF_PACKET
readiness and four owned worker exits. In R31, specific authorization allowed the
same capture's corrected acceptance result to be read and its finite console
workflow checked; no new capture was made.

The independent acceptance passes six source3 Session observations with UDP17 and
L7 DNS120 for three real positive DNS exchanges. Three outside-scope exchanges
produce zero stored records; source0/4 controls are empty. Both whole-marker and
unfiltered Agent/time populations pass twice with unchanged records, wire/host
PID/TID/tuple checks and six exact API details, using25data requests.

An actual restricted Edge run passes all six details, four normal/two NXDOMAIN
observations and empty source0/4 controls with no page errors. Its29data requests
stay in the authorized scope; seven initialization API requests are blocked,
with zero out-of-scope or fabricated requests. Full metadata is not persisted on
the workstation; the reviewed screenshot is masked.

The first planned oracle failed before queries because a worker declaration was
missing. That source, failed result and original capture remain unchanged. The
corrected verifier's explicit planned-source archive bridge and direct regressions
remain recorded; R31 resolves the earlier result-return authorization checkpoint
without relabeling the original failure or changing the captured population.

This round's final resource/restoration checks pass: temporary Query containers,
supervisor and all forwards are stopped, validation ports are closed, and the
original Server/config/Controller baselines are unchanged. M16 remains active
until both repository pushes are verified. The same-server-FD multi-peer case is only a
candidate for the next single milestone after that closure. These results qualify
this finite single-peer slice, not full UDP compatibility or DeepFlow parity.

## Prepare and run

Use owned private0700 parent directories on the two authorized hosts and a fresh
work directory/nonces per execution. Reuse the qualified native artifact only
with the actual new namespace FD/map/readiness gate. The native e1daf/0544 Agent
was not rebuilt here. Normal kernel2/4/5, DNS-only18080, exact positive namespace,
no AF_PACKET/proc/onCPU/DWARF/profile/OTLP and old Server preservation remain
mandatory. A DNS/TCP manifest is not accepted as the new DNS/UDP manifest.

```sh
python3 traflens/lab/managed-dns-udp.py plan
python3 traflens/lab/ebpf-dns-udp.py plan
python3 traflens/lab/verify-ebpf-dns-udp.py
```

Build the independent `traflens/lab/ebpf-dns-udp.c` with the existing static C
build prerequisites and record its exact source/binary hashes. The current fixed
fixture SHA is8858c47a1546427f563dafeeef2a10e237441290ae8c0d893d86db1cc0807ee8;
source SHA isdd82818b93477b7b2276dca1b3459b4651e4c8f81e35d70f88a0c6dfb11c391e.
The earlier unqualified prototype erroneously reported client bound0; both roles
now report bound1. Original prototype artifacts and selftest receipts remain
historical and are not relabeled as this candidate.

```sh
python3 traflens/lab/ebpf-dns-udp.py run --execute --work "$CAPTURE_NEW" \
  --backend-host dev-240 --backend-root "$PEER_LAB" \
  --backend-work "$PEER_CONTROLLER_NEW" --backend-code "$PEER_CODE" \
  --server-container traflens-lab-server --controller-url http://127.0.0.1:20417 \
  --controller-ip "$CONTROLLER_IP" --ctrl-ip "$SOURCE_CTRL_IP" --ctrl-mac "$SOURCE_MAC" \
  --controller-port 20035 --ingester-port 20033 --forward-port 24017 \
  --image "$CACHED_RUNTIME_IMAGE" --artifacts "$QUALIFIED_ARTIFACTS/prepared.json" \
  --workload-bin "$UDP_BINARY" --workload-sha256 "$UDP_BINARY_SHA256"
```

`kernel_dns` is the existing Controller profile/license mode. The new
`traflens.ebpf-dns-udp.capture.v1`/worker/scope schemas and transportudp are
explicit and do not accept TCP receipts. The preparation schema is
`traflens.managed-dns-udp-preparation.v1`. Actual Docker inspect, executable SHA,
PID/startticks, namespace and wire receipts are required; process names alone
prove no identity. Eleven fixed capture/producer/scope/oracle source hashes are
recorded. Worker/drain waits do not establish throughput or general reliability.

## Independent read-only acceptance

After capture cleanup, use the existing finite independent Query/console entry
and a real event-time window of at most60inclusive seconds. Credentials and full
Server configuration are not copied. Only execute/read/export data within the
user's authorization; retain private outputs on the owned host otherwise.

```sh
python3 traflens/lab/verify-ebpf-dns-udp.py --execute \
  --capture-dir "$CAPTURE_NEW" --query-base "$LOOPBACK_QUERY" --console-base "$LOOPBACK_CONSOLE" \
  --from "$EVENT_FROM" --to "$EVENT_TO" --agent "$ACTUAL_AGENT" \
  --native-source "$QUALIFIED_NATIVE_SOURCE" --native-sha256 "$QUALIFIED_NATIVE_SHA256" \
  --output "$ORACLE_NEW"
```

The oracle independently decodes datagrams/TXID/qname/A/RCODE/answers and exact
per-socket/process/tuple/time identities. It requires two whole-marker populations
and two **unfiltered Agent/time** Count/raw populations, all six Session records,
UDP17/L7DNS120/source3, four normal/two NXDOMAIN observations, outside/source0/4
empty and six exact API details. Missing/orphan/excess records, response/schema
failures and mismatched IDs/fields fail instead of being filtered away. There are
32maximum calls/64rows/4MiB bodies/60s total, with bounded per-request timeouts.
These are observation counts, not six business queries or full DNS compatibility.

For the retained pre-query oracle bug only, the planned verifier can differ from
the current corrected verifier. The operator must explicitly provide the actual
planned public source archive:

```sh
# Only if the originally recorded verifier had the retained bug:
# append --planned-verifier-source "$PRIVATE_PLANNED_VERIFIER_ARCHIVE"
```

The archive must be canonical, regular, current-owner/private, at most4MiB, and
its SHA must equal the capture's original planned verifier SHA. It is only hashed,
never executed. The current verifier must actually differ; no parameter/incorrect
archive fails. The other ten producer/runtime/C/scope hashes remain exact. Reports
record planned/archive/current verifier hashes and whether repair was applied.
This does not change the capture, old failed result, scope, wire, population or
native artifact rules. Fresh runs normally need no such option.

## Stop and limits

```sh
python3 traflens/lab/ebpf-dns-udp.py stop --execute --work "$CAPTURE_NEW"
```

Public cleanup removes owned workers, then stops Agent/BPF/tracefs, releases
namespaceFDs, restores the dedicated Controller lease and stops its forward.
Query/console and extra validation forwards use their own exact stop receipts.
Inspect errors are not absence and unknown programs are not detached.

Multi-peer same-server-FD tuple reuse is a source-derived risk, not validated by
this single-peer slice; test it as a separate mainline task. There is no claim of
multi-peer DNS, retry/loss/truncation/fragmentation, encrypted/recursive DNS,
maximum performance, causal tracing or global TXID identity. Keep raw wire/logs,
process/network identities and query outputs private and preserve every failure.
