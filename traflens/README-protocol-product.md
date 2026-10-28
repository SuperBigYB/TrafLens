# DNS and MySQL requests in the real-data console

The request explorer now names HTTP, HTTP/2, DNS and MySQL consistently in its
protocol selector, overview, relationship metadata and request list. Details
include `request_domain`, `response_result` and `response_exception`, alongside
the original protocol/status/source and exact string record ID. Shared resource,
time, protocol, source, relationship and Session filters retain their existing
meaning. Protocol names are display labels; the Query API still uses numeric IDs.

## Actual semantics and scope

Native `server/libs/datatype/flow.go` defines MySQL=60 and DNS=120. The existing
parsers are `agent/src/flow_generator/protocol_logs/sql/mysql.rs` and
`agent/src/flow_generator/protocol_logs/dns.rs`. The official
[DNS mapping](https://get.deepflow.io/docs/features/l7-protocols/network/) and
[MySQL mapping](https://get.deepflow.io/docs/features/l7-protocols/sql/) describe
the protocol context; the current stored records verify the following slice:

- DNS IN A: `request_type=A`, resource/domain=QNAME, `response_code=0` (RCODE),
  `response_status=0`, and `response_result=A=<answer> TTL=60`.
- MySQL protocol 4.1 plaintext `COM_QUERY`: resource is the complete marked
  read-only SELECT, `request_type=COM_QUERY`, successful status=0 and null
  `response_code`. That field is a MySQL error code, not an HTTP status. Null
  alone does not prove success; the UI preserves the recorded status separately.
- This live qualification uses packet source0 and complete Session type2.
  Source3 is a negative console control, not an eBPF DNS/MySQL qualification.

The existing MySQL workload is a bounded **wire-protocol fixture**. It validates
handshake/login, one-column SELECT result rows, EOF and QUIT over real TCP; it
does not execute SQL in a database. No Controller database or unrelated service
is used. This qualifies parsing/capture/ingestion/navigation of those real
exchanges, not general MySQL compatibility, TLS or all SQL commands. The DNS
fixture answers only its exact finite question/ID set over real UDP. Neither
fixture inserts application records into storage.

## Repeat the finite two-host scenario

Reuse the established owned packet-Agent/Server lab and the pinned native Agent
from the managed runtime checkpoint. Identify the two standalone physical 10G
interfaces, their link-local addresses, ownership and original state before
changes. Use fresh private directories and a fresh marker on every attempt.
Keep independent server/client receipts; do not substitute generated expected
rows for verified wire responses. Existing lab tools and profile/background
process restoration rules still apply.

On the source Agent's dedicated profile, enable only DNS/MySQL inference, their
port prefilters (`DNS:18053`, `MySQL:18060`) and a packet BPF of
`ip6 and (udp port 18053 or tcp port 18060)` on the explicitly selected test
interface. Retain the existing data/controller destinations and bounded resource
limits, Session logging and graceful sender drain. Disable eBPF, process and
all four integration inputs as in the qualified packet profile. These are changes
to the existing complete owned profile, not a partial replacement configuration.
Save and compare the original profile byte-for-byte for restoration. Wait for
actual dispatcher and three-listener policy readiness before counted traffic.

Set `MARKER=p6-` followed by24 fresh lowercase hex characters. On each host,
`IFACE` and `PEER_LL` refer to that host's physical test interface and the other
host's bare link-local address; `SERVER_LL` is the server host's assigned bare
address. On the server, run each finite fixture before its matching client:

```sh
# Dedicated server host, one fixture at a time; each self-exits after four exchanges.
python3 traflens/lab/dns-traffic.py serve --address "$SERVER_LL" \
  --interface "$IFACE" --marker "$MARKER-dns" --port 18053 --count 4 \
  --timeout 60 --output "$NEW_PRIVATE_DNS_SERVER_REPORT"
python3 traflens/lab/mysql-traffic.py serve --address "$SERVER_LL" \
  --interface "$IFACE" --marker "$MARKER-mysql" --port 18060 --count 4 \
  --timeout 60 --output "$NEW_PRIVATE_MYSQL_SERVER_REPORT"

# Dedicated client host: run after the corresponding actual server listener is ready.
python3 traflens/lab/dns-traffic.py client --address "$PEER_LL" \
  --interface "$IFACE" --marker "$MARKER-dns" --port 18053 --count 4 \
  --timeout 60 --output "$NEW_PRIVATE_DNS_CLIENT_REPORT"
python3 traflens/lab/mysql-traffic.py client --address "$PEER_LL" \
  --interface "$IFACE" --marker "$MARKER-mysql" --port 18060 --count 4 \
  --timeout 60 --output "$NEW_PRIVATE_MYSQL_CLIENT_REPORT"
```

For the negative control, repeat both server/client pairs with count2,
DNS port18054/marker `$MARKER-dns-negative` and MySQL port18061/marker
`$MARKER-mysql-negative`. Keep those ports outside the packet BPF and protocol
prefilters. All12 wire exchanges must succeed (8 included,4 excluded); all8
endpoint receipts must pass. After the finite fixtures exit, stop only the owned
Agent gracefully and verify successful drain/exit0. Restore the exact profile
and any test-interface state before the read-only oracle.

Create a new private expected JSON containing only
`{"marker":"<fresh p6 marker>","count":4}`. On the owned backend host:

```sh
python3 traflens/lab/verify-protocol-product.py # offline plan; no writes/network
python3 traflens/lab/verify-protocol-product.py --execute --root "$LAB_ROOT" \
  --expected "$EXPECTED" --output "$NEW_PRIVATE_ORACLE_DIR" --agent-id "$AGENT_ID"
```

The oracle independently constructs all exact DNS/SELECT resources and responses
from the finite fixture contract. It queries the **whole marker**, without
protocol/source/status/Agent/port filters hiding mistakes. Two complete reads
must contain the same exact IDs and eight unique resources, including correct
protocol, transport, port, Agent, Session, source, code/status and DNS answer.
Missing, duplicate or unexpected resources (including negative controls) fail.
The fixed limit43 covers at most40 expected positive records plus a sentinel;
count is limited to1..20. It is not a general arbitrary-SQL endpoint.

## Product check and latest result

Use [console startup and access](console/README.md#product-start-and-access-workflow).
Select the fresh marker and packet source, then DNS or MySQL. Each has4 new
records; overview and service relationship selections retain that scope. Open
an exact detail, inspect the DNS answer/RCODE or SELECT/MySQL response semantics,
then verify each excluded marker and source3 returns no records. Stop the owned
console and SSH forward after the check.

The2026-10-28 trial passes both whole-marker reads, all12 wire exchanges and
actual Edge protocol/overview/relationship/detail navigation; page errors0.
Native Agent exit0, exact YAML, test interface/management route, BPF/tracefs,
fixture processes and console all restore; pre-existing services are preserved.
Preparation encountered a private evidence-path error and then a missing
trials parent before Agent creation; the applied profile was restored. The first browser fixture rejected its
own duplicate parameter; a subsequent startup preflight rejected TIME_WAIT
before child creation. All failure artifacts remain private, followed by a
fresh successful browser attempt. No new HTTP/kernel/performance matrix is run.
19 console race tests and249 lab tests pass. Anonymous results are in
`evidence/2026-10-28/protocol-product/summary.json`; raw addresses, markers,
runtime identities, configurations and screenshots remain private.
