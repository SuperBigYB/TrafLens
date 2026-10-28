# Scoped eBPF MySQL classic wire fixture

The explicit100ms-paced finite wire path passes the independent storage/API
and actual Edge functional gate. Unpaced capture completeness remains unproven:
the original17-row failure is retained and has not been repaired. See
[anonymous evidence](evidence/2026-10-29/ebpf-mysql/README.md). This qualifies
a bounded paced protocol fixture, not general native reliability or performance.

## What actually runs

This is a finite MySQL classic TCP wire fixture, not a SQL database. It does
not execute SQL, open database files, use the Controller database, authenticate
a real account, contact an unrelated service, enable TLS/compression or run a
recursive/production client. The username and scramble are fixed protocol-test
data; the password response is empty. All process and wire receipts explicitly
state wire_fixture=true and sql_executed=false. Packet-source MySQL evidence
from M6 is separate and cannot qualify this new source3 eBPF path.

A held positive namespace and a separate held negative namespace each run a
server/client pair on client127.0.0.1 -> server127.0.0.2:18080. Both namespaces
execute the same three new TCP connections: main, error1064 and control. The
positive run is my-24lowerhex; the negative has a different fresh nonce. Each
connection exchanges a real protocol10 greeting, protocol4.1 login with empty
password, authentication OK, COM_QUERY, complete response and COM_QUIT, then
performs real TCP EOF/close handling. Query text is SELECT '<scenario>.<run>'.
The login username is u_<run>, within32bytes. No SQL statement is evaluated.

The main and control responses each contain all five classic result packets:
column-count seq1, ColumnDefinition41 seq2, metadata EOF seq3, text row seq4
and row EOF seq5. The error response is a real ERR packet with code1064,
SQLSTATE42000 and the finite ASCII fixture exception. The five normal result
packets are carried by one actual send and one known-length recv(MSG_WAITALL)
bundle. This respects the qualified kernel inference shape; it does not hide
any of those packets. All classic packet payloads and bundles remain below
the10000byte inference bound. There is no partial-message/retry/large-message
qualification: a short syscall result is retained as partial evidence and
fails this fixture instead of being relabelled as a complete capture.

Each worker records21 real I/O events, not21 MySQL messages:18 data-bearing
send/recv calls (six per TCP connection) plus three recv calls that actually
return0 for TCP EOF. The latter are stage=tcp-eof, bytes0, eof_observed=true,
complete_wire_event=true, complete_mysql_message=false and zero classic
packets. Connect/accept/close are separate connection receipts. Each worker's
wire trace retains26 classic packet copies, including greeting/login/auth,
both protocol EOF packets in each successful result, and QUIT. Its peer records
the corresponding other endpoint of the same bytes; copies are not additional
SQL executions. Original seq, payload hex/SHA, complete bundle hex/SHA, syscall
return bytes/errno, FD/tuple, PID/TID/startticks/namespaces and Unix/monotonic
times remain in the private files. No TCP sequence or native request ID is
fabricated from a MySQL packet sequence.

The server changes only its own Linux comm to mysqld; the client uses
traflens-mysql. This is an explicit compatibility hint for the pinned kernel's
MySQL direction inference, not a claim that either process is a database.
Actual PR_GET_NAME, Docker running PID, proc startticks, executable SHA and
network/PID namespace must agree with the C self and wire records. No unrelated
process is renamed or used. A process name alone cannot qualify provenance.

## Explicit paced qualification and retained first failure

The qualified candidate now waits a fixed100ms after each successful data-bearing
phase and after each actual connection close. Each role therefore performs18
phase waits plus three close waits:21 actual monotonic waits. TCP EOF is still
a real zero-byte recv and adds no phase wait. The protocol remains three new
connections,21 I/O events and26 classic packets per role; no wire bytes or
expected native population are removed. This is a finite paced support path,
not an unpaced reliability or throughput claim.

The independent waits.jsonl preserves each wait's process identity, sequence,
connection/scenario, after-data or after-close type, protocol stage and original
wire sequence, pacing_ms=100, real/monotonic start/end, actual duration, completion
and clock error. Connections retain actual close start/end timestamps. Process
and receipt declare pacing_only_qualification=true and pacing_ms=100; the receipt
also retains pacing_waits, summed actual pacing_duration_ns and the SHA256 of the
complete original waits file. The strict verifier requires all21 complete waits,
each at least100ms, correctly ordered after its real I/O or close and before the
next I/O/connection, within the finite lifetime. Declaring a configured wait alone
cannot qualify it. Neither these waits nor the identity pause is a measurement
of native RRT, application service latency or maximum capture performance.

The original unpaced wire run completed all three real connections and preserved
all21 I/O events/26 classic packets per role, but native storage contained only17
records:16 Sessions and one orphan Request. The server-process main COM_QUIT
observation was absent. The client-process control COM_QUERY had no matching
stored response and remained Request/type0, response_status5. Login observations
were6; queries comprised five complete Sessions plus that orphan; QUIT
observations were5. The original strict oracle1 and Edge1 failed the required
18 complete observations. They remain failures; neither a marker predicate nor
excluding the orphan can convert them into a pass.

Sender drain completed in that original attempt, but numerical lost/drop counters
were not saved. A successful drain therefore does not prove zero kernel, queue,
parser or storage loss. The open-source Reorder implementation is a no-op in the
pinned source. Per-CPU batching, fast phase transitions, rapid FD reuse and close
ordering are hypotheses only; the missing rows do not prove which stage lost or
misordered data. A100ms wait exceeds the nominal10ms buffer push period but is
not evidence that this is the cause or a general repair.

Original unpaced source, binary, first tests, source/artifact hashes, wire and
failed acceptance outputs remain preserved. The paced static binary and test
logs use separate fresh paths. One fresh paced public attempt passes complete capture/storage/API/Edge
acceptance. It qualifies this bounded path without repairing or qualifying
unpaced reliability. The next milestone prioritizes bounded fast-path capture
completeness, actual loss/drop counters and event-order localization; expanding
protocol coverage must not hide the original missing observations.

## Legal profile and typed lifecycle

The MySQL entrypoint uses a fixed ProtocolContract for mysql/my-/kernel_mysql/
MySQL60 and managed-mysql.py. It explicitly reuses the typed finite coordinator;
it does not rewrite shared DNS globals or silently select DNS as a fallback.
The default ebpf-dns.py contract remains DNS/dns-/kernel_dns/DNS120. Stop checks
the saved protocol schema, exact supervisor script and owned state identity.

The dedicated kernel_mysql Controller mode uses ordinary fixed feature
functions2/4/5. Its exact profile enables only MySQL inference on18080, keeps
request-log cBPF disabled, and leaves AF_PACKET, unrelated integration/profile
inputs and process discovery disabled. The fixed profile/template's SQL
obfuscation selection must retain these MySQL literals; do not weaken an
oracle by hiding rewritten or missing values. No ad-hoc capability mask,
default-group edit or arbitrary profile JSON is accepted.

The strict public factory managed-mysql.py produces
traflens.managed-mysql-preparation.v1, protocol=MySQL/TCP, mysql_port=18080,
with SHA256/length entries for only group-profile.json and bootstrap.yaml.
The existing managed-http-agent.py accepts this explicit manifest branch by
reconstructing the exact MySQL factory output. HTTP/DNS-port keys in a MySQL
manifest, changed file hashes, a different profile or the wrong namespace
mount target fail. Preparing documents alone starts no Agent and attaches no
BPF; a manifest is not runtime qualification.

The quiet namespace lease retains exact positive/negative FD and inode
identities. The approved positive namespace is pinned at
/run/traflens/target.netns, and the actual Agent FD, inode and validated native
scope map must agree before any workload. Actual collector readiness, fresh
three-listener policy synchronization and no Agent-owned AF_PACKET socket are
required. Negative traffic uses the same protocol/port and differs in actual
namespace, so port matching cannot substitute for this kernel scope proof.

Four finite workers use an exact cached image and workload SHA, only their
owned namespace, host PID for exact native PID matching, read-only root,
cap-dropALL/no added capabilities,0.5CPU/64MiB/16PIDs and no published ports.
The only mounts are a read-only binary and that role's private writable output.
Creation intent/argv SHA is saved before mutation. Running inspect and actual
PID/startticks/executable/namespace/comm proof must bind to every C record.
A bounded server pause retains the client's live process long enough for that
proof, then unpause occurs even on failure. The pause is an identity gate.
Its presence can affect observed request timing; neither RRT nor performance
is inferred from the pause/sleep duration. Native RRT is microseconds of
observed protocol timing, and zero/NULL is not a healthy latency assertion.

## Complete population and product meaning

The source-derived expectation for the positive namespace is18 complete
Session observations: Login + COM_QUERY + COM_QUIT for each of three actual
TCP connections, at both client-process and server-process observation points.
Greeting is deliberately ignored by the native L7 parser but remains in the
original wire. Authentication OK merges with login. COM_QUIT is request-only,
with an empty resource; it is not an unimportant row to discard. These requirements
are satisfied by the recorded paced run, while the original unpaced run fails.

The complete Agent/time-window query must include all18 rows without a marker,
request-type, source, protocol or nonempty-resource predicate hiding unexpected
records. The whole positive run marker is expected on12 rows (six logins and
six queries). UI q='.'+run selects only the six COM_QUERY observations. The six
empty-resource QUIT rows are checked in the complete population and exact
scope; a marker-only query cannot prove they were captured. The independent
negative nonce must have zero stored marker rows and must not add its empty
QUIT rows to the positive Agent/window population. All original IDs/metadata
must remain identical across two complete reads.

Native MySQL successful response_code is NULL, not HTTP200, numeric0 or the
EOF byte0xfe. ERR1064 maps to native response_status3 here, with the exact
error code and ASCII exception retained. These are MySQL protocol semantics,
not an assertion that a real database failed or that a user caused an error.
The existing MySQL protocol name, source3 selector, request/error filters and
exact detail controls can be reused. Preserve Agent/source/time/record ID on
navigation; do not describe SQL as executed or packet seq as a global request
identifier. Native MySQL session_id is absent; packet seq resets per command
and does not replace native flow/capture correlation.

## Build and public reproduction

The C source and tests are LF. The following static compilation command was
actually exercised with the available GCC. The preserved unpaced version had
ten targeted offline tests; the separately built paced version has12 targeted
offline tests. Those checks covered
standard greeting/login/result/error/QUIT encoding, all26 packet copies and
hashes, partial/sequence rejection, TCP-EOF serializer distinction, default
no-I/O behavior, private exclusive output, an actual clock-only100ms monotonic
wait and a retained insufficient-deadline failure. No server/client was run by
those offline checks. The separate paced runtime/storage/Edge gate passes.

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -static \
  traflens/lab/ebpf-mysql.c -o "$WORKLOAD_BIN"
sha256sum "$WORKLOAD_BIN"
python3 -m unittest discover -s traflens/lab/tests -p test_ebpf_mysql_fixture.py
```

Use an existing canonical owned0700 parent and fresh CAPTURE/BACKEND_WORK
paths, the qualified immutable Agent runtime manifest, an immutable cached
worker image, matching source/peer Controller helper hashes and existing SSH
identity. Use a credential-free numeric-loopback Controller origin bound to
the owned lab Server. Keep real identity, full wire and network metadata in
private remote capture files. The default commands remain offline plans:

```sh
python3 traflens/lab/ebpf-mysql.py
python3 traflens/lab/managed-mysql.py
python3 traflens/lab/managed-http-agent.py
"$WORKLOAD_BIN"
python3 traflens/lab/verify-ebpf-mysql.py
```

The coordinator creates fresh positive/negative nonces and its dedicated
registration, invokes the exact preparation factory, proves namespace/Agent
readiness and then starts the four workers. Do not independently precreate or
overwrite its prepared directory.

```sh
python3 traflens/lab/ebpf-mysql.py run --execute \
  --work "$CAPTURE" --backend-host "$BACKEND_HOST" \
  --backend-root "$BACKEND_ROOT" --backend-work "$BACKEND_WORK" \
  --backend-code "$BACKEND_CODE" --server-container "$SERVER_NAME" \
  --controller-url "$CONTROLLER_LOOPBACK" --controller-ip "$CONTROLLER_DATA_IP" \
  --controller-port 20035 --ingester-port 20033 \
  --ctrl-ip "$HOST_CTRL_IP" --ctrl-mac "$HOST_CTRL_MAC" \
  --artifacts "$RUNTIME/prepared.json" --image "$IMMUTABLE_IMAGE_ID" \
  --workload-bin "$WORKLOAD_BIN" --workload-sha256 "$WORKLOAD_SHA256" \
  --forward-port 24017
```

Use the [existing independent public query/console lifecycle](README-cpu-profile-runtime.md#start-the-independent-bounded-query-runtime) and exact owned
loopback forwards. The read-only verifier's CLI uses original capture receipts,
an event-time window of at most60inclusive seconds and a fresh private output:

```sh
python3 traflens/lab/verify-ebpf-mysql.py --execute \
  --capture-dir "$CAPTURE" --query-base "$QUERY_LOOPBACK" \
  --console-base "$CONSOLE_LOOPBACK" --from "$FROM" --to "$TO" \
  --agent "$AGENT_ID" --output "$FRESH_ORACLE_DIR"
python3 traflens/lab/ebpf-mysql.py stop --execute --work "$CAPTURE"
```

The finite verifier budget is60seconds total, at most48requests,
12seconds/4MiB per response and64rows with an excess-row sentinel. The original
strict populated read failed17 versus18 and is retained. The paced populated
read and all paced API/Edge acceptance pass at the same fixed population limits. It independently decodes full original classic packets and EOF events, binds
the four actual producers, compares complete18-row/marker12/query6 populations
and exact API details, and keeps login/QUIT instead of filtering to the easy
query slice. Errors, schema omissions, excess input and contradictory rows
must fail. UInt64 IDs/flows use exact decimal strings; floats cannot silently
identify another flow. Query acknowledgement or a local subset is not success.

Cleanup first proves owned workers absent, then stops/restores the Agent and
BPF/tracefs, releases namespace pins, restores only its Controller registration
and stops its own forward. Unknown ownership or incomplete recovery retains
resources and failure receipts. Repeated public stop records recovery without
turning a failed capture into a successful one. Stop the separate public query
runtime and only its own exact SSH forwards when acceptance finishes.

Original unpaced acceptance: failed and retained. The sole fresh paced capture,
two complete native populations, all18 API details, actual Edge and public/
idempotent restoration pass.100 targeted checks pass (34MySQL and66shared
regressions), as do the static build and independent review. The unchanged
console64-test/build baseline is historical, and remote CI was not checked.
All Agent/workers exit0 without OOM; old Server ID/image/network/historical M9
config SHA and Controller0Agents/1default/YAML remain. Physical interface/device/
routes match, and query/console/forwards are removed. This preserves the original
17-row failure instead of rewriting it. The next active milestone is M15
fast-path completeness and input/parse/order/loss localization. Full MySQL compatibility, SQL database
execution, TLS, prepared statements, arbitrary message fragmentation, automatic
causal tracing and performance parity are not claimed.

## Sources

The [official upstream MySQL parser](https://github.com/deepflowio/deepflow/blob/main/agent/src/flow_generator/protocol_logs/sql/mysql.rs)
is a reference, not proof of the pinned binary's current behavior. Repo-relative
links below point to the local implementation used by the recorded gate.

- [Native MySQL parser](../agent/src/flow_generator/protocol_logs/sql/mysql.rs):
  greeting/login/response/QUIT and NULL/error-code semantics.
- [Kernel inference](../agent/src/ebpf/kernel/include/protocol_inference.h):
  explicit MySQL port guard, finite syscall shape and self-comm direction hint.
- [Native socket events](../agent/src/ebpf/kernel/socket_trace.bpf.c): actual
  process/socket/capture identities and per-CPU buffer push; not classic packet
  seq as a global ID or a measured loss attribution.
- [Pinned Reorder implementation](../agent/plugins/reorder/src/lib.rs): no-op
  behavior; configuration alone does not supply a working reorder fix.
- [C wire fixture](lab/ebpf-mysql.c) and [offline tests](lab/tests/test_ebpf_mysql_fixture.py).
- [Strict factory](lab/managed-mysql.py), [Controller modes](lab/cpu_profile_controller.py)
  and [Agent manifest branch](lab/managed-http-agent.py).
- [Typed lifecycle entry](lab/ebpf-mysql.py), [shared DNS-default runtime](lab/ebpf-dns.py)
  and [independent verifier](lab/verify-ebpf-mysql.py).

## Reproducing the retained fast-path diagnostic input

[evidence/unpaced-reference.c](evidence/2026-10-29/ebpf-mysql/unpaced-reference.c)
is the exact generic source of the failed unpaced workload, archived separately
from the accepted paced default. Build it in a new private directory with the
same static compiler flags, give it a fresh run/capture directory and retain
its actual result. It is diagnostic input, not a promised passing alternative.
Do not replace old artifacts, timestamps or rows, and do not enable unrelated
capture while diagnosing it. Numeric loss counters were absent in the first
attempt; missing counter evidence must never be relabelled zero.
