# Scoped eBPF DNS/TCP: finite product slice

The public finite lifecycle, strict stored-data/API oracle and actual Edge
functional gate pass. Three positive real queries produce six source3 Sessions;
three real negative-namespace queries produce zero stored records. All original
fields and identities, exact native scope and actual process/wire provenance
are independently checked. See [anonymous evidence](evidence/2026-10-29/ebpf-dns/README.md).
This remains a finite TCP-only product slice, not complete protocol/performance parity.

## Protocol and observation scope

This slice uses the existing native DNS parser with genuine Linux TCP sockets
in two separately owned network namespaces. It is TCP DNS only: not UDP DNS,
DoT, DoH, a recursive resolver, DNS forwarding or general resolver compatibility.
The earlier M6 packet-source DNS checkpoint is separate evidence and does not
prove source3 eBPF DNS/TCP capture. The C workload constructs real DNS protocol
messages and sends them through real sockets; it does not manufacture TCP
packets, capture events, stored rows or Span identities.

The fixed endpoints inside each namespace are client127.0.0.1 and
server127.0.0.2:18080. Each namespace runs three independent new TCP connections
in order: main, nxdomain and control. The question names are
`<scenario>.<dns-run>.traflens.invalid`, with one IN A question per message.
Main returns198.18.0.41 and control returns198.18.0.42, each with one answer and
TTL60. The middle response has RCODE3/NXDOMAIN and no answer, authority or
additional record. Both namespaces execute the same three genuine scenarios;
the negative namespace has a fresh independent run marker. Its traffic uses
the same port, so port matching alone cannot explain exclusion.

Every message includes the standard two-byte network-order TCP DNS length
prefix. Each frame, including that prefix, is below the kernel inference limit
of512bytes. One complete frame is sent in one actual send call and received
with one actual recv(MSG_WAITALL) call of the known finite frame length. There
is no message pooling, DNS-over-TCP multi-query reuse, fragmented-message
qualification or retry path. A partial syscall return is retained as original
partial evidence and fails this minimal fixture; it is never relabelled as a
complete sampled message. This deliberately limited workload does not prove
arbitrary TCP segmentation or general DNS message reassembly.

For the positive namespace, the acceptance expectation is three real queries
and six complete source3 DNS Session observations, one client-process and one
server-process observation for each scenario. Six observations are not six
business queries. The unrelated control is a separate actual TCP exchange.
The three real negative-namespace queries must produce zero records for their
whole marker. The strict independent oracle verifies both complete populations
twice without hidden source/protocol/Agent/time filters.

DNS transaction IDs are16bit values scoped to the relevant flow/exchange.
Their equality is not a global identity, a cross-service causal link or an
AutoTracing parent. The finite oracle must also bind the actual namespace,
Agent, process observation, native flow/tuple and complete DNS wire context.
For this native parser, NXDOMAIN/RCODE3 maps to response_status4 (ClientError).
That recorded classification is not a health verdict, proof of user blame or
a confirmed root cause. An expected NXDOMAIN can be a successful fixture
execution while remaining a DNS error response in the product.

Native request-response time is recorded in microseconds. It is not copied
from the fixture's sleep/pause duration or validated by assuming such a
duration. The bounded server pause used only to retain the client for actual
running-PID proof can perturb observed timing; this run is not a latency or
throughput benchmark. Zero or absent positive timing is not healthy0ms.

## Legal profile, namespace lease and real identities

The dedicated Controller mode is `kernel_dns`, using the ordinary fixed
feature functions2/4/5. It does not inject a temporary capability mask or change
the default group. `kernel_dns_profile` restricts application inference to DNS
only and its DNS port prefilter to18080. AF_PACKET and integration/profile
inputs remain disabled. No packet-source fallback can qualify this milestone.

The public file factory is `traflens/lab/managed-dns.py`. Its manifest schema is
`traflens.managed-dns-preparation.v1`, with `protocol="DNS/TCP"`,
`dns_port=18080`, and exact SHA256/length entries for `group-profile.json` and
`bootstrap.yaml`. It has no HTTP-port field and does not itself start an Agent,
attach BPF, create namespaces or change the Controller. The existing
`managed-http-agent.py` filename is intentionally reused through its explicit
managed-DNS manifest branch. That branch reconstructs the exact DNS factory
profile/bootstrap, checks file hashes and the fixed scope target, and rejects
arbitrary prepared JSON. It does not silently broaden the HTTP branch.

The existing quiet association lease holds distinct positive and negative
namespace FDs/inodes. The Agent receives only the approved positive namespace
at `/run/traflens/target.netns`; the actual pinned FD, namespace inode and
validated native scope map must agree. The actual collector and fresh
three-listener policy-sync proof must pass before traffic. The runtime gate
also proves that the Agent owns no AF_PACKET socket. A configuration file or
namespace path string alone is not this proof. Scope/readiness, application
execution and stored-data acceptance are distinct conclusions.

Four finite worker containers execute the real C binary: positive-server,
positive-client, negative-server and negative-client. Each has an immutable
cached image and workload hash, host PID namespace for exact native PID
comparison, only its owned network namespace, read-only root, cap-dropALL,
no added capabilities,0.5CPU/64MiB/16PIDs and no published ports. Its mounts are
the read-only workload binary and its private writable output directory.
Creation intent and canonical argv SHA are saved before Docker creation.
Actual running Docker inspect and proc PID/startticks/netns/pidns/executable
identity must match the C self process and every wire record. Root capture run
labels and each worker's workload_run are explicitly distinct for the negative
marker. Missing runtime proof cannot be substituted by process names or an old
historical capture. Any daemon-injected security-option normalization keeps
its raw option and the exact independently checked host/daemon condition.

The server first writes ready.json after binding/listening. The coordinator
briefly pauses only that owned server while the client starts and waits for
the first response, verifies the client's actual running identity, and resumes
the server within its bounded identity gate. The C client/server then each
finish three connections and exit. Their process.json, wire.jsonl and
receipt.json retain actual FD/tuple, PID/TID/startticks/namespaces, syscall
return byte count and errno, complete framed hex/SHA, Unix/monotonic times and
actual close completion. The C receipt explicitly keeps
`native_source3_verified=false`; a socket receipt is not storage proof.

## Public reproduction

Use an existing owned mode0700 parent, fresh capture/backend-work paths,
qualified immutable Agent artifacts and an immutable locally cached worker
image. Use only the existing authorized SSH identity and a credential-free
numeric-loopback Controller URL bound to the owned Server. Keep full runtime,
Controller and network metadata in the private capture directory, not a
workstation report or source file. Deploy the exact public Controller helper
dependencies listed by the coordinator's shared helper CODE contract; source
and deployed helper hashes must agree before mutation.

The default commands print offline plans:

```sh
python3 traflens/lab/ebpf-dns.py
python3 traflens/lab/managed-dns.py
python3 traflens/lab/managed-http-agent.py
"$WORKLOAD_BIN"
python3 traflens/lab/verify-ebpf-dns.py
```

The coordinator generates the two fresh DNS run markers and invokes the legal
factory after creating its dedicated registration. Do not independently
precreate or overwrite its prepared directory. The factory's explicit
`prepare` action can separately write reviewed documents to a new private
folder, but that action still does not configure or start the Agent.

```sh
python3 traflens/lab/ebpf-dns.py run --execute \
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

Run performs limited owned preparation, namespace/Agent readiness, independent
negative then positive socket execution and cleanup. It stops the actual Agent
before releasing namespace pins, verifies original BPF/tracefs/container state,
restores only its own Controller resources and retains failures and later
restoration receipts. A pass_execution result is not stored-data acceptance.
Use the public stop entry for interrupted or completed runs; it checks the
saved supervisor/process/resource identity before stopping only its own work:

```sh
python3 traflens/lab/ebpf-dns.py stop --execute --work "$CAPTURE"
```

Use the [existing independent public query/console lifecycle](README-cpu-profile-runtime.md#start-the-independent-bounded-query-runtime) with exact owned
loopback forwards. The strict verifier is read-only and starts no capture or
traffic. Select an explicit interval of at most60inclusive seconds covering
the original fixture events, the recorded historical Agent ID and a new
private output directory. The optional --agent is an assertion against capture
metadata, not permission to substitute another identity.

```sh
python3 traflens/lab/verify-ebpf-dns.py --execute \
  --capture-dir "$CAPTURE" --query-base "$QUERY_LOOPBACK" \
  --console-base "$CONSOLE_LOOPBACK" --from "$FROM" --to "$TO" \
  --agent "$AGENT_ID" --output "$FRESH_ORACLE_DIR"
```

The verifier enforces a60second total deadline, at most32requests,
12seconds and4MiB per response, and at most64rows with an excess-row sentinel.
It independently decodes original framed DNS bytes, checks both processes'
send/recv hashes and real runtime identities, reads full positive and negative
marker populations twice, rejects unexpected Agent/source/type/metadata,
checks source3/0/4 controls and the API's six exact details. Partial/local
success is not acceptance. Its implementation, targeted tests and the actual populated
read pass in the recorded finite gate. Do not weaken a failed predicate, rewrite
a timestamp, synthesize an event/SQL row or hide unexpected records to pass.

## Existing product navigation and verified results

Use the existing real DNS protocol name/selector, source3 selector, resource
filter, Agent/time scope and exact request detail controls in Edge. Existing
DNS details explain RCODE and retain observed response_result; RED error
classification, service relations and other reused controls retain their
existing observation-count semantics. This milestone does not add a UI DNS
transaction-ID field: the current generic detail projection must not be
described as displaying a transaction ID merely because the wire or parser
contains one. Preserve the exact source/Agent/time/record ID on navigation.
Actual Edge passes six exact DNS details, four success observations and two
RCODE3/NXDOMAIN observations, source/protocol labels, error filtering and empty
scopes with zero page errors. Complete raw-to-API comparison, whole-marker
negative exclusion and final resource restoration pass independently.

The assembled change passes74 targeted tests:31 DNS fixture/runtime/oracle
checks and43 compatibility checks for shared preparation/launcher/Controller
functions. The unchanged console64-test/build baseline is reused; remote CI
was not checked. The C fixture was also statically built for its immutable
worker image. For an available GNU/Linux static libc toolchain:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -static \
  traflens/lab/ebpf-dns.c -o "$WORKLOAD_BIN"
sha256sum "$WORKLOAD_BIN"
```

The first runtime failed after the negative server became ready and before
any DNS client/query, because the generic canonical artifact helper correctly
rejects symlinks while /proc/PID/exe is an intentional kernel handle. The fix
keeps generic validation unchanged and adds a bounded readonly live-PID hash,
checking startticks and executable inode/size/mtime before/after. New regression
tests cover real own-process exe and PID-generation changes. Original failure
and restoration receipts remain unchanged; a fresh run then passes.

Agent/four workers exit0 without OOM; public/idempotent stops restore exact
BPF/tracefs/pins, original Controller0Agents/1default/membership/YAML and remove
query/console/forwards. Old Server ID/image/network remain, and config SHA matches
the explicitly historical M9 round14 baseline, not an invented new pre-snapshot.
Physical interface/device/route identities match. The short identity pause is
not a benchmark; this does not prove physical10G or maximum performance.

## Source references

The [official upstream DNS parser](https://github.com/deepflowio/deepflow/blob/main/agent/src/flow_generator/protocol_logs/dns.rs)
is a reference, not proof of this binary's runtime capabilities. The local
qualified implementation and immutable artifacts govern acceptance:

- `agent/src/flow_generator/protocol_logs/dns.rs`: TCP frame handling, DNS
  question/answer parsing, request identity, response status and request timing.
- `agent/src/ebpf/kernel/include/protocol_inference.h`: DNS kernel inference,
  explicit protocol-port guard and the small syscall payload bounds.
- `agent/src/ebpf/kernel/socket_trace.bpf.c`: actual syscall event construction,
  DNS prefix handling and native socket/TCP identity.
- `traflens/lab/ebpf-dns.c`: finite real TCP workload and original wire receipts.
- `traflens/lab/managed-dns.py`, `cpu_profile_controller.py` and
  `managed-http-agent.py`: exact profile/manifest branch and scope readiness.
- `traflens/lab/ebpf-dns.py` and `verify-ebpf-dns.py`: public finite lifecycle and
  independent full-population storage/API acceptance.

The final C source newline normalization changes only CRLF to LF. Preprocessed
output and the rebuilt static executable match the actual runtime bytes exactly;
no new capture or replay was needed for this formatting-only change.
