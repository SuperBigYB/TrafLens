# Controlled HTTP load and real packet-Agent acceptance

`lab/http-load` is a dependency-free Linux Go module for finite HTTP/1.1 workloads
over an existing IPv6 link-local bench connection. It defaults to an offline
plan. It does not configure interfaces, routes, drivers, offloads, sysctls,
Controller profiles, or start an Agent.

The client schedules requests at a fixed monotonic rate, with a bounded number
in flight. Each request has a fresh TCP connection, a unique canonical resource
path, and an exact expected JSON response. It binds the specified local source
address and scope interface; the transport dials only the numeric peer, with no
DNS resolution, proxy, redirects, compression or connection reuse. Status,
HTTP version, content type, content length and response bytes are checked.

Overdue schedule slots are counted as `schedule_late` instead of being sent in
a catch-up burst. Concurrency exhaustion is `concurrency_full`; cancellation,
failed attempts and completed attempts remain separate records. Any failure or
skipped slot fails the workload. This makes an offered load that the generator
could not produce visible rather than attributing it to the Agent.

The server binds the explicit local address/interface, bounds accepted
connections, validates exact method/host/path/sequence, rejects duplicates,
and terminates after all expected writes or its overall deadline. A server
write alone is not delivery proof: require the client's verified responses too.
This trusted bench server has no authentication.

## Build and run

The qualified build uses cached Go 1.26.2, `GOTOOLCHAIN=local`, `GOWORK=off`,
`CGO_ENABLED=0 go build -trimpath`; no dependencies or host packages are installed.
The module requires Go 1.24 or newer. Source and binary hashes are recorded in
the dated evidence; the Agent binary is pinned independently.

```sh
cd traflens/lab/http-load
GOTOOLCHAIN=local GOWORK=off go test -race -count=1 -timeout=60s ./...
CGO_ENABLED=0 GOTOOLCHAIN=local GOWORK=off go build -trimpath -o "$PRIVATE_BINARY" .
"$PRIVATE_BINARY"  # offline plan, without reading network configuration

# On the peer, under an external finite process/resource supervisor:
"$PRIVATE_BINARY" --execute --mode server \
  --interface "$SERVER_INTERFACE" --bind "$SERVER_LINK_LOCAL" --peer "$CLIENT_LINK_LOCAL" \
  --marker "$FRESH_MARKER" --rate 100 --seconds 5 --concurrency 16 \
  --timeout-ms 1000 --output "$NEW_SERVER_REPORT"

# Once the supervisor has proven the owned listener is bound:
"$PRIVATE_BINARY" --execute --mode client \
  --interface "$CLIENT_INTERFACE" --bind "$CLIENT_LINK_LOCAL" --peer "$SERVER_LINK_LOCAL" \
  --marker "$FRESH_MARKER" --rate 100 --seconds 5 --concurrency 16 \
  --timeout-ms 1000 --output "$NEW_CLIENT_REPORT"
```

Execution requires different numeric IPv6 link-local addresses without a zone
suffix (the interface supplies the zone), an unprivileged port, a fresh marker,
and a new absolute report path under an existing private directory. Reports use
exclusive creation and mode0600. Bounds: 1–10,000 scheduled requests/sec,
1–30 seconds, at most200,000 total, 1–128 concurrent connections and 100–5,000ms
per request. The overall deadline includes the offered-load duration, one
request timeout and a ten-second peer startup allowance. These are execution
bounds, not a claim the generator or Agent sustains the maximum settings.

Reports contain private addresses, interfaces, marker and per-request records;
keep them outside version control. Each client record preserves sequence,
scheduled/start offsets, service time and latency from scheduled time to
completion. P50/P99 use nearest-rank completed-request samples. Skipped and
failed requests are not latency samples; always report their counts alongside
percentiles. `process_peak_rss_kib` and CPU seconds belong to the generator,
not the Agent or the whole host. Client elapsed time includes draining requests;
the configured offered-load duration remains the rate denominator.

The fixed transport limits follow the standard
[Go HTTP transport contract](https://pkg.go.dev/net/http#Transport). Agent queue
and capture settings must be matched in subsequent candidate/reference tests;
the [DeepFlow tuning guide](https://get.deepflow.io/docs/best-practice/agent-performance-tuning/)
explains that shrinking queues reduces burst buffering. This tool does not
silently tune those settings to obtain a passing result.

`lab/verify-http-load.py` independently checks a paired report, sequence/schedule,
counts, latency accounting and recomputed percentiles, then emits anonymous
metrics. Optional packet acceptance requires exactly two whole-marker query
files with the exact ten-column schema and expected Agent ID. It rejects missing,
extra, duplicate, wrong-protocol/source/endpoint rows, booleans in integer fields,
duplicate JSON keys and nonfinite values. The caller must collect whole-marker
queries without protocol/Agent/source filters; report files alone cannot prove
how a query was issued. This packet oracle is bounded to1000 unique requests per
run (`LIMIT1001`). For larger workloads use the separately qualified keyset
collector below; the original single-result oracle retains its bound.

```sh
python3 traflens/lab/verify-http-load.py \
  --client "$PRIVATE_CLIENT_REPORT" --server "$PRIVATE_SERVER_REPORT" \
  --query "$PRIVATE_WHOLE_MARKER_READ_ONE" --query "$PRIVATE_WHOLE_MARKER_READ_TWO" \
  --agent-id "$RECEIPTED_AGENT_ID" --output "$NEW_ANONYMOUS_SUMMARY"
```

## Measured scope on 2026-10-27

The dated `evidence/2026-10-27/http-load/summary.json` records two offered rates
over one previously qualified 10G direct link, MTU1500. Each lasts five seconds:
40 requests/sec (200 requests) and100 requests/sec (500 requests). A no-Agent
control and a real native packet-Agent run completed at both rates. All four
client/server pairs verified every response, without failed or skipped slots.

The Agent is exact source `95f5e10dfe63c4b5920c8d7932b683fb896a1479`, binary SHA256
`cbee7383430743230af341a3d28118e4a78bb71f47124e1332509ddd5030ce23`.
No diagnostic queue observer or payload-dump instrumentation was enabled.
Limits:2 CPUs,1GiB,384 PIDs,240s plus10s termination grace; host network, private
PID namespace, read-only root and explicit mounts. Only NET_RAW and SYS_RESOURCE
were added after dropping all capabilities. eBPF, process input, integrations,
profiling and debug were disabled in the applied packet profile. That does not
establish isolation of all host metadata discovery. The captured interface and
TCP port were explicitly limited; log/synthetic-query evidence stays private.

The initial trial used the wrong readiness path, emitted no load, then stopped
and restored its configuration. The successful retry requires `/livez` and the
owned Agent's dispatcher startup record. Expired logical registration was
refreshed only after stopped-process proof and empty Controller inventory.
After the first heartbeat, the CE Controller expanded the capability list;
the retry rechecked the exact identity and explicitly selected packet metrics/
request-log features again. The applied configuration remains the scope control.

For each Agent load, the ordinary strict request oracle required the exact
request/status multiset twice. After stopping the Agent, two additional whole
marker queries, without protocol/Agent/source filters, independently checked
all200/500 unique paths, GET/200/success, Session type2, packet signal source0,
HTTP20, TCP6, client observation point`c`, and the receipted Agent identity.
The expected cardinality is **one captured endpoint per request**; it does not
reuse the earlier eBPF two-endpoint40-row oracle. One supplemental query first
used an invalid column name; that failure is retained separately and its corrected
`protocol` query is the one qualified. Final cleanup removed the owned Agent and
workers, restored exact Controller YAML and the BPF/tracefs baseline, and
preserved existing containers and databases.

This establishes complete collection for these two finite loads. It does not
measure maximum/sustained throughput, Agent CPU/RSS/queue-loss curves, eBPF
performance, telemetry delivery latency, query capacity, or candidate/reference
parity. Client request P99 is not ingestion latency. There is one sample per
rate/mode, so percentile differences are not evidence of an Agent overhead
improvement. Follow with repeated matched-load ramps and a separately pinned
DeepFlow reference before making those claims.


## Exact paginated packet acceptance

`lab/verify-http-pages.py` validates the same paired workload reports, then uses
the [DeepFlow SQL API](https://get.deepflow.io/docs/integration/output/query/sql/)
on the receiving host's fixed loopback query port. The default is an offline
plan: it reads only the supplied reports, without network access or output creation.
The collector requires Linux and an explicit `--execute`; it changes no Agent,
Controller, network, database schema or data. Stop the producer and the owned Agent
before collection, and use a fresh marker for each workload.

```sh
# On the receiver, reports are already copied into a private directory:
python3 traflens/lab/verify-http-pages.py \
  --client "$PRIVATE_CLIENT_REPORT" --server "$PRIVATE_SERVER_REPORT" \
  --agent-id "$RECEIPTED_AGENT_ID" --page-size 64

# The output directory must be new, absolute, beneath an owned mode0700 parent:
python3 traflens/lab/verify-http-pages.py \
  --client "$PRIVATE_CLIENT_REPORT" --server "$PRIVATE_SERVER_REPORT" \
  --agent-id "$RECEIPTED_AGENT_ID" --page-size 64 \
  --timeout 120 --output "$NEW_PRIVATE_CAPTURE_DIRECTORY" --execute

# Recheck the archived SQL and responses with no network access:
python3 traflens/lab/verify-http-pages.py \
  --client "$PRIVATE_CLIENT_REPORT" --server "$PRIVATE_SERVER_REPORT" \
  --agent-id "$RECEIPTED_AGENT_ID" --page-size 64 \
  --replay "$PRIVATE_CAPTURE_DIRECTORY"
```

Each scan checks the whole-marker `Count(row)` before and after reading all rows.
The only filter is the marker and, after the first page, a strictly increasing
canonical resource key. No protocol, Agent or endpoint filter can hide unexpected
rows. Rows are ordered by resource string, so sequence10 precedes sequence2;
acceptance still requires every numeric sequence exactly once. The ten original
columns and numeric types are checked on every page. The one extra lookahead row
is checked and re-read on the next page, exposing duplicates at page boundaries.
A clamped/truncated page, ignored cursor, wrong schema, wrong packet metadata,
missing/extra sequence or changing count fails acceptance. A second complete scan
starts again from the beginning and must independently pass. Two scans are two
exact packet reads in the summary, not two HTTP API calls.

The paired-report limit remains200,000 requests, page sizes64-1000, and response
limits are2MiB per API call. Total calls and wall time (10-300 seconds) are bounded.
A POSIX timer bounds slow-drip reads in addition to socket inactivity timeouts.
Only the initial underfilled count may be polled within that budget; overfilled
counts and malformed data fail immediately. Proxy use and redirects are disabled.
Private files are exclusively created mode0600 under a new mode0700 directory.
SQL, raw responses, input hashes and failures remain private. Malformed JSON is
retained as bounded base64; a successful archive must pass offline replay before
an anonymous summary is emitted. Replay requires the same reports, page size and
receipted Agent identity and verifies exact SQL order, with no missing/extra files.

The14 new regression tests include a synthetic2000-request paired workload,
duplicate boundary rows, missing/clamped/unsorted data, independent second-scan
failure, invalid metadata/counts, SQL-resource injection, archive tampering,
absolute deadlines, offline planning and private success/failure capture. All218
lab tests pass locally. Six previously collected native candidate/reference
500-request samples were rechecked through the live API: each passes two8-page
scans at page size64, totalling96 page requests plus24 count requests. These are
re-reads of the earlier3000 Sessions, not new traffic or higher measured throughput.
The anonymous qualification is in `evidence/2026-10-27/http-pagination/summary.json`.

Stable counts and two exact reads establish consistency during these bounded
reads. They do not provide a transactional snapshot or prove that no future late
write can arrive. The2000-row test is synthetic; a new real workload above1000
requests and repeated higher-rate candidate/reference ramps remain required.
