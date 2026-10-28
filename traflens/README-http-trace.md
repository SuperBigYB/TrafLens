# Exact cross-service HTTP Trace correlation

The console can now correlate real request records across endpoints by exact
Trace ID. It reuses the native HTTP parser's `traceparent` extraction and the
stored `trace_id`, `span_id`, `parent_span_id` fields. See the
[official HTTP field mapping](https://get.deepflow.io/docs/features/l7-protocols/http/)
and the current `processors.request_log.tag_extraction.tracing_tag` configuration
in the repository template. No Agent/Server rebuild or data migration is needed
for the qualified native build.

## Product workflow and API

Start the [existing console](console/README.md#product-start-and-access-workflow).
Use the exact Trace ID input to filter list, overview and service relationships.
This first supported lookup format is a nonzero lowercase32-hex W3C Trace ID;
invalid, empty, duplicate and injection values fail rather than widening the
query. Other/custom Trace ID formats remain raw fields without this navigation.
Request details include all three stored trace/span fields and exact string IDs.

Click `associate Trace` on a request with a supported ID. The Trace dialog keeps
the selected time and capture source, and deliberately removes single-endpoint,
resource and protocol restrictions for the cross-service lookup. The main page's
selection is preserved. Trace records show actual endpoints, observation points
and raw Span/ParentSpan values; exact detail navigation retains the Trace lookup
scope. Empty ParentSpan is shown as unrecorded. Timestamp/record-ID ordering is
presentation and never an inferred parent/child edge or complete causal tree.

`GET /api/trace?trace=<id>&from=<unix>&to=<unix>&source=0` accepts only those four
parameters. Source is optional (omission includes sources), and uses the same
packet0/eBPF3 contract as the list. Defaults and maximum31-day time window apply.
The fixed query returns at most500 records, using a501st sentinel for explicit
truncation. A truncated result is not presented as the complete trace. The
response has `records`, `trace`, `truncated`, `limit` and
`counting=observation_records`; IDs stay decimal strings. The common `trace`
filter is also accepted by requests, overview and services. HTTP/backend errors
remain distinct from an empty successful lookup.

This is HTTP header-based correlation. The fixture actively propagates context;
this does not qualify zero-header AutoTracing, inferred Span ancestry, TLS,
OpenTelemetry ingestion, other kernels or full DeepFlow parity.

## Portable finite HTTP chain

`lab/http-trace.py` is a public standard-library Python fixture. Without
`--execute` it prints an offline plan, makes no connections and creates no files.
Explicit execution validates distinct numeric link-local IPv6 addresses, an
interface, a private new output, ports and context IDs. It neither configures
interfaces nor starts capture or writes Controller. Use only the owned test
link; verify hardware identity and restore original settings through the
existing lab workflow. Do not repurpose the management interface.

The topology is client-host -> peer frontend -> client-host backend. The frontend
makes a real downstream HTTP request carrying the same Trace ID and a distinct
wire span value, validates the backend's context acknowledgement and returns it
to the client. Default5 primary requests plus one unrelated-Trace control produce
12 observed HTTP legs. Each sequence/context is checked independently; no
synthetic events or database rows are injected. Count is bounded1..20, server
lifetime5..90s, per-socket timeout3s; reports use new mode0600 files under private
POSIX parents. Unexpected paths, duplicate sequences or mismatched context fail.

Select unique `MARKER=trace-<24hex>`, nonzero distinct `TRACE`/`OTHER`32-hex IDs,
and count5 consistently across all roles. Start the backend on the client host
and frontend on the peer, then wait for both ready messages before the client:

```sh
# Client host: backend, foreground
python3 traflens/lab/http-trace.py --execute --mode back   --interface "$IFACE" --bind "$LOCAL" --peer "$PEER"   --marker "$MARKER" --trace-id "$TRACE" --other-trace-id "$OTHER"   --count 5 --output "$PRIVATE/backend.json"
# Peer: frontend; reverse LOCAL/PEER and use the peer's own IFACE.
python3 traflens/lab/http-trace.py --execute --mode front   --interface "$IFACE" --bind "$LOCAL" --peer "$PEER"   --marker "$MARKER" --trace-id "$TRACE" --other-trace-id "$OTHER"   --count 5 --output "$PRIVATE/frontend.json"
# Client host: same endpoint/context arguments, --mode client.
```

Ports default18080(front)/18081(back). Enable both in the owned HTTP-only capture
profile and explicitly set APM Trace/Span extraction to `[traceparent]`. Keep
integration and unrelated capture paths disabled. Start the qualified Agent and
wait for actual dispatcher plus three-listener policy readiness before the first
counted request. Use the established40s graceful Agent stop. Servers exit after
all expected requests or their finite deadline; always retain all three reports
and restore owned configuration/processes/link state, including on failure.

The [public oracle](lab/verify-http-trace.py) queries only the owned isolated lab.
Its default is offline. For `--execute`, provide `--root`, private `--expected`,
fresh private `--output` inside that root and `--agent-id`. Expected JSON contains
`marker`, `primary_trace`, `unrelated_trace`, and `records` copied from the two
actual server receipts: each entry has `request_resource`, `trace_id`, `span_id`,
`server_port` (18080front/18081back). The oracle independently recomputes sequence,
wire context and both Trace populations, rejecting relaxed/altered expectations.
It then reads the whole marker without source/Trace/protocol/status filters,
checks every row's context, Agent, source0, HTTP Session and successful response,
and requires two complete reads with the same exact record identities. Default
count5 requires10 primary records plus2 control records. This oracle qualifies
the default ports; changing fixture ports requires updating the acceptance
contract deliberately, not weakening it after a failure.

After copying the two private server reports onto the lab host, assemble the
four-field expected records explicitly (the fixture reports also retain other
wire-receipt fields):

```sh
python3 - "$FRONT_REPORT" "$BACK_REPORT" "$EXPECTED" "$MARKER" "$TRACE" "$OTHER" <<'PY'
import json, os, sys
front, back, output, marker, primary, unrelated = sys.argv[1:]
rows = []
for path, port in [(front, 18080), (back, 18081)]:
    report = json.load(open(path))
    assert report['pass']
    for row in report['records']:
        rows.append({key: row[key] for key in ['request_resource', 'trace_id', 'span_id']} | {'server_port': port})
value = {'marker': marker, 'primary_trace': primary, 'unrelated_trace': unrelated, 'records': rows}
with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
    json.dump(value, stream, indent=2)
PY
python3 traflens/lab/verify-http-trace.py --execute --root "$LAB_ROOT" \
  --expected "$EXPECTED" --output "$NEW_PRIVATE_ORACLE_DIR" --agent-id "$AGENT_ID"
```

## Qualified result

The real two-host chain completes all6 root exchanges and12 legs. The independent
whole-marker oracle passes twice immediately:10 target-Trace records across both
endpoints,10 distinct recorded span values, plus2 unrelated-Trace records. Parent
Span values remain empty. Actual Edge starts from a selected single relationship,
opens all10 cross-endpoint records with time/source preserved, then opens exact
Trace-scoped details. Shared filtering returns5 in the selected relationship,
10 after clearing it,2 for the control Trace and0 for a missing Trace/wrong source.
Rejected-ID and empty states pass; no page errors. Screenshots are inspected.

14 console race tests and243 lab tests pass, including four new console and
seven fixture/oracle regressions. Native Agent exit0, owned processes, original
Controller YAML, source link/management route and BPF/tracefs restore; existing
services remain. The workstation's first console-stop command fails; an explicit
follow-up via the authorized development host stops the same owned console and
verifies actual exit. Both the failure and recovery are retained privately.

[Anonymous evidence](evidence/2026-10-28/http-trace/summary.json) contains only
aggregates/software fingerprints; actual IDs, addresses, requests, SQL and raw
reports/screenshots remain private. The next product milestone is service RED
metrics and navigation to error/slow observations, with actual unit/aggregation
semantics verified first.


## Optional RED scenario

The default successful Trace fixture remains unchanged. Add `--red-pattern` to
all roles only for the explicit200/404/delayed503 scenario; expected application
errors are accepted as fixture outcomes. The oracle requires the corresponding
`red_pattern=true` expected contract. See [service RED workflow](README-service-red.md).
