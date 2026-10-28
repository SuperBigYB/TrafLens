# Service RED metrics and error/slow-record navigation

The console now exposes real Session observation volume/window rate, classified
client/server errors and latency, with service-scoped navigation to errors,
slow records, exact details and Trace correlation. It reuses the existing
[console startup](console/README.md#product-start-and-access-workflow) and does not
deploy or restart backends. Select a service relationship to inspect its RED
metrics, then use the error or slow-record buttons. Visible filters retain the
selected Agent/EPC/endpoints/protocol/source/observation/Trace scope. The Session
selector and error/minimum-duration controls make the narrowed scope explicit.
Trace navigation deliberately keeps only time/source/Trace for the full lookup,
removing error/slow restrictions as well as single-endpoint restrictions.

## Verified semantics

The repository metric description and live Query API identify
`response_duration` as microseconds (for Session, end_time minus start_time).
The [official L7 metrics description](https://web.deepflow.io/embedded-docs/features/l7-protocols/overview)
and [HTTP field mapping](https://get.deepflow.io/docs/features/l7-protocols/http/)
provide the protocol context; the current Agent/Querier enums confirm server
error3 and client error4. HTTP4xx maps to client error and5xx to server error.
Timeout2, unknown5 and parse-failed6 are not part of that classified-error
numerator. A numeric error ratio is not an overall health verdict.

RED queries use only complete Session records (`type=2`). Counts therefore need
not equal an unfiltered all-record overview containing request/response-only
rows. Error ratio is (client+server errors)/selected Session observations.
Repeated observation points are not deduplicated transactions. Rate is the
selected count divided by `to-from+1` seconds because the underlying integer
second bounds are inclusive. It is a window average, not generator RPS or
measured maximum business throughput.

A live existing-data probe reveals that native `Avg(response_duration)` excludes
zero values:2813 Session rows,2808 positive-duration rows, sum455711us and mean
162.29024216524218us. Dividing by all2813 would be wrong. The product explicitly
queries positive durations and exposes their sample count plus unmeasured/zero
count. The UI converts us to ms; maximum us remains an exact decimal string and
is formatted with integer arithmetic. Mean/rates/ratio are floating aggregates,
shown with limited precision. No positive samples -> null mean/maximum; no
Session observations -> null error ratio, not a fabricated0ms/0% health result.

## API and drill-down contract

`GET /api/red` accepts the shared bounded time/resource/source/protocol/Trace and
relationship filters; it rejects list `id`/`limit` overrides. It forces Session
scope. Additional shared predicates are `session=1`,
`error=any|client|server`, and integer `min_ms=1..600000`. Error/minimum-duration
filters also force Session scope in list, overview and relationships. Minimum
ms converts exactly to `response_duration >= min_ms*1000`. Invalid, empty,
duplicate, out-of-range and injection values fail instead of widening queries.

The response contains decimal-string `records`, `client_errors`, `server_errors`,
`errors`, `duration_samples`, `unmeasured_duration_records`; numeric
`window_seconds`/`record_rate`; nullable `error_ratio`, `avg_us`, `max_us`;
`counting=session_observation_records` and `duration_unit=us`. Count precision
survives UInt64 ranges. `max_us` is an exact string when present. The current
filter's error ratio may be100% after choosing error-only records; that describes
that subset, not the original unfiltered service.

Two fixed supported queries share a12s context: Session summary, then positive
latency count/mean/max. An attempted conditional-Sum expression returns HTTP500
on this backend; no production route uses it. There is no arbitrary SQL input.
The queries are not an atomic snapshot. Missing/malformed or contradictory
aggregates, including positive sample count greater than summary count, fail
with502; a successful first query is never published as a healthy partial result
when the second fails. A valid all-zero-duration population keeps its actual
record/error counts but has no positive latency statistic.

## Real controlled scenario and reproduction

The public [finite HTTP fixture](README-http-trace.md) adds an explicit optional
`--red-pattern` flag; default Trace behavior is unchanged. Use that flag on all
three roles with count5. Primary sequence outcomes are200,404,503,200,404, while
the unrelated Trace control remains200. The503 path sleeps250ms on both backend
and frontend. Six root exchanges traverse two real HTTP legs, yielding12 Session
observations:4 client errors,2 server errors,6 successes. Expected application
errors still count as successfully completed fixture exchanges, not healthy
application responses. Always wait for actual dispatcher/three-listener policy
readiness before the first counted exchange, and restore the owned Agent/profile,
interfaces and processes through the documented lab lifecycle.

Do not equate application sleep with complete observed latency. The independent
whole-marker oracle verifies each actual response/Trace/Span/Agent/source and
recomputes RED from the stored per-record durations. In the expected JSON set
`red_pattern=true` and add `response_code` plus `response_status` to each of the
four-field entries described in README-http-trace.md. Copy the actual response
code from the corresponding server receipt; derive status4 for404,3 for503,
otherwise0. The oracle independently recomputes that exact sequence/outcome
contract and rejects changed expectations. It requires two full reads with the
same exact IDs, without source/Trace/status filters hiding mismatches, and emits
`red_stats` from actual positive-duration records. Its default remains offline.

After collecting both server reports on the lab host, generate the explicit
new private expected file without relying on a historical coordinator:

```sh
python3 - "$FRONT_REPORT" "$BACK_REPORT" "$EXPECTED" "$MARKER" "$TRACE" "$OTHER" <<'PY'
import json, os, sys
front, back, output, marker, primary, unrelated = sys.argv[1:]
rows = []
for path, port in [(front, 18080), (back, 18081)]:
    report = json.load(open(path))
    assert report['pass']
    for row in report['records']:
        code = row['response_code']
        item = {key: row[key] for key in ['request_resource', 'trace_id', 'span_id']}
        item.update(server_port=port, response_code=code, response_status=4 if code == 404 else 3 if code == 503 else 0)
        rows.append(item)
value = {'marker': marker, 'primary_trace': primary, 'unrelated_trace': unrelated,
         'red_pattern': True, 'records': rows}
with os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as stream:
    json.dump(value, stream, indent=2)
PY
python3 traflens/lab/verify-http-trace.py --execute --root "$LAB_ROOT" \
  --expected "$EXPECTED" --output "$NEW_PRIVATE_ORACLE_DIR" --agent-id "$AGENT_ID"
```

The fresh two-host trial passes12 records twice:4 client errors,2 server errors,
error ratio0.5,12 positive latency samples. Stored-record mean is64101.5us,
maximum503264us;2 records meet100ms. These are this finite functional sample,
not a latency promise or performance ceiling. Actual Edge verifies the same
metrics against raw records, then selects one service (6 records,2client+1server
errors), drills into its3 errors, opens exact detail and the complete10-record
primary Trace. Clearing relationship retains the error scope; removing it and
choosing100ms yields the2 actual slow records. The success control has2 records
and zero classified errors; wrong-source/empty views show null latency/ratio.
Invalid-query and empty states stay distinct; page errors0. Screenshots are
inspected privately.

19 module race tests/build and245 lab tests pass. New regressions cover inclusive
windows, positive samples versus zero/missing aggregates, exact counters,
contradictory snapshots, shared error/slow/Trace filters and partial-query failure,
plus opt-in fixture/oracle outcome integrity. Native Agent exits0; fixture
processes, original YAML, test link/route/BPF/tracefs and owned console/forwarding
restore; existing services remain. No native rebuild or full kernel/rate matrix
is repeated. The unsupported probe's HTTP status is retained; its body was not
captured. Published results are [anonymous aggregates](evidence/2026-10-28/service-red/summary.json),
with raw identities, queries, reports and screenshots private.

The next product milestone is the DNS/MySQL protocol-to-console slice, reusing
existing protocol fixtures/evidence before selecting one necessary new bounded
acceptance. Full AutoTracing, resource identity enrichment, profiling and
sustained performance remain future work.
