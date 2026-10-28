# Service observation trends and interval drill-down

The console now plots Session observation counts over time and exposes each
interval's classified errors, rate and positive-duration statistics. The existing
resource/service/protocol/source/Trace/error filters apply. Selecting a bar or
interval row changes the visible time fields to that exact inclusive interval,
explicitly selects complete Session records, and retains the other scope. Exact
request details keep those filters. The return button restores the previous time
and record-range selection.

The [DeepFlow SQL API guide](https://get.deepflow.io/docs/integration/output/query/sql/)
and [dashboard guide](https://get.deepflow.io/docs/guide/ee-tenant/dashboard/use/)
describe query/time-interval navigation. The implementation here is qualified
against actual native queries and raw records, rather than inferred from those
guides or a static chart.

## Time and statistics contract

Native `time(time,step) AS bucket` returns integer Epoch seconds. The stored
`time` is `end_time` floored to a second, not request start time. The existing
L7 serializer and24 actual raw records independently confirm that basis. Both
API input bounds are inclusive; a nonempty single-second interval is now valid
across the shared request/overview/RED selection code. UI time controls preserve
seconds rather than truncating a selected interval to minutes.

The qualified native backend uses Asia/Shanghai calendar time. Fixed steps are
60,300,900,3600 and14400 seconds, all dividing its UTC+8 offset;60 and14400 were
also directly probed. Calendar-day/6-hour steps are not assumed to follow UTC
Epoch floor on this backend. Every returned bucket must actually align to the
selected Epoch grid or the product rejects the response. Different backend time
configuration is not silently relabeled as a qualified grid.

The first/last bucket is clipped to the selected from/to, with
`window_seconds=to-from+1`. Rate divides by that **actual coverage**, including
single-second edges, not by the nominal step. Count is Session observation rows;
repeated observations are not deduplicated business transactions. Errors use the
same client4/server3 flags as RED. Latency count/mean/maximum use only positive
`response_duration`, measured in us and displayed as ms. These two queries are
not an atomic snapshot. A displayed zero count is no matching observed rows in
successful queries, not a health assessment or proof of collection completeness.

## Bounded API

`GET /api/trends` shares the existing selection predicates, forces `session=1`,
rejects ID/limit and accepts one optional allowed `step`. Auto mode picks the
smallest allowed step producing at most240 aligned buckets, including both
partial edges. An explicit step that would exceed that bound returns400 instead
of silently reducing precision. All native reads use a shared12-second context,
the shared response-size limit and a fixed `LIMIT 241` sentinel.

The fixed native queries group Count(row)/Sum(client_error)/Sum(server_error),
then positive-duration Count(row)/Avg/Max, by the integer bucket. No conditional
Sum expression or arbitrary query text is exposed. A valid complete aggregate
schema with `values:null` or `[]` is an empty population; missing/null result or
missing columns is502. Duplicate, fractional, misaligned, out-of-range or excess
buckets and contradictory statistics fail502. A successful first query never
becomes a healthy partial chart after a failed second query.

The response has `buckets`, `step_seconds`, `max_buckets=240`,
`counting=session_observation_records`, `duration_unit=us` and `atomic=false`.
Each bucket includes its clipped `from`/`to`, coverage and the same RED fields:
exact string counts/max_us, rate, classified errors/error ratio and positive
latency sample counts/mean. Successful absent count buckets are filled with zero
observations; error ratio and latency remain null. An absent positive-duration
group in a valid second response means zero positive samples, not a failed query.
Duration-only buckets or sample counts larger than the count snapshot are errors.

## Reproduce the accepted workflow

Use the [existing console startup/access](console/README.md#product-start-and-access-workflow).
Choose a resource/service and time range containing two known observation periods,
then a supported resolution. Compare each bucket with raw complete Session
records grouped by floor(end-time-second/step), clipped to the exact selection.
Sum records/errors, count only positive durations, and recompute mean/maximum and
coverage-based rates. Keep the raw exact IDs and repeat the complete read. Click
each nonempty period and open an exact request detail; check all original scope
and the explicit Session selector. Return restores the original range. Also
select an empty interval/source and an over-fine resolution to distinguish empty
statistics from a failed query. Stop only the owned console and SSH forward.

The2026-10-28 gate reuses the M4/M5 qualified two-host HTTP data:24 unique Session
observations in two periods,12 each. A clipped60-second grid contains36 buckets:
the first covers53 seconds, the last50, with34 empty intervals between them.
First/last rates are12/53 and12/50 observations/sec. The earlier period has no
classified errors; the latter has4 client and2 server errors. Positive means/
maxima from actual raw rows are1113.8333333333333/3330us and64101.5/503264us.
The native aggregates and product response match independent raw recomputation.
Moving the first bound beyond the earlier period's single observed second
correctly excludes its12 records; that boundary probe is retained.

Actual Edge checks all36 buckets, both interval-to-detail paths, exact Agent/
protocol/source/resource scope, explicit Session selection/restore, null empty
latency, source3 emptiness and rejected excessive bucket count; page errors0.
32 complete module race tests pass, including7 trend tests and one shared
single-second regression. Independent review found and corrected two issues
before browser acceptance: missing result must not become empty zero-fill, and
clicking a Session chart must explicitly narrow the request range to Session.
No Agent, capture, profile, interface or backend service change is needed.
Raw timestamps/IDs, responses and screenshots remain private; anonymous results
are in `evidence/2026-10-28/service-trends/summary.json`. This functional trend
slice does not establish throughput, current health or full DeepFlow parity.
