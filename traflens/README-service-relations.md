# Real service relationships and request drill-down

The console now provides a directed client-to-server endpoint view backed by
real L7 records. It follows the observation-point and path-to-log distinction
in the [DeepFlow service topology guide](https://get.deepflow.io/docs/guide/ee-tenant/universal-map/service-map/),
with a deliberately finite initial scope. It does not invent service names,
spans, causal edges or deduplicated transaction counts from aggregate records.

## Run and operate

Use the existing [console startup workflow](console/README.md#product-start-and-access-workflow)
with the existing query/Controller services. No new backend deployment or data
migration is required. Select time, resource, capture source and application
protocol. The service relationship section uses those same filters and shows
client IP -> server IP:port, record count and observation context. IPv6 server
addresses are bracketed.

Click a relationship to populate its exact endpoint/scope predicates and open
the matching request list. The overview and protocol drill-down retain them;
request details retain the complete selected predicate and exact string ID.
Use "clear relationship" to remove endpoint/context predicates while preserving
the visible time/resource/source/protocol filters. Loading, empty, unavailable
and rejected-filter states remain distinct. All backend text is rendered as
text content, not HTML.

Identity is the recorded tuple: Agent ID, client/server EPC IDs, client/server
IPs, server port, transport and application protocol, capture source and
observation point. Client ephemeral ports are intentionally not a service key.
This is an endpoint relationship within the recorded address space, not a
universal application identity. Overlapping namespaces/interfaces within the
same Agent/EPC can still share an IP tuple; namespace, Kubernetes and process
identity enrichment are not supplied by this slice. Unknown raw EPC values are
shown as recorded rather than reinterpreted as a named resource.

Counts are observation records of all matching record types. A client-process
and server-process observation of one exchange are separate groups, each with
its own navigable records. Do not sum these as distinct HTTP transactions.
Relationships are the top100 by count and deterministic tuple order. A101st
row only indicates truncation; the UI asks for narrower filters and does not
invent the total number of relationships.

## API contract

`GET /api/services` accepts the list's `from`, `to`, `q`, `proto` and `source`
filters. The following exact predicates are shared by services, overview,
list and ID detail: `agent`, `client_epc`, `server_epc`, `client_ip`, `server_ip`,
`server_port`, `transport`, `point`. Duplicate, unknown, invalid and injection
values fail. Addresses are numeric IP literals without a zone; backend IP tags
do not contain interface zones. EPC IDs are signed32-bit, Agent/port unsigned
16-bit and transport unsigned8-bit. Explicit0/empty observation point retains
an unknown value rather than silently widening a query. Service/overview
aggregates reject list `id`/`limit` arguments.

The response contains `relations` (columns/values), `truncated`, `limit` and
`counting=observation_records`. Record counts are decimal strings to preserve
UInt64 precision in the browser. A successful null/empty backend result becomes
an empty relation list; backend rejection and malformed count responses fail
with502. One fixed bounded aggregation queries `flow_log.l7_flow_log`; arbitrary
SQL, fields or upstream destinations are not accepted. Existing response/time
limits apply. List/overview/relationships are independent bounded reads, not a
transactional snapshot.

## Fresh two-host acceptance

The unchanged qualified native Agent captures real HTTP traffic across the
owned10G link to two server ports. Each endpoint completes200 requests at20RPS
for10 seconds, with zero generator failures/skips. Each endpoint's200 rows pass
two exact paginated oracle scans. Actual headless Edge shows two relationships
and total400, then100 list rows and total200 after selecting one relationship.
All endpoint/EPC/Agent/source/protocol/observation filters survive list, protocol
and exact-ID detail navigation. Clearing the relationship restores both. An
unused port and the wrong source yield zero; empty/error states and zero page
errors pass. Screenshots are inspected privately.

Existing qualified eBPF data is also read without restarting capture:40 records
split into20c-p and20s-p relationships; selecting one yields20 records. Four new
meaningful module regressions cover filter boundaries, cross-route consistency,
UInt64 counts/truncation and empty/failure distinction. All10 module tests pass
with the race detector; the console builds successfully.

A shortened initial wait emitted traffic before actual policy synchronization:
the first endpoint stored121/200 while the second stored200/200. This failed
sample and its UI failure are retained, not repaired or relaxed. A fresh trial
waits for actual dispatcher plus three-listener policy readiness and passes
200/200 on both endpoints. Earlier coordinator path/directory preparation
failures never started an Agent. All attempts preserve exact Controller YAML,
owned-process cleanup and link/route/BPF/tracefs restoration; no unknown program
is detached. Existing services remain. This is finite functional acceptance,
not sustained capacity, complete topology/tracing or full parity.

For reproduction, use the existing owned lab/packet Agent and
`lab/http-load` client/server workflow on two chosen ports; apply an owned
HTTP-only profile covering both ports before starting. Keep integration disabled,
verify actual collector/three-listener readiness before the first counted
request, give the Agent40s stop grace, then run `lab/verify-http-pages.py` for
each unique marker twice. Configure and restore only the owned test interfaces
and group, preserving exact original YAML. The minimal filter changes are:
`extra_bpf_filter = ip6 and (tcp port <A> or tcp port <B>)` and HTTP port
prefilter `<A>,<B>`. Use a fresh common marker prefix for the two services when
checking the combined console view. Stop the console and SSH forward separately.

[Anonymous evidence](evidence/2026-10-28/service-relations/summary.json) contains
only aggregates/software fingerprints. Addresses, markers, IDs, queries, reports,
configuration and screenshots remain private. The next milestone is Trace ID
correlation across real service requests; it must verify actual propagation and
stored trace fields before claiming any call path.
