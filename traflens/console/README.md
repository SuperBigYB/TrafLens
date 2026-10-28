# TrafLens minimal console

This first product slice reuses the existing query and Controller APIs and
ships as one standard-library Go executable with embedded HTML. No separate
frontend dependency installation is required. It provides a real request list,
time/resource filters, exact string-ID detail lookup, empty/loading/error states,
a reduced Agent inventory, and a total/protocol overview with drill-down.

Build and test from this module with Go1.26.2:

```sh
go test -race ./...
go build -trimpath -o traflens-console .
./traflens-console -query http://127.0.0.1:20416 -controller http://127.0.0.1:20417
```

Run beside the existing lab backend, then open `http://127.0.0.1:20880`. For a
remote backend host, forward only the console loopback port with SSH, for example
`ssh -L 20880:127.0.0.1:20880 <backend-host>`. Stop the foreground process with
Ctrl-C. Backend containers and databases have separate lifecycles; this command
does not deploy, start or stop them. The binary rejects non-loopback listeners.
It is a local single-organization development console, not a multi-user public
service; it uses the same organization1 access context as the lab.

The initial view covers the latest24h; adjust both dates to inspect historical
records. Each query covers at most31 days and returns the latest100 rows (API
limit1..500). Request IDs remain decimal strings to avoid JavaScript precision
loss. Detail queries reuse the selected time range. Response durations and
protocol/source fields retain backend names/values in this initial detail view.
The status panel displays the Controller's numeric state without inventing
connection-health semantics.

Routes: `GET /`, `GET /api/requests?from=<unix>&to=<unix>&q=<resource>&limit=100`,
`GET /api/requests?from=<unix>&to=<unix>&id=<decimal-id>`, and `GET /api/agents`.
SQL is assembled from fixed fields and bounded filters; the browser cannot send
arbitrary SQL or choose an upstream destination. Backend requests have a10s
timeout and4MiB response limit; redirects/proxies are disabled. Backend errors
are shown distinctly from successful empty queries.

## Real product acceptance (2026-10-28)

Race-enabled module tests, build and startup script build pass. A new two-host
200RPS/10s workload completes2000 requests;2000 stored records pass two exact
API scans. Headless Microsoft Edge actually queries the new marker, displays
100 rows and total2000, opens a matching exact string-ID detail, and drills down
through the HTTP protocol group. Empty/rejected-filter states and Agent inventory
are checked; zero page errors. Screenshots are visually reviewed privately.

Controller YAML, link/route/BPF baselines and persistent service identities are
preserved. Owned console/Agent/generators/forwarding stop after validation.
Unrelated background test containers change independently; that activity is
recorded. The first attempt uses a no-longer-cached image and is retained as
failed; a transient preexisting BPF ID disappears then, without any unknown
program detachment. A fresh attempt records the current cached image and passes
restoration checks. This is functional acceptance, not matched performance.
Anonymous results: [summary.json](../evidence/2026-10-28/console-product/summary.json).

## Product start and access workflow

1. Prepare/start the community Server, Controller, MySQL and ClickHouse with the
   existing [lab workflow](../lab/README.md). Reuse an already-running owned lab;
   do not recreate its containers or data to start the console. Confirm the query
   and Controller APIs use the local endpoints selected for this environment.
2. From a checkout on that backend host, start the product entry point:

   ```sh
   TRAFLENS_GO=/path/to/go1.26.2 bash traflens/scripts/console.sh
   # Optional explicit backend configuration:
   TRAFLENS_GO=/path/to/go1.26.2 bash traflens/scripts/console.sh \
     -query http://127.0.0.1:20416 -controller http://127.0.0.1:20417
   ```

   The script builds into ignored `.traflens/bin/` and runs in the foreground.
   `bash traflens/scripts/console.sh build` only builds. It does not download a
   toolchain or restart existing services. A wrong Go version fails clearly.
3. From the workstation, use `ssh -N -L 20880:127.0.0.1:20880 <backend-host>`,
   then open `http://127.0.0.1:20880`. Keep the forwarding session open.
4. Generate traffic using the configured Agent and documented workload workflow.
   Adjust the time range and resource filter; the overview and list share these
   filters. Select a protocol group to drill down, then open request details.
   Total count covers all matching records; protocol groups show the top32 and
   the list the latest100. This is a record overview, not distinct transactions
   or a request-rate measurement.
5. Stop the console foreground process and SSH forwarding with Ctrl-C. Stop
   backend services only through their separate owned-lab workflow when desired.

The overview route is `GET /api/overview` with the same `from`, `to`, `q`, `proto`
filters as the list. It rejects detail/pagination arguments. Two bounded queries
return the exact total and protocol counts; the backend does not provide a
transactional snapshot across these requests. Empty and unavailable states are
shown separately. The console remains a loopback, organization1 development
entry point, not an authenticated public deployment.


## Capture-source exploration

The source selector filters both list and overview: `source=0` means packet
capture, `source=3` means eBPF, and omitting it shows both. Invalid source values
fail rather than widening the query. The list labels capture source and the
detail retains raw `signal_source` plus process observation side. A client and
server observation of one HTTP exchange are separate records; totals count
records, not deduplicated exchanges.

A finite managed eBPF trial on the pinned native binary completes20 positive
HTTP exchanges and40 out-of-scope negative exchanges. The unchanged strict
oracle requires40 positive Sessions (20c-p+20s-p) on two reads, source3 and
correct process/socket identity, with zero negative rows. The Agent holds the
positive namespace FD, its scope configuration map matches, and it owns no
AF_PACKET socket. Actual headless Edge selects source3 and displays40 rows,
total40 and correct source3 detail; source0 for the same marker returns zero.
Source-filter/race tests pass. See
[ebpf-console/summary.json](../evidence/2026-10-28/ebpf-console/summary.json).

M2 is now closed with the public [bounded managed runtime](../README-managed-http-runtime.md),
including a fresh trial through its startup/readiness/stop entry. The earlier
collection/UI result above remains a historical checkpoint.


## Service relationships

The shared filters also drive `GET /api/services` and the directed endpoint
relationship view. Click a relationship to inspect its matching requests,
overview and exact-ID details; clear it to return to all matching endpoints.
Agent/EPC/IP/port/transport/protocol/source/observation context stays explicit.
Groups are observation records, not unique transactions; top100 truncation is
shown. UInt64 relation counts and request IDs remain strings. See the full
[service relationship API and acceptance](../README-service-relations.md).


## Exact cross-service Trace lookup

Requests now expose raw trace/span fields. The exact W3C Trace input filters
requests/overview/services; a supported record's Trace button opens a bounded
cross-endpoint view while preserving time/source and removing the selected
relationship/resource/protocol restrictions for that view. Detail navigation
keeps the exact Trace context. Empty parent-span values stay unrecorded; order
is not a causal tree. See [HTTP Trace workflow and API](../README-http-trace.md).
