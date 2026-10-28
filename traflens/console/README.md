# TrafLens minimal console

This first product slice reuses the existing query and Controller APIs and
ships as one standard-library Go executable with embedded HTML. No separate
frontend dependency installation is required. It provides a real request list,
time/resource filters, exact string-ID detail lookup, empty/loading/error states,
and a reduced Agent inventory. A traffic overview is still pending.

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

Validation so far: race-enabled module tests, optimized-path normal build, and
live list/detail/inventory API checks against the existing lab data. The live
check reads5 historical rows and verifies exact ID lookup, then removes its
owned process. Browser interaction, a newly generated workload through the UI,
overview and unified deployment remain explicit M1 gates. See the local project
execution plan and `../STATE.md`; this slice does not close milestone M1.
