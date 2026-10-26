# Observed upstream limitations

Observed with server binary revision `4922b11ff560b64412bee6b1092f605e4dbda0a0`
and source checkout `742d143a242bbb053705f4241241c58dcdc3abea`, 2026-10-26.

- `POST /v1/query/` with `db=flow_log` and SQL
  `SELECT count() FROM l7_flow_log` produces a recovered index-out-of-range panic,
  HTTP 400, and concatenated JSON (`SERVER_ERROR` followed by `{}`). The supported
  `SELECT Count(row) FROM l7_flow_log` succeeds and is covered by upstream query
  fixtures. Backlog: reject unsupported empty-argument aggregation cleanly and
  emit one well-formed response. No production fix is included in this lab.
- The executable's custom main flag set accepts `-f`, while controller startup
  reparses the global flag set and rejects it. The lab uses the documented default
  `/etc/server.yaml` path and launches the Server without arguments.
- The GUI JSON group-config endpoint requires some dict-valued leaves (for
  example `port_number_prefilters`) to be YAML strings. Sending a normal nested
  JSON object there panics instead of returning a validation error. The lab uses
  the YAML endpoint and verifies the stored document exactly.
- Standalone startup logs missing Kubernetes CA-file messages. In this lab,
  metadata migration, controller health, ClickHouse tables, and a real query
  succeeded despite those messages. Native Agent registration and ingestion
  require their own end-to-end verification.
