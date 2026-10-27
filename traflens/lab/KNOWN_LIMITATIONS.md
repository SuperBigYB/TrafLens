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

- After the lab's ClickHouse restart, the first DNS batch produced20 verified
  wire exchanges but19 L7 rows. Its missing q0 had a complete, successfully
  parsed L4 flow; a concurrent CKwriter broken-pipe warning dropped one L7 item.
  The writer's failed-write branch drops that batch without retry. Warning logs
  have no flow ID, so identifying that one dropped item as q0 remains an inference.
  Warm and subsequent fresh-process cold batches passed20/20. No recovery/delivery
  fix is included; future retry changes must test partial delivery and duplicates.


Writer follow-up: safe pre-input recovery and a bounded restart case now pass
with candidate4b2799823. The original failed cases remain historical evidence.
An additional baseline BEFORE case lost DNS q0 without any injected restart,
so a complete first-record causal explanation remains open. Post-supply errors
are deliberately reported as uncertain without replay until server-side
idempotency is designed. See `README-writer-recovery.md` for the tested boundary.


## API follow-up — source c91b1a3c5

The empty-aggregation and nested-dict items above are historical failures. The
current Server rejects empty functions with one typed HTTP400, and accepts both
nested JSON mappings and the GUI YAML-text form. Malformed configuration returns
one valid error object without changing the last good stored value. A real
candidate first exposed a shared response bug (`DATA` had no value for nil byte
data); standard encoding/RawMessage and UTF8 checks now close it. HTTP13/13 passes,
including exact numeric persistence, native Count(row) equivalence and cleanup.
See [the API guide](../README-api-validation.md) and aggregate evidence.

The custom startup-flag issue is resolved by the follow-up below. Generic dict/null behavior does not
validate every Rust Agent field shape or operational range. Post-supply storage
ambiguity, first-record loss and broad performance validation remain separate.


## Startup flag follow-up - runtime source 121bdbe26f

The startup-flag item above is historical. Controller.Start no longer reparses
the process-global flag set after the executable has already accepted its own
`-f` path; the standalone controller caller still parses its flags explicitly.
The actual subprocess regression reaches a supplied invalid YAML file and exits1,
where the old code exited2 with an unknown-flag error. The owned Server now starts
with explicit `-f /etc/server.yaml` and passes HTTP13/13 with both databases and
unrelated containers retained. See the API guide and namespace checkpoint.


## Native Agent stop and pending delivery - 2000-request follow-up

A new pinned-reference200RPS/10s workload completed all2000 client/server exchanges,
then stopped the Agent immediately. Only1894 unique request resources persisted;
sequences1894-1999 remained absent through the bounded90s verification. NIC error/
drop counters did not increase and the Agent exited0. The original failure is
retained, not classified as a passing performance sample. This experiment does
not establish the candidate's behavior under immediate stop.

Both pinned native sources call `clean_and_exit(0)` in `Agent::stop`; that helper
sleeps one second and calls `std::process::exit`, without a coordinated pipeline
drain at this call site. The exact stage holding the missing tail is unproven.
A later sequence proves all2000 rows while the Agent remains running, stops it,
and rechecks the exact rows twice. All six matched runs then pass; this operating
procedure does **not** fix shutdown delivery. A bounded producer-to-consumer drain,
explicit failure on unfinished delivery and immediate-stop regression remain
required before shutdown reliability or complete performance parity claims.
See [the qualified workload guide](../README-http-ramp.md).
