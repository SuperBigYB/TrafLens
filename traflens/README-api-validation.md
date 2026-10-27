# Query and configuration API validation

This checkpoint uses core source
`c91b1a3c5ee61654d3f5ba89b00d689b21f56614`. It addresses the historical empty
aggregation panic, duplicate recovery responses, configuration conversion failures,
and malformed controller response envelopes. Earlier observations remain in
[the lab limitations](lab/KNOWN_LIMITATIONS.md).

[Core CI 40405314725](https://github.com/SuperBigYB/TrafLens/actions/runs/40405314725)
passed both jobs for this exact core source. The isolated candidate HTTP acceptance
below also passed.

## Query behavior

An empty argument list reaching aggregate translation now returns the existing
typed `INVALID_POST_DATA` error. For example, `SELECT count() FROM l7_flow_log`
returns HTTP 400 with one JSON object instead of an index panic. This does not
introduce an empty-argument count shorthand. The established `Count(row)` form
still translates to `COUNT(1)`, including the upstream alias and HAVING fixtures.

Unexpected panics abort the handler chain. Before a response has been written,
recovery emits one HTTP 500 `SERVER_ERROR` object with a generic description;
panic values and stack traces are not returned to the client. If a response has
already been written, recovery appends nothing and preserves its status, headers,
and body. It cannot repair an incomplete response. Normal responses are unchanged.

## Configuration behavior

The JSON configuration POST/PUT routes use a local `UseNumber` decoder and require
one complete, non-null JSON object. They do not change Gin's global decoder
settings. Integer-schema fields, including sequence items, are checked from their
original numeric tokens before conversion. A representable large odd integer such
as `9007199254740993` is preserved; whole decimal/exponent forms such as `1000.0`
and `1e3` become 1000. A fraction close enough to an integer to round in float64 is
rejected instead of silently becoming that integer.

The exact integer scanner performs work linear in token length, saturates exponent
parsing, and accumulates at most a native integer's digits. It does not allocate a
power or big integer proportional to an exponent. Non-integer numeric schemas
retain the existing finite float64 policy.

Native YAML numeric types are checked before re-encoding can hide them. Whole
floats are rejected at integer-schema paths, including sequences whose values
come from YAML aliases or merge keys. Integer aliases remain valid. Float schema
defaults retain their float tags during validation, so valid values such as 1.5
are accepted. Successfully validated native YAML is returned byte for byte,
including operator comments.

JSON dict-valued fields accept structured collections or the established YAML
collection text. For example, a nested `port_number_prefilters` object becomes a
native YAML mapping; its GUI JSON readback remains YAML text. Scalar dict values
and malformed collection text return typed HTTP 400 errors. The service classifies
input/conversion errors without reclassifying existing DB lookup or write errors.

## Controller response serialization

The shared controller response helper now marshals the complete envelope with the
standard JSON encoder. Raw byte data is embedded as `json.RawMessage`, preserving
JSON values and integer tokens while escaping status and description strings.
Nil or empty byte slices explicitly mean absent data and become `DATA: null`.
Valid pagination, ordinary maps/lists, and existing successful content types are
preserved.

Serialization and UTF-8 checks happen before headers are written. Invalid nonempty
raw JSON, invalid UTF-8 raw strings, or an ordinary marshal failure produce one
generic HTTP 500 `SERVER_ERROR` object. A valid typed input error with nil byte
data remains HTTP 400; it does not become success. Direct byte/string response
helpers also return a valid generic error envelope when serialization fails.

## Local validation

Recorded Go results have zero failures or skips:

- Configuration: **53 top-level tests / 163 passing test events**.
- Configuration service: **11 top-level tests / 36 passing test events**.
- Configuration router: **3 top-level tests / 23 passing test events**.
- Both query packages: **17 top-level tests / 51 passing test events**.
- Shared controller response: **7 top-level tests / 19 passing test events**.

The independent 2048-case integer oracle is included in the configuration result;
its input cases are not added again to these test counts. The recorded race gates
report no race warnings. The current lab helper suite passes **134 tests**,
including strict empty/null Agent-inventory handling. The `c91b1a3c5` core CI
snapshot contains **133** lab tests; the additional helper regression belongs to
the following helper/documentation checkpoint, whose CI result is not claimed here.

From `server/`, with the pinned Go toolchain and prepared vendored dependencies:

```sh
GOMAXPROCS=2 GOFLAGS=-p=2 go test -mod=vendor -race -short -count=1 -timeout 120s \
  ./agent_config ./controller/http/service/agent ./controller/http/router/agent \
  ./controller/http/common/response ./querier/engine/clickhouse ./querier/querier
```

From the repository root:

```sh
python3 -m unittest discover -s traflens/lab/tests -p 'test_*.py'
```

## Isolated HTTP acceptance

The rebuilt Server reporting exact core source `c91b1a3c5` passed **13/13 cases**.
The three empty aggregations each returned one typed HTTP 400 object. The supported
`Count(row)` query returned **40**, exactly matching native ClickHouse `count()`
snapshots before and after the API request. Dict POST/PUT persisted the expected
mapping; invalid updates and the close-to-integer fraction were rejected without
mutation. Large odd, whole-decimal, and exponent-form integers persisted exactly.

The temporary group/configuration was removed, and original group configurations
and Agent inventory were preserved. Both database container/start identities were
retained across the Server replacement; container identities stayed unchanged
during acceptance. Final health checks found the controller and query service
healthy, all lab containers running, **161 MySQL tables**, and **zero Agents**.
A scan for the private generated database password found no match in Server logs.
Only aggregate evidence is published in the
[API checkpoint summary](evidence/2026-10-27/api-ebpf/summary.json).

Failed controls remain preserved privately. The first `f9802bfef` candidate stopped
at its seventh case because a typed error's nil byte data produced a missing JSON
`DATA` value; temporary-resource cleanup succeeded. That production defect led to
the shared response repair. A first `c91b1a3c5` run then stopped in the helper's
inventory verification because it did not accept the controller's legitimate
null empty-Agent inventory. This was a helper observation error, not another
production failure. Strict null-as-empty handling was added, malformed inventory
shapes remain rejected, and the complete rerun passed all thirteen cases.

`lab/accept-api.py` runs on the lab host against an existing owned stack. It uses
Python 3 and the lab's existing **PyYAML 5.4.1**; it does not install dependencies.
The expected commit must match the Server binary. Use a fresh private output
directory for every run, for example:

```sh
python3 /tmp/traflens-lab-code-20261026/accept-api.py \
  --root /tmp/traflens-lab-20261026 \
  --lab-tools /tmp/traflens-lab-code-20261026 \
  --output /tmp/traflens-lab-20261026/evidence/api-candidate-c91b1a3c5 \
  --expected-commit c91b1a3c5ee61654d3f5ba89b00d689b21f56614
```

The helper checks three empty aggregations, the supported count control, dict
POST/PUT and persisted reads, rejected updates without mutation, four raw-number
cases, and cleanup. `Count(row)` must have exactly one count column and one
nonnegative integer value, equal to native ClickHouse `count()` snapshots before
and after the API request.

Configuration writes target a newly created random, empty temporary group. Cleanup
requires the creation receipt's exact UUID and name plus no active, disabled or
pending members. Existing groups, their configurations, Agents, and container
identities are checked for preservation. Raw requests/responses and resource
snapshots remain under the private lab evidence directory with restrictive file
permissions; only aggregate results should be published.

`--baseline` performs query controls without group/configuration writes. Known
empty-function failures remain failed cases in its summary. A baseline process
exit does not turn those failures into passes, and the supported count control
must succeed in either mode.

## Boundaries

Generic dict map/list/null handling is not a complete per-field Agent shape or
comment-range validator. Existing semantic range and nullable-collection behavior
remain. A caller that directly supplies an already rounded float64 cannot recover
the original JSON token; validation concerns the received value. These API checks
use existing stored data with no active Agent. They do not validate full Agent
eBPF collection, payload collection/ingestion, or sustained performance. They also
do not prove that every malformed SQL statement is panic-free, that a partially
written HTTP response can be repaired, or that full DeepFlow functional and
performance parity has been achieved.


## Explicit startup path follow-up

Runtime source `121bdbe26f147b96e532e702ab9819d2ad6ad353` closes the historical
`-f` reparsing failure. The executable owns its flag parsing; Controller.Start
uses the supplied configuration path directly. A subprocess test verifies that
a nondefault invalid YAML path reaches configuration validation rather than an
unknown-flag exit. The standalone controller entry point retains global parsing.
The owned Server was rebuilt and started with explicit `-f /etc/server.yaml`;
the same thirteen actual API cases pass, preserving both database identities,
their start times/mounts, and unrelated containers. A full Server-log scan found
no generated private database password. This validation is separate from the
new standalone eBPF payload experiment; no managed Agent ran in that experiment.
