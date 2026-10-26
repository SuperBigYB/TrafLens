# Isolated native-server lab

This three-container lab uses the locally built TrafLens server, its matching
runtime resources, and the MySQL/ClickHouse versions from the pinned upstream
Compose example. It is a functional validation environment, not a production
deployment or a performance comparison. No Grafana, deepflow-app, Redis, or
Kubernetes installation is needed for the initial collection/query path.

On the source checkout (dev-79):

```sh
python3 traflens/lab/package.py --output .traflens/work/server-lab-runtime.tar.gz
```

Use the same Go toolchain on `PATH` as the server build, or pass its
`--zoneinfo /path/to/go/lib/time/zoneinfo.zip` explicitly. Packaging includes the
complete IANA timezone archive and records its SHA256. The runtime sets
`ZONEINFO=/usr/share/zoneinfo.zip`; a bare Ubuntu image lacks the timezone data
needed by ClickHouse `DateTime('Asia/Shanghai')` writers. The image cache key
covers the entire runtime archive and Dockerfile recipe, including this asset.
Each archive is extracted into its own `runtimes/<archive-sha256>` stage. Removed
files cannot survive from a prior package. Reusing an existing Server requires
its actual image ID to match the requested image; otherwise start fails with an
explicit `--recreate-server` instruction and does not write new readiness data.

Copy that archive and `traflens/lab/` to dev-240, then run:

```sh
python3 lab.py start --runtime-package /tmp/server-lab-runtime.tar.gz
```

The default private runtime directory is `/tmp/traflens-lab-20261026`. The script
creates only `traflens-lab-*` containers/volumes and the `traflens-lab` network.
Existing resources must carry its exact ownership label before it changes them.
Repeated starts reuse resources; `--recreate` replaces only owned containers and
retains their database volumes. `lab.py stop` stops those three containers without
deleting data. Restart policy is disabled.
Use `--recreate-server` to replace only the Server after a runtime-package change;
both database containers remain running.

CPU/memory caps: MySQL 1 CPU/1 GiB, ClickHouse 2 CPUs/4 GiB, Server 2 CPUs/4 GiB.
Database ports remain internal to the private bridge. Only control/data ports
20035 and 20033 are published on `192.168.1.240`; management/query ports 20417 and
20416 bind to loopback. Node and advertised ports match the published ports.

MySQL credentials are generated locally, stored in mode-600 private files, and
never included in source or packaging. Error-level Server logging suppresses
upstream informational configuration dumps that include database credentials.
Do not copy runtime configuration, container inspect output, or private files
into Git or evidence. The tracked server YAML is a template only.

ClickHouse retains the upstream `df_cluster` and `df_storage` names; its worker
pools and query memory are bounded. Flow logs and metrics use four-hour TTLs and
small write queues suitable for smoke tests.

Readiness checks cover MySQL, ClickHouse, and `/v1/health/`. They do not prove
Agent registration, ingestion, query correctness, or feature/performance parity.
Run `python3 verify.py` to save health, schema, limits, sanitized error logs, and
a real `SELECT Count(row) FROM l7_flow_log` response under the private runtime
directory's `evidence/`. This uses the query language's supported `Count(row)`
syntax, as covered by the upstream query-engine fixtures.
After Agent traffic is available, verify a unique request marker in
`flow_log.l7_flow_log` through `POST /v1/query/` and record raw evidence.

Before starting any Agents, run `python3 configure-agent.py` on the lab host.
It requires the lab's sole default group to be empty, checks all requested keys
and numeric ranges against the live controller template, applies the config via
the current YAML API, and verifies an exact read-back. JSON documents are valid
YAML and preserve nested dict fields without the GUI JSON endpoint's special
string representation. It writes `agent-static.yaml` in the private runtime root;
copy this to dev-79's `.traflens/work/agent-run/config.yaml`.

This initially empty resource inventory cannot automatically classify a host by
cloud/VM interfaces. Run `python3 register-agent.py` on dev-240 to register the
actual dev-79 IP/MAC as a physical-machine Agent in the controller's seeded
Region/AZ. The script refuses foreign Agents, uses the official `/v1/vtaps/`
API, selects packet metrics/request-log features 2 and 4 through the public
feature-management API, and refreshes the owned Agent cache. No dummy cloud/VM
inventory is inserted.

After building the packet Agent on dev-79, run:

```sh
python3 traflens/lab/run-agent.py --seconds 900
```

Run it in a managed terminal or detach its standard streams explicitly. The
supervisor records binary/config hashes, source HEAD and dirty paths, manages
only its child process group, allows at most three exits/restarts, and stops
after fifteen minutes. Sending SIGTERM to the supervisor stops its Agent group.
The private supervisor identity binds PID/start ticks, resolved checkout, and
helper path. `run-agent.py --stop` checks the stored identity against `/proc`
before signaling; missing or reused identities fail closed. New launches refuse
any recorded live supervisor, including the same helper targeting another repo.
Logs, provenance, and PID files live only in `.traflens/work/agent-run/`.
Before sending marked HTTP requests, confirm the controller has Agent ID 1 and
the native `/livez` endpoint reports an active local dispatcher. A stats TCP
connection alone does not prove that packet capture is running.
Also wait for the first fresh `Grpc finish update ... on 3 listener` message after
that process starts. The earlier zero-listener sync precedes policy consumers.

`watch-queues.py --seconds 90` observes debug copies of the flow/app/parser-sender
queues on three ephemeral loopback UDP ports and turns them off on exit. It does
not consume the main data path. It uses the pinned Linux Agent's public
bincode-standard debug protocol and records ACKs and observed item counts.

For backend diagnosis, build the standard-library-only `backend-probe.go` from
the server module, copy its binary to dev-240, and execute it with only the owned
Server's network namespace selected by `nsenter -t <container-pid> -n`.
The default commands read per-type receiver, L7 decoder, and platform status;
the optional `warn` argument changes only the listed ingest logging modules.
It leaves global/controller logging untouched. `sample-backend.py --seconds 90`
samples those read-only counters every two seconds so ten-second snapshots are
captured during a marked workload. Keep probe output and sanitized logs in the
private runtime evidence directory; never copy raw configuration or environment.

Run the guard regressions with:

```sh
python3 -m unittest discover -s traflens/lab/tests -p 'test_*.py'
```

## 2026-10-26 validation

The real two-host IPv6 HTTP path passed: 20 client GETs, 20 server HTTP 200
responses, and exactly the same 20 unique request paths returned by the TrafLens
query API. The accepted marker is `smoke-20261026105159-timezone-fixed`; the packet
Agent production revision is `6aec171bf820e5ce516349ed3677395050b8a384`. This is
functional acceptance with packet capture and resource caps, not a throughput
comparison or eBPF runtime equivalence.

The diagnosis used real layers, in order: 40 raw HTTP request/response queue
items, 40 flow reports, 20 merged sessions queued to UniformSender; official
receiver status confirmed TCP delivery; a ten-second decoder snapshot counted
20 HTTP logs with zero decode errors/drops. Writer WARN then identified all
20 failed inserts as missing `Asia/Shanghai` timezone data in this lab's initial
Ubuntu image. Bundling the Go IANA archive resolved that runtime packaging defect;
the production server code was unchanged.

Final checks also exposed lab limits that were too small for background and
Distributed-table work. An 8-query user limit rejected queries, and the artificial
128-thread global pool saturated below the observed 176 connections. The final
lab profile allows 64 concurrent user queries, 2 threads per query, a 1024-thread
global pool and 1024 container PIDs. CPU remains 2 cores, container memory 4 GiB,
server query memory 3 GiB total/1 GiB per query. The owned ClickHouse was restarted
to load the corrected settings, retaining its data volume; these are lab
configuration corrections, not product-code fixes. Existing unrelated containers
were not restarted or reconfigured.

After that correction, five consecutive reads through the query API each returned
the exact 20 stored paths with GET/200, in 4.7–17.4 ms. The final health/schema/query
check passed and a scan of the full Server logs found no private MySQL password.
The bounded Agent and queue observers were stopped; the three owned lab containers
remain running with restart policy `no`.

The smoke config captures only `enp1s0f0` and TCP port 18080. It disables eBPF,
process discovery, integration listeners, profiling, and log backhaul; enables
HTTP request logs; uses an 8 MiB AF_PACKET ring; limits Agent CPU/memory to
2 cores/1024 MiB; and uses schema-valid minimum queue sizes. Its native liveness
probe uses port 39091. These limits and protocol filters make it a functional
test configuration and are unsuitable for comparing unrestricted throughput.

See `KNOWN_LIMITATIONS.md` for issues observed while bringing up this pinned
upstream version. The lab does not patch those production code paths.
