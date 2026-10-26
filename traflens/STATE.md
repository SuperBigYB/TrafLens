# TrafLens development checkpoint - 2026-10-26

The objective remains ongoing: validate and extend DeepFlow functionality and
performance. Read this file, `git status --short --branch`, and the latest evidence
before each hourly iteration. Source presence, a successful build and a healthy
process are separate from successful collection and product parity.

## Checkout and source

- Primary: `dev-79:/root/yb/git/TrafLens`, branch `main`, tracking `github/main`.
- Upstream pin: `8741e924ff0ae3964a135985c51e5a6ce6bde397`,
  `v7.2.3-1-g8741e924f`; original history, notices and package paths retained.
- GitLab `origin`: `git@192.168.1.50:yb/TrafLens.git`.
- GitHub `github`: `git@github.com:SuperBigYB/TrafLens.git`.
- Reference `upstream`: `git@github.com:deepflowio/deepflow.git`, push disabled.
- GitLab SSH currently rejects this host key. Use the provided token only through
  the ephemeral SSH-stdin helper in ignored `.traflens/work/` when needed; never
  store it in a URL, config, source, evidence or credential file. GitLab has no
  HTTPS listener. Push both remotes without force and verify exact branch SHAs.

## Validated service foundation

- Complete community server builds via `make -C traflens server`: Go 1.26.2,
  official vendor patches, protobuf generation and private tool dependencies.
- Queue, LRU and flow-metrics package tests pass; 18 Python tooling tests and
  five top-level protobuf compatibility tests plus subtests pass. Negative schema
  renumbering controls are correctly rejected.
- Initial production fix `4922b11ff560b64412bee6b1092f605e4dbda0a0` repairs IPv6
  tag clone independence, anomaly/OOO merges, metric separators and lexical tags.
- `742d143a242bbb053705f4241241c58dcdc3abea` isolates 24 upstream-only jobs and
  adds native TrafLens CI. Its server CI passed, with binary artifact, in run
  <https://github.com/SuperBigYB/TrafLens/actions/runs/40297869105>.
- Both Server and packet Agent jobs passed for `6944472ea` in run
  <https://github.com/SuperBigYB/TrafLens/actions/runs/40314728930>.
  The next checkpoint expands the selected Agent gate to time and plugin ABI
  regressions. Check the new commit's actual run before claiming its remote gate.

## Agent correctness and builds

- `035a19064d171ed690422c5521ab25f12e66bb80` fixes the stale pcap lock edge,
  libtrace feature gating, asynchronous workspace-wide formatter side effects,
  and stale embedded Git revision metadata. No dependency versions were upgraded.
- `6aec171bf820e5ce516349ed3677395050b8a384` fixes blacklist accounting, request/
  response ordering, fragment/flow-end double counting and timeout retirement,
  and the IPv6 `/0` shift overflow reproduced by real traffic.
- The `6aec171bf` checkpoint passes HTTP 20, DNS 4, MySQL 8 and policy-labeler
  19 tests (51 total). The one DNS test reading an eBPF `.log` fixture requires
  `libtrace`; native builds retain it. It is not silently ignored in that mode.
- Full default-feature, optimized native Agent release build passed on dev-240
  from exact committed source `6aec171bf...`, with no source overlays. It built
  `libtrace.a` and 10 BPF ELF objects. Source tree was clean after the build;
  host version/ldd probes passed and embedded CommitId matches the source.
- Binary: `/tmp/traflens-native-build-20261026/artifacts/deepflow-agent-native-linux-amd64-6aec171b`
  on dev-240, 77,910,288 bytes, SHA256
  `04f3dabfd86c8d2ea6457aa4bd2d4309584c35fe07bcc04aa937c53fc734eaa4`.
- Native build uses official image digest recorded in evidence plus existing
  Rust 1.97.1, offline dependency caches, 4 CPUs/8 GiB and no container network or
  privileged mode. Image Rust 1.83 could not reuse the newer offline Git cache;
  the toolchain fallback changed no dependency versions.

## Isolated runtime and actual traffic

- dev-240 has owned `traflens-lab-{mysql,clickhouse,server}` resources, private
  bridge/volumes, pinned images and generated private credentials. Existing
  multimeter and gitlab-runner containers were preserved.
- CPU/RAM caps: MySQL 1 core/1 GiB, ClickHouse 2/4 GiB, Server 2/4 GiB.
  Metadata schema has 161 tables/version 7.1.0.40; ClickHouse schemas, controller
  health and a real `Count(row)` query succeed.
- Controller/data: `192.168.1.240:20035/20033`; APIs only loopback 20417/20416.
  Scripts and exact bring-up constraints are in `lab/README.md`.
- Physical Agent ID 1 is registered through public APIs, with NPM/request-log
  features, bounded supervisor, 2 cores/1024 MiB, interface `enp1s0f0`, TCP port
  18080 and HTTP only. eBPF/integrations/proc discovery remain disabled in this
  functional smoke configuration. Full native build is not eBPF runtime proof.
- HTTP is generated over scoped IPv6 on the first 10G link. First 20-request run
  returned HTTP 200 but crashed the Agent at the IPv6 `/0` boundary; regression
  and runtime logs directly identified the defect now fixed.
- A later instrumented 20-request run produced 40 raw app records, 40 tagged
  flows and 20 complete HTTP Sessions with exact request paths/status 200 in the
  Agent's final protolog sender queue. Observers copied data and did not consume
  the primary queues.
- The initial minimal Ubuntu runtime omitted the IANA timezone database. Receiver
  and decoder counters proved 20 HTTP records arrived and decoded with zero
  decoder drops; CKWriter then failed on `DateTime('Asia/Shanghai')` timezone
  inference. The lab package now includes Go 1.26.2's `zoneinfo.zip`, sets
  `ZONEINFO`, and includes runtime assets/recipe in its image cache key. Only the
  owned Server container was replaced; both databases and volumes were retained.
- Final marker `smoke-20261026105159-timezone-fixed` PASSED: 20 client requests,
  20 server responses and 20 unique queried rows; every resource path matches
  exactly, with method GET and response code 200. Acceptance JSON and raw inputs
  are retained. This proves low-rate packet-mode IPv6 HTTP collection, transport,
  persistence and querying, not broad protocol/eBPF/performance parity.
- Absence of a separate L7 TCP connection log is normal: senders share
  `GLOBAL_CONNECTION` by default. Queue observers copied records without consuming
  the application queues and were bounded/disabled after diagnosis.
- Subsequent verification exposed an undersized ClickHouse thread pool in the
  lab configuration. After restarting only the owned ClickHouse container with
  its data volume retained, five fresh query-API reads each returned the exact
  same twenty GET/200 rows (4.7-17.4 ms). This measures these low-rate queries,
  not ingestion throughput or performance parity. CPU/RAM caps stayed unchanged.
- All 11 lab regression tests pass, including supervisor PID/start-time/repo
  ownership, existing-container image provenance and clean content-addressed
  runtime extraction. The private-password scan of complete Server logs found
  no match. The Agent supervisor is stopped; three owned lab containers remain.

## Protocol acceptance and boundary repairs - next checkpoint

- `4f0a7d96d833f770668dea304a5a6afaef2c0fbd` repairs future/cross-hour
  response-time inference, rejects non-ASCII/invalid minute-second inputs before
  slicing, and enforces the 120-second limit at microsecond precision.
- The same commit repairs the C plugin's dangling empty-string pointer and
  safely retains a NUL-terminated process name, including a full 15-byte comm,
  across each callback. It also aligns the public C header with the existing
  Rust response/check-result ABI and rebuilds the test shared object through a
  new Makefile. Fifty-five C/Rust size/alignment/offset comparisons pass.
- Default-feature native Release from exact `4f0a7d96d` also passes, with
  ten BPF objects, no source overlays and clean source after archiving/restoring
  the generated test ELF. Six native CFFI tests pass, including the libtrace
  MetaPacket process-name case; the native response-time module passes 15/15.
  Binary SHA256 is
  `2f6bd8507bb50aeaa94af5a475b5d81466e23281a074c3ed1cef2eb8670dda53`.
  Follow-up native WASM tests pass one of five and fail four despite a valid
  process name. Those four need further diagnosis; missing packet-mode process
  context does not explain all WASM failures. Live eBPF tracing is still untested.
- Final packet selected gate passes 73 tests: HTTP 20, DNS 4, MySQL 8, labeler
  19, response-time 15, process-name/ABI 5 and shared-object integration 2.
  The 46 lab tests cover independent DNS/MySQL wire vectors, deadlines, malformed
  responses, group ownership and exact query multisets. DNS acceptance requires
  the exact answer address/TTL; duplicate rows cannot hide missing requests.
- A complete packet library run now finishes without SIGSEGV: 294 cases,
  276 passed and 18 failed. All eighteen failures were reproduced individually
  against the compatible pinned upstream baseline. Its pristine locked build
  cannot run; the explicit minimal build-only overlays and exact evidence are in
  `evidence/2026-10-26/baseline/`. This is not a full upstream-suite pass.
- The three-protocol profile preserves all original resource/interface limits,
  adding only UDP 18053/DNS and TCP 18060/MySQL to HTTP 18080. Updating a populated
  group requires an explicit flag and the sole exact registered dev-79 identity;
  the operator must stop the owned Agent before applying restart-tagged settings.
- Real cross-host MySQL wire acceptance passed: complete greeting/login,
  20 unique COM_QUERY SQL strings and verified one-row results, then exact
  20-row query-API readback of SQL/type/success status twice. This is a bounded
  protocol fixture, not execution against a real database engine or TLS proof.
- DNS first batch `dns-20261026-ingest1` failed strict acceptance at 19/20.
  q0 had one request/one response in L4, DNS parsed successfully, but no L7 row.
  A contemporaneous CKwriter broken-pipe warning explicitly dropped one L7 item;
  correspondence to q0 is a strong inference because the warning has no flow ID.
  No reliability fix is included and the failed evidence is preserved.
- The next warm DNS batch and a new-process, no-warmup cold DNS batch each passed
  exact 20/20 domain/type/rcode/status/A-address/TTL query readback twice. Each
  observed batch independently captured 40 packets with zero kernel capture
  drops, 40 app records and 20 complete sender Sessions. The later passes do not
  erase or establish a fix for the first loss. Both bounded Agent runs stopped;
  queue observers are off, and only the three owned lab containers remain.

## Remaining validation and priorities

1. Fix and fault-test CKwriter connection recovery and failed-batch delivery
   semantics. Reproduce a database restart with marked traffic, and verify both
   loss and duplicate behavior; do not add blind retries with unknown delivery.
2. Extend protocol acceptance to a real MySQL database, DNS error/truncation/TCP,
   reconnects, TLS, loss, agent/server restart and sustained workloads.
3. Resolve the remaining 18 packet-library failures: six tunnel plugin stubs,
   segmentation/reassembly stub, defaults/snapshot/PCAP/Hessian compatibility,
   handshake RTT and service score assertions, and five packet-mode WASM fixture
   cases (four also fail in native mode with different assertions). Keep expected behavior intact and validate the feature-mode matrix.
4. Validate native eBPF/syscall/profiling at runtime, other protocols and storage
   robustness; then trace application and GUI. A native build is not runtime proof.
5. Fix API robustness cases in `lab/KNOWN_LIMITATIONS.md`, then compare pinned
   candidate/reference collector workloads with loss, CPU/RSS, flow/span rates
   and visibility delay before performance or full-parity claims.

Both direct links were enabled at runtime only; no management routes/persistent
network/offload settings were changed. Initial iperf3 4-stream/10-second receiver
rates were 9.166-9.277 Gbit/s, with nonzero TCP retransmits and zero NIC drop/error
counters. These are preliminary raw-link measurements on shared hosts.

Use `lab.py stop` for only owned containers; preserve their data volumes. Agent
supervisors expire after 15 minutes or three exits, and stop only their own child
process group. Runtime secrets/logs stay ignored; sanitize evidence before commit.
Keep the hourly task active: full feature/performance parity is not achieved.
