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
- The packet Agent CI extension runs the selected packet tests and functional
  build using pinned Rust 1.97.1. Check the new commit's actual run result before
  treating this newly added job as a passed remote gate.

## Agent correctness and builds

- `035a19064d171ed690422c5521ab25f12e66bb80` fixes the stale pcap lock edge,
  libtrace feature gating, asynchronous workspace-wide formatter side effects,
  and stale embedded Git revision metadata. No dependency versions were upgraded.
- `6aec171bf820e5ce516349ed3677395050b8a384` fixes blacklist accounting, request/
  response ordering, fragment/flow-end double counting and timeout retirement,
  and the IPv6 `/0` shift overflow reproduced by real traffic.
- The final packet entry point passes HTTP 20, DNS 4, MySQL 8 and policy-labeler
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

## Remaining validation and priorities

1. Expand the passed HTTP acceptance case to DNS/MySQL, reconnects, loss and
   restart/recovery tests. Add independently verified acceptance cases instead of
   inferring full product behavior from a single successful workload.
2. The broad packet `--lib` attempt observed 15 failures then a plugin test
   SIGSEGV. Baseline comparison is pending; do not attribute them all to upstream
   or claim the full suite passed. Raw inventory is committed with that caveat.
3. Validate native eBPF/syscall/profiling at runtime, other protocols, storage
   robustness and all feature acceptance cases; then trace application and GUI.
4. Fix the confirmed API robustness cases listed in `lab/KNOWN_LIMITATIONS.md`
   without confusing unsupported query syntax with storage health.
5. Compare pinned candidate/reference with repeatable collector-on/off workloads,
   packet loss, CPU/RSS, flow/span rates and visibility delay before parity claims.

Both direct links were enabled at runtime only; no management routes/persistent
network/offload settings were changed. Initial iperf3 4-stream/10-second receiver
rates were 9.166-9.277 Gbit/s, with nonzero TCP retransmits and zero NIC drop/error
counters. These are preliminary raw-link measurements on shared hosts.

Use `lab.py stop` for only owned containers; preserve their data volumes. Agent
supervisors expire after 15 minutes or three exits, and stop only their own child
process group. Runtime secrets/logs stay ignored; sanitize evidence before commit.
Keep the hourly task active: full feature/performance parity is not achieved.
