# TrafLens development checkpoint - 2026-10-26

Objective remains ongoing: validate and extend DeepFlow functionality and
performance, starting from the community implementation. Read this file and
`git status --short --branch` before each hourly iteration. Check upstream
changes deliberately; do not silently replace the reference version.

## Source and checkout

- Development: `ssh dev-79`, `/root/yb/git/TrafLens`, branch `main`.
- Reference: `8741e924ff0ae3964a135985c51e5a6ce6bde397`,
  `v7.2.3-1-g8741e924f`, with complete upstream Git history and Apache-2.0 notice.
- Canonical GitLab remote: `origin = git@192.168.1.50:yb/TrafLens.git`.
- GitHub remote: `github = git@github.com:SuperBigYB/TrafLens.git`.
- Read-only reference: `upstream = git@github.com:deepflowio/deepflow.git`;
  its local push URL is disabled.
- GitLab SSH authentication on dev-79 currently fails. A provided token can
  authenticate an ephemeral HTTP credential helper for this internal GitLab,
  which has no HTTPS listener. Never store that token in URLs, files, commits,
  Git configuration or logs. The transient bridge used in this run is under
  ignored `.traflens/work/`; it reads the token from SSH stdin only.

## Validated in this checkpoint

- Full community server builds with upstream `server/Makefile` and its vendor
  patches/generators. `make -C traflens server` reproduces the build using a
  checksum-pinned Go 1.26.2, private generator binaries/GOPATH and Python venv.
  The binary is `server/bin/deepflow-server`; `-v` prints its source version.
- The 18 Python distribution-tool tests pass on Linux.
- Five top-level protobuf smoke tests plus subtests pass. Candidate generated
  Go decodes wire fixtures encoded from the pinned upstream schemas. Unknown
  fields, wide counters, signed IDs, HTTP request/response metadata and field
  contracts are covered. Intentional field-renumbering controls fail as expected.
- Complete short tests pass for `server/libs/queue`, `server/libs/hmap/lru` and
  `server/libs/flow-metrics`. The inherited tests first required API migration;
  behavioral regressions were then reproduced and repaired.
- Production fixes: both IPv6 addresses are independent after `CloneTag`;
  anomaly merges preserve derived and out-of-order counts; CIT, SYN/ACK retransmit
  and OOO metric fields have valid line-protocol separators; tag keys emit in
  lexical order without runtime sorting; IPv6 path emits `ip_version=6`.
- The queue/LRU tests print inherited countable-pool cleanup warnings despite
  passing. These logs are preserved, not counted as evidence of full-suite health.

Evidence and limitations are indexed in `EVIDENCE.md` and
`evidence/2026-10-26/`. Official reference links are in `REFERENCES.md`.

## Lab and throughput evidence

- Link 0: dev-79 `enp1s0f0` <-> dev-240 `enp2s0f0`.
- Link 1: dev-79 `enp1s0f1` <-> dev-240 `enp2s0f1`.
- Both were administratively down; they were enabled at runtime only. Scoped
  IPv6 link-local connectivity works in both directions. Management addresses,
  routes, persistent network configuration and offloads were not changed.
- One iperf3 3.9 run per direction/link, 4 streams x 10 seconds, MTU 1500:
  link 0 receiver rates 9.237/9.277 Gbit/s; link 1 9.243/9.166 Gbit/s.
  Sender TCP retransmits: 23/67/73/324. NIC drop/error counters were zero.
  Hosts were shared and server compilation overlapped; no collector was active.
  Treat these as preliminary link measurements, not collection benchmarks.
- Temporary port 15201 servers exited; no benchmark listener remains.
- dev-79 root filesystem had about 25 GiB free after initial builds. dev-240 has
  substantially more disk but only about 6 GiB available RAM in the initial
  snapshot. Inspect current resource use before deploying storage or load tests.

## Next iteration priorities

1. Build the Linux agent using `agent/build.md` and pinned native/Rust
   dependencies; run parser fixtures and retain an actual build/test log.
2. Establish an isolated resource-bounded community stack: metadata database,
   ClickHouse, controller, ingester and querier. Preserve existing host services.
3. Register both lab agents and prove HTTP traffic on a direct link becomes
   correctly tagged L4/L7 records retrievable through the query API.
4. Add trace reconstruction and GUI components with their own pinned versions,
   dependency/license inventory and end-to-end tests.
5. Turn the edition feature inventory into observable acceptance cases. Full
   upstream suite, enterprise-specific capabilities, GUI, agent eBPF/profiling,
   resource discovery, packet capture/replay and tracing accuracy still require
   validation; source presence is not an acceptance pass.
6. Compare candidate and pinned reference on identical workloads and resource
   limits: collector on/off business overhead, HTTP spans, active/new TCP flows,
   large-packet throughput, small-packet PPS, loss, CPU/RSS and visibility delay.
   Repeat runs; record payload sizes, concurrency, NIC offloads and sampling.

Commit tested changes, push to both requested remotes without force, and verify
their exact branch SHA at each checkpoint. Keep the hourly automation active
until the objective has been demonstrably achieved or the user changes it.
