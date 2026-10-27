# TrafLens development checkpoint - 2026-10-27

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

## ClickHouse write recovery checkpoint

- `f89e5647c58e1ff02b1fbd7f53b4aada07789350` adds a real ch-go native-protocol
  input gate. It retains serialized rows across only provably pre-supply network
  failures, replaces broken clients, and resets/counts a logical batch once.
  No vendor, table engine, deduplication or external API signature was changed.
- `4b2799823516bc49ff2f3c840a782cd57361f28f` extends recovery to at most 13
  attempts under a shared ten-second context, with 100ms exponential backoff
  capped at one second. A 550ms refusal regression fails the initial 200ms policy
  and passes the new one. Driver cancellation may add about one second cleanup.
- Thirteen top-level Go tests plus real-protocol subcases pass, including race
  checks. They cover stale idle sockets, failure before metadata, lost reply
  after data, exception preservation, empty metadata, DateTime inference, one
  EOF block, bounded dialing and single final accounting. CI now includes the
  owning package with `-race`. All 65 lab helper tests also pass.
- Actual candidate Server on dev-240 embeds exact source `4b2799823`, binary
  SHA256 `b820516ca626e213f71a4955e68e6fccda09b57603b0bd6234d2a4855a8447aa`;
  runtime archive SHA256
  `5c1690d76be3c12699a43a23e80a19488f321884438b1965627008d6e89484e0`.
  Only the owned Server container was replaced before the candidate experiment;
  databases/data volumes were retained and unrelated containers were preserved.
- Baseline Server `4922b11ff` and candidate use the same `6aec171bf` packet Agent
  and exact protocol config. After an offline inventory
  entry was found absent, the same owned dev-79 identity was safely re-registered as Agent ID2.
  Re-run `register-agent.py` before capture rather than assuming ID1 persists.
- Baseline `f20261026b2` failed BEFORE fault injection at HTTP20/MySQL20/DNS19;
  its guard correctly prevented a restart. This loss is preserved separately.
  The initial `b1` preparation was abandoned without traffic or mutation when
  the helper's after-failure recovery checks were corrected.
- Controlled warm baseline `f20261026b3` and candidate `f20261026c1` each record
  one explicit DNS preconditioning exchange outside measured requests. Each
  then sends twenty HTTP/DNS/MySQL requests in each of before/during/after,
  with one owned ClickHouse restart overlapping all three protocols. Baseline
  gives 60/60, 59/60, 60/60 and final FAIL; candidate gives 60/60 in every phase,
  all nine exact multisets match twice again at finalization, and final PASS.
  Thus this controlled case improves 179/180 to 180/180 with no duplicate rows.
  All phase overlap uses dev-240 server timestamps, not cross-host clocks.
- Persisted candidate L7-writer intervals show six retries, five failed retry
  attempts, zero failed/uncertain rows, and successful writes. These are sampled
  interval increments, not a cumulative gauge; the initial 61 seconds before
  the first stored point are unobserved. The total includes warmup and
  fixture connection messages beyond the 180 marked requests.
- A failed INSERT after input supply remains an uncertain outcome and is never
  blindly replayed. This does not provide durable buffering, general exactly-once
  delivery, unbounded outage coverage or retries of independent DDL paths.
  The controlled pass does not erase the unfaulted first-DNS-loss evidence or
  establish unrestricted load/performance parity. The bounded Agent is stopped.

## Tunnel decoder checkpoint

- The four public tunnel plugin stubs are replaced with independent ERSPAN
  I/II/III, TEB, Tencent keyed GRE and IPv4 VXLAN-GPE/NSH decoders. Public Rust
  signatures and tunnel enums are unchanged; no dependency/vendor update or
  private implementation is imported. Standard wire formats and the existing
  Go pseudo-MAC contract guide the implementation.
- The Agent caller now validates header bounds and IPv4 options, respects IHL,
  checks UDP and inner-IP logical lengths, returns IPv6 Geneve offset 56,
  snapshots Tencent outer addresses before synthetic Ethernet mutation, rejects
  excessive tiers/unrepresentable IPIP offsets transactionally, and accepts
  minimal IPIP and consistent snaplen-truncated captures.
- All 28 decoder tests and 26 Agent decapsulation tests pass. The complete
  selected packet CI gate passes 127 cases (99 Agent plus 28 tunnel crate).
  The full packet library finishes 307 cases: 295 pass and 12 fail. All six
  previous tunnel failures now pass; the twelve remaining names match the
  previous eighteen-case inventory. They remain unresolved, not ignored.
- Thirteen new caller regressions cover independent wire vectors, every prefix,
  invalid L2/tier values, declared-length padding, IPv4 options, snaplen, nested
  identity and packet/metadata transactionality. An explicit hybrid negative
  control using the old 52fa57a8b caller with the new decoders fails ten of these
  thirteen, including two panics, the incorrect Geneve offset and address
  corruption. This is not a pristine upstream suite comparison.
- Independent review found three additional length-validation gaps; the final
  candidate includes focused rejection and valid-snaplen controls for each.
  See `README-tunnels.md` and `evidence/2026-10-26/tunnels/` for raw results.
- Outer-IPv6 GRE/GPE, extension chains, outer fragment reassembly, ERSPAN raw-IP
  frame types/custom C/K extensions and IPIP layouts with IP header no larger
  than L2 remain unsupported. No new live tunnel traffic or throughput claim
  follows from these parser tests.
- Exact source `ff05c646d` passes the complete default-feature native Release,
  all 54 native tunnel tests, host version/ldd and clean-source checks. Binary
  SHA256 `14f60cbf02ebce613732b2f9b45bdeb3197e37a2ed90f0a6693fd3c7205ffe90`; ten BPF ELF files and libtrace are built. The first
  4778380b2 build failed version acceptance despite passing tests; legacy Git
  cache invalidation is repaired and its failed evidence retained. Three real
  repository-layout probes pass; CI now checks embedded CommitId against HEAD.
  Both current lab Agent binaries embed ff05c646d; the bounded Agent remains
  stopped. Full native suite/live tracing and actual tunneled traffic remain
  separate pending gates.

## Actual tunnel-wire checkpoint - 2026-10-27

- New bounded link/traffic/capture/acceptance helpers validate eleven supported
  tunnel layouts with IPv4/IPv6 inner HTTP and DNS on the first direct link.
  The final tn20261026w3 case sends 260 frames at 20 pps: 20 HTTP and 20 DNS
  synthetic conversations, not a real HTTP service or DNS resolver workload.
- Actual receiver PCAP contains all 260 frames in identical byte order to the
  generated frames, with zero kernel capture drops. The Agent observes 80 app
  records and sends 40 complete Sessions. Both exact protocol multisets match
  twice, including DNS answer address and TTL60. All 40 L7 records also match
  inner endpoints/types and their persisted L4 tunnel metadata/closure twice.
- ERSPAN/TEB intentionally trim metadata (L7 tunnel_type zero); Tencent GRE
  retains type3 and GPE/NSH type5, tier1, full key/VNI and the original outer
  transport addresses. Both inner directions are mirrored 240-to-79; the outer
  response addresses must not be reversed. L7 has no tunnel ID/outer-IP fields.
- Retained failures remain explicit: w1 Local mode splits retained-tunnel
  request/response flows; its capture expired before emission and is not loss
  evidence. w2 Mirror merges these but only gives HTTP18/20 and DNS18/20 because
  default NPB BPF excludes ERSPANIII before decoding. Final lab-only mode1 with
  skip_npb_bpf=true fixes the configuration, retaining strict full BPF/MAC/IP
  scope and all CPU/memory/output limits. No Rust production default is changed.
- Both 240-second link leases clean their exact bench-only /32 addresses and
  peer routes in all three cases; final cleanup succeeds with no unknown state.
  The bounded Agent and observers are stopped. Only the three owned lab
  containers remain; unrelated containers and management routes are preserved.
- Runtime packet source ff05c646d and Server4b2799823 are verified by version
  and binary hashes. All119 lab helper tests pass, including real offline BPF,
  independent wire/checksum/TCP/DNS vectors and strict metadata counterexamples.
  CI installs tcpdump so the offline BPF gate cannot be skipped for its absence.
  Sources, raw PCAPs/queries, failures and exact hashes are under
  evidence/2026-10-27/tunnel-wire/. See README-tunnel-wire.md for commands.

## Adjacent TCP-window checkpoint - 2026-10-27

- Source `155c5ff79ce19d31efd6cf1522c5b40a2b150d31` replaces the community
  segmentation stub with opt-in adjacent two-packet sliding parse windows.
  Original packets feed L4 once; windows/tails feed L7. Tests cover TCP sequence
  wrap/gaps/truncation/control boundaries, metadata ownership, byte budget,
  interleaved ACK/retransmission metrics, report-tail drain and direction changes.
- The controller exposes the disabled-by-default port-list setting. Four focused
  Go tests cover template metadata, round trips and numeric legacy-list upgrade.
  Configured service scores and reverse cache updates are repaired; the stale
  handshake fixture follows the existing first-ACK completion algorithm.
- All168 selected Rust and124 lab Python tests pass. Full packet-library result
  is321=312PASS/9FAIL, no ignored tests. Full agent_config retains the same
  observed5 top-level and7 subcase failure names/panic as isolated parent395f;
  cases after the panic remain unverified. Focused success is not a full pass.
- Actual case sw20261027a1 passes300 ordered byte-identical received frames,
  zero kernel capture drops, exact HTTP20/DNS20 multisets twice, and all40
  associated tunnel metadata/flow closures twice. Both HTTP directions split
  after two bytes. Profile segmentation retains strict Mirror capture scope,
  Agent2CPU/1024MiB,20pps, bounded100s capture/90s observers/240s link leases.
  Both temporary network leases clean completely; Agent and observers stop.
  Only owned Server is recreated; both databases retain identity/start times.
- Live packet Agent and Server embed155c5ff79. Separate default-feature optimized
  native Release passes41 selected tests, exact version/ldd/libtrace and10BPF
  ELF checks. Primary repository is clean; archived jattach dependency has one
  pre-existing Makefile static-library build patch. All10 non-Makefile files,
  including5 C sources, and26 OTel files match pins. Patch/hashes and the BPF
  proof-glob correction are retained; dependency build metadata is qualified.
- Core CI40371413194 passes both jobs, including168 Cargo/124 lab/focusedGo and
  embedded CommitId gates. Public result summary and guide: README-tcp-window.md and
  evidence/2026-10-27/tcp-window/summary.json. Full raw evidence stays ignored
  locally. No general TCP stream, live eBPF, sustained
  performance or complete DeepFlow parity is claimed.

## Complete Agent-library checkpoint - 2026-10-27

- Core source `913231d6a7918edadd8db48a4e5d38ec9b76601d` closes the earlier9 packet-library failures. Complete
  packet library371/371, default-feature native library382/382,
  tunnel28/28 and window21/21 pass with no ignored tests. CI now runs the full
  packet library instead of the prior168-case subset. Python124 and focusedGo4
  still pass; both local binaries build from committed source.
- Configuration restores Lua defaults/capture4 naming and aligns existing
  Triple/Dameng filter maps without enabling those protocols. RocketMQ golden
  changes retain all prior fields; the existing public memcached PCAP changes
  only four global-header bytes, retaining every one of20421 packet records.
- Hessian complete ASCII/chunk bounds fix EOF/truncation defects and preserve
  Java/Hessian separation. Legacy SDK2023/current layouts and merge-cache end
  flags are repaired. Guest memory/context errors fail safely, modern WASI
  imports remain within an empty capability context, and only typed exit0 is
  accepted during initialization. HTTP metadata uses already captured headers.
- Two reproducible Go guests use a pinned compiler/SDK and an explicit IsEnd
  fixture patch. The unchanged2023 guest passes native integration. Native
  source is clean, with the disclosed pre-existing jattach Makefile build patch.
  The first GCC4.8 link failure and first legacy-fixture failure are retained;
  restoring image login-shell GCC11 resolves the environment issue.
- Public aggregates: evidence/2026-10-27/agent-protocols/summary.json; detailed
  logs and environment evidence remain ignored. Guide: README-agent-protocols.md.
  Live eBPF, sustained workloads and complete DeepFlow parity remain pending.

## Configuration and plugin checkpoint - 2026-10-27

- Core `62429a607627051c3f242247ff646c67fee80e3e` closes the inherited full Go configuration suite:
 44 top-level/129 total pass events (85 subtests) under `-race`, no failures or skips. CI now
 gates the entire package. Template bounds/types/recursive errors, embedded JSON
 string preservation, legacy profiling/tagged-only migration, reusable upgrader
 state, DB/YAML error propagation and atomic unit-overflow rejection are repaired.
- Missing plugin merge IDs and mixed active/batch merge modes fail before shared
 cache/performance mutation. Read-only peek preserves LRU order; C retains its
 per-item rejection contract. Conservative same-key batch mode changes are
 rejected. Shared timeout algorithms remain unchanged; RTT threshold is not TTL.
- Complete packet382+28+21=431 and native393+28+21=442 pass,
 no failures/ignored tests. Scoped56 plugin cases include real host-import guests,
 C collision and12 direct unchanged-algorithm baseline controls. Python124+18 pass.
 Exact-source Server/packet/native binaries build; native original2023 keeper,
 version/ldd/libtrace/tenBPF checks pass. Existing jattach build overlay is qualified.
- Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40395398781. Guide: README-config-parity.md.
 Aggregate evidence: evidence/2026-10-27/config-parity/summary.json. Raw logs and
 environment/configuration evidence remain ignored. No new runtime deployment or
 traffic acceptance was performed; earlier wire results remain separate.

## API and eBPF runtime checkpoint - 2026-10-27

- Final Server source `c91b1a3c5ee61654d3f5ba89b00d689b21f56614` fixes empty-function query panics and
 malformed controller error JSON. Empty arguments return one typed400; recovery
 writes generic500 only before a response is written, otherwise aborting without
 appending. Nil byte data is null; descriptions and
 pages are encoded safely, and invalid raw JSON/UTF8 fails before headers.
- Local UseNumber preserves JSON integer tokens. A bounded linear scanner
 accepts exact whole decimal/exponent values within Go-int bounds; native YAML
 float/alias/merge values cannot masquerade as integers. Four inherited test
 selectors are removed. Generic dict/null and operational range limits remain.
- Six relevant Go packages pass race:91 top-level/292 total test-pass events.
 The 2048 bounded rational-oracle vectors are included in one config test.
 Local lab tools134 pass. Source CI includes config and five API package gates.
- Actual candidate HTTP13/13 passes: three empty functions, native Count(row)
 equivalence, nested-map and GUI-text persistence, invalid-update atomicity,
 exact raw integers/whole decimals/exponents, and empty-group cleanup. Original
 configurations and inventory are preserved; both database container/start/volume
 identities survive Server-only replacement. First f980 malformed DATA failure
 and later observer null-list failure are retained privately.
- Independent libtrace runtime gate links source624 artifacts:81 loaded program
 sections and30 attachment wrappers, RUNNING then STOP,20 synthetic TCP roundtrips,
 zero callbacks. Full port bypass and disabled protocol maps are read back;
 all owned programs disappear and host BPF/tracefs inventories are restored.
 This is system-wide-hook lifecycle/rejection proof, not full Agent payload or
 ingestion/profiling/performance acceptance. The prior jattach build overlay stays
 qualified. Guides: README-api-validation.md and README-ebpf-runtime.md.
- Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40405314725. Public aggregates:
 evidence/2026-10-27/api-ebpf/summary.json. Raw HTTP, configs, identifiers,
 process/container metadata and logs stay ignored locally.

## Socket namespace and native verifier checkpoint - 2026-10-27

- Core `a0cb0fb9c111cb7b34168d459fd3e188b07826e6` adds a disabled-by-default current-task netns socket fence,
  immutable local managed-Agent bootstrap with a process-lifetime namespace FD,
  and preflight rejection of unsafe capture/profiling/controller candidates.
  It is not a socket-owner or kernel PID ACL; host hooks and some metadata
  access remain global. Full managed-Agent payload ingestion remains pending.
- Native stack pressure, leaked output-buffer references, outlined fork helpers
  rejected by the map-only loader, and an uninitialized PID/thread bitfield are
  repaired. All failed candidates/verifier/harness observations stay private.
  Nine C tests run364 assertions, including actual-function/poisoned-stack cases;
  the offline ELF checker rejects the real seven-object bad build and accepts
  all ten corrected objects. Published tool/lab suites pass31/154.
- Exact native403+28+21=452 and packet392+28+21=441 pass, no failed/ignored tests.
  The unchanged original2023 keeper passes. Native binary SHA256 is
  `7e3ecc60f8c0199e7f66ec1c64508e1f7eb13cef545944ff39783e94287630ae`. The inherited jattach Makefile build-only overlay
  remains qualified. Core CI: https://github.com/SuperBigYB/TrafLens/actions/runs/40423638878 (both jobs passed; owning7 Go race packages
  and CKwriter race also pass). Later helper/docs HEAD CI is checked separately.
- Actual standalone libtrace runs pass all three modes: default all-bypass and
  wrong-owned-netns controls each deliver0 callbacks; selected netns delivers
  80 exact data+2 close callbacks. Each mode completes20 positive+40 negative
  same-port/equal-length HTTP roundtrips (180 total). All81 loaded programs and
  30 attachment wrappers stop/clean; full BPF/tracefs inventories and preexisting
  containers are preserved. No Agent/Server ingestion or performance claim.
- Server `-f` reparsing is repaired. Runtime Server source121bdbe26f starts with
  explicit `-f /etc/server.yaml` and passes real HTTP13/13; database and unrelated
  container/start/mount identities are retained. Current Agent inventory is0.
- Guide: README-ebpf-netns-scope.md; aggregates:
  evidence/2026-10-27/ebpf-scope/{summary,runtime}.json. Raw configuration,
  namespace/process/container IDs and logs stay ignored. Runtime191-file private
  manifest fingerprint: `afae099b0ca69584d54c1fac3f30c136d76aa780d8dd158f7999caba48883e32`.

## Remaining validation and priorities

1. Design persistence/server-side idempotency for ambiguous commits and longer
   outages before replaying supplied blocks. Extend recovery coverage to DDL,
   queue pressure and process restart, and investigate unfaulted cold/idle DNS
   first-record loss independently of the passed warm restart experiment.
2. Extend tunnel acceptance to malformed/lost/reordered traffic, real services
   and sustained workloads; extend protocol
   acceptance to a real MySQL database, DNS error/truncation/TCP,
   reconnects, TLS, loss, agent/server restart and sustained workloads.
3. Extend Hessian Unicode/map coverage and general TCP streams; keep current
   ASCII and adjacent-window limits explicit. The complete configuration race,
   packet/default-native library and guarded plugin-identity gates now pass.
4. Extend the passed standalone exclusive-netns payload gate to full managed
   Agent collection, transport, persistence and exact queries, then TLS/profiling
   and trace application/GUI. Respect the initial restricted profile and pin FD
   lifetime; private-PID Agent readiness and end-to-end ingestion remain pending.
5. Extend remaining API shape/range cases (the startup-flag issue is resolved) in
   `lab/KNOWN_LIMITATIONS.md`; compare pinned candidate/reference workloads with
   loss, CPU/RSS, flow/span rates and visibility delay before parity claims.

Both direct links were enabled at runtime only; no management routes/persistent
network/offload settings were changed. Initial iperf3 4-stream/10-second receiver
rates were 9.166-9.277 Gbit/s, with nonzero TCP retransmits and zero NIC drop/error
counters. These are preliminary raw-link measurements on shared hosts.

Use `lab.py stop` for only owned containers; preserve their data volumes. Agent
supervisors expire after 15 minutes or three exits, and stop only their own child
process group. Runtime secrets/logs stay ignored; sanitize evidence before commit.
Keep the hourly task active: full feature/performance parity is not achieved.

Latest completed source CI: both jobs passed for
`a0cb0fb9c111cb7b34168d459fd3e188b07826e6` in <https://github.com/SuperBigYB/TrafLens/actions/runs/40423638878>.
The final helper/documentation head's actual CI is verified separately. Exact
native/runtime source and Server runtime source are distinct as recorded above.
Full feature/performance parity remains ongoing.
