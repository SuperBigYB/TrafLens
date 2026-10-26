# Two-host tunnel wire acceptance

This gate sends synthetic Ethernet frames across the direct 10G link from
dev-240 to the packet Agent on dev-79, then checks persisted application records
and associated flow metadata through the isolated Server's query API. It uses
the decoders described in [README-tunnels.md](README-tunnels.md). It does not
run a browser, HTTP service or DNS resolver, and it is not a throughput or
DeepFlow feature-parity benchmark. This checkpoint changes lab tools and
configuration; it makes no further Rust production changes.

`--flavors all --count 1` generates 40 requests: 20 HTTP GET/200 and 20 DNS A
exchanges. Eleven flavors cover ERSPAN I/II/III, TEB, Tencent GRE v0/v1,
GPE Ethernet, GPE raw IPv4/IPv6, and NSH MD1/MD2. Most run with both inner IP
families; the two raw-IP flavors each use their named family. HTTP includes a
synthetic TCP handshake and close. The total is 260 frames, bounded to 20pps,
1000 frames, 1514 bytes per frame and a 120-second emit deadline.

The generated `traffic.pcap` uses deterministic epoch 1700000000 timestamps
(2023). Those timestamps are not the run's emission time. Actual start/end UTC
times are in `result.json`; receiver capture times are separate evidence.
Neither generating a PCAP nor successful `send()` establishes ingestion success.

## Capture configuration and link lease

The `tunnels` profile retains 2 CPU/1024 MiB, the 8 MiB AF_PACKET ring, one
`enp1s0f0` capture worker, disabled eBPF/process discovery and the existing output
limits, including `l7_throttle=1000`. Its bounded workload is below that limit.
HTTP TCP18080 and DNS UDP18053 are the only enabled application protocols/ports;
their tag blacklists and ignored L7 observation-point list are empty.

Its lab-only settings are:

```text
inputs.cbpf.common.capture_mode = 1
inputs.cbpf.af_packet.skip_npb_bpf = true
inputs.cbpf.af_packet.bpf_filter_disabled = false
inputs.cbpf.preprocess.tunnel_decap_protocols = [1, 2, 3, 4, 5]
inputs.cbpf.preprocess.tunnel_trim_protocols = [ERSPAN, TEB]
```

Mirror mode keeps inner request/response flow matching stable despite the fixed
outer MAC direction in retained tunnels. Skipping the built-in NPB exclusions
admits ERSPAN III's GRE protocol 0x22eb. The user BPF remains enabled and exact:

```text
ether src 58:47:ca:7c:78:59 and ether dst 58:47:ca:77:66:e2 and ip src 198.18.0.240 and ip dst 198.18.0.79 and (ip proto 47 or udp dst port 4790)
```

VXLAN/IPIP/Geneve decoder selectors remain available for nested content. The
filter does not admit additional outer VXLAN, IPIP or Geneve traffic. The
`http` and `protocols` profiles retain their previous Local mode and filters.

Both hosts have IP forwarding enabled. To keep benchmark packets from being
forwarded toward a management/default route, `tunnel-link.py` leases only:

- dev-79: `enp1s0f0`, MAC `58:47:ca:77:66:e2`, local `198.18.0.79/32`, peer `.240/32`.
- dev-240: `enp2s0f0`, MAC `58:47:ca:7c:78:59`, local `198.18.0.240/32`, peer `.79/32`.

The address label is `<interface>:tlens`; the peer route uses that interface,
the local source address, protocol `static`, metric 42796 and table `main`.
Default execution only prints a plan. `--execute` requires the expected MAC/UP
interface and refuses any pre-existing bench address or covering non-default
route anywhere in the host's IPv4 tables. It creates a fresh private
`/tmp/traflens-tunnel-link-<marker>` directory and never reuses one.

Each 10–300 second lease uses a monotonic deadline and cleans up on normal
expiry, SIGTERM, SIGINT or SIGHUP. It deletes only successful additions whose
interface identity, label/prefix and route ownership fields still match.
Partial route-add failure rolls back the acknowledged address. Changed foreign
items are preserved and reported as cleanup failures. A timed-out or
signal-killed `ip` child has an unknown kernel result: the helper records
`uncertain_add`, refuses blind deletion and exits unsuccessfully. Inspect that
state before any manual recovery; do not retry the same marker.

`lease.json` records `ready`/`finished`, deadline, interface identity, errors and
`cleanup_ok`; `argv.json` records the invoked arguments. `preflight.json` retains
only bench-related results and the direct interface identity, never the full
host address/route dump. Directories are mode700 and JSON files mode600. No
sysctl, firewall, management/default route or persistent network setup changes.

## Run from a control shell and the two hosts

Start with the existing owned lab and packet binary prepared according to
[lab/README.md](lab/README.md). Use root for the two raw-network host shells.
Keep their sessions open while leases run. Choose a fresh lowercase DNS-label
marker of at most 24 characters, and use exactly the same marker everywhere.
The examples use `tn20261027x1`; replace it for every new run. Never overwrite a
failed case or treat a repeated marker as a new experiment.

From the control machine, synchronize the matching helpers into the existing
dev-240 helper directory. For example, copy the changed profile and smoke base:

```sh
scp -3 dev-79:/root/yb/git/TrafLens/traflens/lab/configure-agent.py dev-79:/root/yb/git/TrafLens/traflens/lab/agent-smoke.json dev-240:/tmp/traflens-lab-code-20261026/
```

Also copy `tunnel-link.py`, `tunnel-traffic.py`, `verify-requests.py` and
`verify-tunnels.py` from that source directory to the same helper directory.
Compare their SHA256 values on both hosts. The existing `lab.py` must match the
checkout. These are code files; do not copy private lab configuration or secrets.

First stop the owned Agent on dev-79:

```sh
cd /root/yb/git/TrafLens
python3 traflens/lab/run-agent.py --stop
```

Then apply and read back the profile on dev-240. The populated group must contain
only the exact registered dev-79 identity; use the existing registration helper
if that inventory has expired, rather than assuming a fixed Agent ID.

```sh
cd /tmp/traflens-lab-code-20261026
python3 configure-agent.py --profile tunnels --update-owned-agent
```

On dev-79, create a fresh run directory, start its bounded supervisor, and lease
the local bench address/route:

```sh
set -euo pipefail
cd /root/yb/git/TrafLens
marker=tn20261027x1
run=.traflens/work/tunnel-wire/$marker
test ! -e "$run"
mkdir -m 700 -p "$run"
python3 traflens/lab/run-agent.py --seconds 900 > "$run/agent-supervisor.log" 2>&1 &
python3 traflens/lab/tunnel-link.py --role dev-79 --marker "$marker" --seconds 240 --execute > "$run/link-79.log" 2>&1 &
lease_pid=$!
```

On dev-240, start the matching lease in a separate shell; keep its PID for wait:

```sh
cd /tmp/traflens-lab-code-20261026
marker=tn20261027x1
python3 tunnel-link.py --role dev-240 --marker "$marker" --seconds 240 --execute > "/tmp/$marker-link-240.log" 2>&1 &
lease_pid=$!
```

Read each host's `/tmp/traflens-tunnel-link-$marker/lease.json` and require
`status=ready` with adequate remaining time. Wait for the new Agent's mirror
dispatcher and fresh `Grpc finish update ... on 3 listener`, not the earlier
zero-listener sync. On dev-79, start capture and queue observation:

```sh
bash traflens/lab/capture-tunnel-wire.sh "$marker"
```

It requires more than 110 lease seconds remaining, verifies `/livez` and the
current process's readiness log, captures for 100 seconds, and observes queue
copies for 90 seconds. While that command runs, the control shell must read
`.traflens/work/tunnel-wire/$marker/capture-ready.json` on dev-79 and require
`ready=true`. Confirm both leases are still ready before transmitting.

Only after capture is ready, emit on dev-240:

```sh
cd /tmp/traflens-lab-code-20261026
out=/tmp/traflens-lab-20261026/tunnel-wire/$marker
python3 tunnel-traffic.py emit --marker "$marker" --flavors all --count 1 --pps 20 --timeout 120 --execute --output-dir "$out"
python3 verify-requests.py --expected "$out/expected-http.json" --output "$out/acceptance-http.json"
python3 verify-requests.py --expected "$out/expected-dns.json" --output "$out/acceptance-dns.json"
python3 verify-tunnels.py --manifest "$out/manifest.json" --output "$out/acceptance-tunnels.json"
```

The emitter requires a fresh output directory and a matching live dev-240 lease;
its local guard cannot establish dev-79 readiness. Inspect each exit code and
`passed` result. Application checks require exact multisets twice, including
DNS answer address and TTL60, so duplicate or half-session rows cannot hide a
missing request. Tunnel acceptance links exact uint64 L7 flow IDs to their
persisted L4 rows and requires a complete bidirectional closing report for every
flow, two consecutive successful reads, and no metadata contradictions.

After capture and queries complete, use `wait "$lease_pid"` in each lease's
launch shell. Require both final states to have `cleanup_ok=true`,
`address_added=false`, `route_added=false`, `uncertain_add=null` and no error.
Stop only the owned Agent using `run-agent.py --stop` on dev-79. Preserve emitter
JSON/manifest/PCAP, receiver PCAP/tcpdump counters, queue observations, exact query
responses, Agent provenance and both final lease states. Leave unrelated Agents,
containers, addresses and routes alone.

## Persisted metadata contract

ERSPAN and TEB are configured for trim: their persisted L7 tunnel type is zero,
and L4 type/tier/IDs are zero with unspecified outer addresses (`::`). Their
original session ID/key is intentionally discarded by that policy.

Tencent retains tunnel type3 and the full GRE key. GPE/NSH retains type5 and its
VNI. Their associated L4 reports must have tier1, matching TX/RX ID and outer
source `198.18.0.240` / destination `198.18.0.79`. The outer source/destination
remain in that order for both inner directions: both synthetic conversations
were emitted from dev-240. Early L4 reports may contain zero metadata, but any
nonzero value must agree and every flow must eventually close with complete
bidirectional metadata. L7 contains tunnel type, not the tunnel ID or outer IPs;
those assertions belong to L4. Queue observations corroborate the pipeline but
do not replace database acceptance.

## Recorded runs

Evidence is retained under `evidence/2026-10-27/tunnel-wire/`. The run IDs remain
`tn20261026w1`, `tn20261026w2`, `tn20261026w3`: emission occurred on October26 UTC;
local acceptance crossed midnight in Asia/Shanghai. All runs remain separate.

- w1 used Local mode. HTTP returned six rows; DNS returned thirty, including
  twenty-four unmerged half sessions. These are failures, not thirty successes.
  ERSPAN I/II and TEB were present; retained tunnel directions split into
  separate flows. Offline production decoding still accepted all 260 frames.
- w2 used Mirror mode and captured all 260 frames with zero kernel drops.
  HTTP 18/20 and DNS 18/20 formed 36 complete sessions. ERSPAN III was missing
  because the default built-in NPB BPF excludes GRE 0x22eb. The next correction
  changes only the lab profile, retaining the exact user filter.
- w3 used Mirror mode plus `skip_npb_bpf=true`. It emitted 260/260 frames at 20pps
  from `2026-10-26T15:58:36.174Z` to `15:58:49.205Z`, about 13.03 seconds.
  The receiver recorded 260 captured/260 filter matches/zero kernel drops;
  app queues held 80 request/response items and the sender held 40 complete
  sessions. HTTP 20/20 and DNS 20/20 passed exact multiset checks twice, including
  exact DNS A answers and TTL60. All 40 associated L7/L4 flows passed complete
  bidirectional metadata/closure checks twice with no contradictions.

The packet binary embeds source `ff05c646d60df4dfafa26a7572121c97413d62e3`,
SHA256 `f45bb1570dd529f4ff8e2ad1ee62f4804094b4f24c88982459156f411a9a54f8`.
The live lab Server embeds `4b2799823516bc49ff2f3c840a782cd57361f28f`,
SHA256 `b820516ca626e213f71a4955e68e6fccda09b57603b0bd6234d2a4855a8447aa`.
All 119 lab helper tests pass. Each run's two-host 240-second leases completed
normal cleanup. w3 finished on dev-79 at `2026-10-26T16:02:03.085Z` and on dev-240
at `16:02:05.275Z`, both with `cleanup_ok=true`, address/route-added flags false,
and no unknown result or error. Final exact bench-route queries were empty and
management routes were unchanged. The owned Agent was stopped; the final process
check found no Agent remaining. Raw evidence and provenance are retained with
the earlier failures.

This is one low-rate synthetic wire acceptance. It does not validate real
application execution, sustained 10G throughput, loss under load, nested tunnel
workloads, outer IPv6 tunnel transport, eBPF runtime behavior or complete
DeepFlow parity.
