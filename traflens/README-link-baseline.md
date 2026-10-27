# Direct 10G network baseline

This is a TCP network-capacity prerequisite for TrafLens performance work.
It runs with Agent capture disabled. It does **not** measure packet capture,
HTTP session processing, ingestion, query throughput, or parity with DeepFlow.

`lab/link-endpoint.py` defaults to an offline plan. Explicit execution requires
an existing, standalone physical 10G interface, its assigned numeric IPv6
link-local address, a distinct link-local peer, a verified executable SHA256,
and a new work directory under a root-owned private directory. It does not
add addresses, routes, change MTU/offloads/sysctls, or install host packages.

## Qualified software and limits

- iperf3 3.22 source: [ESnet download](https://downloads.es.net/pub/iperf/iperf-3.22.tar.gz).
  SHA256 `1c0d0fb02c52626111d6e132db80edfbf27bbaff8bd9245df2a371dcb0b35a92`.
- Build in the existing SDK image
  `ghcr.io/deepflowio/rust-build@sha256:b018b2a5970d3c8f36a95f56dec56ad780020ec782419e42c571c7be5867d310`,
  GCC 11.2.1, `CFLAGS=-O2 ./configure --disable-shared --without-openssl --enable-static-bin`,
  then `make -j2`. The build had no network, a read-only root filesystem,
  no added capabilities, 2 CPUs, 512 MiB memory and 128 PIDs. No system install.
  Authentication support is disabled in this build; use only the trusted direct
  bench link and the finite listener described below.
- Qualified static binary: SHA256
  `7271e9c687e534e996b3c1b9854d80c7f70db6e6517d8cedacf130d8c7937a8e`,
  1,331,864 bytes. The offline verifier requires this exact binary fingerprint.
  A different build must be explicitly requalified.
- Runtime Ubuntu 22.04 root filesystem layer:
  `sha256:6b7908e4c7473003628ddbd1d8ad378db659f0bf29a3019f7bb7150e9bfd109d`.
  The tool accepts two pinned image IDs because the Docker classic and OCI
  storage backends identify the imported image differently. Both were inspected
  for the same root layer, architecture and configuration.
- Each endpoint: 2 CPUs, 256 MiB memory and swap limit, 64 PIDs, all capabilities
  dropped, `no-new-privileges`, read-only root, host network, private PID namespace,
  one executable mounted read-only, 16 MiB temporary filesystem. No privileged mode.
- TCP, MTU 1500, 10 seconds measured after 2 omitted warmup seconds, 1 or 4 streams.
  Test each direction separately, with three repeats on each of two direct links.

## Running paired endpoints

Prepare matching pinned binaries and a private work parent on both hosts.
Use explicit local interface names for the IPv6 zone on each host. No real
addresses, interface names or run tokens should be committed with results.

```sh
python3 traflens/lab/link-endpoint.py  # offline plan; no host reads or changes

# On the peer, use a fresh private SERVER_WORK and a fresh 32-character hex RUN_ID.
python3 traflens/lab/link-endpoint.py --execute --role server \
  --work "$SERVER_WORK" --binary "$IPERF_BINARY" --sha256 "$IPERF_SHA256" \
  --image "$PINNED_IMAGE_ID" --interface "$SERVER_INTERFACE" \
  --bind "$SERVER_LINK_LOCAL" --peer "$CLIENT_LINK_LOCAL" --run-id "$RUN_ID"

# Start this promptly from a coordinator only after the peer's ready.json exists.
python3 traflens/lab/link-endpoint.py --execute --role client \
  --work "$CLIENT_WORK" --binary "$IPERF_BINARY" --sha256 "$IPERF_SHA256" \
  --image "$PINNED_IMAGE_ID" --interface "$CLIENT_INTERFACE" \
  --bind "$CLIENT_LINK_LOCAL" --peer "$SERVER_LINK_LOCAL" --run-id "$RUN_ID" \
  --streams 1
```

Add `--reverse` to both invocations for reverse traffic and use `--streams 4`
for four streams. Keep default duration/omit/port for the qualified matrix.
The server is one-off. Readiness proves the exact bound listener belongs to
the created container's iperf process. An independent `timeout` bounds each
endpoint to 37 seconds plus a 5 second termination grace. The supervisor
records logs and exit state, checks exact ownership before stop/remove, and
verifies preexisting running containers are preserved. It refuses a known
capture process or an existing labeled link-test container. A killed supervisor
can leave a stopped container; cleanup must still verify its exact receipt.

`result.json` passing means the worker and its cleanup passed. Qualification
also requires the separate offline verifier. Collect both hosts' work files
privately; save peer files in `<case>-server/`, client files in `<case>/`.
The private JSONL index has `label`, `link` (1/2), `reverse` (boolean),
`streams` (1/4), and the private `run_id`. Labels follow
`matrix-1-forward-p1-r1` through the complete 24-case matrix.

```sh
python3 traflens/lab/verify-link-baseline.py \
  --root "$PRIVATE_EVIDENCE" --index "$PRIVATE_INDEX" --output "$NEW_SUMMARY"
python3 -m unittest discover -s traflens/lab/tests -p 'test_link_baseline.py' -v
```

The verifier rejects failed exits/cleanup, changed selected-link configuration,
wrong software/run/addresses/ports/direction, missing or duplicate streams,
partial intervals, inconsistent byte sums/rates, mismatching independent server
output, counter resets, growing NIC error/drop counters, or insufficient selected
NIC bytes. It rejects duplicate JSON keys and nonfinite numbers. It requires all
24 samples and summarizes all three repeats, without selecting only fast runs.

The real receiving endpoint's `end.sum_received` is the throughput source.
In iperf3.22 the independent server output has a zero placeholder for its remote
direction; the client has exchanged summaries for both directions. The nested
server output omits the top-level run token, so the independent server's token,
cookie, connections, intervals and end counters are checked separately.
Some 3.22 omit transitions merge one warmup second into the first interval
flagged as measured; tiny final intervals also occur. Interval qualification
checks the complete 12-second timeline and monotonic omit phase, while the
end summaries independently require a 10-second measurement. Interval rates
at that transition are not used as the reported throughput.
The `sender` boolean is not used to infer measurement direction. See
[ESnet invocation and JSON documentation](https://software.es.net/iperf/invoking.html).

Process CPU percentages are iperf's process accounting, not whole-host CPU or
IRQ cost. TCP retransmissions are retained; unchanged NIC error/drop counters
do not establish end-to-end zero loss. Separate directional tests do not establish
simultaneous full-duplex capacity. Results do not cover UDP/PPS, small payloads,
other MTUs, loaded hosts or sustained operation.

## Evidence and next performance gate

The dated `evidence/2026-10-27/link-baseline/summary.json` contains only aggregate
measurements, individual anonymous samples, software fingerprints, and the
fingerprint of the private evidence manifest. Raw addresses, MACs, host/container
identities, tokens, commands and logs stay in ignored, private evidence.
Physical-link configuration and main IPv4 routes were compared before/after;
IPv6 source/route selection was checked for each endpoint. Full raw topology
snapshots are not identical: address lease lifetimes and bridge timers change,
and an unrelated virtual interface changed. Those raw differences are retained;
they are not presented as an exact full-host topology match.
After the measured matrix and its cleanup snapshot, kernel logs recorded
i40e/VFIO driver transitions and intermittent carrier loss. Further live tests
were stopped; two additional no-client lifecycle attempts were refused before
resource creation. Those attempts are separate from the sealed matrix. The
current supervisor also preserves its result and completed container-cleanup
proof if the interface or Docker postcheck becomes unavailable during shutdown;
regressions exercise both failures. The worker-source hash in the dated summary
identifies the sealed measurement version, before this reporting improvement.
Four failed preflight/readiness attempts are retained separately from the single
successful prototype and the 24 measured cases; no failed throughput run is hidden.

The next gate must place real workload on these verified links and compare a
pinned TrafLens candidate against a pinned DeepFlow reference under the same
features, filters, queue sizes, resource limits and load. Record offered and
completed requests, exact sessions, capture/queue drops, CPU/RSS and latency at
each load. Queue buffering and enabled features affect Agent results; use the
[DeepFlow performance tuning guide](https://get.deepflow.io/docs/best-practice/agent-performance-tuning/)
and the checked-in Agent configuration as the configuration basis. This network
baseline alone cannot satisfy that gate.
