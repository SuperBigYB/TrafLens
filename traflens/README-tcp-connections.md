# TCP observations: finite packet product slice

The public finite lifecycle, strict independent oracle and actual Edge product
gate passed on the two-host pipeline. See [anonymous evidence](evidence/2026-10-29/tcp-connections/README.md)
for the real three normal/reset/refused sockets, three outside-filter controls,
all original report comparisons, browser results and precise restoration.
Earlier failed attempts remain preserved separately; success does not rewrite them.

This M12 workflow reads real native L4 TCP observations. It does not claim
complete connection inventory, loss-free capture, application health or physical
10G performance. A source3 eBPF socket flow has no qualified full TCP L4 lifecycle
in this core: its close type is forced to Timeout. This workflow therefore uses
packet source0 on only the existing host loopback interface.

## Meaning and scope

The capture is restricted to ^lo$, fixed client127.77.0.1/server127.77.0.2 and
TCP ports18081/18082/18083. Normal HTTP, an actual abortive server close and an
actual bound-but-not-listening refusal each execute once. A different fresh
fixture on18084/18085/18086 is outside the installed filter. The runtime checks
actual packet sockets and installed classic-BPF instructions before sending
any fixture traffic; profile text alone is insufficient. Native sockets may
physically bind all interfaces. In that case the complete installed forward
control-flow graph must prove its IFINDEX=lo guard dominates every accepting
return, in addition to the exact address/port prefix. Non-lo frames are rejected
in the kernel before copying to the collector. Raw binding0 remains recorded;
it is not described as a physical lo socket bind. No physical interface,
route, sysctl, default group or unrelated service is changed. Agent privileges
are cap-dropALL plus onlyNET_RAW, hostNET/privatePID, readonly root,2CPU/1GiB/
384PIDs,180seconds plus40seconds Docker stop grace. After that stop, the
public launcher allows up to90seconds for actual BPF/tracefs/lo restoration,
recording bounded polls rather than treating process exit as restoration. The
coordinator gives this complete stop operation a160second supervisor timeout;
these are distinct bounds, not extra traffic time or proof that cleanup passed.
All eBPF, process discovery and integration/profile inputs remain disabled.

Rows are observation reports. Three actual positive socket connections do not
imply exactly three database rows. Close code5 is a periodic Force Report, not
a closed connection, and every original periodic row must be retained. The
strict finite oracle accepts3..64 original reports for three native flow IDs:
normal, reset and refused each require one terminal report (close!=5), with
close codes1/2/15 respectively. It groups all reports by the independently
recorded socket tuple and exact native flow ID. For each direction, the sum of
per-report packet/byte counters must equal the final lifetime totals, and no
intermediate cumulative total may exceed the terminal total. Cumulative totals
themselves are never summed across reports. An extra/missing/contradictory row
fails acceptance rather than being filtered away. Packet
and byte counters are original native observations, and bytes include packet
headers rather than just application data. RTT fields are microseconds from
TCP handshake observations/maxima, distinct from HTTP response duration. A raw
RTT0 has no positive measurement and must not be rendered as healthy0ms. Raw
close codes and names are shown; RST/timeout is not by itself a confirmed root
cause. Code20 is native Normal - Client RST, distinct from failure groups.

Native time and deletion deadlines are separate from application/socket time.
The stored L4 `time` is the integer-second floor of its recorded `end_time`:
`time_epoch = end_us // 1_000_000`. In the qualified profile, the normal,
refused-at-establishment and established-then-server-RST paths retain nodes
until their native deletion deadlines of2/5/35seconds respectively after the
relevant recent packet. In particular an actual application `ECONNRESET` does
not mean that native conntrack immediately deletes or emits its terminal node.
The recorded flow `duration` is independently based on packet timestamps; it
must not be replaced by the deletion delay, application elapsed time, or
`end_time - start_time` for every report. RTT is a further distinct measurement.

The public coordinator now leaves the Agent running for50seconds of natural
drain after the actual fixtures. This covers the qualified35second RST expiry
and downstream report/queue scheduling without fabricating a close event or
rewriting stored time. The50second wait is an execution prerequisite, not an
assertion that data reached storage. The original failed/short-drain captures
remain evidence and are not converted into passing runs.

References: [official upstream L4 schema](https://github.com/deepflowio/deepflow/blob/main/server/ingester/flow_log/log_data/l4_flow_log.go),
[local pinned schema](../server/ingester/flow_log/log_data/l4_flow_log.go),
[local close-code names](../server/querier/db_descriptions/clickhouse/tag/enum/close_type.en),
[native eBPF/packet flow handling](../agent/src/flow_generator/flow_map.rs).
The checked code and actual native API schema govern this finite implementation;
a current upstream page is not proof that this runtime supports every field.

## Query and navigation

GET /api/connections requires one explicit from/to/agent, at most300inclusive
seconds; optional id/flow/server_port are exact unsigned integers. It fixes
source0/TCP6 and returns at most64reports using a65row sentinel; an excess input
is rejected before showing partial data. Native response budget is4MiB and
12seconds. UInt64 IDs/flow IDs, microsecond times, counters and RTT stay decimal
strings. Missing result/columns, malformed values or contradictory scope fail
HTTP502, excess rows413, malformed scope400; successful complete-schema empty
values return an empty observation list. Row/response/deadline limits do not
bound all ClickHouse scanning or pre-response driver memory.

GET /api/connection-requests requires the same base scope plus an exact L4
observation id. It rereads that row, then queries complete HTTP/source0 Session
observations with its exact native flow ID, Agent, TCP tuple and EPC scope in
the chosen window. Multiple reports/requests are retained. This is matching
recorded flow evidence, not one request per connection, process-generation proof
or causality within a periodic report. Empty HTTP matches remain explicitly
unlinked; endpoint/time similarity alone never makes a link. The actual TCP
panel opens the exact L4 report and links matching HTTP rows to exact request
details with original Agent/source0/time/ID pinned.

## Public reproduction

Use canonical private mode0700 parents and fresh CAPTURE/BACKEND_WORK paths.
Use the qualified native artifacts described in
[managed runtime prerequisites](README-managed-http-runtime.md#prerequisites-and-configuration);
the ordinary packet bootstrap has no ebpf-socket-netns-scope key. Deploy the
matching public Controller dependencies named by ebpf-association.py CODE to
BACKEND_CODE on the owned lab host; the run checks all source/peer hashes before
mutation. Existing SSH identity and a credential-free loopback Controller origin
bound to the owned Server are required. Do not copy full Server configuration.

```sh
python3 traflens/lab/tcp-connections.py
python3 traflens/lab/tcp-packet-agent.py
python3 traflens/lab/tcp-traffic.py
python3 traflens/lab/verify-tcp-connections.py
python3 traflens/lab/tcp-connections.py run --execute \
  --work "$CAPTURE" --backend-host "$BACKEND_HOST" \
  --backend-root "$BACKEND_ROOT" --backend-work "$BACKEND_WORK" \
  --backend-code "$BACKEND_CODE" --server-container "$SERVER_NAME" \
  --controller-url "$CONTROLLER_LOOPBACK" --controller-ip "$CONTROLLER_DATA_IP" \
  --controller-port 20035 --ingester-port 20033 \
  --ctrl-ip "$HOST_CTRL_IP" --ctrl-mac "$HOST_CTRL_MAC" \
  --artifacts "$RUNTIME/prepared.json" --forward-port 24017
```

Run first prepares its dedicated group/Agent using normal functions2/4/5, then
starts/proves the finite packet Agent. The native core defaults to disabled,
applies the Controller user configuration first, then constructs/starts capture
components; it does not first capture with default all-interface configuration.
Readiness uses the new run's owned bound native regular log files as well as
Docker output, with source/hash and finite byte checks rather than relying on
stdout alone. Only after actual dispatcher/listener,
AF_PACKET/lo and installed-filter readiness does it run independent negative
and positive socket fixtures. It then records the50second natural drain,
stops/restores and unregisters its own resources. Stop retains the immutable
actual Docker `FinishedAt` and exit identity in `packet-agent/exit-state.json`
before container removal, independently of later restoration poll completion.
Pass execution is not stored-data acceptance.

Use the [existing independent public query/console lifecycle](README-cpu-profile-runtime.md#start-the-independent-bounded-query-runtime), minimal
password-free connection fields and exact owned SSH loopback forwards. The old
Server image/binary remains running. Select the recorded historical Agent ID
and an explicit window whose lower second includes both fixtures' original real
Unix timestamps. The mandatory upper second is
`TO = ceil(actual_Agent_FinishedAt_unix_seconds) + 60`, calculated from the
unchanged UTC/nanosecond `finished_at` in `packet-agent/exit-state.json`.
Equivalently, for the exact parsed integer `finished_ns`, use
`TO = (finished_ns + 999999999) // 1000000000 + 60`.
Native Force Report aligns its report end on the60second reporting interval;
therefore a stored report's `time` can extend beyond capture exit. The extra60
seconds is a bounded query/report-alignment margin, not additional capture,
a modified timestamp, the time the verifier runs, or the later BPF-restoration
completion time. The verifier requires this exact upper bound. The complete
window must still fit the API's300inclusive-second limit; if it cannot, retain
and report the failure rather than silently trimming reports. Then:

```sh
python3 traflens/lab/verify-tcp-connections.py --execute \
  --fixture-dir "$CAPTURE/positive" --negative-fixture-dir "$CAPTURE/negative" \
  --agent-runtime-dir "$CAPTURE/packet-agent" \
  --query-base "$QUERY_LOOPBACK" --console-base "$CONSOLE_LOOPBACK" \
  --from "$FROM" --to "$TO" --agent "$AGENT_ID" --output "$FRESH_ORACLE_DIR"
python3 traflens/lab/tcp-connections.py stop --execute --work "$CAPTURE"
```

The strict verifier separately checks genuine socket calls/errno/HTTP byte
hashes, real Agent/BPF/runtime/restoration proof, two complete raw populations,
all raw Force Report and terminal values/counter conservation, the exact
`time=floor(end_time)` contract, all API values, three terminal details,
same-native-flow normal HTTP evidence and empty negative scopes. Raw report
count is not a claim of that many unique socket/business connections.
Do not rewrite sampling times, synthesize TCP packets/SQL rows, filter away extra
sources/flows or turn failed capture results into success. Use the TCP form in
the real console for all three close cases and normal HTTP detail navigation.
Stop the independent public query runtime and only its exact owned SSH forwards.
Failed directories and separate restoration receipts are retained.
## Verified delivery and remaining limits

The fresh public run produces3 native source0 reports for3 distinct actual
positive TCP sockets; this sample happens to contain no periodic reports. Its
three outside-filter socket controls are absent from the complete raw Agent/time
population. Two full reads match; all counters/API values, three precise L4
details and one normal HTTP same-flow Session match the independent socket
oracle. Actual Edge confirms all reports/details, exact HTTP navigation and
empty/over-budget controls with zero page errors.64 complete console race tests,
the console build,49 targeted TCP tool checks and independent readonly review
pass. Remote CI was not checked.

The actual native translator describes flow_id as UInt64 even for the tested
toString(flow_id) alias. Go parses its raw decimal JSON bytes directly into
UInt64 and returns a decimal string to the browser; Python's native oracle uses
exact arbitrary-precision JSON integers. Neither uses floating point for flow
identity. Fractions, exponent encodings, booleans and overflow are rejected.
The first oracle's overly strict string assumption and the first browser's
same-flow502 remain separate failed evidence; the corrected runs reuse the
same captured rows without replay or timestamp edits.

Early template/bind/readiness attempts did not execute fixtures. A subsequent
short-drain capture performed real sockets but its15second restoration gate
failed; later unchanged public stop proved restoration and did not alter the
failure result. This also exposed why2/5/35second native deletion deadlines and
report-aligned time must be respected. The final run uses50second natural drain,
immutable actual exit evidence and exact restoration checks; Agent exits0, and
public/idempotent stop, old Controller/Server/hardware checks and removal of
temporary query/console/forwards pass. The old Server configuration comparison
uses the explicitly historical M9 round14 qualified SHA, not an invented new
R19 pre-snapshot. Physical10G, sustained throughput, packet-loss accuracy,
generic host inventory and complete eBPF TCP lifecycle are not qualified here.
