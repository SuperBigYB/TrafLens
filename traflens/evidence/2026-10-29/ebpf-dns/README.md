# M13 scoped eBPF DNS/TCP product acceptance

The public finite lifecycle, independent framed-wire/native/API oracle and real
Edge pass. Three actual positive TCP queries (A success, NXDOMAIN and independent
A control) produce six complete source3 process Sessions; three actual queries
with a separate marker in the negative namespace produce zero stored records.
Both namespaces use the same port18080. Two whole-marker complete populations
retain original IDs/all projected fields without Agent/time/source/protocol
filters hiding mistakes. Source3=6; packet0 and OTLP4=0.

The verifier independently decodes original TCP-DNS frames and compares actual
send/receive SHA, DNS IDs/answers/RCODE, tuples, host PID/TID, precise namespace
FD/map and four real Docker running-inspect receipts. Native RRT microseconds
match the bounded actual event/call interval; no pause duration is used as an
assumed response time. All six existing API details match original records.
Real Edge verifies six exact details, source/protocol and two NXDOMAIN error
observations, answers and empty scopes with zero page errors.

Agent and four workers exit0 without OOM. Public/idempotent stops remove all
owned resources, restore exact BPF/tracefs/pins and original Controller0/1/YAML,
and preserve old Server ID/image/network and explicitly historical M9 config
SHA. Physical interface/device/routes and all temporary ports are restored.
74 targeted tests and independent review pass; the unchanged console64-test
baseline was reused, and remote CI was not checked.

The first run failed before DNS queries because an artifact path checker
rejected the intentional live /proc/PID/exe handle. A dedicated guarded read
fixed that proof; the fresh second run passes. Both original results remain.
This qualifies a small TCP slice, not UDP, generic DNS compatibility, complete
AutoTracing or performance parity. See [public reproduction](../../../README-ebpf-dns.md)
and summary.json. Raw identities/wire remain private on the development hosts.
