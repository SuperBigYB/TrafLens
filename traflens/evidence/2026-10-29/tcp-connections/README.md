# M12 finite TCP product acceptance

The public finite packet lifecycle, independent storage/API oracle and actual
Edge navigation pass. Three real positive TCP sockets (normal HTTP, server reset,
connection refused) produce three source0 L4 reports with close codes1/2/15.
Three real outside-filter sockets produce zero stored records. Both complete
Agent/time reads have identical original IDs/values, without source, tuple,
protocol, port or close-code filters. Native packet/byte/lifetime counters and
all API fields are independently compared. One genuine normal HTTP Session is
linked by exact native flow/Agent/tuple/EPC/source/window; the other two have none.

The actual Edge run displays all three reports, reads all three precise L4
details, opens the exact normal HTTP record, and checks empty and over-budget
scopes. No page errors occurred. The screenshot masks inputs and socket endpoints.

The Agent exits0; public and idempotent stop restore actual BPF/tracefs/lo,
Controller inventory and YAML. Old Server ID/image/network are unchanged; its
configuration matches the explicitly historical M9 round14 SHA. Independent
query/console containers and exact owned forwards are removed, physical device,
interface and route identities are unchanged. See summary.json for anonymous
metrics, checks, retained failures and limits; private raw evidence stays on the
two development machines. This functional gate does not establish performance
or complete DeepFlow parity.

Reproduction: [TCP lifecycle and semantics](../../../README-tcp-connections.md).
