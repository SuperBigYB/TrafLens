# Current Agent resources and observed services

The real-data console now includes a current Controller registration directory.
Selecting a resource applies its exact numeric Agent ID to overview, service
relationships, RED and request list/detail. The visible Agent filter can also
query a registration absent from the current directory without silently removing
that restriction. Changing Agent clears the previous service relationship;
clearing a relationship retains Agent. The explicit Agent-and-relationship clear
button removes both while preserving other visible filters. Trace correlation
still deliberately expands to the selected time/source/Trace across Agents.

## Identity and access boundaries

This is a **current Agent registration directory**, not a complete independent
host/container/Kubernetes inventory. The live qualified registration has no
independent launch-server, EPC or pod-cluster resource ID. A management/control
IP is registration metadata, not proof of an application server's identity.
See the [official Agent guide](https://get.deepflow.io/docs/guide/ee-tenant/system/agent/)
for registration, control-address and state semantics.

Controller creates a UUID registration identity and an auto-increment numeric
ID. L7 storage contains only UInt16 `agent_id`, not that registration UUID or a
registration generation. A directory selection therefore links observations by
number. It cannot prove historical host identity after reset, restore, import or
ID reuse. The UI shows the registration UUID and this limitation; it does not
manufacture an association from a resource name. Current registry and historical
queries are separate reads, not an atomic identity snapshot.

The existing local console always sends Controller organization1/user1/type1.
Controller uses that organization database and its default-user/team rules.
`TEAM_ID` is a returned attribute, not an authorization decision implemented by
this console. This is the single-organization lab view, not a multi-tenant login
or permission product. Request-supplied organization/team overrides are rejected.
Keep the [loopback and SSH access workflow](console/README.md#product-start-and-access-workflow).

Relevant implementation anchors are `server/controller/http/service/vtap.go`,
`server/controller/http/service/vtap_filter.go`, `server/controller/common/const.go`,
the Controller MySQL DDL, and `server/ingester/flow_log/log_data/l7_flow_log.go`.

## Bounded API and UI behavior

`GET /api/resources` returns `resources`, `limit=100`, `truncated`, fixed `scope`
and an association explanation. Only these fields are projected for each current
registration: ID, LCUUID, NAME, CTRL_IP, TYPE, STATE, ENABLE and TEAM_ID. Arbitrary
raw registration fields such as licenses or control MAC are not exposed here.
Results are ordered by numeric ID. The upstream response retains the shared10s/
4MiB bounds; there is no arbitrary upstream URL or SQL input.

`GET /api/resources?agent=<1..65535>` matches the complete validated inventory
before applying the100-row display bound, so an ID outside the first page is
still found. A valid absent ID returns an explicit empty array. Unknown,
duplicate, malformed or out-of-range parameters return400. Upstream failures,
missing/null/malformed inventory, duplicate ID/UUID or invalid required fields
return502, not an invented successful empty inventory. A genuine explicit empty
array is distinct. The directory labels truncation; a manually selected ID absent
from a truncated list is described as unverified, not definitely unregistered.

The shared data APIs use `agent=<UInt16>` as an exact observation filter. Their
time/resource/protocol/source/Session/error/minimum-duration predicates continue
to apply; exact details retain that scope and the string record ID. An absent
registration does not imply historical observations must be empty, and a
registered Agent with no selected observations is not automatically unhealthy.
STATE/ENABLE codes remain visible, without turning historical data into current
health. Refresh only rereads the current directory; it starts no collection.

## Reproduce the accepted product slice

Start the console through its existing public entry point. Open the resource
directory, choose a real registration, then select a time/resource/source range
containing already qualified observations. Follow one relationship to requests
and exact detail; verify the visible Agent remains the selected ID. Change Agent
manually to an absent ID, submit and check both the registration explanation and
exact data scope. Clear Agent/relationship and verify the original other filters
remain. Select an actually absent source to distinguish a present registration
from an empty observation population. Stop the owned console/SSH forward using
the same documented process lifecycle.

The2026-10-28 gate reuses the M6 two-host data rather than repeating capture:
8 source0 Session observations (DNS4/MySQL4), two relationships and two complete
reads with the same exact IDs. The currently registered Agent is STATE0
(disconnected) and ENABLE1; historical rows still exist. Actual Edge compares all
eight projected fields against the independent Controller response, then follows
resource -> services/RED -> request -> exact detail. Manual unknown Agent clears
the previous relationship and produces an empty selected population; clearing
Agent restores8 records. Source3 is empty while the current registration remains.
Page errors0 and actual console exit are verified. No Agent, profile, interface
or backend service is started or changed by this qualification.

The complete console module passes24 race tests, including5 new resource tests
for projection/scope, high-ID exact lookup and truncation, empty/failure states,
invalid inputs and duplicate/malformed identities. An independent review finds
no blocking issue. Anonymous results are in
`evidence/2026-10-28/resource-directory/summary.json`; raw registration identities,
addresses, query responses and screenshots stay private. This is the M7 numeric
Agent resource slice, not full host/container discovery, a current-health verdict
or complete DeepFlow parity.
