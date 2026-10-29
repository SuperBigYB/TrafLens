# Scoped UDP DNS functional qualification

The passed functional gates cover only the single-peer, finite DNS/UDP slice described in [UDP_DNS.md](../../../UDP_DNS.md). The existing production Agent was used without a native rebuild. Round 31 resumed the unchanged Round 25 capture after explicit permission to return the own-test anonymous verdicts and perform scoped browser verification.

## Actual checks

- Three positive DNS transactions observed at both own processes produced six source-3 Session records. Four observations retained successful answers; two retained NXDOMAIN RCODE 3 and native status 4. Three outside-namespace transactions produced no stored records. Packet and application-span source controls were empty.
- The strict verifier performed two whole-marker and two whole-Agent/time reads, compared complete IDs and original projections, and checked six exact details against unprefixed UDP DNS datagram bytes, process/thread identity, socket tuple and response timing units. No filtered-away orphan or synthetic storage rows were used.
- Headless Microsoft Edge compared all six actual details and exercised protocol/source/error controls. A context-level guard was installed before navigation: seven initial unscoped calls were aborted, 29 scoped data requests were allowed, and no outside-scope request or fabricated API response was forwarded. Only an anonymous result and a screenshot masking the resource/endpoint column were saved locally.
- This completion round performed no new DNS capture, upload, Agent deployment or native build. The 74 targeted checks are the recorded Round 25 baseline; they were not rerun as new evidence. Remote CI was not checked.

## Preserved failure and source bridge

The first verifier failed before a data query because its extracted module lacked `WorkerContract` and `DNS_WORKER`. Its original source, failed result and capture are retained. The corrected verifier accepts an explicit, private, canonical archived planned source only to verify that original hash; it never executes the archive. The other ten producer/runtime/scope source checks remain exact. The later strict result is separate from the original failure.

Private evidence remains on the authorized development machines under `.traflens/work/ebpf-dns-udp-20261029/round25/` and `round31/`, including the capture, original failure, corrected acceptance, public Query stop and the final independent restoration proof. Raw L7 metadata and record IDs are not included in this public directory. `summary.json` contains only anonymous qualification and artifact information.

## Limits

This is one fixed peer, one bound UDP socket per role and three serial distinct 16-bit transaction IDs, with small datagrams. Six observations are not six business queries. Multi-peer reuse of one server socket, repeated transaction IDs, retries, fragmentation, encrypted DNS, general DNS compatibility, maximum throughput and lifetime loss guarantees remain unqualified. The source-derived multi-peer risk is a proposed next milestone, not an observed failure or an implemented fix.

## Final resource gate

Both Query containers and their supervisor are gone, all owned source/peer/workstation forwards are stopped and their validation ports are closed. The original Server ID/image/network/config hash and Controller inventory/group membership/YAML match their baselines. This round made no capture, Agent, physical-network or BPF change; the Round 25 capture restoration proof remains historical. The first restoration checker failed because a reference path was missing; its failed attempt is preserved separately from the later minimum resource check. The qualification commit bd5c659e8886a352f8430c670d652969323e5af4 was pushed normally and independently verified at both GitHub and GitLab main refs. M16 is closed; M17 alone addresses the still-unproven multi-peer transaction scope.
