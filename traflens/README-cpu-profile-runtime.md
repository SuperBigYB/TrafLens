# Finite real CPU profile lifecycle

This workflow connects an owned Go runtime self-sampling artifact to native
profile integration, strict bounded queries and the actual console. It does not
turn on native system-wide on-CPU/DWARF profiling, attach to another process or
infer CPU percentages. All commands default to offline plans unless explicitly
executed. Use the existing owned two-host lab; do not recreate its databases or
replace its image-embedded Server for this workflow.

## Prepare binaries and private inputs

Use the [finite CPU workload](cpu-workload/README.md) to obtain an actual pprof
and immutable receipt under the documented resource limits. Keep its original
sampling time and SHA256. An accepted artifact still within the backend TTL can
be reused; each necessary integration trial gets a fresh application/transport
identity, while the original pprof label and time remain unchanged. Replaying an
old marker to hide failure is not acceptance.

Build the uploader from its public standalone source with the configured Go:

```sh
GOWORK=off CGO_ENABLED=0 "$GO" build -trimpath \
  -o "$PRIVATE_PARENT/profile-uploader" traflens/lab/cpu_profile_upload.go
```

Build the console with its [existing entry](console/README.md). For a prepared
server vendor tree with no changed generator inputs, the qualified standalone
Querier build is:

```sh
(cd server && GOWORK=off CGO_ENABLED=0 "$GO" build -mod=vendor \
  -tags=go_json -trimpath -o "$PRIVATE_PARENT/querier-candidate" \
  querier/cmd/querier/main.go)
```

Use the server Makefile to prepare vendor/generated inputs when needed. Preserve
upstream licensing. Explicitly identify and SHA256-check the existing native
Agent, its compatible runtime library directory, the two query binaries, the
uploader and a preloaded image. The tools do not download or replace them.
Output parents must be canonical, owned and private0700; every execution output
must be fresh. Runtime receipts/raw samples/configuration remain private.

Deploy `cpu-profile.py`, `cpu_profile_common.py`, `cpu_profile_controller.py`,
`lab.py`, `configure-agent.py` and `agent-smoke.json` from `traflens/lab/` into a
private `$BACKEND_CODE` on the backend. Deploy `profile-query-runtime.py` there
and the Querier/console binaries into their explicit private paths. This code
copy contains public source, not the backend's Server YAML or credentials.
The first query-runtime slice supports an explicitly password-free ClickHouse
account; it does not accept/save a password or copy the old Server config.

## Start the independent bounded query runtime

On the backend, remove `--execute` first to inspect the offline plan, then run:

```sh
python3 "$BACKEND_CODE/profile-query-runtime.py" run --execute \
  --lab-root "$OWNED_LAB_ROOT" --work "$NEW_QUERY_WORK" \
  --network "$OWNED_LAB_NETWORK" --image "$SERVER_IMAGE_ID" \
  --querier-binary "$QUERIER_BINARY" --querier-sha256 "$QUERIER_SHA256" \
  --console-binary "$CONSOLE_BINARY" --console-sha256 "$CONSOLE_SHA256" \
  --clickhouse-host "$CLICKHOUSE_HOST" --clickhouse-port 9000 \
  --clickhouse-user "$PASSWORD_FREE_USER" --seconds 600
```

The script verifies the running Server/network ownership and immutable image,
then creates only its own limited, read-only, capability-free containers. The
Querier joins the existing lab network and publishes only127.0.0.1:20818. The
restricted console uses host networking solely to reach the existing loopback
APIs and listens only127.0.0.1:20880. No host filesystem/proc/device tree is
mounted. Both commands have hard timeouts and the supervisor restores only its
own resources. The standalone Querier uses `/etc/server.yaml`; no ineffective
`-f` override is relied on.

Without `--app/--from/--to/--agent`, readiness proves the new bounded protocol
and console empty semantics only. This is deliberately not sample acceptance.
With an existing real scope, these optional arguments additionally require its
nonempty native/console agreement and the actual N-1 row-cap rejection. There
is no fallback to legacy unbounded ProfileTracing on older Server versions.

## Integrate the one owned artifact

On the sampling host, inspect the default plan and then execute once:

```sh
python3 traflens/lab/cpu-profile.py --execute \
  --backend-host "$BACKEND_SSH_ALIAS" --backend-root "$OWNED_LAB_ROOT" \
  --backend-code "$BACKEND_CODE" --backend-output "$NEW_CONTROLLER_WORK" \
  --controller-ip "$CONTROLLER_IP" --controller-port 20035 --ingester-port 20033 \
  --image "$PRELOADED_AGENT_IMAGE_ID" \
  --agent "$AGENT_BINARY" --agent-sha256 "$AGENT_SHA256" --libs "$AGENT_LIBS" \
  --uploader "$UPLOADER_BINARY" --uploader-sha256 "$UPLOADER_SHA256" \
  --profile "$ORIGINAL_PPROF" --receipt "$ORIGINAL_RECEIPT" \
  --output "$NEW_INTEGRATION_WORK"
```

The public entry generates a fresh run, creates an independent temporary
Controller group/Agent with supported PROFILE_INT11, and hashes existing group
YAML instead of copying its contents. It enables only profile integration,
turning off eBPF, DWARF/on-CPU, process, packet-request collection and all other
integrations. Its wildcard receiver is contained in a new private Docker network
and namespace, with no published port. The namespace/Agent/uploader are read-only,
cap-drop-all and CPU/memory/PID limited. An actual namespace TCP LISTEN socket
and owned Agent log must agree before uploading the unchanged verified artifact
to fixed loopback39093. Raw gzip omits Content-Type/Encoding as required by the
existing native library.

The upload runs once; HTTP acknowledgement is explicitly not stored-data
acceptance. The finite Agent exits/drains, owned containers/network and temporary
Controller entries are removed, and original identities/memberships/license
settings/YAML hashes/route/BPF baseline are checked. Docker inspection errors are
not interpreted as proof that a collector disappeared. The result preserves the
original sample time/SHA and exposes the new application/Agent in private
`ingestion-metadata.json` for the following verifier.

## Verify stored samples and actual browser behavior

Use only the new integration's application, Agent and original time. If the
sampling host's Go tool is used, create a loopback SSH query tunnel to the
backend's20818 endpoint; for example:

```sh
ssh -N -L 127.0.0.1:20819:127.0.0.1:20818 "$BACKEND_SSH_ALIAS"
```

In another terminal run the public bounded oracle:

```sh
python3 traflens/lab/verify-cpu-profile.py --execute \
  --query-base http://127.0.0.1:20819 \
  --app "$NEW_APP" --agent "$NEW_AGENT" --from "$ORIGINAL_FROM" --to "$ORIGINAL_TO" \
  --pprof "$ORIGINAL_PPROF" --pprof-raw "$SAVED_GO_PPROF_RAW" \
  --receipt "$ORIGINAL_RECEIPT" --go "$GO" --output "$NEW_ORACLE_WORK"
```

The verifier independently reruns local `go tool pprof -raw`, checks the original
receipt/hash/provenance and exact saved raw output, and collapses real stacks.
It reads the complete marker population twice without hiding incorrect Agent,
time/language/event/unit rows. IDs and supported metadata/weight projections
must match, Count/Sum must agree, native N-1 must reject and N must return the
complete exact stack weights. The final fingerprint must remain stable. This
fingerprint is not a compressed-stack byte checksum; actual decoded stacks are
checked independently against the real profile. Wrong time/Agent and a different
language are empty controls, not proof of an authoritative L7 source column.
Failures and partial attempts stay in the fresh private output.

Forward the backend console20880 over SSH as in its README, open the CPU form,
select the actual profile time/application/historical Agent, inspect the hotspot
and choose a function's actual stack paths. Confirm weights against the oracle
and check a wrong Agent/application/time. Keep absence distinct from upstream or
unsupported errors; do not infer current Agent health or OS/container identity.

## Stop and recover only owned resources

Normal integration execution already restores its temporary collection resources.
For interruption/recovery, use its exact private receipt directory:

```sh
python3 traflens/lab/cpu-profile.py stop --output "$INTEGRATION_WORK"
python3 "$BACKEND_CODE/profile-query-runtime.py" stop --execute --work "$QUERY_WORK"
```

The first entry verifies supervisor identity/locks, collector ownership and
stopped proof before deleting its Controller lease. The second verifies exact
container IDs/labels/spec fingerprints and retains the existing Server/network.
Stop the two owned SSH forwarding sessions as well. Retain failure evidence and
resolve a mismatched identity; never stop/delete a foreign resource or bypass a
failed ownership check. The original Server binary/configuration is not changed.

The earlier generic-writer pre-input failure remains unexplained; neither opening
a log level nor a later successful trial establishes a reliability fix. This
workflow is the finite Go self-profile product slice, not eBPF CPU, multi-language
continuous profiling, complete flamegraph qualification or performance parity.
