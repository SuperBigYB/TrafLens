# TrafLens distribution

Current validation and next steps: [STATE.md](STATE.md).
The complete configuration race gate and plugin merge safeguards are documented
in [the configuration and plugin guide](README-config-parity.md).
For the packet Agent see [its build/test entry point](README-agent-packet.md);
the full libtrace release build is documented in
[the native build procedure](README-agent-native.md). The reproducible isolated
storage/controller/query environment and marked HTTP workload are in
[the lab workflow](lab/README.md). [EVIDENCE.md](EVIDENCE.md) indexes actual runs.

TrafLens starts from the upstream DeepFlow open-source core. Preserve upstream
licenses, notices, module paths, and generated-code workflows. Imported code is
an initial implementation baseline; it does not establish verified feature or
performance parity with any DeepFlow edition.

`upstream.json` records the pinned upstream commit in its `sha` field. Changes
and validation evidence belong in the TrafLens work log. Build and test each
upstream module through its own documented entry points.

## Host snapshot and checks

Run from the repository root on each development/test host:

```sh
make -C traflens test
make -C traflens preflight INTERFACES='enp1s0f0 enp1s0f1'
python3 traflens/scripts/preflight.py --interface enp1s0f0 \
  --output traflens/evidence/preflight.json
make -C traflens server
```

Use the actual interface names on each host. The snapshot reports UTC time,
source revision/worktree status, upstream pin, kernel/CPU/memory/disk, local tool
versions, and requested interface addresses/carrier/speed. It does not install
packages, configure interfaces, start services, connect to remote services, or
collect environment variables or credentials. Only `--output` writes a file.

Missing tools, inaccessible values, and unavailable Linux `/proc` or `/sys`
fields remain explicit `null` values or errors. Successful JSON collection is
not a readiness or performance pass. A link reported as down needs separate
configuration/physical-link investigation before throughput testing.

`make -C traflens test` validates the distribution tools only. The server target
delegates to upstream `server/Makefile`, including its vendored dependency
patches and generated prerequisites. Satisfy the pinned checkout's compiler,
protobuf, native-library, storage, and connectivity prerequisites first.

The Linux server wrapper reads the exact Go version from `server/go.mod`.
`TRAFLENS_GO=/path/to/go` selects a verified executable. Otherwise a compatible
bootstrap Go can select the cached Go toolchain module; the Linux amd64 Go
1.26.2 module checksum is pinned in the script. Automatic toolchain selection
through `GOTOOLCHAIN` is disabled.

Go generator binaries and Python dependencies live under `.traflens/tools`;
the existing Go module cache is reused through `GOMODCACHE`. The private GOPATH
links protobuf includes to the complete gogo module cache, avoiding vendor
regeneration races. Upstream `server/Dockerfile.builder` pins gogo generators
to v1.3.2 and tmpl to v1.1.0; its ujson package is unpinned, so this distribution
uses a project venv with ujson==5.10.0. System `protoc`, `make`, `git`, `patch`,
`awk`, and Python3 must already be installed.

Downloads are disabled by default with `GOPROXY=off`. To prepare missing tools
and permit the upstream build to fetch its dependencies explicitly:

```sh
TRAFLENS_DOWNLOAD_TOOLS=1 make -C traflens server
# Optional proxy for this invocation only:
TRAFLENS_DOWNLOAD_TOOLS=1 TRAFLENS_GOPROXY=https://goproxy.cn,direct \
  make -C traflens server
```

Cached generator binaries are reused after checking their embedded module
versions; the existing venv is reused when its ujson version matches. The
wrapper neither changes global Go configuration nor uses system pip.
