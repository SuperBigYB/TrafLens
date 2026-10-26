# Reference baseline

Core implementation is pinned by `upstream.json`, not by the moving default
branch of a web page. This checkout began at `v7.2.3-1-g8741e924f`.

- Official core and architecture: <https://github.com/deepflowio/deepflow>
  (Apache-2.0, Rust/C/eBPF agent and Go controller/ingester/querier).
- Core build rules: `AGENTS.md`, `server/Makefile`,
  `server/Dockerfile.builder`, `agent/build.md`, and owning module manifests in
  this pinned checkout. `server/go.mod` requires Go 1.26.2 even though the
  inherited `AGENTS.md` still mentions an older Go version.
- Official edition inventory: <https://deepflow.io/docs/about/editions/>.
  A community-core import is not evidence of complete enterprise functionality.
- Deployment: <https://deepflow.io/embedded-docs/ce-install/cloud-host>.
  The documented server deployment uses Kubernetes; merely compiling the
  server does not validate controller registration or storage/query behavior.
- Separate trace application: <https://github.com/deepflowio/deepflow-app>.
- Separate Grafana GUI: <https://github.com/deepflowio/deepflow-gui-grafana>.
  These two repositories declare AGPL-3.0 and are not imported in this baseline.
- Official agent benchmark methodology (2023):
  <https://www.deepflow.io/blog/zh/030-deepflow-agent-ebpf-benchmark/index.html>.
  Use its workloads as references, not its historic numbers as this lab's
  baseline. Active TCP flows, new connections per second, HTTP requests, spans,
  wire throughput, captured packets and stored records are separate quantities.

Future comparisons must pin both candidate and reference builds, record exact
configs and resource limits, and measure drops, CPU, memory, collector overhead
and end-to-end visibility under repeatable workloads. The first iperf evidence
only characterizes the physical links with no collector running.
