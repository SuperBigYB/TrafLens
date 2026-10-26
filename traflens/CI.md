# TrafLens continuous integration

`.github/workflows/traflens-ci.yml` validates pushes to `main`, pull requests
and manual dispatches on GitHub-hosted Ubuntu 24.04. It uses the exact Go version
from `server/go.mod`, pinned official Actions commits, read-only repository
permissions and the project-local build wrapper.

The job runs the Python tooling tests, builds the complete community server,
tests queue/LRU/flow-metrics and checks candidate protobuf decoders against the
pinned upstream wire fixtures. Successful runs retain a Linux amd64 server,
source-version text and SHA-256 checksum as an Actions artifact for seven days.
This is the currently validated CI scope; agent/eBPF, the full upstream suite and
end-to-end storage/query/UI validation remain separate work.

The inherited DeepFlow workflows are preserved with job-level repository guards.
Their 24 jobs across 17 files execute only in `deepflowio/deepflow`; existing tag
and comment conditions, triggers and dependency relationships are retained.
TrafLens uses its own validation workflow instead of upstream Cirun runners,
registry/OSS credentials, branch cleanup, AI automation or Gitee synchronization.

## Initial mirror failure

Run <https://github.com/SuperBigYB/TrafLens/actions/runs/40294963547> failed in
`clone repo` on commit `a1947910b8c1530f9829f485e8cacba030445b40`. The inherited
script expanded its hardcoded organization and current repository basename into
`https://github.com/deepflowio/TrafLens.git`, which is not the source repository.
Its exact error was `fatal: could not read Username for 'https://github.com': No
such device or address`, exit 128. The mirror push step was skipped.

The first import retained that upstream-only automation; the repository guards
correct this adaptation mistake. The old failed run remains a historical record.
Validation of the correction comes from runs on the new commit, with the upstream
mirror job skipped and `TrafLens CI` actually building and testing this repository.
