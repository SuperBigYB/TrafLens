# Configuration and plugin validation — 2026-10-27

`summary.json` records exact source `62429a607` and aggregate test/build results.
Configuration counts distinguish top-level tests from all nested pass events.
The scoped plugin tests are included in the complete Agent-library counts.

The private manifest fingerprints before/after controls, final tests, builds,
independent reviews and failed intermediate attempts. Its detailed file list,
logs, configuration and environment data remain ignored locally. Only aggregate
results and hashes are published. No new runtime traffic was captured for this
checkpoint. Earlier accepted low-rate wire cases are separate experiments.

Default-feature release compilation includes libtrace and ten BPF ELF objects.
The inherited jattach Makefile overlay is disclosed in the summary; the main
tracked snapshot is clean. Compilation does not establish kernel load/attach,
runtime profiling, sustained throughput or complete DeepFlow parity.

See [the guide](../../../README-config-parity.md) for behavior and reproduction.
