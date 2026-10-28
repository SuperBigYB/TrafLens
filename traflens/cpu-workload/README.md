# Finite self CPU sampling fixture

This Linux-only, standard-library Go program runs one known CPU loop and records
that **same process** with `runtime/pprof`. It starts no network listener, uploads
nothing and attaches no kernel profiler. Its default command only prints a plan
and creates no files. The explicit execution duration is limited to5..20 seconds.

Build in this module with the configured Go toolchain:

```sh
GOWORK=off CGO_ENABLED=0 go build -trimpath -o "$PRIVATE_BINARY" .
"$PRIVATE_BINARY" # offline plan
"$PRIVATE_BINARY" --execute --seconds 10 --run "$FRESH_CPU_RUN_TOKEN" \
  --output "$NEW_PRIVATE_RUN_DIRECTORY"
```

The token must be `cpu-` followed by24 fresh lowercase hexadecimal characters.
The output must be a new canonical absolute directory with an existing owned
private parent, without symlink components. It is created with mode0700;
`cpu.pprof` and `receipt.json` are created with exclusive mode0600. Existing output
is never reused. SIGTERM/INT stop the loop and finalize the runtime profile;
the receipt marks signal interruption rather than completion of the duration.

The qualified external lifecycle should enforce one CPU, bounded memory/PIDs,
no network and a hard deadline around this process. The program sets
GOMAXPROCS=1 and stops its workload on its own timer; these are not a substitute
for those container resource controls. No host sysctl or external service is
changed. This binary is a finite fixture, not a continuous host profiler.

The profile is the actual gzip protobuf stream emitted by `runtime/pprof`, with
a `traflens_run` sample label. `main.traflensCPUHotLoop` is deliberately noinline
and retains its checksum to prevent dead-code removal. The receipt records the
run, actual self PID, UTC wall bounds, actual wall/self CPU time, loop batches,
checksum and profile size/SHA256. Those values establish the fixture execution
and artifact, not that a particular function was actually sampled.

Inspect the real profile with `go tool pprof -raw` or `-top` before claiming CPU
sample content or the expected hotspot. The receipt's `sample_content_checked`
is always false; downstream verification must prove that separately. A nonempty
file, source function name or successful process exit alone does not qualify
profiling ingestion. Different sample types may have different units; do not
derive an absolute CPU percentage from the receipt or relabel sample counts as
nanoseconds without checking the real profile/decoder contract.

Any later supported profiling integration must preserve and label its actual
source. This self-sampled Go runtime profile is not eBPF on-CPU qualification.
