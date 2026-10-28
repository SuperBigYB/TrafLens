# Bounded native socket capture ordering

`Reorder` orders enabled protocol captures before stateful L7 parsing. The key is
the opaque **full socket generation ID plus raw source**, not a file descriptor
or an ID whose generation bits have been masked. A new ordered socket expects
sequence0. An initial2 is buffered; the measured input `[2,3,4,5,6(close),0,1]`
therefore emits0..6 without changing wire timing. An inclusive `get_end_seq()`
advances the expected sequence for an item consuming a range.

This crate does not choose the protocol default. Disabled protocol data stays on
its original pass-through path even when it shares a key with an enabled flow.
An Unknown CLOSE follows an **already tracked** key. Without a tracked key it
passes through and increments `untracked-close-bypass`; this is explicitly not
an unknown-protocol or cross-source association guarantee. ID0 also passes
through and is counted, because anonymous captures cannot establish a socket
identity. The current product qualification targets plaintext MySQL source0;
the crate does not establish a TLS/source-domain relationship.

## Gaps, close and time

Only contiguous captures are emitted. Duplicate, old or overlapping ranges are
dropped explicitly. A CLOSE cannot cross a missing sequence in an ordered flow.
Gap timeout, cache pressure, stop and reconfiguration **do not synthesize the
missing capture** or send buffered CLOSE early. They discard the affected
buffered ownership and record the reason. A failed-flow tombstone rejects later
captures of that generation during its bounded retention.

The time watermark is `max(previous, incoming event time, explicit flush time)`
in milliseconds. Regressing timestamps cannot extend a gap. Extra out-of-order
arrivals do not refresh the existing gap deadline. Contiguous progress can
establish a new gap and deadline. The dispatcher must call `flush` on a bounded
idle ticker and pass further traffic through `inject_item`, which also expires
gaps. This is an event/dispatcher watermark, not a separate wall-clock thread.

Contiguous output has already been delivered when `flush_all()` is called.
Anything still buffered is behind a gap and is counted as `shutdown-dropped`;
it is not emitted in arrival order. `reconfigure()` performs this same ownership
release, then changes the checker/limits without falsely closing its shared
counter source. `Drop` releases retained ownership, zeros gauges and closes the
counter source.

## Hard bounds

- Global buffered item limit: configured cache size, clamped to1..65,536.
- Per-flow pending limit:256 items and1MiB of accounted item memory.
- Global accounted cache/state limit:64MiB.
- At most16,384 flow states, including closed/failed tombstones.
- Gap timeout: configured duration, clamped to1ms..30s.
- Closed and failed tombstone retention:60s, additionally subject to the hard
  state/memory bound. An established Open connection's empty checkpoint does
  **not** expire on normal idle: after0 and a long quiet interval,1/2 still pass
  immediately. Idle/checkpoint states are reclaimed before pending flows only
  when the hard state/memory bound requires it.

Each item is charged its `get_size()` plus128 bytes for cache bookkeeping; each
state is charged512 bytes for state/index bookkeeping. Payload-owning production
implementations must return actual owned vector capacities/object estimates.
The default0 method preserves compatibility for legacy trait implementations;
it cannot measure their arbitrary external allocations. The charge is a bounded
cache accounting model, not an exact process RSS or allocator measurement. An
in-order item returned immediately is not retained by this cache.

Resource pressure fails the affected ordering context explicitly. State eviction
can end retained generation knowledge; no finite cache promises indefinite
duplicate suppression after a tombstone expires or is evicted.
Every such state eviction increments `flow-evictions`. If an evicted live
generation later resumes above0, the cache cannot invent its lost checkpoint:
it holds the new gap and drops it on the bounded deadline, with actual drop
counters. This is a documented pressure failure, not ordinary idle behavior.

## Counter meanings

`flow-counter` is the retained state count, including tombstones; it is not the
number of open application connections. `packet-counter`, `buffered-bytes` and
`accounted-bytes` are current gauges and do not reset when sampled.

Counted values reset on sampling: `drop-before-window` counts items discarded by
expired gaps; `gap-timeouts` counts those affected flows; `drop-out-of-order`
counts old/duplicate/overlapping arrivals. `budget-dropped`, `shutdown-dropped`,
`late-after-close`, `failed-flow-dropped` and `invalid-range-dropped` distinguish
other actual drops. `flow-evictions` counts bounded state evictions.
`max-seq-gap` is the largest observed forward gap since the previous sample.
`bypassed`, `untracked-close-bypass` and `zero-id-bypass` describe passthrough,
not successful ordering. `sequence-exhausted` records an emitted inclusive range
ending at `u64::MAX`; its state becomes terminal instead of wrapping to0.

Run the narrow crate tests from `agent` with the installed compiler/tooling and
locked offline cache:

```sh
cargo test -p reorder --locked --offline
```

Some prepared environments require explicit `RUSTC`, `RUSTDOC`, `RUSTFMT` and
linker paths for the existing workspace build scripts. These tests include the
measured42-header ordering replay and independent failure/boundary cases. A
passing replay/build does not prove a newly built native Agent has passed real
capture, storage, UI or performance acceptance.
