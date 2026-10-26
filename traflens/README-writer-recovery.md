# ClickHouse writer recovery

The writer uses the repository's pinned `ch-go v0.69.0` and sends one serialized
column block per logical cache flush. CKItems have already returned to their
object pools when writing starts, so retries retain the column block and row
order rather than retaining or rebuilding released CKItems.

## Safe replay boundary

An INSERT failure can occur after ClickHouse has committed the rows. EOF,
timeout, or a lost acknowledgement alone cannot distinguish that outcome.
The current local MergeTree tables do not enable a deduplication window or
stable insert tokens. The writer therefore retries only failures for which it
can prove it has not supplied row data. See the [ClickHouse retry contract](https://clickhouse.com/docs/concepts/features/operations/insert/deduplicating-inserts-on-retries).

For the existing `INSERT INTO <local table> VALUES` statements without inline
values or external data, a zero-row view of the first input column defers the
first block. It forwards column inference and records matching server metadata.
The first OnInput callback checks that metadata and its driver context, marks
input as possibly sent, then restores the original column before encoding.
The next callback exposes zero rows and returns EOF; it does not resend the
driver's nonempty EOF tail or reset the retained column data.

If the driver closes its metadata channel before cancelling after an error,
the callback waits for the driver's child context. This preserves the original
network error or server exception and never supplies rows from absent metadata.
Server exceptions and failures after input supply are not replayed. Every
failed connection is closed and discarded; safe retries use the same endpoint.

## Bounds and counters

Each flush has a shared 10-second context covering dial, handshake, insert and
backoff, plus a fixed maximum of 13 attempts. Backoff starts at 100 milliseconds,
doubles to a one-second cap, and stops when the budget or attempt limit expires.
The underlying driver's existing cancellation cleanup may take about one more
second; this is not a strict ten-second process wall-clock limit.

The earlier two-extra-attempt policy could exhaust all attempts in about 200ms
while the database was still unavailable. A regression retains that failure and
checks successful same-block recovery after a 550ms connection refusal window.

- `write-success-count` and `write-failed-count` count rows once per logical batch.
- `write-uncertain-count` is a subset of failed rows for which data may have been
  committed; these rows are not blindly replayed.
- `retry-count` counts additional attempts, and `retry-failed-count` counts failed
  additional attempts. They count attempts, not rows.

The serialized block is reset and the connection rotation advances exactly once
after the logical flush ends, regardless of attempts. Empty caches do not dial.
Normal inserts add no extra query or Ping round trip; the streaming callback
does introduce a separate data flush before its end-of-input marker.

## Validation and remaining work

Run from `server/` with the pinned server Go toolchain:

```sh
go test -mod=vendor -race ./ingester/pkg/ckwriter -timeout 120s -count=1
```

The tests use real vendored ch-go and a net.Pipe native-protocol peer, including
stale idle sockets, disconnect before server sample, lost acknowledgement after
data, exception preservation, empty metadata, DateTime inference, row ordering,
single-block EOF, bounded retries and one final reset/counter update.

The controlled lab fault test keeps its before/during/after raw requests and
exact query multisets. A passing recovery case is evidence for that workload
and outage only. This implementation does not add a disk queue, transactionally
deduplicated replay, unlimited outage buffering or retries of independent DDL
initialization paths. Delivery across ambiguous commits requires a separate
server-side idempotency and persistence design.
