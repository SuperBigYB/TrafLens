# Safe pre-input recovery window

Base candidate: f89e5647c58e1ff02b1fbd7f53b4aada07789350. It is the initial short-retry strategy, built but not claimed live-validated. Only the CKwriter retry policy and its existing test file changed.

A new regression refuses every dial until550ms after batch start. Before the production change, it fails after201.617495ms/3dials, dropping both rows (before-recovery.log). After the change, it recovers around0.70s and delivers both retained row values once in one real native-protocol block (after-recovery.log).

Safe pre-input retries now use at most13total attempts under the same10s batch context. Backoff is100,200,400,800ms, then1s maximum. Immediate-refusal attempts occur around0/0.1/0.3/0.7/1.5/2.5...9.5s. Actual dial/query duration may make the deadline stop retries earlier, so13 is an upper bound, not a guaranteed count. The existing driver cancellation cleanup may add up to1s beyond the context.

The input-supply gate and retry error classifier are byte-for-byte unchanged fromf89. Unknown commit outcomes and server Exceptions still do not replay. The original serialized columnBlock, endpoint choice, final row accounting and single Reset are preserved; SQL/DDL RETRY_COUNT remains2.

Validation: full-package race once passes all13top-level tests plus two retry subcases (11.622s). The13attempt exhaustion test took9.51s and was deliberately not multiplied across repeated suites. Fast critical stale-idle/sample-before-input/lost-ACK/Exception cases pass20race rounds (5.320s). All exact commands and source hashes are in metadata.json. Independent read-only peer review approved the change.

This is not a live ClickHouse restart acceptance or zero-loss guarantee. Root owns official Server rebuild/deployment and the real fault test; this subtask restarted no services, launched no Agent, and generated no external traffic. Production source is frozen for the next commit.
