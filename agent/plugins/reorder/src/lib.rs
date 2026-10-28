/*
 * Copyright (c) 2024 Yunshan Networks
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::sync::Arc;
use std::time::Duration;

use public::packet::Downcast;
use public::{
    counter,
    l7_protocol::{L7Protocol, L7ProtocolChecker},
};

pub trait CacheItem: Downcast {
    /// Full socket generation identity, never a recycled file descriptor.
    fn get_id(&self) -> u64;
    fn get_source(&self) -> u8 {
        0
    }
    fn get_seq(&self) -> u64;
    fn get_end_seq(&self) -> u64 {
        self.get_seq()
    }
    // The spelling is retained for existing implementations. Milliseconds.
    fn get_timestmap(&self) -> u64;
    fn get_l7_protocol(&self) -> L7Protocol;
    fn is_segment_start(&self) -> bool;
    fn is_socket_closed(&self) -> bool {
        false
    }
    /// Owned item memory estimate, including payload allocations/capacity.
    /// Legacy implementations pay fixed bookkeeping only and should override.
    fn get_size(&self) -> usize {
        0
    }
}

const MAX_BUFFERED_ITEMS: usize = 65_536;
const MAX_FLOW_ITEMS: usize = 256;
const MAX_FLOW_BYTES: usize = 1 << 20;
const MAX_ACCOUNTED_BYTES: usize = 64 << 20;
const MAX_FLOW_STATES: usize = 16_384;
const ITEM_OVERHEAD: usize = 128;
const STATE_OVERHEAD: usize = 512;
const STATE_RETENTION_MS: u64 = 60_000;
type Key = (u64, u8);

#[derive(Default)]
pub struct ReorderCounter {
    drop_before_window: AtomicU64,
    drop_out_of_order: AtomicU64,
    flow_counter: AtomicU64,
    packet_counter: AtomicU64,
    max_seq_gap: AtomicU64,
    buffered_bytes: AtomicU64,
    accounted_bytes: AtomicU64,
    gap_timeouts: AtomicU64,
    budget_dropped: AtomicU64,
    shutdown_dropped: AtomicU64,
    late_after_close: AtomicU64,
    failed_flow_dropped: AtomicU64,
    flow_evictions: AtomicU64,
    invalid_range_dropped: AtomicU64,
    bypassed: AtomicU64,
    untracked_close_bypass: AtomicU64,
    zero_id_bypass: AtomicU64,
    sequence_exhausted: AtomicU64,
    closed: AtomicBool,
}

pub struct StatsReorderCounter(Arc<ReorderCounter>);
impl StatsReorderCounter {
    pub fn new(count: Arc<ReorderCounter>) -> Self {
        Self(count)
    }
}

impl counter::OwnedCountable for StatsReorderCounter {
    fn closed(&self) -> bool {
        self.0.closed.load(Relaxed)
    }

    fn get_counters(&self) -> Vec<counter::Counter> {
        use counter::{
            CounterType::{Counted, Gauged},
            CounterValue::Unsigned,
        };
        vec![
            (
                "drop-before-window",
                Counted,
                Unsigned(self.0.drop_before_window.swap(0, Relaxed)),
            ),
            (
                "drop-out-of-order",
                Counted,
                Unsigned(self.0.drop_out_of_order.swap(0, Relaxed)),
            ),
            (
                "flow-counter",
                Gauged,
                Unsigned(self.0.flow_counter.load(Relaxed)),
            ),
            (
                "packet-counter",
                Gauged,
                Unsigned(self.0.packet_counter.load(Relaxed)),
            ),
            (
                "max-seq-gap",
                Counted,
                Unsigned(self.0.max_seq_gap.swap(0, Relaxed)),
            ),
            (
                "buffered-bytes",
                Gauged,
                Unsigned(self.0.buffered_bytes.load(Relaxed)),
            ),
            (
                "accounted-bytes",
                Gauged,
                Unsigned(self.0.accounted_bytes.load(Relaxed)),
            ),
            (
                "gap-timeouts",
                Counted,
                Unsigned(self.0.gap_timeouts.swap(0, Relaxed)),
            ),
            (
                "budget-dropped",
                Counted,
                Unsigned(self.0.budget_dropped.swap(0, Relaxed)),
            ),
            (
                "shutdown-dropped",
                Counted,
                Unsigned(self.0.shutdown_dropped.swap(0, Relaxed)),
            ),
            (
                "late-after-close",
                Counted,
                Unsigned(self.0.late_after_close.swap(0, Relaxed)),
            ),
            (
                "failed-flow-dropped",
                Counted,
                Unsigned(self.0.failed_flow_dropped.swap(0, Relaxed)),
            ),
            (
                "flow-evictions",
                Counted,
                Unsigned(self.0.flow_evictions.swap(0, Relaxed)),
            ),
            (
                "invalid-range-dropped",
                Counted,
                Unsigned(self.0.invalid_range_dropped.swap(0, Relaxed)),
            ),
            (
                "bypassed",
                Counted,
                Unsigned(self.0.bypassed.swap(0, Relaxed)),
            ),
            (
                "untracked-close-bypass",
                Counted,
                Unsigned(self.0.untracked_close_bypass.swap(0, Relaxed)),
            ),
            (
                "zero-id-bypass",
                Counted,
                Unsigned(self.0.zero_id_bypass.swap(0, Relaxed)),
            ),
            (
                "sequence-exhausted",
                Counted,
                Unsigned(self.0.sequence_exhausted.swap(0, Relaxed)),
            ),
        ]
    }
}

struct Pending {
    item: Box<dyn CacheItem>,
    end: u64,
    bytes: usize,
}

#[derive(PartialEq)]
enum Status {
    Open,
    Failed,
    Closed,
}

struct Flow {
    next: u64,
    pending: BTreeMap<u64, Pending>,
    bytes: usize,
    deadline: u64,
    status: Status,
}

impl Flow {
    fn new() -> Self {
        Self {
            next: 0,
            pending: BTreeMap::new(),
            bytes: 0,
            deadline: u64::MAX,
            status: Status::Open,
        }
    }
}

pub struct Reorder {
    protocols: Box<dyn L7ProtocolChecker>,
    counter: Arc<ReorderCounter>,
    flows: BTreeMap<Key, Flow>,
    deadlines: BTreeSet<(u64, Key)>,
    idle_states: BTreeSet<(u64, Key)>,
    max_items: usize,
    timeout_ms: u64,
    clock: u64,
    buffered_items: usize,
    buffered_bytes: usize,
}

impl Reorder {
    pub fn new(
        protocols: Box<dyn L7ProtocolChecker>,
        counter: Arc<ReorderCounter>,
        cache_size: usize,
        timeout: Duration,
    ) -> Self {
        counter.closed.store(false, Relaxed);
        let this = Self {
            protocols,
            counter,
            flows: BTreeMap::new(),
            deadlines: BTreeSet::new(),
            idle_states: BTreeSet::new(),
            max_items: cache_size.clamp(1, MAX_BUFFERED_ITEMS),
            timeout_ms: timeout.as_millis().clamp(1, 30_000) as u64,
            clock: 0,
            buffered_items: 0,
            buffered_bytes: 0,
        };
        this.sync_counters();
        this
    }

    /// Reconfiguration never lets an unresolved gap/close escape in arrival order.
    pub fn reconfigure(
        &mut self,
        protocols: Box<dyn L7ProtocolChecker>,
        cache_size: usize,
        timeout: Duration,
    ) -> Vec<Box<dyn CacheItem>> {
        let output = self.flush_all();
        self.protocols = protocols;
        self.max_items = cache_size.clamp(1, MAX_BUFFERED_ITEMS);
        self.timeout_ms = timeout.as_millis().clamp(1, 30_000) as u64;
        output
    }

    fn sync_counters(&self) {
        self.counter
            .flow_counter
            .store(self.flows.len() as u64, Relaxed);
        self.counter
            .packet_counter
            .store(self.buffered_items as u64, Relaxed);
        self.counter
            .buffered_bytes
            .store(self.buffered_bytes as u64, Relaxed);
        self.counter
            .accounted_bytes
            .store(self.accounted_bytes() as u64, Relaxed);
    }

    fn accounted_bytes(&self) -> usize {
        self.buffered_bytes
            .saturating_add(self.flows.len().saturating_mul(STATE_OVERHEAD))
    }

    fn take_flow(&mut self, key: Key) -> Option<Flow> {
        let flow = self.flows.remove(&key)?;
        self.deadlines.remove(&(flow.deadline, key));
        self.idle_states.remove(&(flow.deadline, key));
        Some(flow)
    }

    fn put_flow(&mut self, key: Key, flow: Flow) {
        self.deadlines.insert((flow.deadline, key));
        if flow.pending.is_empty() {
            self.idle_states.insert((flow.deadline, key));
        }
        self.flows.insert(key, flow);
    }

    fn remove_pending(&mut self, flow: &mut Flow, seq: u64) -> Pending {
        let entry = flow.pending.remove(&seq).unwrap();
        self.buffered_items -= 1;
        self.buffered_bytes -= entry.bytes;
        flow.bytes -= entry.bytes;
        entry
    }

    fn discard_pending(&mut self, flow: &mut Flow) -> u64 {
        let count = flow.pending.len() as u64;
        self.buffered_items -= flow.pending.len();
        self.buffered_bytes -= flow.bytes;
        flow.pending.clear();
        flow.bytes = 0;
        count
    }

    fn expire(&mut self, timestamp: u64) {
        self.clock = self.clock.max(timestamp);
        // Snapshot each eligible key once: saturated timestamps cannot loop by
        // reinserting a failed-state deadline at u64::MAX.
        let due: Vec<Key> = self
            .deadlines
            .iter()
            .take_while(|(t, _)| *t <= self.clock)
            .map(|(_, key)| *key)
            .collect();
        for key in due {
            let mut flow = self.take_flow(key).unwrap();
            if !flow.pending.is_empty() {
                let dropped = self.discard_pending(&mut flow);
                self.counter.drop_before_window.fetch_add(dropped, Relaxed);
                self.counter.gap_timeouts.fetch_add(1, Relaxed);
                flow.status = Status::Failed;
                flow.deadline = self.clock.saturating_add(STATE_RETENTION_MS);
                self.put_flow(key, flow);
            } else if flow.status == Status::Open {
                // A quiet live connection still needs its exact next checkpoint.
                // It is reclaimed only by explicit bounded state pressure.
                self.put_flow(key, flow);
            }
        }
    }

    fn ensure_state_budget(&mut self) {
        while self.flows.len() >= MAX_FLOW_STATES
            || self.accounted_bytes().saturating_add(STATE_OVERHEAD) > MAX_ACCOUNTED_BYTES
        {
            let key = self
                .idle_states
                .first()
                .or_else(|| self.deadlines.first())
                .map(|(_, key)| *key);
            let Some(key) = key else {
                break;
            };
            let mut flow = self.take_flow(key).unwrap();
            let dropped = self.discard_pending(&mut flow);
            self.counter.budget_dropped.fetch_add(dropped, Relaxed);
            self.counter.flow_evictions.fetch_add(1, Relaxed);
        }
    }

    fn overlaps(flow: &Flow, start: u64, end: u64) -> bool {
        flow.pending
            .range(..=start)
            .next_back()
            .is_some_and(|(_, e)| e.end >= start)
            || flow
                .pending
                .range(start..)
                .next()
                .is_some_and(|(next, _)| *next <= end)
    }

    fn emit_contiguous(
        &mut self,
        flow: &mut Flow,
        mut entry: Pending,
        output: &mut Vec<Box<dyn CacheItem>>,
    ) {
        loop {
            let close = entry.item.is_socket_closed();
            let end = entry.end;
            output.push(entry.item);
            if close || end == u64::MAX {
                flow.status = Status::Closed;
                if end == u64::MAX {
                    self.counter.sequence_exhausted.fetch_add(1, Relaxed);
                }
                let dropped = self.discard_pending(flow);
                self.counter.late_after_close.fetch_add(dropped, Relaxed);
                break;
            }
            flow.next = end + 1;
            if !flow.pending.contains_key(&flow.next) {
                break;
            }
            entry = self.remove_pending(flow, flow.next);
        }
        flow.deadline = if flow.pending.is_empty() && flow.status == Status::Open {
            u64::MAX
        } else {
            self.clock.saturating_add(if flow.pending.is_empty() {
                STATE_RETENTION_MS
            } else {
                self.timeout_ms
            })
        };
    }

    /// Expiry discards unresolved gaps; it never releases a CLOSE across one.
    pub fn flush(&mut self, timestamp: u64) -> Vec<Box<dyn CacheItem>> {
        self.expire(timestamp);
        self.sync_counters();
        Vec::new()
    }

    /// Stop/reconfigure releases ownership explicitly. Under the maintained
    /// invariant every buffered entry is behind a gap, so none can be emitted.
    pub fn flush_all(&mut self) -> Vec<Box<dyn CacheItem>> {
        self.counter
            .shutdown_dropped
            .fetch_add(self.buffered_items as u64, Relaxed);
        self.flows.clear();
        self.deadlines.clear();
        self.idle_states.clear();
        self.buffered_items = 0;
        self.buffered_bytes = 0;
        self.sync_counters();
        Vec::new()
    }

    pub fn inject_item(&mut self, item: Box<dyn CacheItem>) -> Vec<Box<dyn CacheItem>> {
        self.expire(item.get_timestmap());
        let key = (item.get_id(), item.get_source());
        let protocol = item.get_l7_protocol();
        let tracked_unknown_close = item.is_socket_closed()
            && protocol == L7Protocol::Unknown
            && self.flows.contains_key(&key);
        if key.0 == 0 || (!self.protocols.is_enabled(protocol) && !tracked_unknown_close) {
            self.counter.bypassed.fetch_add(1, Relaxed);
            if key.0 == 0 {
                self.counter.zero_id_bypass.fetch_add(1, Relaxed);
            }
            if item.is_socket_closed() {
                self.counter.untracked_close_bypass.fetch_add(1, Relaxed);
            }
            self.sync_counters();
            return vec![item];
        }
        let start = item.get_seq();
        let end = item.get_end_seq();
        if end < start {
            self.counter.invalid_range_dropped.fetch_add(1, Relaxed);
            self.sync_counters();
            return Vec::new();
        }
        let mut flow = if let Some(flow) = self.take_flow(key) {
            flow
        } else {
            self.ensure_state_budget();
            Flow::new()
        };
        let mut output = Vec::new();
        if flow.status != Status::Open {
            if flow.status == Status::Closed {
                self.counter.late_after_close.fetch_add(1, Relaxed);
            } else {
                self.counter.failed_flow_dropped.fetch_add(1, Relaxed);
            }
        } else if start < flow.next || Self::overlaps(&flow, start, end) {
            self.counter.drop_out_of_order.fetch_add(1, Relaxed);
        } else if start == flow.next {
            self.emit_contiguous(
                &mut flow,
                Pending {
                    item,
                    end,
                    bytes: 0,
                },
                &mut output,
            );
        } else {
            self.counter
                .max_seq_gap
                .fetch_max(start - flow.next, Relaxed);
            let bytes = item.get_size().saturating_add(ITEM_OVERHEAD);
            let exhausted = self.buffered_items >= self.max_items
                || flow.pending.len() >= MAX_FLOW_ITEMS
                || flow.bytes.saturating_add(bytes) > MAX_FLOW_BYTES
                || self
                    .accounted_bytes()
                    .saturating_add(STATE_OVERHEAD)
                    .saturating_add(bytes)
                    > MAX_ACCOUNTED_BYTES;
            if exhausted {
                let dropped = self.discard_pending(&mut flow) + 1;
                self.counter.budget_dropped.fetch_add(dropped, Relaxed);
                flow.status = Status::Failed;
                flow.deadline = self.clock.saturating_add(STATE_RETENTION_MS);
            } else {
                if flow.pending.is_empty() {
                    flow.deadline = self.clock.saturating_add(self.timeout_ms);
                }
                flow.bytes += bytes;
                self.buffered_bytes += bytes;
                self.buffered_items += 1;
                flow.pending.insert(start, Pending { item, end, bytes });
            }
        }
        self.put_flow(key, flow);
        self.sync_counters();
        output
    }
}

impl Drop for Reorder {
    fn drop(&mut self) {
        let _ = self.flush_all();
        self.counter.closed.store(true, Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use public::counter::OwnedCountable;
    use std::any::Any;

    struct Enabled;
    impl L7ProtocolChecker for Enabled {
        fn is_disabled(&self, p: L7Protocol) -> bool {
            !self.is_enabled(p)
        }
        fn is_enabled(&self, p: L7Protocol) -> bool {
            p == L7Protocol::MySQL
        }
    }

    struct Item {
        id: u64,
        seq: u64,
        end: u64,
        size: usize,
        timestamp: u64,
    }
    impl Downcast for Item {
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }
        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }
    impl CacheItem for Item {
        fn get_id(&self) -> u64 {
            self.id
        }
        fn get_seq(&self) -> u64 {
            self.seq
        }
        fn get_end_seq(&self) -> u64 {
            self.end
        }
        fn get_timestmap(&self) -> u64 {
            self.timestamp
        }
        fn get_l7_protocol(&self) -> L7Protocol {
            L7Protocol::MySQL
        }
        fn is_segment_start(&self) -> bool {
            false
        }
        fn get_size(&self) -> usize {
            self.size
        }
    }
    fn item(seq: u64, end: u64, size: usize, timestamp: u64) -> Box<dyn CacheItem> {
        Box::new(Item {
            id: 1,
            seq,
            end,
            size,
            timestamp,
        })
    }
    fn reorder() -> (Reorder, Arc<ReorderCounter>) {
        let count = Arc::new(ReorderCounter::default());
        (
            Reorder::new(
                Box::new(Enabled),
                count.clone(),
                16,
                Duration::from_millis(100),
            ),
            count,
        )
    }
    fn value(stats: &StatsReorderCounter, name: &str) -> u64 {
        let (_, _, value) = stats
            .get_counters()
            .into_iter()
            .find(|(key, _, _)| *key == name)
            .unwrap();
        match value {
            counter::CounterValue::Unsigned(n) => n,
            _ => panic!("unsigned reorder counter required"),
        }
    }

    #[test]
    fn gauge_accounts_owned_bytes_and_releases_them_without_resetting_on_read() {
        let (mut reorder, count) = reorder();
        let stats = StatsReorderCounter::new(count);
        assert!(reorder.inject_item(item(2, 2, 40, 10)).is_empty());
        assert_eq!(value(&stats, "buffered-bytes"), (40 + ITEM_OVERHEAD) as u64);
        assert_eq!(value(&stats, "packet-counter"), 1);
        assert_eq!(
            value(&stats, "accounted-bytes"),
            (STATE_OVERHEAD + 40 + ITEM_OVERHEAD) as u64
        );
        assert_eq!(value(&stats, "buffered-bytes"), (40 + ITEM_OVERHEAD) as u64);
        assert_eq!(reorder.inject_item(item(0, 0, 40, 11)).len(), 1);
        assert_eq!(
            reorder
                .inject_item(item(1, 1, 40, 12))
                .iter()
                .map(|x| x.get_seq())
                .collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(value(&stats, "packet-counter"), 0);
        assert_eq!(value(&stats, "buffered-bytes"), 0);
        assert_eq!(value(&stats, "flow-counter"), 1);
        assert!(reorder.flush_all().is_empty());
        assert_eq!(value(&stats, "accounted-bytes"), 0);
    }

    #[test]
    fn counted_gap_timeout_is_not_a_synthetic_flush_and_late_data_is_separate() {
        let (mut reorder, count) = reorder();
        assert!(reorder.inject_item(item(2, 2, 1, 10)).is_empty());
        assert!(reorder.flush(109).is_empty());
        assert_eq!(reorder.buffered_items, 1);
        assert!(reorder.flush(110).is_empty());
        assert_eq!(reorder.buffered_items, 0);
        assert_eq!(count.drop_before_window.load(Relaxed), 1);
        assert_eq!(count.gap_timeouts.load(Relaxed), 1);
        assert!(reorder.inject_item(item(0, 0, 1, 111)).is_empty());
        assert_eq!(count.failed_flow_dropped.load(Relaxed), 1);
        let stats = StatsReorderCounter::new(count);
        assert_eq!(value(&stats, "gap-timeouts"), 1);
        assert_eq!(value(&stats, "gap-timeouts"), 0);
    }

    #[test]
    fn declared_size_overflow_fails_closed_without_allocating_or_wrapping() {
        let (mut reorder, count) = reorder();
        assert!(reorder.inject_item(item(1, 1, usize::MAX, 10)).is_empty());
        assert_eq!(count.budget_dropped.load(Relaxed), 1);
        assert_eq!(reorder.buffered_bytes, 0);
        assert_eq!(reorder.buffered_items, 0);
        assert!(reorder.inject_item(item(0, 0, 0, 11)).is_empty());
    }

    #[test]
    fn inclusive_ranges_advance_once_and_overlaps_never_duplicate_captures() {
        let (mut reorder, count) = reorder();
        assert_eq!(reorder.inject_item(item(0, 2, 1, 10)).len(), 1);
        assert_eq!(reorder.inject_item(item(3, 3, 1, 11)).len(), 1);
        assert!(reorder.inject_item(item(2, 2, 1, 12)).is_empty());
        assert!(reorder.inject_item(item(5, 4, 1, 13)).is_empty());
        assert_eq!(count.drop_out_of_order.load(Relaxed), 1);
        assert_eq!(count.invalid_range_dropped.load(Relaxed), 1);
    }

    #[test]
    fn saturated_clock_expiry_is_bounded_and_drop_zeros_gauges() {
        let (mut reorder, count) = reorder();
        assert!(reorder.inject_item(item(2, 2, 1, u64::MAX - 1)).is_empty());
        assert!(reorder.flush(u64::MAX).is_empty());
        assert!(reorder.flush(u64::MAX).is_empty());
        drop(reorder);
        assert!(count.closed.load(Relaxed));
        assert_eq!(count.accounted_bytes.load(Relaxed), 0);
        assert_eq!(count.packet_counter.load(Relaxed), 0);
    }

    #[test]
    fn live_connection_checkpoint_survives_normal_idle_beyond_tombstone_retention() {
        let (mut reorder, count) = reorder();
        assert_eq!(reorder.inject_item(item(0, 0, 1, 10)).len(), 1);
        assert!(reorder.flush(STATE_RETENTION_MS * 2).is_empty());
        assert_eq!(count.flow_counter.load(Relaxed), 1);
        assert_eq!(
            reorder
                .inject_item(item(1, 1, 1, STATE_RETENTION_MS * 2 + 1))
                .len(),
            1
        );
        assert_eq!(
            reorder
                .inject_item(item(2, 2, 1, STATE_RETENTION_MS * 2 + 2))
                .len(),
            1
        );
        assert_eq!(count.gap_timeouts.load(Relaxed), 0);
        assert_eq!(count.drop_before_window.load(Relaxed), 0);
    }

    #[test]
    fn checkpoint_state_pressure_is_bounded_and_eviction_never_fabricates_continuity() {
        let (mut reorder, count) = reorder();
        for id in 1..=MAX_FLOW_STATES as u64 + 1 {
            let output = reorder.inject_item(Box::new(Item {
                id,
                seq: 0,
                end: 0,
                size: 1,
                timestamp: 10,
            }));
            assert_eq!(output.len(), 1);
        }
        assert_eq!(count.flow_counter.load(Relaxed), MAX_FLOW_STATES as u64);
        assert_eq!(count.flow_evictions.load(Relaxed), 1);
        assert!(reorder.inject_item(item(1, 1, 1, 11)).is_empty());
        assert_eq!(count.flow_evictions.load(Relaxed), 2);
        assert!(reorder.flush(111).is_empty());
        assert_eq!(count.drop_before_window.load(Relaxed), 1);
        assert_eq!(count.gap_timeouts.load(Relaxed), 1);
    }
}
