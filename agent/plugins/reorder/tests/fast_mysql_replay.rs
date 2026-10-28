//! Independent ordering regressions, with no network, payload or native Agent.
//!
//! The 42 (anonymous socket ordinal, cap_seq, CLOSE) entries below reproduce
//! retained R22 C callback invocation order. All other fixture metadata is
//! constructed for this test. Passing this replay is not a new capture result.

use std::any::Any;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use public::counter::OwnedCountable;
use public::l7_protocol::{L7Protocol, L7ProtocolChecker};
use public::packet::Downcast;
use reorder::{CacheItem, Reorder, ReorderCounter, StatsReorderCounter};

struct MysqlOnly(bool);

impl L7ProtocolChecker for MysqlOnly {
    fn is_disabled(&self, protocol: L7Protocol) -> bool {
        !self.is_enabled(protocol)
    }

    fn is_enabled(&self, protocol: L7Protocol) -> bool {
        self.0 && protocol == L7Protocol::MySQL
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    uid: u64,
    source: u8,
    seq: u64,
    end: u64,
    time_ms: u64,
    close: bool,
    protocol: L7Protocol,
    label: usize,
}

struct Event {
    row: Row,
    bytes: usize,
    live: Arc<AtomicUsize>,
}

impl Drop for Event {
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Downcast for Event {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl CacheItem for Event {
    fn get_id(&self) -> u64 {
        self.row.uid
    }

    fn get_source(&self) -> u8 {
        self.row.source
    }

    fn get_seq(&self) -> u64 {
        self.row.seq
    }

    fn get_end_seq(&self) -> u64 {
        self.row.end
    }

    fn get_timestmap(&self) -> u64 {
        self.row.time_ms
    }

    fn get_l7_protocol(&self) -> L7Protocol {
        self.row.protocol
    }

    fn is_segment_start(&self) -> bool {
        false
    }

    fn is_socket_closed(&self) -> bool {
        self.row.close
    }

    fn get_size(&self) -> usize {
        self.bytes
    }
}

fn event(live: &Arc<AtomicUsize>, uid: u64, seq: u64) -> Box<Event> {
    live.fetch_add(1, Ordering::SeqCst);
    Box::new(Event {
        row: Row {
            uid,
            source: 0,
            seq,
            end: seq,
            time_ms: 1_000 + seq,
            close: false,
            protocol: L7Protocol::MySQL,
            label: 0,
        },
        bytes: 128,
        live: live.clone(),
    })
}

fn rows(items: Vec<Box<dyn CacheItem>>) -> Vec<Row> {
    items
        .into_iter()
        .map(|item| {
            let event = item
                .into_any()
                .downcast::<Event>()
                .unwrap_or_else(|_| panic!("Ordering changed the input item type"));
            event.row.clone()
        })
        .collect()
}

fn reorder(capacity: usize, timeout_ms: u64) -> Reorder {
    Reorder::new(
        Box::new(MysqlOnly(true)),
        Arc::new(ReorderCounter::default()),
        capacity,
        Duration::from_millis(timeout_ms),
    )
}

// Retained measured order only: no original UID, process, address or payload.
const R22_ORDER: [(u64, u64, bool); 42] = [
    (0, 0, false),
    (1, 0, false),
    (2, 0, false),
    (0, 1, false),
    (0, 2, false),
    (0, 3, false),
    (0, 4, false),
    (0, 5, false),
    (0, 6, true),
    (3, 0, false),
    (3, 1, false),
    (3, 2, false),
    (1, 1, false),
    (1, 2, false),
    (1, 3, false),
    (1, 4, false),
    (1, 5, false),
    (1, 6, true),
    (2, 1, false),
    (2, 2, false),
    (2, 3, false),
    (2, 4, false),
    (2, 5, false),
    (2, 6, true),
    (3, 3, false),
    (3, 4, false),
    (3, 5, false),
    (3, 6, true),
    (4, 0, false),
    (4, 1, false),
    (4, 2, false),
    (4, 3, false),
    (4, 4, false),
    (4, 5, false),
    (4, 6, true),
    (5, 2, false),
    (5, 3, false),
    (5, 4, false),
    (5, 5, false),
    (5, 6, true),
    (5, 0, false),
    (5, 1, false),
];

#[test]
fn replay_measured_42_callback_order_preserves_every_item_and_orders_each_socket() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(128, 100);
    let mut actual = Vec::new();
    let mut originals = BTreeMap::new();
    for (label, &(socket, seq, close)) in R22_ORDER.iter().enumerate() {
        let mut item = event(&live, socket + 1, seq);
        item.row.close = close;
        item.row.label = label;
        originals.insert((socket + 1, seq), item.row.clone());
        actual.extend(rows(queue.inject_item(item)));
    }
    actual.extend(rows(queue.flush_all()));
    assert_eq!(actual.len(), 42, "No missing or invented observed header");
    let mut by_socket: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    for row in &actual {
        assert_eq!(Some(row), originals.get(&(row.uid, row.seq)));
        by_socket.entry(row.uid).or_default().push(row.seq);
    }
    assert_eq!(by_socket.len(), 6);
    for seqs in by_socket.values() {
        assert_eq!(seqs, &(0..=6).collect::<Vec<_>>());
    }
    assert_eq!(actual.iter().filter(|row| row.close).count(), 6);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn first_observed_two_and_early_close_cannot_establish_a_false_baseline() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    for seq in 2..=6 {
        let mut item = event(&live, 7, seq);
        item.row.close = seq == 6;
        assert!(rows(queue.inject_item(item)).is_empty());
    }
    assert_eq!(rows(queue.inject_item(event(&live, 7, 0)))[0].seq, 0);
    let result = rows(queue.inject_item(event(&live, 7, 1)));
    assert_eq!(
        result.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5, 6]
    );
    assert!(result.last().unwrap().close);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn gap_deadline_does_not_refresh_on_more_out_of_order_data_or_clock_regression() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 10);
    let mut first = event(&live, 8, 2);
    first.row.time_ms = 1_000;
    assert!(queue.inject_item(first).is_empty());
    assert!(queue.flush(1_009).is_empty());
    let mut later = event(&live, 8, 3);
    later.row.time_ms = 990;
    assert!(queue.inject_item(later).is_empty());
    assert!(queue.flush(1_010).is_empty());
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "Expired gap must release every buffered item"
    );
    assert!(
        queue.inject_item(event(&live, 8, 0)).is_empty(),
        "Timeout cannot reopen a partial generation"
    );
}

#[test]
fn close_behind_a_missing_sequence_is_never_manufactured_on_flush_or_stop() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    assert_eq!(rows(queue.inject_item(event(&live, 9, 0)))[0].seq, 0);
    let mut close = event(&live, 9, 2);
    close.row.close = true;
    assert!(queue.inject_item(close).is_empty());
    assert!(queue.flush_all().is_empty());
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn duplicate_and_old_headers_do_not_become_a_second_transaction_or_reopen_close() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    assert_eq!(rows(queue.inject_item(event(&live, 10, 0)))[0].seq, 0);
    assert!(queue.inject_item(event(&live, 10, 0)).is_empty());
    assert!(queue.inject_item(event(&live, 10, 2)).is_empty());
    assert!(queue.inject_item(event(&live, 10, 2)).is_empty());
    assert_eq!(
        rows(queue.inject_item(event(&live, 10, 1)))
            .iter()
            .map(|row| row.seq)
            .collect::<Vec<_>>(),
        vec![1, 2]
    );
    let mut close = event(&live, 10, 3);
    close.row.close = true;
    assert_eq!(rows(queue.inject_item(close))[0].seq, 3);
    assert!(queue.inject_item(event(&live, 10, 0)).is_empty());
    assert!(queue.inject_item(event(&live, 10, 2)).is_empty());
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn full_uid_and_raw_source_are_independent_even_where_old_flow_mask_would_collide() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    let keys = [(11, 0), (11 | (1 << 48), 0), (11, 1)];
    let mut actual = Vec::new();
    for &(uid, source) in &keys {
        let mut pending = event(&live, uid, 1);
        pending.row.source = source;
        assert!(queue.inject_item(pending).is_empty());
    }
    for &(uid, source) in &keys {
        let mut first = event(&live, uid, 0);
        first.row.source = source;
        actual.extend(rows(queue.inject_item(first)));
    }
    let seen: BTreeSet<_> = actual
        .iter()
        .map(|row| (row.uid, row.source, row.seq))
        .collect();
    assert_eq!(seen.len(), 6);
    for &(uid, source) in &keys {
        assert_eq!(
            actual
                .iter()
                .filter(|row| (row.uid, row.source) == (uid, source))
                .map(|row| row.seq)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
    }
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn unknown_close_follows_an_already_tracked_socket_but_is_not_a_new_protocol_opt_in() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    assert!(queue.inject_item(event(&live, 12, 1)).is_empty());
    let mut close = event(&live, 12, 2);
    close.row.close = true;
    close.row.protocol = L7Protocol::Unknown;
    assert!(queue.inject_item(close).is_empty());
    let result = rows(queue.inject_item(event(&live, 12, 0)));
    assert_eq!(
        result.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![0, 1, 2]
    );
    assert!(result[2].close);
    let mut untracked = event(&live, 13, 6);
    untracked.row.close = true;
    untracked.row.protocol = L7Protocol::Unknown;
    assert_eq!(rows(queue.inject_item(untracked))[0].seq, 6);
}

#[test]
fn disabled_dns_and_anonymous_uid_zero_keep_their_original_passthrough() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    let mut dns = event(&live, 14, 5);
    dns.row.protocol = L7Protocol::DNS;
    assert_eq!(rows(queue.inject_item(dns))[0].seq, 5);
    assert_eq!(rows(queue.inject_item(event(&live, 0, 2)))[0].seq, 2);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn disabled_protocol_data_never_enters_a_different_protocols_existing_socket_state() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(32, 100);
    assert!(queue.inject_item(event(&live, 19, 1)).is_empty());
    let mut dns = event(&live, 19, 5);
    dns.row.protocol = L7Protocol::DNS;
    assert_eq!(rows(queue.inject_item(dns))[0].seq, 5);
    let result = rows(queue.inject_item(event(&live, 19, 0)));
    assert_eq!(
        result.iter().map(|row| row.seq).collect::<Vec<_>>(),
        vec![0, 1]
    );
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn item_and_byte_pressure_fail_closed_instead_of_releasing_a_partial_flow() {
    let live = Arc::new(AtomicUsize::new(0));
    let mut queue = reorder(2, 100);
    for seq in 1..=3 {
        assert!(queue.inject_item(event(&live, 15, seq)).is_empty());
    }
    assert_eq!(live.load(Ordering::SeqCst), 0);
    assert!(queue.inject_item(event(&live, 15, 0)).is_empty());
    let mut huge = event(&live, 16, 1);
    huge.bytes = (1 << 20) + 1;
    assert!(queue.inject_item(huge).is_empty());
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn reconfigure_and_drop_release_gaps_without_counter_source_closure() {
    let live = Arc::new(AtomicUsize::new(0));
    let counter = Arc::new(ReorderCounter::default());
    let observed = StatsReorderCounter::new(counter.clone());
    let mut queue = Reorder::new(
        Box::new(MysqlOnly(true)),
        counter,
        32,
        Duration::from_millis(100),
    );
    assert!(queue.inject_item(event(&live, 17, 2)).is_empty());
    assert!(queue
        .reconfigure(Box::new(MysqlOnly(false)), 32, Duration::from_millis(100))
        .is_empty());
    assert_eq!(live.load(Ordering::SeqCst), 0);
    assert!(!observed.closed());
    assert_eq!(rows(queue.inject_item(event(&live, 17, 3)))[0].seq, 3);
    assert!(queue
        .reconfigure(Box::new(MysqlOnly(true)), 32, Duration::from_millis(100))
        .is_empty());
    assert!(queue.inject_item(event(&live, 18, 2)).is_empty());
    assert_eq!(live.load(Ordering::SeqCst), 1);
    drop(queue);
    assert_eq!(live.load(Ordering::SeqCst), 0);
    assert!(observed.closed());
}
