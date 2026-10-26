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

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use public::packet::Downcast;

/// An owned packet carrier. Implementations must preserve their concrete type
/// when appending payload, because the Agent downcasts returned packets.
///
/// memory_size includes the carrier and its owned dynamic allocations. It must
/// stay stable while cached; reverse_direction only flips direction metadata.
pub trait Segment: Downcast + Send {
    fn is_c2s(&self) -> bool;
    fn get_tcp_seq(&self) -> u32;
    fn next_tcp_seq(&self) -> u32;
    fn merge_segments(&mut self, other: &[u8]);
    fn get_payload(&self) -> &[u8];
    fn get_payload_length(&self) -> u16;
    fn reverse_direction(&mut self);
    fn memory_size(&self) -> usize;
    fn is_control(&self) -> bool {
        false
    }
}

const MAX_CARRIER_BYTES: usize = 64 * 1024;
const DEFAULT_RETAINED_BYTES: usize = 64 * 1024 * 1024;

struct Budget {
    limit: usize,
    used: AtomicUsize,
}

impl Budget {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    fn reserve(self: &Arc<Self>, bytes: usize) -> Option<Reservation> {
        if bytes == 0 || bytes > MAX_CARRIER_BYTES {
            return None;
        }
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let next = used.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(Reservation {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(current) => used = current,
            }
        }
    }
}

struct Reservation {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct Cached {
    segment: Box<dyn Segment>,
    reservation: Reservation,
}

impl Cached {
    fn into_segment(self) -> Box<dyn Segment> {
        let Self {
            segment,
            reservation,
        } = self;
        // Once returned for parsing, a packet is no longer retained in a slot.
        drop(reservation);
        segment
    }
}

static RETAINED_BUDGET: LazyLock<Arc<Budget>> =
    LazyLock::new(|| Arc::new(Budget::new(DEFAULT_RETAINED_BYTES)));

/// Bounded, same-direction two-packet sliding parsing windows.
///
/// This follows the public configuration's consecutive-packet contract:
/// https://github.com/deepflowio/deepflow/blob/main/server/agent_config/example.yaml
/// For p1,p2,p3, inject emits p1+p2 and p2+p3, and flush returns original p3.
/// Window bytes intentionally overlap. This is not an ordered TCP stream or an
/// application-message framer; gaps, overlaps and retransmissions are not joined.
/// All sequence additions wrap modulo 2^32 (RFC 9293 section 3.4).
pub struct PacketSegmentationReassembly {
    pending: [Option<Cached>; 2],
    newest_direction: usize,
    budget: Arc<Budget>,
}

impl Default for PacketSegmentationReassembly {
    fn default() -> Self {
        Self::with_budget(Arc::clone(&RETAINED_BUDGET))
    }
}

impl PacketSegmentationReassembly {
    fn with_budget(budget: Arc<Budget>) -> Self {
        Self {
            pending: [None, None],
            newest_direction: 0,
            budget,
        }
    }

    pub fn does_support() -> bool {
        true
    }

    pub fn reverse(&mut self) {
        for cached in self.pending.iter_mut().flatten() {
            cached.segment.reverse_direction();
        }
        self.pending.swap(0, 1);
        self.newest_direction ^= 1;
    }

    pub fn flush(&mut self) -> Option<Vec<Box<dyn Segment>>> {
        let mut output = Vec::new();
        // Keep the cached packets' arrival order across the two directions.
        for direction in [self.newest_direction ^ 1, self.newest_direction] {
            if let Some(cached) = self.pending[direction].take() {
                output.push(cached.into_segment());
            }
        }
        if output.is_empty() {
            None
        } else {
            Some(output)
        }
    }

    pub fn inject(&mut self, segment: Box<dyn Segment>) -> Option<Vec<Box<dyn Segment>>> {
        if segment.is_control() {
            let direction = usize::from(!segment.is_c2s());
            let mut output = Vec::with_capacity(2);
            if let Some(cached) = self.pending[direction].take() {
                output.push(cached.into_segment());
            }
            output.push(segment);
            return Some(output);
        }
        let current_len = segment.get_payload_length();
        if current_len == 0 {
            // ACK/control carriers may have no captured payload at all. Never
            // inspect their payload, and do not interrupt a data lookahead slot.
            return Some(vec![segment]);
        }

        let direction = usize::from(!segment.is_c2s());
        let previous = self.pending[direction].take().map(Cached::into_segment);
        let Some(reservation) = self.budget.reserve(segment.memory_size()) else {
            // Neither carrier has been modified. Preserve all input on a size
            // or shared-budget failure; never hide bytes to satisfy the limit.
            let mut output = Vec::with_capacity(2);
            if let Some(previous) = previous {
                output.push(previous);
            }
            output.push(segment);
            return Some(output);
        };

        let mut output = None;
        if let Some(mut previous) = previous {
            let previous_len = previous.get_payload_length();
            if usize::from(previous_len) + usize::from(current_len) <= usize::from(u16::MAX)
                && previous.next_tcp_seq() == segment.get_tcp_seq()
                && previous.get_payload().len() == usize::from(previous_len)
                && segment.get_payload().len() == usize::from(current_len)
            {
                previous.merge_segments(segment.get_payload());
            }
            output = Some(vec![previous]);
        }

        // Retain the original current carrier, never the merged parsing window.
        self.pending[direction] = Some(Cached {
            segment,
            reservation,
        });
        self.newest_direction = direction;
        output
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::mem::size_of;

    use super::*;

    struct TestSegment {
        id: u32,
        c2s: bool,
        seq: u32,
        logical_len: u16,
        payload: Vec<u8>,
        padding: Vec<u8>,
        forbid_payload: bool,
        control: bool,
        reverse_calls: usize,
    }

    impl TestSegment {
        fn new(id: u32, c2s: bool, seq: u32, payload: &[u8]) -> Self {
            Self {
                id,
                c2s,
                seq,
                logical_len: u16::try_from(payload.len()).unwrap(),
                payload: payload.to_vec(),
                padding: Vec::new(),
                forbid_payload: false,
                control: false,
                reverse_calls: 0,
            }
        }

        fn boxed(self) -> Box<dyn Segment> {
            Box::new(self)
        }
    }

    impl Downcast for TestSegment {
        fn as_any_mut(&mut self) -> &mut dyn Any {
            self
        }

        fn into_any(self: Box<Self>) -> Box<dyn Any> {
            self
        }
    }

    impl Segment for TestSegment {
        fn is_c2s(&self) -> bool {
            self.c2s
        }

        fn get_tcp_seq(&self) -> u32 {
            self.seq
        }

        fn next_tcp_seq(&self) -> u32 {
            self.seq.wrapping_add(u32::from(self.logical_len))
        }

        fn merge_segments(&mut self, other: &[u8]) {
            self.payload.extend_from_slice(other);
            self.logical_len = u16::try_from(self.payload.len()).unwrap();
        }

        fn get_payload(&self) -> &[u8] {
            assert!(!self.forbid_payload, "control payload was inspected");
            &self.payload
        }

        fn get_payload_length(&self) -> u16 {
            self.logical_len
        }

        fn reverse_direction(&mut self) {
            self.c2s = !self.c2s;
            self.reverse_calls += 1;
        }

        fn memory_size(&self) -> usize {
            size_of::<Self>() + self.payload.capacity() + self.padding.capacity()
        }

        fn is_control(&self) -> bool {
            self.control
        }
    }

    fn budget(limit: usize) -> Arc<Budget> {
        Arc::new(Budget::new(limit))
    }

    fn engine() -> PacketSegmentationReassembly {
        PacketSegmentationReassembly::with_budget(budget(1024 * 1024))
    }

    fn unpack(value: Option<Vec<Box<dyn Segment>>>) -> Vec<Box<TestSegment>> {
        value
            .unwrap()
            .into_iter()
            .map(|segment| segment.into_any().downcast::<TestSegment>().unwrap())
            .collect()
    }

    fn retained(budget: &Budget) -> usize {
        budget.used.load(Ordering::Acquire)
    }

    #[test]
    fn three_packets_produce_two_overlapping_windows_and_original_tail() {
        let mut reassembly = engine();
        assert!(reassembly
            .inject(TestSegment::new(1, true, 100, &vec![2; 1448]).boxed())
            .is_none());
        let first =
            unpack(reassembly.inject(TestSegment::new(2, true, 1548, &vec![0x2c; 1448]).boxed()));
        assert_eq!(first.len(), 1);
        assert_eq!(
            (first[0].id, first[0].seq, first[0].logical_len),
            (1, 100, 2896)
        );
        assert_eq!((first[0].payload[1447], first[0].payload[1448]), (2, 0x2c));

        let second =
            unpack(reassembly.inject(TestSegment::new(3, true, 2996, &vec![0x7e; 1448]).boxed()));
        assert_eq!(
            (second[0].id, second[0].seq, second[0].logical_len),
            (2, 1548, 2896)
        );
        assert_eq!(
            (second[0].payload[1447], second[0].payload[1448]),
            (0x2c, 0x7e)
        );
        let tail = unpack(reassembly.flush());
        assert_eq!(
            (tail[0].id, tail[0].seq, tail[0].logical_len),
            (3, 2996, 1448)
        );
        assert!(tail[0].payload.iter().all(|byte| *byte == 0x7e));
        assert!(reassembly.flush().is_none());
    }

    #[test]
    fn first_data_packet_waits_and_empty_flush_is_idempotent() {
        let mut reassembly = engine();
        assert!(reassembly.flush().is_none());
        assert!(reassembly
            .inject(TestSegment::new(1, true, 8, b"abc").boxed())
            .is_none());
        let output = unpack(reassembly.flush());
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].payload, b"abc");
        assert!(reassembly.flush().is_none());
    }

    #[test]
    fn gap_overlap_and_retransmission_preserve_both_original_packets() {
        for (seq, bytes) in [
            (90, b"xyz".as_slice()),
            (100, b"abc".as_slice()),
            (101, b"xyz".as_slice()),
            (104, b"xyz".as_slice()),
        ] {
            let mut reassembly = engine();
            reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
            let previous = unpack(reassembly.inject(TestSegment::new(2, true, seq, bytes).boxed()));
            assert_eq!((previous[0].id, previous[0].logical_len), (1, 3));
            assert_eq!(previous[0].payload, b"abc");
            let current = unpack(reassembly.flush());
            assert_eq!((current[0].id, current[0].seq), (2, seq));
            assert_eq!(current[0].payload, bytes);
        }
    }

    #[test]
    fn adjacent_sequence_numbers_wrap_at_u32_max() {
        for (start, first, second) in [
            (u32::MAX, b"a".as_slice(), b"b".as_slice()),
            (u32::MAX - 2, b"abcd".as_slice(), b"efg".as_slice()),
        ] {
            let mut reassembly = engine();
            reassembly.inject(TestSegment::new(1, true, start, first).boxed());
            let seq = start.wrapping_add(first.len() as u32);
            let output = unpack(reassembly.inject(TestSegment::new(2, true, seq, second).boxed()));
            assert_eq!(output[0].seq, start);
            assert_eq!(output[0].payload, [first, second].concat());
        }
    }

    #[test]
    fn truncated_or_padded_capture_is_never_concatenated() {
        for (previous_len, current_len) in [(5, 3), (3, 5), (2, 3), (3, 2)] {
            let mut reassembly = engine();
            let mut previous = TestSegment::new(1, true, 100, b"abc");
            previous.logical_len = previous_len;
            let mut current = TestSegment::new(2, true, 100 + previous_len as u32, b"def");
            current.logical_len = current_len;
            reassembly.inject(previous.boxed());
            let output = unpack(reassembly.inject(current.boxed()));
            assert_eq!(output[0].payload, b"abc");
            assert_eq!(output[0].logical_len, previous_len);
            assert_eq!(unpack(reassembly.flush())[0].payload, b"def");
        }
    }

    #[test]
    fn exact_u16_payload_limit_can_merge_without_retaining_the_window() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, true, 100, &vec![1; 32767]).boxed());
        let output =
            unpack(reassembly.inject(TestSegment::new(2, true, 32867, &vec![2; 32768]).boxed()));
        assert_eq!(output[0].logical_len, u16::MAX);
        assert_eq!(output[0].payload.len(), usize::from(u16::MAX));
        assert_eq!(unpack(reassembly.flush())[0].logical_len, 32768);
    }

    #[test]
    fn merging_above_u16_limit_returns_unmodified_previous_and_current() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, true, 100, &vec![1; 32768]).boxed());
        let output =
            unpack(reassembly.inject(TestSegment::new(2, true, 32868, &vec![2; 32768]).boxed()));
        assert_eq!(output[0].logical_len, 32768);
        assert!(output[0].payload.iter().all(|byte| *byte == 1));
        assert_eq!(unpack(reassembly.flush())[0].logical_len, 32768);
    }

    #[test]
    fn directions_have_independent_lookahead_and_flush_keeps_arrival_order() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, false, 50, b"rsp").boxed());
        reassembly.inject(TestSegment::new(2, true, 100, b"req").boxed());
        let request = unpack(reassembly.inject(TestSegment::new(3, true, 103, b"uest").boxed()));
        assert_eq!(request[0].payload, b"request");
        let remaining = unpack(reassembly.flush());
        assert_eq!(remaining.iter().map(|s| s.id).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(remaining[0].payload, b"rsp");
        assert_eq!(remaining[1].payload, b"uest");
    }

    #[test]
    fn pure_acks_pass_immediately_without_reading_payload_or_interrupting_data() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
        for (id, c2s) in [(2, true), (3, false)] {
            let mut control = TestSegment::new(id, c2s, u32::MAX, b"");
            control.forbid_payload = true;
            let output = unpack(reassembly.inject(control.boxed()));
            assert_eq!((output[0].id, output[0].logical_len), (id, 0));
        }
        let output = unpack(reassembly.inject(TestSegment::new(4, true, 103, b"def").boxed()));
        assert_eq!(output[0].payload, b"abcdef");
        assert_eq!(unpack(reassembly.flush())[0].id, 4);
    }

    #[test]
    fn controls_flush_only_their_direction_and_are_never_cached() {
        for payload in [b"".as_slice(), b"control-data".as_slice()] {
            let shared = budget(1024 * 1024);
            let mut reassembly = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
            reassembly.inject(TestSegment::new(1, true, 100, b"req").boxed());
            reassembly.inject(TestSegment::new(2, false, 50, b"rsp").boxed());
            let response_bytes = TestSegment::new(2, false, 50, b"rsp").memory_size();
            let mut control = TestSegment::new(3, true, 103, payload);
            control.control = true;
            control.forbid_payload = true;
            let output = unpack(reassembly.inject(control.boxed()));
            assert_eq!(output.iter().map(|s| s.id).collect::<Vec<_>>(), [1, 3]);
            assert_eq!(output[0].payload, b"req");
            assert_eq!(output[1].payload, payload);
            assert_eq!(retained(&shared), response_bytes);
            let remaining = unpack(reassembly.flush());
            assert_eq!(remaining.len(), 1);
            assert_eq!(remaining[0].id, 2);
            assert_eq!(retained(&shared), 0);
        }
    }

    #[test]
    fn control_without_pending_packet_is_a_single_original_passthrough() {
        let mut reassembly = engine();
        let mut control = TestSegment::new(1, true, u32::MAX, b"syn-data");
        control.control = true;
        control.forbid_payload = true;
        let output = unpack(reassembly.inject(control.boxed()));
        assert_eq!(output.len(), 1);
        assert_eq!(output[0].payload, b"syn-data");
        assert!(reassembly.flush().is_none());
    }

    #[test]
    fn reverse_flips_carriers_and_swaps_direction_slots() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
        reassembly.reverse();
        let output = unpack(reassembly.inject(TestSegment::new(2, false, 103, b"def").boxed()));
        assert_eq!(output[0].payload, b"abcdef");
        assert!(!output[0].c2s);
        assert_eq!(output[0].reverse_calls, 1);
        assert!(!unpack(reassembly.flush())[0].c2s);
    }

    #[test]
    fn two_reversals_restore_both_directions_and_flush_order() {
        let mut reassembly = engine();
        reassembly.inject(TestSegment::new(1, false, 50, b"rsp").boxed());
        reassembly.inject(TestSegment::new(2, true, 100, b"req").boxed());
        reassembly.reverse();
        reassembly.reverse();
        let output = unpack(reassembly.flush());
        assert_eq!(
            output.iter().map(|s| (s.id, s.c2s)).collect::<Vec<_>>(),
            [(1, false), (2, true)]
        );
        assert_eq!((output[0].reverse_calls, output[1].reverse_calls), (2, 2));
    }

    #[test]
    fn raw_capture_above_carrier_cap_passes_without_retention() {
        let shared = budget(1024 * 1024);
        let mut reassembly = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
        let mut oversized = TestSegment::new(2, true, 103, b"def");
        oversized.padding = vec![0; MAX_CARRIER_BYTES];
        let output = unpack(reassembly.inject(oversized.boxed()));
        assert_eq!(output.iter().map(|s| s.id).collect::<Vec<_>>(), [1, 2]);
        assert_eq!(output[0].payload, b"abc");
        assert_eq!(output[1].payload, b"def");
        assert_eq!(retained(&shared), 0);
        assert!(reassembly.flush().is_none());
    }

    #[test]
    fn exact_carrier_cap_is_allowed_and_flush_releases_reservation() {
        let shared = budget(MAX_CARRIER_BYTES);
        let mut reassembly = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        let mut segment = TestSegment::new(1, true, 1, b"abc");
        let padding = MAX_CARRIER_BYTES - segment.memory_size();
        segment.padding = vec![0; padding];
        assert_eq!(segment.memory_size(), MAX_CARRIER_BYTES);
        assert!(reassembly.inject(segment.boxed()).is_none());
        assert_eq!(retained(&shared), MAX_CARRIER_BYTES);
        assert_eq!(unpack(reassembly.flush())[0].payload, b"abc");
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn shared_budget_exhaustion_passes_current_without_retaining_it() {
        let first = TestSegment::new(1, true, 100, b"abc");
        let bytes = first.memory_size();
        let shared = budget(bytes);
        let mut left = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        let mut right = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        left.inject(first.boxed());
        let output = unpack(right.inject(TestSegment::new(2, true, 100, b"xyz").boxed()));
        assert_eq!(output[0].id, 2);
        assert!(right.flush().is_none());
        assert_eq!(retained(&shared), bytes);
        drop(left);
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn replacement_budget_failure_returns_both_unmodified_carriers() {
        let first = TestSegment::new(1, true, 100, b"abc");
        let bytes = first.memory_size();
        let shared = budget(2 * bytes);
        let mut left = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        let mut right = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        left.inject(first.boxed());
        right.inject(TestSegment::new(2, true, 100, b"xyz").boxed());
        let output = unpack(left.inject(TestSegment::new(3, true, 103, b"longer").boxed()));
        assert_eq!(output.iter().map(|s| s.id).collect::<Vec<_>>(), [1, 3]);
        assert_eq!(output[0].payload, b"abc");
        assert_eq!(output[1].payload, b"longer");
        assert_eq!(retained(&shared), bytes);
        assert!(left.flush().is_none());
        drop(right);
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn replacing_cached_carrier_releases_old_bytes_before_reserving_current() {
        let bytes = TestSegment::new(1, true, 100, b"abc").memory_size();
        let shared = budget(bytes);
        let mut reassembly = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
        let output = unpack(reassembly.inject(TestSegment::new(2, true, 103, b"def").boxed()));
        assert_eq!(output[0].payload, b"abcdef");
        assert_eq!(retained(&shared), bytes);
        assert_eq!(unpack(reassembly.flush())[0].payload, b"def");
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn reverse_never_changes_retained_bytes_and_drop_releases_both_slots() {
        let shared = budget(1024 * 1024);
        let mut reassembly = PacketSegmentationReassembly::with_budget(Arc::clone(&shared));
        reassembly.inject(TestSegment::new(1, true, 100, b"abc").boxed());
        reassembly.inject(TestSegment::new(2, false, 50, b"response").boxed());
        let bytes = retained(&shared);
        assert!(bytes > 0);
        reassembly.reverse();
        assert_eq!(retained(&shared), bytes);
        reassembly.reverse();
        assert_eq!(retained(&shared), bytes);
        drop(reassembly);
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn concurrent_budget_reservations_never_exceed_limit_or_leak() {
        let shared = budget(256);
        let threads = (0..8)
            .map(|_| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        if let Some(held) = shared.reserve(64) {
                            assert!(retained(&shared) <= 256);
                            drop(held);
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().unwrap();
        }
        assert_eq!(retained(&shared), 0);
    }

    #[test]
    fn default_instances_share_process_budget_and_remain_send() {
        fn assert_send<T: Send>() {}
        assert_send::<PacketSegmentationReassembly>();
        let left = PacketSegmentationReassembly::default();
        let right = PacketSegmentationReassembly::default();
        assert!(Arc::ptr_eq(&left.budget, &right.budget));
        assert_eq!(left.budget.limit, DEFAULT_RETAINED_BYTES);
        assert!(PacketSegmentationReassembly::does_support());
    }
}
