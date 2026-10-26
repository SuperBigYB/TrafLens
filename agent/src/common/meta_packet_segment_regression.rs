// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::*;

fn packet(payload: &[u8], logical_len: u16, padding: usize) -> MetaPacket<'static> {
    let mut raw = vec![0u8; 54];
    raw[..12].copy_from_slice(&[2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1]);
    raw[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    raw[14] = 0x45;
    raw[16..18].copy_from_slice(&(40 + logical_len).to_be_bytes());
    raw[22] = 64;
    raw[23] = 6;
    raw[26..34].copy_from_slice(&[198, 18, 0, 1, 198, 18, 0, 2]);
    raw[34..36].copy_from_slice(&40000u16.to_be_bytes());
    raw[36..38].copy_from_slice(&18080u16.to_be_bytes());
    raw[38..42].copy_from_slice(&100u32.to_be_bytes());
    raw[46] = 0x50;
    raw[47] = 0x10;
    raw.extend_from_slice(payload);
    raw.resize(raw.len() + padding, 0);
    let size = raw.len();
    let mut packet = MetaPacket::empty();
    // Capture headers may carry unfinished offload checksums, as on the live path.
    packet
        .update(raw, true, false, Duration::from_secs(1), size)
        .unwrap();
    packet.into_owned()
}

#[test]
fn segment_snapshot_preserves_metadata_and_restarts_its_parse_view() {
    let mut original = packet(b"abc", 3, 0);
    original.gpid_0 = 11;
    original.gpid_1 = 12;
    original.pod_id = 13;
    original.second_in_minute = 14;
    original.vlan = 123;
    original.raw_payload_len = 2;
    original.sub_packet_index = 1;
    original.tunnel = Some(TunnelInfo {
        id: 42,
        tier: 1,
        ..Default::default()
    });
    let snapshot = original
        .to_owned_segment()
        .into_any()
        .downcast::<MetaPacket>()
        .unwrap();
    assert_eq!(
        (snapshot.gpid_0, snapshot.gpid_1, snapshot.pod_id),
        (11, 12, 13)
    );
    assert_eq!(
        (
            snapshot.second_in_minute,
            snapshot.vlan,
            snapshot.raw_payload_len
        ),
        (14, 123, 2)
    );
    assert_eq!(snapshot.tunnel, original.tunnel);
    assert_eq!(snapshot.sub_packet_index, 0);
    assert_eq!(original.sub_packet_index, 1);
    assert_eq!(
        snapshot.raw.as_ref().unwrap().to_vec(),
        original.raw.as_ref().unwrap().to_vec()
    );
}

#[test]
fn segment_sequence_wrap_and_direction_are_reversible() {
    let mut packet = packet(b"abc", 3, 0);
    let ProtocolData::TcpHeader(header) = &mut packet.protocol_data else {
        unreachable!()
    };
    header.seq = u32::MAX - 1;
    assert_eq!(packet.next_tcp_seq(), 1);
    let direction = packet.lookup_key.direction;
    packet.reverse_direction();
    assert_ne!(packet.lookup_key.direction, direction);
    packet.reverse_direction();
    assert_eq!(packet.lookup_key.direction, direction);
}

#[test]
fn padding_does_not_become_tcp_data_between_two_segments() {
    let mut packet = packet(b"a", 1, 5);
    assert_eq!(packet.get_payload(), b"a");
    packet.merge_segments(b"bc");
    assert_eq!(packet.get_payload(), b"abc");
    assert_eq!(packet.get_l4_payload().unwrap(), b"abc");
    assert_eq!(
        (
            packet.payload_len,
            packet.l4_payload_len,
            packet.raw_payload_len
        ),
        (3, 3, 1)
    );
    assert_eq!(
        packet.packet_len as usize,
        packet.raw.as_ref().unwrap().len()
    );
    assert_eq!(packet.packet_len, 57);
}

#[test]
fn empty_and_snaplen_payloads_are_safe_and_cannot_be_extended_across_a_gap() {
    let empty = MetaPacket::empty();
    assert!(empty.get_payload().is_empty());
    assert!(empty.to_owned_segment().get_payload().is_empty());
    let mut short = packet(b"a", 3, 0);
    let before = short.raw.as_ref().unwrap().to_vec();
    assert_eq!(short.get_payload(), b"a");
    short.merge_segments(b"bc");
    assert_eq!(short.raw.as_ref().unwrap().to_vec(), before);
    assert_eq!((short.payload_len, short.l4_payload_len), (3, 3));
}

#[test]
fn invalid_metadata_lengths_reject_before_mutating_bytes() {
    for field in 0..3 {
        let mut packet = packet(b"a", 1, 0);
        match field {
            0 => packet.payload_len = u16::MAX,
            1 => packet.packet_len = u32::MAX,
            _ => packet.l4_payload_len = u16::MAX,
        }
        let before = packet.raw.as_ref().unwrap().to_vec();
        let lengths = (packet.packet_len, packet.payload_len, packet.l4_payload_len);
        packet.merge_segments(b"b");
        assert_eq!(packet.raw.as_ref().unwrap().to_vec(), before);
        assert_eq!(
            (packet.packet_len, packet.payload_len, packet.l4_payload_len),
            lengths
        );
    }
}

#[test]
fn retained_memory_counts_capacity_and_control_flags_form_boundaries() {
    let mut packet = packet(b"abc", 3, 0);
    let initial = packet.memory_size();
    let RawPacket::OwnedVec(raw) = packet.raw.as_mut().unwrap() else {
        unreachable!()
    };
    let old_capacity = raw.capacity();
    raw.reserve(4096);
    let new_capacity = raw.capacity();
    assert!(new_capacity > old_capacity);
    assert_eq!(packet.memory_size() - initial, new_capacity - old_capacity);
    assert!(!packet.is_control());
    for flag in [TcpFlags::SYN, TcpFlags::FIN, TcpFlags::RST] {
        let ProtocolData::TcpHeader(header) = &mut packet.protocol_data else {
            unreachable!()
        };
        header.flags = flag | TcpFlags::ACK;
        assert!(packet.is_control());
    }
}
