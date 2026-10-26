// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Layout references: RFC 2784 with verified erratum 3719, RFC 2890, and
// Cisco's draft-foschiano-erspan-03 sections 3 and 4 (an expired I-D, not an RFC).

const CHECKSUM: u16 = 0x8000;
const ROUTING: u16 = 0x4000;
const KEY: u16 = 0x2000;
const SEQUENCE: u16 = 0x1000;
const STRICT_SOURCE_ROUTE: u16 = 0x0800;
const VERSION: u16 = 0x0007;
const ERSPAN_II_LE: u16 = 0xbe88;
const ERSPAN_III_LE: u16 = 0xeb22;
const TEB_LE: u16 = 0x5865;
const ETHERNET_HEADER_LEN: usize = 14;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct GreHeader {
    // Both offsets are relative to the outer IP header, not the frame start.
    pub(crate) payload_offset: usize,
    pub(crate) payload_end: usize,
    // Logical IP length may exceed payload_end in a snaplen-truncated capture.
    pub(crate) ip_total_len: usize,
    pub(crate) key: Option<u32>,
}

fn be16(data: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(
        data.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn be32(data: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes(
        data.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn valid_ipv4_options(options: &[u8]) -> bool {
    let mut offset = 0;
    while offset < options.len() {
        match options[offset] {
            0 => return true, // EOL: remaining header bytes are padding.
            1 => offset += 1, // NOP has no length octet.
            _ => {
                let Some(&length) = options.get(offset + 1) else {
                    return false;
                };
                if length < 2 || usize::from(length) > options.len() - offset {
                    return false;
                }
                offset += usize::from(length);
            }
        }
    }
    true
}

// Flags are a big-endian decoded value. protocol_le follows the existing
// Agent caller's little-endian EtherType enum, independently of host endian.
// Version one is an explicit Tencent compatibility opt-in, not generic PPTP.
// This is a passive capture parser: checksums may be pending TX offload.
pub(crate) fn parse_gre(
    packet: &[u8],
    l2_len: usize,
    flags: u16,
    protocol_le: u16,
    ip_header_size: usize,
    allow_version_one: bool,
) -> Option<GreHeader> {
    let ip = packet.get(l2_len..)?;
    let fixed = ip.get(..20)?;
    let ihl = usize::from(fixed[0] & 0x0f) * 4;
    if fixed[0] >> 4 != 4 || ihl < 20 || ihl != ip_header_size || fixed[9] != 47 {
        return None;
    }
    // A non-initial fragment does not start with a GRE header. First fragments
    // can still expose the complete tunnel and inner header, like a snaplen cut.
    if be16(fixed, 6)? & 0x1fff != 0 {
        return None;
    }
    let ip_total_len = usize::from(be16(fixed, 2)?);
    let payload_end = ip_total_len.min(ip.len());
    let ip = ip.get(..payload_end)?;
    if !valid_ipv4_options(ip.get(20..ihl)?) {
        return None;
    }
    let mut offset = ihl.checked_add(4)?;
    let base = ip.get(ihl..offset)?;
    if be16(base, 0)? != flags || u16::from_le_bytes([base[2], base[3]]) != protocol_le {
        return None;
    }
    let version = flags & VERSION;
    if (version != 0 && !(allow_version_one && version == 1))
        || flags & (ROUTING | STRICT_SOURCE_ROUTE) != 0
    {
        return None;
    }
    // RFC 2784 erratum 3719: bits 5..12 are ignored by receivers. Their old
    // recursion/flags interpretations do not add fields in this GRE profile.
    if flags & CHECKSUM != 0 {
        ip.get(offset..offset.checked_add(4)?)?;
        offset += 4; // Checksum followed by Reserved1; neither changes layout.
    }
    let key = if flags & KEY != 0 {
        let value = be32(ip, offset)?;
        offset += 4;
        Some(value)
    } else {
        None
    };
    if flags & SEQUENCE != 0 {
        ip.get(offset..offset.checked_add(4)?)?;
        offset += 4;
    }
    Some(GreHeader {
        payload_offset: offset,
        payload_end,
        ip_total_len,
        key,
    })
}

pub(crate) fn decapsulate_teb(
    packet: &[u8],
    l2_len: usize,
    flags: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    let gre = parse_gre(packet, l2_len, flags, TEB_LE, ip_header_size, false)?;
    if gre.payload_offset.checked_add(ETHERNET_HEADER_LEN)? > gre.payload_end {
        return None;
    }
    Some((gre.payload_offset, gre.key.unwrap_or_default()))
}

pub(crate) fn decapsulate_erspan(
    packet: &[u8],
    l2_len: usize,
    flags: u16,
    gre_protocol_type: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    if !matches!(gre_protocol_type, ERSPAN_II_LE | ERSPAN_III_LE) {
        return None;
    }
    // Cisco's ERSPAN GRE profile uses S only. Reserved receiver-ignored bits
    // remain ignored, but C/K are not part of any supported ERSPAN format.
    let options = flags & (CHECKSUM | KEY | SEQUENCE);
    if options & (CHECKSUM | KEY) != 0 {
        return None;
    }
    let gre = parse_gre(
        packet,
        l2_len,
        flags,
        gre_protocol_type,
        ip_header_size,
        false,
    )?;
    let ip = packet.get(l2_len..)?.get(..gre.payload_end)?;
    let mut offset = gre.payload_offset;
    let session = if options == 0 && gre_protocol_type == ERSPAN_II_LE {
        0 // Type I has neither sequence nor ERSPAN feature header.
    } else {
        if options != SEQUENCE {
            return None;
        }
        let (length, version) = if gre_protocol_type == ERSPAN_II_LE {
            (8, 1)
        } else {
            (12, 2)
        };
        let end = offset.checked_add(length)?;
        let header = ip.get(offset..end)?;
        if header[0] >> 4 != version {
            return None;
        }
        let session = u32::from(be16(header, 2)? & 0x03ff);
        if version == 1 {
            if be32(header, 4)? & 0xfff0_0000 != 0 {
                return None;
            }
        } else {
            // This caller requires an Ethernet payload. FT=2 carries a raw
            // IP packet and cannot be exposed as Ethernet without rebuilding it.
            if (header[10] >> 2) & 0x1f != 0 {
                return None;
            }
        }
        offset = end;
        if version == 2 && header[11] & 1 != 0 {
            let end = offset.checked_add(8)?;
            ip.get(offset..end)?; // Fixed-width platform metadata stays opaque.
            offset = end;
        }
        session
    };
    if offset.checked_add(ETHERNET_HEADER_LEN)? > gre.payload_end {
        return None;
    }
    Some((offset, session))
}

#[cfg(test)]
mod tests {
    use super::*;

    const INNER: [u8; 14] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x08, 0x00,
    ];

    fn frame(l2: usize, ihl: usize, flags: u16, protocol: u16, payload: &[u8]) -> Vec<u8> {
        let mut ip = vec![0u8; ihl];
        ip[0] = 0x40 | (ihl / 4) as u8;
        ip[8] = 64;
        ip[9] = 47;
        ip.extend_from_slice(&flags.to_be_bytes());
        ip.extend_from_slice(&protocol.to_be_bytes());
        if flags & CHECKSUM != 0 {
            ip.extend_from_slice(&[0xca, 0xfe, 0xba, 0xbe]);
        }
        if flags & KEY != 0 {
            ip.extend_from_slice(&0x1234_5678u32.to_be_bytes());
        }
        if flags & SEQUENCE != 0 {
            ip.extend_from_slice(&0x8765_4321u32.to_be_bytes());
        }
        ip.extend_from_slice(payload);
        let length = ip.len() as u16;
        ip[2..4].copy_from_slice(&length.to_be_bytes());
        let mut packet = vec![0u8; l2];
        packet.extend_from_slice(&ip);
        packet
    }

    fn erspan_header(version: u8, session: u16, optional: bool) -> Vec<u8> {
        let mut header = vec![0u8; if version == 1 { 8 } else { 12 }];
        header[0] = version << 4;
        header[2..4].copy_from_slice(&(0xb800 | (session & 0x03ff)).to_be_bytes());
        if version == 1 {
            header[5..8].copy_from_slice(&[0x0a, 0xbc, 0xde]);
        } else {
            header[4..8].copy_from_slice(&0x1122_3344u32.to_be_bytes());
            header[8..10].copy_from_slice(&0x5566u16.to_be_bytes());
            header[10] = 0x80; // P=1; FT=Ethernet.
            header[11] = 0xfc | u8::from(optional); // Hw/D/Gra do not change size.
            if optional {
                header.extend_from_slice(&[0xfc, 1, 2, 3, 4, 5, 6, 7]);
            }
        }
        header
    }

    #[test]
    fn teb_all_checksum_key_sequence_layouts_and_ipv4_options() {
        for flags in [
            0,
            CHECKSUM,
            KEY,
            SEQUENCE,
            CHECKSUM | KEY,
            CHECKSUM | SEQUENCE,
            KEY | SEQUENCE,
            CHECKSUM | KEY | SEQUENCE,
        ] {
            for ihl in [20, 24, 60] {
                let packet = frame(18, ihl, flags, 0x6558, &INNER);
                let options = flags.count_ones() as usize * 4;
                assert_eq!(
                    decapsulate_teb(&packet, 18, flags, ihl),
                    Some((
                        ihl + 4 + options,
                        if flags & KEY != 0 { 0x1234_5678 } else { 0 }
                    ))
                );
            }
        }
    }

    #[test]
    fn ipv4_options_obey_tlv_lengths_and_eol_padding() {
        for options in [
            [1, 1, 0, 0],
            [0x94, 4, 0, 0],
            [0x82, 3, 7, 0],
            [0, 0x82, 1, 0xff],
        ] {
            let mut packet = frame(14, 24, KEY, 0x6558, &INNER);
            packet[34..38].copy_from_slice(&options);
            assert_eq!(
                decapsulate_teb(&packet, 14, KEY, 24),
                Some((32, 0x1234_5678))
            );
        }
        for options in [
            [0x82, 1, 0, 0],
            [0x82, 0, 0, 0],
            [0x82, 5, 0, 0],
            [1, 1, 1, 0x82],
            [1, 0x82, 4, 0],
        ] {
            let mut packet = frame(14, 24, KEY, 0x6558, &INNER);
            packet[34..38].copy_from_slice(&options);
            assert_eq!(decapsulate_teb(&packet, 14, KEY, 24), None, "{options:x?}");
        }
    }

    #[test]
    fn erspan_type_i_ii_iii_wire_vectors() {
        let type_i = frame(18, 20, 0, 0x88be, &INNER);
        assert_eq!(
            decapsulate_erspan(&type_i, 18, 0, ERSPAN_II_LE, 20),
            Some((24, 0))
        );
        for (version, protocol, id, optional, offset) in [
            (1, 0x88be, 0x3ff, false, 36),
            (2, 0x22eb, 0x2aa, false, 40),
            (2, 0x22eb, 0x155, true, 48),
        ] {
            let mut payload = erspan_header(version, id, optional);
            payload.extend_from_slice(&INNER);
            let packet = frame(14, 20, SEQUENCE, protocol, &payload);
            assert_eq!(
                decapsulate_erspan(&packet, 14, SEQUENCE, protocol.swap_bytes(), 20),
                Some((offset, u32::from(id)))
            );
        }
    }

    #[test]
    fn every_required_header_and_ethernet_truncation_is_rejected() {
        let mut vectors = vec![(frame(14, 20, 0, 0x88be, &INNER), 0, ERSPAN_II_LE)];
        for (version, protocol, optional) in
            [(1, 0x88beu16, false), (2, 0x22eb, false), (2, 0x22eb, true)]
        {
            let mut payload = erspan_header(version, 123, optional);
            payload.extend_from_slice(&INNER);
            vectors.push((
                frame(14, 20, SEQUENCE, protocol, &payload),
                SEQUENCE,
                protocol.swap_bytes(),
            ));
        }
        for (packet, flags, protocol) in vectors {
            for length in 0..packet.len() {
                assert_eq!(
                    decapsulate_erspan(&packet[..length], 14, flags, protocol, 20),
                    None,
                    "ERSPAN cut={length} flags={flags:#x}"
                );
            }
        }
        for flags in [0, CHECKSUM, KEY, SEQUENCE, CHECKSUM | KEY | SEQUENCE] {
            let packet = frame(14, 20, flags, 0x6558, &INNER);
            for length in 0..packet.len() {
                assert_eq!(
                    decapsulate_teb(&packet[..length], 14, flags, 20),
                    None,
                    "TEB cut={length} flags={flags:#x}"
                );
            }
        }
    }

    #[test]
    fn snaplen_truncation_after_inner_header_is_accepted() {
        let mut payload = erspan_header(2, 321, true);
        payload.extend_from_slice(&INNER);
        payload.extend_from_slice(&[0x77; 64]);
        let packet = frame(14, 20, SEQUENCE, 0x22eb, &payload);
        for length in 14 + 48 + 14..=packet.len() {
            assert_eq!(
                decapsulate_erspan(&packet[..length], 14, SEQUENCE, ERSPAN_III_LE, 20),
                Some((48, 321))
            );
        }
        let packet = frame(14, 20, CHECKSUM | KEY | SEQUENCE, 0x6558, &[0x44; 100]);
        for length in 14 + 36 + 14..=packet.len() {
            let header = parse_gre(
                &packet[..length],
                14,
                CHECKSUM | KEY | SEQUENCE,
                TEB_LE,
                20,
                false,
            )
            .unwrap();
            assert_eq!(header.ip_total_len, packet.len() - 14);
            assert_eq!(header.payload_end, length - 14);
            assert_eq!(
                decapsulate_teb(&packet[..length], 14, CHECKSUM | KEY | SEQUENCE, 20),
                Some((36, 0x1234_5678))
            );
        }
    }

    #[test]
    fn ignores_receiver_reserved_gre_bits_including_erratum_bit_five() {
        for bit in 3..=10 {
            let flags = (1u16 << bit) | KEY;
            let packet = frame(14, 20, flags, 0x6558, &INNER);
            assert_eq!(
                decapsulate_teb(&packet, 14, flags, 20),
                Some((28, 0x1234_5678))
            );
            let packet = frame(14, 20, 1u16 << bit, 0x88be, &INNER);
            assert_eq!(
                decapsulate_erspan(&packet, 14, 1u16 << bit, ERSPAN_II_LE, 20),
                Some((24, 0))
            );
        }
    }

    #[test]
    fn rejects_routing_ssr_and_versions_without_tencent_opt_in() {
        for flags in [ROUTING, STRICT_SOURCE_ROUTE, 1, 2, 3, 4, 5, 6, 7] {
            let packet = frame(14, 20, flags, 0x6558, &INNER);
            assert_eq!(decapsulate_teb(&packet, 14, flags, 20), None);
            let packet = frame(14, 20, flags, 0x88be, &INNER);
            assert_eq!(
                decapsulate_erspan(&packet, 14, flags, ERSPAN_II_LE, 20),
                None
            );
        }
        let packet = frame(14, 20, KEY | SEQUENCE | 1, 0x0800, &INNER);
        assert!(parse_gre(&packet, 14, KEY | SEQUENCE | 1, 0x0008, 20, true).is_some());
        assert!(parse_gre(&packet, 14, KEY | SEQUENCE | 1, 0x0008, 20, false).is_none());
    }

    #[test]
    fn rejects_mismatched_arguments_wrong_ipv4_and_noninitial_fragments() {
        let packet = frame(14, 20, KEY, 0x6558, &INNER);
        assert_eq!(decapsulate_teb(&packet, 14, 0, 20), None);
        assert_eq!(decapsulate_teb(&packet, 14, KEY, 24), None);
        assert!(parse_gre(&packet, 14, KEY, 0x6558, 20, false).is_none());
        for (index, value) in [(14, 0x65), (14, 0x44), (23, 17), (21, 1)] {
            let mut bad = packet.clone();
            bad[index] = value;
            assert_eq!(decapsulate_teb(&bad, 14, KEY, 20), None, "byte={index}");
        }
        assert_eq!(decapsulate_teb(&packet, usize::MAX, KEY, 20), None);
        assert_eq!(decapsulate_teb(&packet, 14, KEY, usize::MAX), None);
        let mut first_fragment = packet.clone();
        first_fragment[20] = 0x20;
        assert_eq!(
            decapsulate_teb(&first_fragment, 14, KEY, 20),
            Some((28, 0x1234_5678))
        );
    }

    #[test]
    fn ipv4_logical_end_does_not_borrow_ethernet_padding() {
        let mut packet = frame(14, 20, KEY, 0x6558, &INNER);
        let shorter = (packet.len() - 14 - 1) as u16;
        packet[16..18].copy_from_slice(&shorter.to_be_bytes());
        packet.extend_from_slice(&[0; 64]);
        assert_eq!(decapsulate_teb(&packet, 14, KEY, 20), None);
        for length in [0u16, 19, 20, 23] {
            packet[16..18].copy_from_slice(&length.to_be_bytes());
            assert_eq!(decapsulate_teb(&packet, 14, KEY, 20), None);
        }
    }

    #[test]
    fn erspan_rejects_wrong_profile_version_and_non_ethernet_frame_type() {
        for flags in [CHECKSUM, KEY, CHECKSUM | SEQUENCE, KEY | SEQUENCE] {
            let packet = frame(14, 20, flags, 0x88be, &INNER);
            assert_eq!(
                decapsulate_erspan(&packet, 14, flags, ERSPAN_II_LE, 20),
                None
            );
        }
        let mut payload = erspan_header(1, 123, false);
        payload.extend_from_slice(&INNER);
        let mut packet = frame(14, 20, SEQUENCE, 0x88be, &payload);
        packet[42] = 0x20;
        assert_eq!(
            decapsulate_erspan(&packet, 14, SEQUENCE, ERSPAN_II_LE, 20),
            None
        );
        packet[42] = 0x10;
        packet[46] = 0x80;
        assert_eq!(
            decapsulate_erspan(&packet, 14, SEQUENCE, ERSPAN_II_LE, 20),
            None
        );
        for frame_type in [1, 2, 3, 31] {
            let mut payload = erspan_header(2, 123, false);
            payload[10] = frame_type << 2;
            payload.extend_from_slice(&INNER);
            let packet = frame(14, 20, SEQUENCE, 0x22eb, &payload);
            assert_eq!(
                decapsulate_erspan(&packet, 14, SEQUENCE, ERSPAN_III_LE, 20),
                None
            );
        }
        let packet = frame(14, 20, 0, 0x22eb, &INNER);
        assert_eq!(decapsulate_erspan(&packet, 14, 0, ERSPAN_III_LE, 20), None);
    }

    fn pcap_packets(data: &[u8]) -> Vec<&[u8]> {
        assert_eq!(&data[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
        let mut offset = 24;
        let mut packets = Vec::new();
        while offset < data.len() {
            let size =
                u32::from_le_bytes(data[offset + 8..offset + 12].try_into().unwrap()) as usize;
            offset += 16;
            packets.push(&data[offset..offset + size]);
            offset += size;
        }
        packets
    }

    #[test]
    fn existing_pcap_frames_match_protocol_offsets_and_ids() {
        let type_i = pcap_packets(include_bytes!(
            "../../../resources/test/common/decapsulate_erspan1.pcap"
        ));
        for packet in &type_i[..2] {
            assert_eq!(
                decapsulate_erspan(packet, 18, 0, ERSPAN_II_LE, 20),
                Some((24, 0))
            );
        }
        let erspan = pcap_packets(include_bytes!(
            "../../../resources/test/common/decapsulate_test.pcap"
        ));
        for packet in &erspan[..2] {
            assert_eq!(
                decapsulate_erspan(packet, 14, SEQUENCE, ERSPAN_II_LE, 20),
                Some((36, 100))
            );
        }
        assert_eq!(
            decapsulate_erspan(erspan[3], 14, SEQUENCE, ERSPAN_III_LE, 20),
            Some((40, 0))
        );
        let teb = pcap_packets(include_bytes!(
            "../../../resources/test/common/vmware-gre-teb.pcap"
        ));
        assert_eq!(
            decapsulate_teb(teb[2], 14, KEY, 20),
            Some((28, 0x0200_0000))
        );
    }

    #[test]
    fn malformed_vectors_never_panic_or_escape_capture_bounds() {
        let valid = frame(14, 20, CHECKSUM | KEY | SEQUENCE, 0x6558, &INNER);
        for index in 0..valid.len() {
            for value in [0u8, 1, 0xff] {
                let mut packet = valid.clone();
                packet[index] = value;
                for l2 in [0, 1, 14, usize::MAX] {
                    if let Some((offset, _)) =
                        decapsulate_teb(&packet, l2, CHECKSUM | KEY | SEQUENCE, 20)
                    {
                        assert!(l2
                            .checked_add(offset)
                            .and_then(|n| n.checked_add(14))
                            .is_some_and(|end| end <= packet.len()));
                    }
                    let _ = decapsulate_erspan(&packet, l2, SEQUENCE, ERSPAN_III_LE, 20);
                }
            }
        }
    }
}
