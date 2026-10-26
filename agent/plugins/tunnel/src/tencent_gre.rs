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

use crate::gre::parse_gre;

const ETHERNET_LEN: usize = 14;

/// Decode the keyed Tencent GRE layout, including its private version-one form.
///
/// Flags are host-order values read big-endian; protocol is the caller's
/// little-endian EtherType (0x0008/0xdd86). The returned offset is relative to
/// outer L3 and points to a synthetic Ethernet header immediately before the
/// inner IP header. Key halves become MAC suffixes, matching the existing Go
/// decoder and FastPath pseudo-MAC contract in server/libs/datatype/decapsulate.go.
///
/// This write can overlap outer IPv4 addresses: callers must save outer metadata
/// before calling and only commit it after success. Failure never changes bytes.
/// Header capture is required, while a snaplen-truncated payload is permitted.
pub fn decapsulate_tencent_gre(
    packet: &mut [u8],
    l2_len: usize,
    flags: u16,
    gre_protocol_type: u16,
    ip_header_size: usize,
) -> Option<(usize, u32)> {
    if l2_len < ETHERNET_LEN {
        return None;
    }
    let gre = parse_gre(
        packet,
        l2_len,
        flags,
        gre_protocol_type,
        ip_header_size,
        true,
    )?;
    let key = gre.key?;
    let inner_start = l2_len.checked_add(gre.payload_offset)?;
    let captured_end = l2_len.checked_add(gre.payload_end)?;
    let inner = packet.get(inner_start..captured_end)?;
    let declared_len = gre.ip_total_len.checked_sub(gre.payload_offset)?;
    let ether_type = match gre_protocol_type {
        0x0008 => {
            ipv4_header(inner, declared_len)?;
            [0x08, 0x00]
        }
        0xdd86 => {
            let ip = inner.get(..40)?;
            if ip[0] >> 4 != 6 || 40 + u16::from_be_bytes([ip[4], ip[5]]) as usize > declared_len {
                return None;
            }
            [0x86, 0xdd]
        }
        _ => return None,
    };
    let offset = gre.payload_offset.checked_sub(ETHERNET_LEN)?;
    let ethernet_start = l2_len.checked_add(offset)?;
    let key_bytes = key.to_be_bytes();
    let mut ethernet = [0; ETHERNET_LEN];
    ethernet[4..6].copy_from_slice(&key_bytes[2..4]);
    ethernet[10..12].copy_from_slice(&key_bytes[..2]);
    ethernet[12..].copy_from_slice(&ether_type);
    // No fallible validation is performed after this sole packet mutation.
    packet
        .get_mut(ethernet_start..inner_start)?
        .copy_from_slice(&ethernet);
    Some((offset, key))
}

fn ipv4_header(ip: &[u8], declared_len: usize) -> Option<()> {
    let base = ip.get(..20)?;
    let ihl = ((base[0] & 0x0f) as usize) * 4;
    let total_len = u16::from_be_bytes([base[2], base[3]]) as usize;
    if base[0] >> 4 != 4 || ihl < 20 || total_len < ihl || total_len > declared_len {
        return None;
    }
    let header = ip.get(..ihl)?;
    let mut pos = 20;
    while pos < ihl {
        match header[pos] {
            0 => break,
            1 => pos += 1,
            _ => {
                let len = *header.get(pos + 1)? as usize;
                if len < 2 || len > ihl - pos {
                    return None;
                }
                pos += len;
            }
        }
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: u32 = 0x1234_abcd;

    fn ipv4(options: &[u8], payload_len: usize) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let ihl = 20 + options.len();
        let mut ip = vec![0; ihl];
        ip[0] = 0x45 + (options.len() / 4) as u8;
        ip[2..4].copy_from_slice(&((ihl + payload_len) as u16).to_be_bytes());
        ip[8] = 64;
        ip[9] = 6;
        ip[12..20].copy_from_slice(&[10, 1, 2, 3, 10, 4, 5, 6]);
        ip[20..].copy_from_slice(options);
        ip.extend_from_slice(&vec![0x5a; payload_len]);
        ip
    }

    fn ipv6() -> Vec<u8> {
        let mut ip = vec![0; 48];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
        ip[6] = 17;
        ip[7] = 64;
        ip[40..].fill(0x55);
        ip
    }

    fn packet(options: &[u8], flags: u16, protocol: u16, inner: &[u8]) -> Vec<u8> {
        let mut gre = Vec::from(flags.to_be_bytes());
        gre.extend_from_slice(&protocol.to_le_bytes());
        if flags & 0x8000 != 0 {
            gre.extend_from_slice(&[0x12, 0x34, 0, 0]);
        }
        if flags & 0x2000 != 0 {
            gre.extend_from_slice(&KEY.to_be_bytes());
        }
        if flags & 0x1000 != 0 {
            gre.extend_from_slice(&0x89ab_cdefu32.to_be_bytes());
        }
        gre.extend_from_slice(inner);
        let mut frame = vec![0; 14];
        frame[12..14].copy_from_slice(&[8, 0]);
        let mut ip = ipv4(options, gre.len());
        ip[9] = 47;
        ip.truncate(20 + options.len());
        frame.extend_from_slice(&ip);
        frame.extend_from_slice(&gre);
        frame
    }

    fn assert_none(mut frame: Vec<u8>, l2_len: usize, flags: u16, protocol: u16, ihl: usize) {
        let before = frame.clone();
        assert_eq!(
            decapsulate_tencent_gre(&mut frame, l2_len, flags, protocol, ihl),
            None
        );
        assert_eq!(frame, before);
    }

    #[test]
    fn independent_optional_fields_versions_and_inner_protocols() {
        for flags in [
            0x2000, 0x3000, 0xa000, 0xb000, 0x2001, 0x3001, 0xa001, 0xb001,
        ] {
            for options in [vec![], vec![1, 1, 0, 0], vec![0x82, 4, 0xaa, 0xbb]] {
                for (protocol, inner, ether_type) in [
                    (0x0008, ipv4(&[1, 1, 0, 0], 12), [8, 0]),
                    (0xdd86, ipv6(), [0x86, 0xdd]),
                ] {
                    let mut frame = packet(&options, flags, protocol, &inner);
                    let before = frame.clone();
                    let ihl = 20 + options.len();
                    let optional = if flags & 0x8000 != 0 { 4 } else { 0 }
                        + if flags & 0x1000 != 0 { 4 } else { 0 };
                    let expected = ihl + 8 + optional - 14;
                    assert_eq!(
                        decapsulate_tencent_gre(&mut frame, 14, flags, protocol, ihl),
                        Some((expected, KEY))
                    );
                    let start = 14 + expected;
                    assert_eq!(&frame[start..start + 6], &[0, 0, 0, 0, 0xab, 0xcd]);
                    assert_eq!(&frame[start + 6..start + 12], &[0, 0, 0, 0, 0x12, 0x34]);
                    assert_eq!(&frame[start + 12..start + 14], &ether_type);
                    assert_eq!(&frame[start + 14..], &inner);
                    assert_eq!(&frame[..start], &before[..start]);
                }
            }
        }
    }

    #[test]
    fn every_header_prefix_is_transactional_payload_snaplen_is_supported() {
        for flags in [0x2000, 0x3001, 0xa000, 0xb001] {
            for (protocol, inner, inner_header_len) in
                [(0x0008, ipv4(&[1, 1, 0, 0], 12), 24), (0xdd86, ipv6(), 40)]
            {
                let frame = packet(&[1, 1, 0, 0], flags, protocol, &inner);
                let minimum = frame.len() - inner.len() + inner_header_len;
                for end in 0..minimum {
                    assert_none(frame[..end].to_vec(), 14, flags, protocol, 24);
                }
                for end in minimum..=frame.len() {
                    let mut captured = frame[..end].to_vec();
                    assert!(
                        decapsulate_tencent_gre(&mut captured, 14, flags, protocol, 24).is_some(),
                        "{flags:#x}/{protocol:#x}/{end}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_unsupported_flags_and_protocols_without_mutation() {
        for flags in [0, 0x1000, 0x8000, 0x6000, 0x2800, 0x2002, 0x2007] {
            assert_none(
                packet(&[], flags, 0x0008, &ipv4(&[], 0)),
                14,
                flags,
                0x0008,
                20,
            );
        }
        for protocol in [0x0800, 0x86dd, 0x5865, 0, 0xffff] {
            assert_none(
                packet(&[], 0x2000, protocol, &ipv4(&[], 0)),
                14,
                0x2000,
                protocol,
                20,
            );
        }
        // RFC 2784 erratum 3719: bits 5..12, not 6..12, are receive-ignored.
        for reserved in [0x0008, 0x0010, 0x0080, 0x0400, 0x07f8] {
            let flags = 0x2000 | reserved;
            let mut frame = packet(&[], flags, 0x0008, &ipv4(&[], 0));
            assert_eq!(
                decapsulate_tencent_gre(&mut frame, 14, flags, 0x0008, 20),
                Some((14, KEY))
            );
        }
    }

    #[test]
    fn rejects_caller_arguments_envelope_and_inner_disagreement() {
        let frame = packet(&[1, 1, 0, 0], 0xb001, 0x0008, &ipv4(&[1, 1, 0, 0], 12));
        assert_none(frame.clone(), 14, 0x3001, 0x0008, 24);
        assert_none(frame.clone(), 14, 0xb001, 0xdd86, 24);
        assert_none(frame.clone(), 14, 0xb001, 0x0008, 20);
        assert_none(frame.clone(), usize::MAX, 0xb001, 0x0008, 24);
        assert_none(frame.clone(), 13, 0xb001, 0x0008, 24);
        // Outer IPv4 IHL/version, fragment, protocol, malformed option length;
        // inner version/IHL/options and declared length.
        for (at, value) in [
            (14, 0x44),
            (14, 0x66),
            (21, 1),
            (23, 17),
            (34, 0x82),
            (35, 0x82),
            (54, 0x60),
            (54, 0x44),
            (74, 0x82),
            (75, 0x82),
        ] {
            let mut bad = frame.clone();
            bad[at] = value;
            assert_none(bad, 14, 0xb001, 0x0008, 24);
        }
        for (at, len) in [(16, 20u16), (16, 40), (56, 20), (56, 100)] {
            let mut bad = frame.clone();
            bad[at..at + 2].copy_from_slice(&len.to_be_bytes());
            assert_none(bad, 14, 0xb001, 0x0008, 24);
        }
        let mut v6_bad = packet(&[], 0x2000, 0xdd86, &ipv6());
        v6_bad[14 + 28] = 0x40;
        assert_none(v6_bad, 14, 0x2000, 0xdd86, 20);
        let mut v6_bad = packet(&[], 0x2000, 0xdd86, &ipv6());
        v6_bad[14 + 28 + 4..14 + 28 + 6].copy_from_slice(&100u16.to_be_bytes());
        assert_none(v6_bad, 14, 0x2000, 0xdd86, 20);
    }

    #[test]
    fn full_width_and_zero_keys_preserve_the_fastpath_mac_contract() {
        for key in [0u32, 0x0001_0285, 0xffff_ffff] {
            let mut frame = packet(&[], 0x3001, 0x0008, &ipv4(&[], 0));
            frame[38..42].copy_from_slice(&key.to_be_bytes());
            assert_eq!(
                decapsulate_tencent_gre(&mut frame, 14, 0x3001, 0x0008, 20),
                Some((18, key))
            );
            let bytes = key.to_be_bytes();
            assert_eq!(&frame[32..38], &[0, 0, 0, 0, bytes[2], bytes[3]]);
            assert_eq!(&frame[38..44], &[0, 0, 0, 0, bytes[0], bytes[1]]);
        }
    }

    #[test]
    fn vlan_outer_offset_is_relative_to_its_full_l2_header() {
        let inner = ipv4(&[], 12);
        let mut frame = packet(&[], 0x2000, 0x0008, &inner);
        frame.splice(12..14, [0x81, 0, 0, 7, 8, 0]);
        assert_eq!(
            decapsulate_tencent_gre(&mut frame, 18, 0x2000, 0x0008, 20),
            Some((14, KEY))
        );
        assert_eq!(&frame[46..], &inner);
    }

    #[test]
    fn ethernet_padding_cannot_complete_logically_short_datagram() {
        let mut frame = packet(&[], 0x3001, 0x0008, &ipv4(&[], 12));
        frame[16..18].copy_from_slice(&40u16.to_be_bytes());
        assert_none(frame, 14, 0x3001, 0x0008, 20);
    }
}
