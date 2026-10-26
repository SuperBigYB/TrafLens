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

// Wire formats: draft-ietf-nvo3-vxlan-gpe-13 sections 3/4 and RFC 8300 section 2.
// https://www.ietf.org/archive/id/draft-ietf-nvo3-vxlan-gpe-13.html
// https://www.rfc-editor.org/rfc/rfc8300.html
const ETHERNET_LEN: usize = 14;

/// Return an inner Ethernet offset relative to the outer IP header and the VNI.
///
/// Ethernet payloads are left intact. For a raw IP payload, the fourteen bytes
/// immediately before it become an Ethernet header using the outer MACs. All
/// checks precede the sole write, so failure leaves the packet unchanged.
/// Supports IPv4/UDP transport, Ethernet or raw IPv4/IPv6, and one NSH layer.
/// OAM, unknown next protocols and outer IP fragments are not decoded.
/// Captured payload may be shorter than IP/UDP lengths (snaplen), but every
/// header used here must be captured and fit within the declared datagram.
pub fn decapsulate_gpe_vxlan(packet: &mut [u8], l2_len: usize) -> Option<(usize, u32)> {
    if l2_len < ETHERNET_LEN {
        return None;
    }
    let ip = packet.get(l2_len..)?;
    let ihl = ipv4_header_len(ip)?;
    if ip[9] != 17 || u16::from_be_bytes([ip[6], ip[7]]) & 0x3fff != 0 {
        return None;
    }
    let total_len = u16::from_be_bytes([ip[2], ip[3]]) as usize;
    let udp = ip.get(ihl..ip.len().min(total_len))?;
    let header = udp.get(..16)?;
    let udp_len = u16::from_be_bytes([header[4], header[5]]) as usize;
    if u16::from_be_bytes([header[2], header[3]]) != 4790
        || udp_len < 16
        || udp_len > total_len - ihl
    {
        return None;
    }
    let flags = header[8];
    // Ignore receive-reserved bits; BUM is valid. OAM needs a separate parser.
    if flags & 0x08 == 0 || flags & 0x30 != 0 || flags & 0x01 != 0 {
        return None;
    }
    let vni = u32::from_be_bytes([0, header[12], header[13], header[14]]);
    let mut next_protocol = header[11];
    if flags & 0x04 == 0 {
        if next_protocol != 0 {
            return None;
        }
        next_protocol = 3;
    }
    let datagram = udp.get(..udp.len().min(udp_len))?;
    let mut inner = 16;
    if next_protocol == 4 {
        let nsh = datagram.get(inner..)?;
        let base = nsh.get(..8)?;
        // Unsupported version and OAM; unassigned bits are ignored on receipt.
        if base[0] & 0xc0 != 0 || base[0] & 0x20 != 0 {
            return None;
        }
        let nsh_len = ((base[1] & 0x3f) as usize) * 4;
        match base[2] & 0x0f {
            1 if nsh_len == 24 => {}
            2 if nsh_len >= 8 => {
                let metadata = nsh.get(8..nsh_len)?;
                let mut pos = 0;
                while pos < metadata.len() {
                    let tlv = metadata.get(pos..pos + 4)?;
                    let value_len = (tlv[3] & 0x7f) as usize;
                    pos += 4 + ((value_len + 3) & !3);
                    if pos > metadata.len() {
                        return None;
                    }
                }
            }
            _ => return None,
        }
        // Also check fixed metadata capture and the declared UDP boundary.
        nsh.get(..nsh_len)?;
        inner = inner.checked_add(nsh_len)?;
        next_protocol = base[3];
    }
    let payload = datagram.get(inner..)?;
    let declared_payload_len = udp_len.checked_sub(inner)?;
    let absolute_inner = l2_len.checked_add(ihl)?.checked_add(inner)?;
    let ether_type = match next_protocol {
        1 => {
            let header_len = ipv4_header_len(payload)?;
            let ip_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
            if header_len > declared_payload_len || ip_len > declared_payload_len {
                return None;
            }
            [0x08, 0x00]
        }
        2 => {
            let header = payload.get(..40)?;
            let ip_len = 40 + u16::from_be_bytes([header[4], header[5]]) as usize;
            if header[0] >> 4 != 6 || ip_len > declared_payload_len {
                return None;
            }
            [0x86, 0xdd]
        }
        3 => {
            payload.get(..ETHERNET_LEN)?;
            if declared_payload_len < ETHERNET_LEN {
                return None;
            }
            return Some((absolute_inner.checked_sub(l2_len)?, vni));
        }
        _ => return None,
    };
    let ethernet_start = absolute_inner.checked_sub(ETHERNET_LEN)?;
    let mut ethernet = [0; ETHERNET_LEN];
    ethernet[..12].copy_from_slice(packet.get(..12)?);
    ethernet[12..].copy_from_slice(&ether_type);
    let offset = ethernet_start.checked_sub(l2_len)?;
    packet
        .get_mut(ethernet_start..absolute_inner)?
        .copy_from_slice(&ethernet);
    Some((offset, vni))
}

// Check header capture and IPv4 option lengths, but permit a snaplen-truncated
// payload. Checksums are not checked because capture offload may leave them unset.
fn ipv4_header_len(ip: &[u8]) -> Option<usize> {
    let base = ip.get(..20)?;
    let ihl = ((base[0] & 0x0f) as usize) * 4;
    if base[0] >> 4 != 4 || ihl < 20 {
        return None;
    }
    let header = ip.get(..ihl)?;
    if (u16::from_be_bytes([base[2], base[3]]) as usize) < ihl {
        return None;
    }
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
    Some(ihl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip4(payload_len: usize, options: &[u8]) -> Vec<u8> {
        assert_eq!(options.len() % 4, 0);
        let mut ip = vec![0; 20 + options.len()];
        ip[0] = 0x45 + (options.len() / 4) as u8;
        let total_len = (ip.len() + payload_len) as u16;
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..20].copy_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]);
        ip[20..].copy_from_slice(options);
        ip
    }

    fn ipv4() -> Vec<u8> {
        let mut ip = ip4(12, &[]);
        ip[9] = 6;
        ip.extend_from_slice(&[0x5a; 12]);
        ip
    }

    fn ipv6() -> Vec<u8> {
        let mut ip = vec![0; 48];
        ip[0] = 0x60;
        ip[4..6].copy_from_slice(&8u16.to_be_bytes());
        ip[6] = 17;
        ip[7] = 64;
        ip[40..].fill(0xa5);
        ip
    }

    fn ethernet() -> Vec<u8> {
        let mut frame = vec![0x44; 14];
        frame[12..14].copy_from_slice(&[8, 0]);
        frame.extend_from_slice(&ipv4());
        frame
    }

    fn nsh(md_type: u8, next: u8, metadata: &[u8]) -> Vec<u8> {
        assert_eq!(metadata.len() % 4, 0);
        let mut nsh = vec![
            0x0f,
            0xc2 + (metadata.len() / 4) as u8,
            md_type,
            next,
            0x12,
            0x34,
            0x56,
            0xff,
        ];
        nsh.extend_from_slice(metadata);
        nsh
    }

    fn packet(options: &[u8], flags: u8, next: u8, payload: &[u8]) -> Vec<u8> {
        let udp_len = 16 + payload.len();
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 8, 0];
        frame.extend_from_slice(&ip4(udp_len, options));
        frame.extend_from_slice(&[0x13, 0x88, 0x12, 0xb6]);
        frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
        frame.extend_from_slice(&[0, 0, flags, 0, 0, next, 0x12, 0xab, 0xcd, 0]);
        frame.extend_from_slice(payload);
        frame
    }

    fn unchanged_none(mut frame: Vec<u8>, l2_len: usize) {
        let before = frame.clone();
        assert_eq!(decapsulate_gpe_vxlan(&mut frame, l2_len), None);
        assert_eq!(frame, before);
    }

    #[test]
    fn independent_direct_protocol_vectors() {
        for (next, payload, expected, ether_type) in [
            (1, ipv4(), 22, [8, 0]),
            (2, ipv6(), 22, [0x86, 0xdd]),
            (3, ethernet(), 36, [8, 0]),
        ] {
            let mut frame = packet(&[], 0x0c, next, &payload);
            let before = frame.clone();
            assert_eq!(
                decapsulate_gpe_vxlan(&mut frame, 14),
                Some((expected, 0x12abcd))
            );
            if next == 3 {
                assert_eq!(frame, before);
            } else {
                let start = 14 + expected;
                assert_eq!(&frame[start..start + 12], &before[..12]);
                assert_eq!(&frame[start + 12..start + 14], &ether_type);
                assert_eq!(&frame[start + 14..], &payload);
                assert_eq!(&frame[..start], &before[..start]);
            }
        }
    }

    #[test]
    fn independent_nsh_metadata_vectors() {
        let metadata_cases = [
            (1, vec![0x55; 16]),
            (2, vec![]),
            // Two TLVs, including a non-word-sized value and nonzero padding.
            (2, vec![0, 1, 2, 0x83, 1, 2, 3, 0xff, 0, 2, 3, 0]),
        ];
        for (md_type, metadata) in metadata_cases {
            for (next, payload) in [(1, ipv4()), (2, ipv6()), (3, ethernet())] {
                let mut inner = nsh(md_type | 0xa0, next, &metadata);
                inner.extend_from_slice(&payload);
                let mut frame = packet(&[1, 1, 0, 0], 0xce, 4, &inner);
                // Receive-reserved flags/fields are ignored, BUM is supported.
                frame[14 + 24 + 9] = 0x77;
                let expected = 24 + 16 + 8 + metadata.len() - if next == 3 { 0 } else { 14 };
                assert_eq!(
                    decapsulate_gpe_vxlan(&mut frame, 14),
                    Some((expected, 0x12abcd))
                );
            }
        }
    }

    #[test]
    fn legacy_p_zero_is_ethernet_only() {
        let mut frame = packet(&[], 0x08, 0, &ethernet());
        let before = frame.clone();
        assert_eq!(decapsulate_gpe_vxlan(&mut frame, 14), Some((36, 0x12abcd)));
        assert_eq!(frame, before);
        unchanged_none(packet(&[], 0x08, 3, &ethernet()), 14);
    }

    #[test]
    fn every_header_prefix_fails_without_mutation_payload_snaplen_succeeds() {
        for (next, payload, header_len) in [(1, ipv4(), 20), (2, ipv6(), 40), (3, ethernet(), 14)] {
            let mut inner = nsh(2, next, &[0, 1, 2, 1, 3, 0, 0, 0]);
            inner.extend_from_slice(&payload);
            let frame = packet(&[1, 1, 0, 0], 0x0c, 4, &inner);
            let minimum = 14 + 24 + 16 + 16 + header_len;
            for end in 0..minimum {
                unchanged_none(frame[..end].to_vec(), 14);
            }
            for end in minimum..=frame.len() {
                let mut captured = frame[..end].to_vec();
                assert!(
                    decapsulate_gpe_vxlan(&mut captured, 14).is_some(),
                    "{next}/{end}"
                );
            }
        }
    }

    #[test]
    fn rejects_invalid_flags_protocol_and_nsh_lengths_transactionally() {
        for flags in [0, 4, 0x09, 0x0d, 0x18, 0x28, 0x38] {
            unchanged_none(packet(&[], flags, 1, &ipv4()), 14);
        }
        for next in [0, 5, 0x7e, 0x80, 0xff] {
            unchanged_none(packet(&[], 0x0c, next, &ipv4()), 14);
        }
        for (byte, value) in [
            (0, 0x40),
            (0, 0x20),
            (1, 0xc1),
            (1, 0xc5),
            (2, 0),
            (2, 3),
            (3, 4),
            (3, 0),
        ] {
            let mut inner = nsh(1, 1, &[0; 16]);
            inner[byte] = value;
            inner.extend_from_slice(&ipv4());
            unchanged_none(packet(&[], 0x0c, 4, &inner), 14);
        }
        // An MD2 TLV whose padded value crosses the declared NSH boundary.
        let mut inner = nsh(2, 1, &[0, 1, 2, 5, 0, 0, 0, 0]);
        inner.extend_from_slice(&ipv4());
        unchanged_none(packet(&[], 0x0c, 4, &inner), 14);
    }

    #[test]
    fn rejects_envelope_and_inner_mismatches_without_mutation() {
        let valid = packet(&[1, 1, 0, 0], 0x0c, 1, &ipv4());
        for (at, value) in [
            (14, 0x44),
            (14, 0x65),
            (23, 47),
            (20, 0x20),
            (21, 1),
            (34, 0x44),
            (35, 0x44),
            (40, 0x11),
            (41, 0xb5),
            (42, 1),
            (43, 15),
            (54, 0x60),
        ] {
            let mut bad = valid.clone();
            bad[at] = value;
            unchanged_none(bad, 14);
        }
        let mut bad = valid.clone();
        bad[16..18].copy_from_slice(&24u16.to_be_bytes());
        unchanged_none(bad, 14);
        let mut bad = valid.clone();
        bad[42..44].copy_from_slice(&200u16.to_be_bytes());
        unchanged_none(bad, 14);
        let mut bad = valid.clone();
        // Inner declared IP length exceeds the logical UDP payload.
        bad[56..58].copy_from_slice(&200u16.to_be_bytes());
        unchanged_none(bad, 14);
        unchanged_none(valid.clone(), usize::MAX);
        unchanged_none(valid, 13);
    }

    #[test]
    fn vlan_outer_and_inner_ipv4_options_preserve_payload() {
        let mut inner = ip4(12, &[0x82, 4, 0xaa, 0xbb]);
        inner.extend_from_slice(&[0x55; 12]);
        let mut frame = packet(&[0x82, 4, 0xcc, 0xdd], 0x0c, 1, &inner);
        frame.splice(12..14, [0x81, 0, 0, 7, 8, 0]);
        let before = frame.clone();
        assert_eq!(decapsulate_gpe_vxlan(&mut frame, 18), Some((26, 0x12abcd)));
        assert_eq!(&frame[58..], &inner);
        assert_eq!(&frame[44..56], &before[..12]);
        let mut bad_inner = inner;
        bad_inner[21] = 1;
        unchanged_none(packet(&[], 0x0c, 1, &bad_inner), 14);
    }

    #[test]
    fn ipv6_version_and_logical_length_are_checked() {
        let mut bad = ipv6();
        bad[0] = 0x40;
        unchanged_none(packet(&[], 0x0c, 2, &bad), 14);
        let mut bad = ipv6();
        bad[4..6].copy_from_slice(&100u16.to_be_bytes());
        unchanged_none(packet(&[], 0x0c, 2, &bad), 14);
    }

    #[test]
    fn ethernet_padding_cannot_supply_missing_declared_headers() {
        let mut frame = packet(&[], 0x0c, 1, &ipv4());
        frame[38..40].copy_from_slice(&16u16.to_be_bytes());
        unchanged_none(frame, 14);
    }
}
