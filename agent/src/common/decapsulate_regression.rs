// SPDX-License-Identifier: Apache-2.0

use super::*;

fn bitmap() -> TunnelTypeBitmap {
    TunnelTypeBitmap::new(&vec![
        TunnelType::Vxlan,
        TunnelType::VxlanNsh,
        TunnelType::Geneve,
        TunnelType::Ipip,
        TunnelType::Erspan,
        TunnelType::Teb,
        TunnelType::TencentGre,
    ])
}

fn ethernet(l2: usize, ip_type: u16) -> Vec<u8> {
    let mut packet = vec![0; l2];
    packet[..6].copy_from_slice(&[2, 0, 0, 0, 0, 1]);
    packet[6..12].copy_from_slice(&[2, 0, 0, 0, 0, 2]);
    if l2 > 14 {
        for offset in (12..l2 - 2).step_by(4) {
            packet[offset..offset + 2].copy_from_slice(&0x8100u16.to_be_bytes());
        }
    }
    packet[l2 - 2..].copy_from_slice(&ip_type.to_be_bytes());
    packet
}

fn ipv4(l2: usize, header: usize, protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = ethernet(l2, 0x0800);
    let mut ip = vec![0; header];
    ip[0] = 0x40 | (header / 4) as u8;
    ip[2..4].copy_from_slice(&((header + payload.len()) as u16).to_be_bytes());
    ip[8] = 64;
    ip[9] = protocol;
    ip[12..16].copy_from_slice(&[10, 1, 2, 3]);
    ip[16..20].copy_from_slice(&[10, 4, 5, 6]);
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(payload);
    packet
}

fn ipv6(protocol: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = ethernet(14, 0x86dd);
    let mut ip = [0; 40];
    ip[0] = 0x60;
    ip[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    ip[6] = protocol;
    ip[7] = 64;
    ip[8] = 0xfe;
    ip[9] = 0x80;
    ip[23] = 1;
    ip[24] = 0xfe;
    ip[25] = 0x80;
    ip[39] = 2;
    packet.extend_from_slice(&ip);
    packet.extend_from_slice(payload);
    packet
}

fn udp(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut udp = vec![0x9c, 0x40];
    udp.extend_from_slice(&port.to_be_bytes());
    udp.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    udp
}

fn vxlan_options() -> Vec<u8> {
    let mut payload = vec![8, 0, 0, 0, 0x12, 0x34, 0x56, 0];
    payload.extend_from_slice(&ethernet(14, 0x0800));
    ipv4(14, 24, 17, &udp(4789, &payload))
}

fn geneve_v6() -> Vec<u8> {
    let mut payload = vec![0, 0, 0x65, 0x58, 0x12, 0x34, 0x56, 0];
    payload.extend_from_slice(&ethernet(14, 0x0800));
    ipv6(17, &udp(6081, &payload))
}

fn tencent() -> Vec<u8> {
    let inner = ipv4(14, 20, 1, &[]);
    let mut gre = vec![0x20, 0, 8, 0, 0, 1, 2, 0x85];
    gre.extend_from_slice(&inner[14..]);
    ipv4(14, 20, 47, &gre)
}

#[test]
fn ipv4_options_are_used_for_udp_and_vni_offsets() {
    let mut packet = vxlan_options();
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 40);
    assert_eq!(info.id, 0x123456);
    assert_eq!(info.tunnel_type, TunnelType::Vxlan);
    assert_eq!(info.src, Ipv4Addr::new(10, 1, 2, 3));
}

#[test]
fn payload_snaplen_is_allowed_but_declared_header_bounds_are_enforced() {
    let mut packet = vxlan_options();
    // Advertising more payload must not make a complete captured tunnel header invalid.
    packet[16..18].copy_from_slice(&1024u16.to_be_bytes());
    assert_eq!(
        TunnelInfo::default().decapsulate(&mut packet, 14, &bitmap()),
        40
    );
    // Declaring the packet shorter than the IPv4 header must not borrow Ethernet padding.
    packet[16..18].copy_from_slice(&23u16.to_be_bytes());
    let before = packet.clone();
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 0);
    assert_eq!(packet, before);
    assert_eq!(info, TunnelInfo::default());
}

#[test]
fn short_udp_length_cannot_consume_padding_as_tunnel_data() {
    let mut packet = vxlan_options();
    packet[14 + 24 + 4..14 + 24 + 6].copy_from_slice(&7u16.to_be_bytes());
    assert_eq!(
        TunnelInfo::default().decapsulate(&mut packet, 14, &bitmap()),
        0
    );
}

#[test]
fn ipv6_geneve_returns_inner_ethernet_offset() {
    let mut packet = geneve_v6();
    let expected = packet[14 + 56..].to_vec();
    let mut info = TunnelInfo::default();
    let offset = info.decapsulate_v6(&mut packet, 14, &bitmap());
    assert_eq!(offset, 56);
    assert_eq!(&packet[14 + offset..], &expected);
    assert_eq!(info.id, 0x123456);
    assert_eq!(info.tunnel_type, TunnelType::Geneve);
    assert!(info.is_ipv6);
}

#[test]
fn tencent_rewrite_keeps_original_outer_addresses() {
    let mut packet = tencent();
    let inner = packet[42..].to_vec();
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 14);
    assert_eq!(info.src, Ipv4Addr::new(10, 1, 2, 3));
    assert_eq!(info.dst, Ipv4Addr::new(10, 4, 5, 6));
    assert_eq!(info.mac_src, 2);
    assert_eq!(info.mac_dst, 1);
    assert_eq!(info.id, 0x00010285);
    assert_eq!(info.tunnel_type, TunnelType::TencentGre);
    assert_eq!(
        &packet[28..42],
        &[0, 0, 0, 0, 2, 0x85, 0, 0, 0, 0, 0, 1, 8, 0]
    );
    assert_eq!(&packet[42..], &inner);
}

#[test]
fn nested_tencent_preserves_the_outermost_tunnel_identity() {
    let mut packet = tencent();
    let original = TunnelInfo {
        tier: 1,
        src: Ipv4Addr::new(192, 0, 2, 1),
        dst: Ipv4Addr::new(192, 0, 2, 2),
        id: 42,
        tunnel_type: TunnelType::Vxlan,
        ..Default::default()
    };
    let mut info = original;
    assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 14);
    assert_eq!(
        info,
        TunnelInfo {
            tier: 2,
            ..original
        }
    );
}

#[test]
fn minimal_ipip_packets_do_not_need_an_erspan_sized_guard() {
    let inner = ipv4(14, 20, 1, &[]);
    let mut packet = ipv4(14, 20, 4, &inner[14..]);
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 6);
    assert_eq!(&packet[34..], &inner[14..]);
    assert_eq!(&packet[20..34], &ethernet(14, 0x0800));
    let mut packet = ipv6(4, &inner[14..]);
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate_v6(&mut packet, 14, &bitmap()), 26);
    assert!(info.is_ipv6);
    assert_eq!(&packet[54..], &inner[14..]);
}

#[test]
fn ipip_unrepresentable_offsets_do_not_mutate_or_wrap() {
    let inner = ipv4(14, 20, 1, &[]);
    let mut packet = ipv4(22, 20, 4, &inner[14..]);
    let before = packet.clone();
    let mut info = TunnelInfo::default();
    assert_eq!(info.decapsulate_ipip(&mut packet, 22, false, false), 0);
    assert_eq!(packet, before);
    assert_eq!(info, TunnelInfo::default());
}

#[test]
fn fragmented_underlay_is_not_misinterpreted_as_a_tunnel_header() {
    for flags in [1u16, 0x2000, 0x2010] {
        let mut packet = vxlan_options();
        packet[20..22].copy_from_slice(&flags.to_be_bytes());
        let before = packet.clone();
        let mut info = TunnelInfo::default();
        assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 0);
        assert_eq!(packet, before);
        assert_eq!(info, TunnelInfo::default());
    }
}

#[test]
fn public_decapsulators_reject_short_and_extreme_inputs_without_panicking() {
    // Independent valid IPv4-options, IPv6-Geneve and keyed-GRE frames cover
    // every captured prefix and invalid L2/tier argument at the public boundary.
    for frame in [vxlan_options(), geneve_v6(), tencent()] {
        for length in 0..=frame.len() {
            for l2 in [0, 1, 13, 14, 18, 22, usize::MAX] {
                for tier in [0, 1, TUNNEL_TIER_LIMIT, u8::MAX] {
                    for method in 0..14 {
                        let mut packet = frame[..length].to_vec();
                        let before = packet.clone();
                        let mut info = TunnelInfo {
                            tier,
                            ..Default::default()
                        };
                        let initial = info;
                        let offset = match method {
                            0 => info.decapsulate(&mut packet, l2, &bitmap()),
                            1 => info.decapsulate_v6(&mut packet, l2, &bitmap()),
                            2 => info.decapsulate_udp(&mut packet, l2, &bitmap()),
                            3 => info.decapsulate_v6_udp(&packet, l2, &bitmap()),
                            4 => info.decapsulate_vxlan(&packet, l2),
                            5 => info.decapsulate_v6_vxlan(&packet, l2),
                            6 => info.decapsulate_geneve(&packet, l2),
                            7 => info.decapsulate_v6_geneve(&packet, l2),
                            8 => info.decapsulate_gpe_vxlan(&mut packet, l2),
                            9 => info.decapsulate_gre(&mut packet, l2, &bitmap()),
                            10 => info.decapsulate_erspan(&packet, l2, 0, 0xbe88, 20),
                            11 => info.decapsulate_teb(&packet, l2, 0x2000, 20),
                            12 => info.decapsulate_ipip(&mut packet, l2, false, false),
                            _ => info.decapsulate_tencent_gre(&mut packet, l2, 0x2000, 0x0008, 20),
                        };
                        if offset == 0 {
                            assert_eq!(
                                packet, before,
                                "method={method},len={length},l2={l2},tier={tier}"
                            );
                            assert_eq!(
                                info, initial,
                                "method={method},len={length},l2={l2},tier={tier}"
                            );
                        } else {
                            assert!(l2
                                .checked_add(offset)
                                .is_some_and(|start| start <= packet.len()));
                            assert_eq!(info.tier, tier + 1);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn udp_declared_length_must_fit_logical_ip_even_with_padding() {
    for (mut packet, ipv6, header, expected) in [
        (vxlan_options(), false, 24, 40),
        (geneve_v6(), true, 40, 56),
    ] {
        packet[14 + header + 4..14 + header + 6].copy_from_slice(&1200u16.to_be_bytes());
        let before = packet.clone();
        let mut info = TunnelInfo::default();
        let offset = if ipv6 {
            info.decapsulate_v6(&mut packet, 14, &bitmap())
        } else {
            info.decapsulate(&mut packet, 14, &bitmap())
        };
        assert_eq!(offset, 0);
        assert_eq!(info, TunnelInfo::default());
        assert_eq!(packet, before);
        // A short capture with consistent logical IP/UDP lengths is valid.
        if ipv6 {
            packet[18..20].copy_from_slice(&1200u16.to_be_bytes());
            assert_eq!(info.decapsulate_v6(&mut packet, 14, &bitmap()), expected);
        } else {
            packet[16..18].copy_from_slice(&1224u16.to_be_bytes());
            assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), expected);
        }
    }
}

#[test]
fn ipv4_options_tlv_lengths_are_validated_before_udp_dispatch() {
    for options in [[0x82, 1, 0, 0], [0x82, 5, 0, 0], [1, 1, 1, 0x82]] {
        let mut packet = vxlan_options();
        packet[34..38].copy_from_slice(&options);
        let before = packet.clone();
        let mut info = TunnelInfo::default();
        assert_eq!(info.decapsulate(&mut packet, 14, &bitmap()), 0);
        assert_eq!(packet, before);
        assert_eq!(info, TunnelInfo::default());
    }
    // EOL terminates option parsing; the remaining bytes are padding.
    let mut packet = vxlan_options();
    packet[34..38].copy_from_slice(&[0, 0x82, 1, 0xff]);
    assert_eq!(
        TunnelInfo::default().decapsulate(&mut packet, 14, &bitmap()),
        40
    );
}

#[test]
fn ipip_inner_length_must_fit_logical_outer_but_capture_may_be_short() {
    let v4 = ipv4(14, 20, 1, &[])[14..].to_vec();
    let v6 = ipv6(59, &[])[14..].to_vec();
    for (mut inner, protocol, overlay_v6) in [(v4, 4, false), (v6, 41, true)] {
        if overlay_v6 {
            inner[4..6].copy_from_slice(&460u16.to_be_bytes());
        } else {
            inner[2..4].copy_from_slice(&500u16.to_be_bytes());
        }
        let mut packet = ipv4(14, 20, protocol, &inner);
        packet.extend_from_slice(&[0xaa; 500]);
        let before = packet.clone();
        let mut info = TunnelInfo::default();
        assert_eq!(info.decapsulate_ipip(&mut packet, 14, false, overlay_v6), 0);
        assert_eq!(packet, before);
        assert_eq!(info, TunnelInfo::default());
        // Re-declare a complete logical inner datagram, capture its headers only.
        packet.truncate(34 + inner.len());
        packet[16..18].copy_from_slice(&520u16.to_be_bytes());
        assert_eq!(info.decapsulate_ipip(&mut packet, 14, false, overlay_v6), 6);
        assert_eq!(&packet[34..], &inner);
    }
}
