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

use super::*;

fn setup(
    enabled: bool,
) -> (
    ModuleConfig,
    FlowMap,
    Receiver<AppProto>,
    Receiver<Arc<BatchedBox<TaggedFlow>>>,
) {
    let (mut config, mut map, flows) =
        _new_flow_map_and_receiver(AgentType::TtProcess, None, false);
    if enabled {
        assert!(PacketSegmentationReassembly::does_support());
        config.flow.packet_segmentation_reassembly.insert(18080);
    }
    let debugger = QueueDebugger::new();
    let (sender, logs, _) = queue::bounded_with_debug(256, "reassembly-logs", &debugger);
    map.l7_log_output = BufferedSender::new(sender, QUEUE_BATCH_SIZE, map.stats_counter.clone());
    (config, map, logs, flows)
}

fn config_ref(config: &ModuleConfig) -> Config<'_> {
    Config {
        flow: &config.flow,
        log_parser: &config.log_parser,
        collector: &config.collector,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        ebpf: None,
    }
}

fn packet(
    base: Duration,
    ordinal: u64,
    reverse: bool,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> MetaPacket<'static> {
    let mut wire = vec![0u8; 54 + payload.len()];
    let (source, destination, sport, dport, source_mac, destination_mac) = if reverse {
        ([10, 0, 0, 2], [10, 0, 0, 1], 18080u16, 40001u16, 2, 1)
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2], 40001u16, 18080u16, 1, 2)
    };
    wire[5] = destination_mac;
    wire[11] = source_mac;
    wire[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
    wire[14] = 0x45;
    wire[16..18].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
    wire[22] = 64;
    wire[23] = 6;
    wire[26..30].copy_from_slice(&source);
    wire[30..34].copy_from_slice(&destination);
    wire[34..36].copy_from_slice(&sport.to_be_bytes());
    wire[36..38].copy_from_slice(&dport.to_be_bytes());
    wire[38..42].copy_from_slice(&seq.to_be_bytes());
    wire[42..46].copy_from_slice(&ack.to_be_bytes());
    wire[46] = 0x50;
    wire[47] = flags;
    wire[48..50].copy_from_slice(&4096u16.to_be_bytes());
    wire[54..].copy_from_slice(payload);
    let length = wire.len();
    let mut packet = MetaPacket::default();
    packet
        .update(
            wire,
            false,
            false,
            base + Duration::from_micros(ordinal * 1000),
            length,
        )
        .unwrap();
    packet
}

fn handshake(base: Duration) -> Vec<MetaPacket<'static>> {
    vec![
        packet(base, 0, false, 100, 0, 0x02, b""),
        packet(base, 1, true, 500, 101, 0x12, b""),
        packet(base, 2, false, 101, 501, 0x10, b""),
    ]
}

fn inject(map: &mut FlowMap, config: &ModuleConfig, packet: &mut MetaPacket) {
    map.inject_meta_packet(&config_ref(config), packet);
}

fn transport_snapshot(map: &mut FlowMap) -> serde_json::Value {
    let node = map
        .node_map
        .as_mut()
        .unwrap()
        .0
        .values_mut()
        .next()
        .unwrap()
        .first_mut()
        .unwrap();
    let flow = &mut node.tagged_flow.flow;
    node.meta_flow_log
        .as_mut()
        .unwrap()
        .copy_and_reset_l4_perf_data(flow.reversed, flow);
    let perf = &flow.flow_perf_stats.as_ref().unwrap().tcp;
    let peers = flow
        .flow_metrics_peers
        .iter()
        .map(|peer| {
            serde_json::json!({
                "packet_count": peer.packet_count,
                "total_packet_count": peer.total_packet_count,
                "byte_count": peer.byte_count,
                "total_byte_count": peer.total_byte_count,
                "l3_byte_count": peer.l3_byte_count,
                "l4_byte_count": peer.l4_byte_count,
                "tcp_flags": peer.tcp_flags.bits(),
                "total_tcp_flags": peer.total_tcp_flags.bits(),
                "first_micros": peer.first.as_micros(),
                "last_micros": peer.last.as_micros(),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "peers": peers,
        "tcp": perf,
        "total_retrans_count": perf.total_retrans_count,
    })
}

fn http_logs(map: &mut FlowMap, logs: &Receiver<AppProto>) -> Vec<(String, LogMessageType)> {
    map.l7_log_output.flush();
    let mut result = Vec::new();
    while let Ok(log) = logs.recv(Some(Duration::from_millis(1))) {
        if let AppProto::MetaAppProto(log) = log {
            if let L7ProtocolInfo::HttpInfo(http) = &log.l7_info {
                result.push((http.path.clone(), log.base_info.head.msg_type));
            }
        }
    }
    result
}

fn base_time() -> Duration {
    Duration::from_secs(
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
}

#[test]
fn original_transport_metrics_match_with_interleaved_ack_and_retransmission() {
    let base = base_time();
    let request_tail = b"T /split HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n";
    let request_end = 103 + request_tail.len() as u32;
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let mut trace = handshake(base);
    trace.extend([
        packet(base, 3, false, 101, 501, 0x18, b"GE"),
        packet(base, 4, true, 501, 103, 0x10, b""),
        packet(base, 5, false, 103, 501, 0x18, request_tail),
        packet(base, 6, false, 103, 501, 0x18, request_tail),
        packet(base, 7, true, 501, request_end, 0x10, b""),
        packet(base, 8, true, 501, request_end, 0x18, response),
        packet(
            base,
            9,
            false,
            request_end,
            501 + response.len() as u32,
            0x10,
            b"",
        ),
    ]);
    let mut histories = Vec::new();
    for enabled in [false, true] {
        let (config, mut map, _logs, _flows) = setup(enabled);
        map.reset_start_time(base);
        let mut snapshots = Vec::new();
        for mut packet in trace.clone() {
            inject(&mut map, &config, &mut packet);
            snapshots.push(transport_snapshot(&mut map));
        }
        // Flushing a delayed application tail must not add transport metrics.
        let node = map
            .node_map
            .as_mut()
            .unwrap()
            .0
            .values_mut()
            .next()
            .unwrap()
            .pop()
            .unwrap();
        let mut node = node;
        map.flush_reassembled_metrics(&config_ref(&config), &mut node);
        map.node_map
            .as_mut()
            .unwrap()
            .0
            .values_mut()
            .next()
            .unwrap()
            .push(node);
        snapshots.push(transport_snapshot(&mut map));
        histories.push(snapshots);
    }
    assert_eq!(histories[0], histories[1]);
    assert!(histories[1][6]["total_retrans_count"].as_u64().unwrap() > 0);
    let peers = histories[1][9]["peers"].as_array().unwrap();
    assert_eq!(
        peers
            .iter()
            .map(|peer| peer["total_packet_count"].as_u64().unwrap())
            .sum::<u64>(),
        trace.len() as u64
    );
    assert_eq!(
        peers
            .iter()
            .map(|peer| peer["total_byte_count"].as_u64().unwrap())
            .sum::<u64>(),
        trace
            .iter()
            .map(|packet| packet.packet_len as u64)
            .sum::<u64>()
    );
}

#[test]
fn contiguous_split_http_first_line_parses_but_a_sequence_gap_does_not() {
    let base = base_time();
    for (enabled, gap, wanted) in [(false, 0, 0), (true, 0, 1), (true, 1, 0)] {
        let (config, mut map, logs, _flows) = setup(enabled);
        map.reset_start_time(base);
        let mut packets = handshake(base);
        packets.push(packet(base, 3, false, 101, 501, 0x18, b"GE"));
        packets.push(packet(
            base,
            4,
            false,
            103 + gap,
            501,
            0x18,
            b"T /split HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n",
        ));
        for packet in &mut packets {
            inject(&mut map, &config, packet);
        }
        let mut observed = http_logs(&mut map, &logs);
        map.inject_flush_ticker(&config_ref(&config), base + Duration::from_secs(5));
        observed.extend(http_logs(&mut map, &logs));
        assert_eq!(
            observed,
            vec![("/split".to_owned(), LogMessageType::Request); wanted],
            "enabled={enabled}, gap={gap}"
        );
    }
}

#[test]
fn forced_report_flushes_keepalive_tail_and_complete_http_windows_are_unique() {
    let base = base_time();
    let (config, mut map, logs, _flows) = setup(true);
    map.reset_start_time(base);
    for packet in &mut handshake(base) {
        inject(&mut map, &config, packet);
    }
    let mut seq = 101;
    for index in 0..3 {
        let request = format!("GET /window-{index} HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n");
        let mut current = packet(base, index + 3, false, seq, 501, 0x18, request.as_bytes());
        seq += request.len() as u32;
        inject(&mut map, &config, &mut current);
    }
    let mut observed = http_logs(&mut map, &logs);
    assert_eq!(observed.len(), 2); // Last original carrier is still pending.
    map.inject_flush_ticker(&config_ref(&config), base + Duration::from_secs(5));
    observed.extend(http_logs(&mut map, &logs));
    assert_eq!(
        observed,
        (0..3)
            .map(|index| (format!("/window-{index}"), LogMessageType::Request))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        map.node_map
            .as_ref()
            .unwrap()
            .0
            .values()
            .map(Vec::len)
            .sum::<usize>(),
        1
    );
    map.inject_flush_ticker(&config_ref(&config), base + Duration::from_secs(6));
    assert!(http_logs(&mut map, &logs).is_empty());
}

#[test]
fn forced_report_direction_correction_keeps_next_original_packet_aligned() {
    let base = base_time();
    let (config, mut map, logs, _flows) = setup(true);
    map.reset_start_time(base);
    for packet in &mut handshake(base) {
        inject(&mut map, &config, packet);
    }
    let request = b"GET /late-direction HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n";
    let mut current = packet(base, 3, false, 101, 501, 0x18, request);
    inject(&mut map, &config, &mut current);
    let mut node = map
        .node_map
        .as_mut()
        .unwrap()
        .0
        .values_mut()
        .next()
        .unwrap()
        .pop()
        .unwrap();
    FlowMap::reverse_flow(&mut node, false);
    let mut next = packet(base, 4, true, 501, 101 + request.len() as u32, 0x10, b"");
    // match_node ran before draining the tail, against the reversed flow key.
    next.lookup_key.direction = PacketDirection::ClientToServer;
    map.node_updated_aftercare(
        &config_ref(&config),
        &mut node,
        base + Duration::from_secs(60),
        Some(&mut next),
    );
    assert_eq!(
        http_logs(&mut map, &logs),
        vec![("/late-direction".to_owned(), LogMessageType::Request)]
    );
    assert_eq!(
        node.tagged_flow.flow.flow_key.ip_src,
        std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
    );
    assert_eq!(next.lookup_key.direction, PacketDirection::ServerToClient);
}

#[test]
fn equal_or_unmatched_endpoints_do_not_invent_a_direction() {
    let mut node = FlowNode::default();
    node.tagged_flow.flow.flow_key.ip_src = "127.0.0.1".parse().unwrap();
    node.tagged_flow.flow.flow_key.ip_dst = "127.0.0.1".parse().unwrap();
    node.tagged_flow.flow.flow_key.port_src = 18080;
    node.tagged_flow.flow.flow_key.port_dst = 18080;
    let mut packet = MetaPacket::empty();
    packet.lookup_key.src_ip = "127.0.0.1".parse().unwrap();
    packet.lookup_key.src_port = 18080;
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        packet.lookup_key.direction = direction;
        assert_eq!(
            FlowMap::align_packet_direction(&node, &mut packet),
            direction == PacketDirection::ClientToServer
        );
        assert_eq!(packet.lookup_key.direction, direction);
    }
    packet.lookup_key.src_ip = "192.0.2.5".parse().unwrap();
    packet.lookup_key.src_port = 40000;
    packet.lookup_key.direction = PacketDirection::ServerToClient;
    assert!(!FlowMap::align_packet_direction(&node, &mut packet));
    assert_eq!(packet.lookup_key.direction, PacketDirection::ServerToClient);
}
