/*
 * Copyright (c) 2026 TrafLens contributors
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

use std::collections::HashMap;

use public::bitmap::Bitmap;

use crate::common::l7_protocol_log::L7ParseResult;
use crate::common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam};
use crate::flow_generator::protocol_logs::HttpLog;

use super::*;

const PORT: u16 = 18080;
const PID: u32 = 1234;
const FLOW_ID: u64 = 0x1234;

struct HttpFixture {
    flow: FlowConfig,
    parser: LogParserConfig,
    table: AppTable,
    checker: L7ProtocolChecker,
    log: FlowLog,
}

fn packet(index: u64, response: bool) -> MetaPacket<'static> {
    let payload = if response {
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()
    } else {
        format!("GET /cold/{index:02} HTTP/1.1\r\nHost: fixture.invalid\r\n\r\n").into_bytes()
    };
    let mut packet = MetaPacket::default();
    packet.lookup_key.timestamp =
        Timestamp::from_secs(
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ) + Timestamp::from_micros((index * 2 + u64::from(response)) * 100);
    packet.lookup_key.proto = IpProtocol::TCP;
    packet.lookup_key.eth_type = EthernetType::IPV4;
    packet.lookup_key.src_ip = Ipv4Addr::LOCALHOST.into();
    packet.lookup_key.dst_ip = Ipv4Addr::LOCALHOST.into();
    packet.lookup_key.src_port = if response { PORT } else { 43210 };
    packet.lookup_key.dst_port = if response { 43210 } else { PORT };
    packet.lookup_key.l2_end_0 = response;
    packet.lookup_key.l2_end_1 = !response;
    packet.tap_port = TapPort::from_ebpf(PID, 0);
    packet.signal_source = SignalSource::EBPF;
    packet.ebpf_type = EbpfType::TracePoint;
    packet.socket_role = 2;
    packet.process_id = PID;
    packet.flow_id = FLOW_ID;
    packet.cap_start_seq = (index - 1) * 2 + u64::from(response);
    packet.cap_end_seq = packet.cap_start_seq;
    packet.raw_from_ebpf = payload;
    packet.payload_len = packet.raw_from_ebpf.len() as u16;
    packet.raw_payload_len = packet.payload_len;
    packet.packet_len = packet.payload_len as u32 + 54;
    packet
}

impl HttpFixture {
    fn new(warm: bool) -> Self {
        let flow: FlowConfig = (&UserConfig::standalone_default()).into();
        let parser = LogParserConfig::default();
        let mut table = AppTable::default();
        let mut enabled = L7ProtocolBitmap::default();
        enabled.set_enabled(L7Protocol::Http1);
        let mut ports = Bitmap::new(u16::MAX as usize, false);
        ports.set(PORT as usize, true).unwrap();
        let checker =
            L7ProtocolChecker::new(&enabled, &HashMap::from([(L7Protocol::Http1, ports)]));
        let first = packet(1, false);
        if warm {
            table.set_protocol_from_ebpf(
                &first,
                L7ProtocolEnum::L7Protocol(L7Protocol::Http1),
                0,
                0,
            );
        }
        #[cfg(feature = "libtrace")]
        let (protocol, port) = table
            .get_protocol_from_ebpf(&first, 0, 0)
            .map(|(protocol, port, _, _)| (protocol, port))
            .unwrap_or((L7ProtocolEnum::default(), PORT));
        // Packet-only builds omit the eBPF cache lookup; exercise the same
        // FlowLog constructor states directly. Native tests use the real cache.
        #[cfg(not(feature = "libtrace"))]
        let (protocol, port) = (
            if warm {
                L7ProtocolEnum::L7Protocol(L7Protocol::Http1)
            } else {
                L7ProtocolEnum::default()
            },
            PORT,
        );
        let cache = Rc::new(RefCell::new(L7PerfCache::new(128)));
        let counters = Arc::new(FlowMapCounter::new(cache.borrow().counters()));
        let log = FlowLog::new(
            false,
            &mut MemoryPool::new(1),
            true,
            cache,
            L4Protocol::Tcp,
            protocol,
            false,
            Arc::new(FlowPerfCounter::default()),
            port,
            Default::default(),
            Default::default(),
            counters,
            10_000_000,
            60,
            None,
            Arc::new(AtomicI64::new(0)),
            None,
        )
        .unwrap();
        Self {
            flow,
            parser,
            table,
            checker,
            log,
        }
    }

    fn parse(&mut self, packet: &mut MetaPacket) -> Vec<L7ProtocolInfo> {
        match self.log.parse_l7(
            &self.flow,
            &self.parser,
            packet,
            true,
            true,
            &mut self.table,
            0,
            0,
            &self.checker,
        ) {
            Ok(L7ParseResult::Single(info)) => vec![info],
            Ok(L7ParseResult::Multi(infos)) => infos,
            Ok(L7ParseResult::None) | Err(_) => vec![],
        }
    }
}

fn parsed_heads(warm: bool, response_first: bool) -> Vec<LogMessageType> {
    let mut fixture = HttpFixture::new(warm);
    let mut events = [packet(1, false), packet(1, true)];
    if response_first {
        events.reverse();
    }
    events
        .iter_mut()
        .flat_map(|packet| fixture.parse(packet))
        .map(|info| info.app_proto_head().unwrap().msg_type)
        .collect()
}

#[test]
fn ordered_cold_and_response_first_warm_parse_both_heads() {
    assert_eq!(
        parsed_heads(false, false),
        [LogMessageType::Request, LogMessageType::Response]
    );
    assert_eq!(
        parsed_heads(true, true),
        [LogMessageType::Response, LogMessageType::Request]
    );
}

#[test]
fn response_first_cold_preserves_the_first_response() {
    assert_eq!(
        parsed_heads(false, true),
        [LogMessageType::Response, LogMessageType::Request]
    );
}

#[test]
fn response_first_cold_preserves_all_twenty_raw_pairs() {
    let mut fixture = HttpFixture::new(false);
    let mut requests = 0;
    let mut responses = 0;
    for index in 1..=20 {
        let mut events = [packet(index, false), packet(index, true)];
        if index == 1 {
            events.reverse();
        }
        for event in &mut events {
            for info in fixture.parse(event) {
                match info.app_proto_head().unwrap().msg_type {
                    LogMessageType::Request => requests += 1,
                    LogMessageType::Response => responses += 1,
                    _ => panic!("Expected a raw request or response"),
                }
            }
        }
    }
    assert_eq!((requests, responses), (20, 20));
}

#[test]
fn response_inference_requires_socket_role_direction_and_raw_ebpf_source() {
    for kind in [EbpfType::None, EbpfType::GoHttp2Uprobe, EbpfType::IOEvent] {
        let mut event = packet(1, true);
        event.lookup_key.direction = PacketDirection::ServerToClient;
        event.ebpf_type = kind;
        let param = ParseParam::new(
            &event,
            None,
            Default::default(),
            Default::default(),
            false,
            true,
        );
        assert_eq!(
            HttpLog::new_v1().check_payload(&event.raw_from_ebpf, &param),
            None
        );
    }
    for role in [0, 3] {
        let mut fixture = HttpFixture::new(false);
        let mut event = packet(1, true);
        event.socket_role = role;
        assert!(fixture.parse(&mut event).is_empty());
    }
    let event = packet(1, true);
    let param = ParseParam::new(
        &event,
        None,
        Default::default(),
        Default::default(),
        false,
        true,
    );
    assert_eq!(
        HttpLog::new_v1().check_payload(&event.raw_from_ebpf, &param),
        None
    );
    for kind in [EbpfType::TracePoint, EbpfType::TlsUprobe] {
        for role in [1, 2] {
            let mut event = packet(1, true);
            event.lookup_key.direction = PacketDirection::ServerToClient;
            event.ebpf_type = kind;
            event.socket_role = role;
            let param = ParseParam::new(
                &event,
                None,
                Default::default(),
                Default::default(),
                false,
                true,
            );
            assert_eq!(
                HttpLog::new_v1().check_payload(&event.raw_from_ebpf, &param),
                Some(LogMessageType::Response)
            );
        }
    }
}

#[test]
fn malformed_response_cannot_initialize_http_inference() {
    for line in [
        "HTTP/2.0 200 OK",
        "HTTP/1.1X200 OK",
        "HTTP/1.1 200XOK",
        "HTTP/1.1\t200 OK",
        "HTTP/1.1 099 Bad",
        "HTTP/1.1 601 Bad",
        "HTTP/1.1 abc Bad",
        "HTTP/1.1 200",
        "HTTP/1.1 20",
        "HTTP/1.1 200 \u{80}",
    ] {
        let mut fixture = HttpFixture::new(false);
        let mut event = packet(1, true);
        event.raw_from_ebpf = format!("{line}\r\nContent-Length: 0\r\n\r\n").into_bytes();
        event.packet_len = event.raw_from_ebpf.len() as u32 + 54;
        assert!(fixture.parse(&mut event).is_empty(), "accepted {line:?}");
        assert_eq!(
            fixture.log.l7_protocol_enum.get_l7_protocol(),
            L7Protocol::Unknown
        );
    }
    let mut fixture = HttpFixture::new(false);
    let mut truncated = packet(1, true);
    truncated.raw_from_ebpf = b"HTTP/1.1 200 OK".to_vec();
    truncated.packet_len = truncated.raw_from_ebpf.len() as u32 + 54;
    assert!(fixture.parse(&mut truncated).is_empty());
}

#[test]
fn response_inference_preserves_protocol_port_and_tcp_gates() {
    let mut fixture = HttpFixture::new(false);
    let mut wrong_port = packet(1, true);
    wrong_port.lookup_key.src_port = PORT + 1;
    assert!(fixture.parse(&mut wrong_port).is_empty());
    let mut event = packet(1, true);
    event.lookup_key.direction = PacketDirection::ServerToClient;
    event.lookup_key.proto = IpProtocol::UDP;
    let param = ParseParam::new(
        &event,
        None,
        Default::default(),
        Default::default(),
        false,
        true,
    );
    assert_eq!(
        HttpLog::new_v1().check_payload(&event.raw_from_ebpf, &param),
        None
    );
}

#[cfg(feature = "libtrace")]
#[test]
fn native_cold_response_first_pairs_become_twenty_complete_sessions() {
    use crate::config::handler::LogParserAccess;
    use crate::flow_generator::protocol_logs::SessionAggregator;
    use arc_swap::{access::Map, ArcSwap};

    let mut fixture = HttpFixture::new(false);
    let mut flow = TaggedFlow::default();
    flow.flow.flow_id = FLOW_ID;
    flow.flow.signal_source = SignalSource::EBPF;
    flow.flow.flow_key.proto = IpProtocol::TCP;
    flow.flow.flow_key.tap_port = TapPort::from_ebpf(PID, 0);
    flow.flow.tap_side = TapSide::ServerProcess;
    let debugger = QueueDebugger::new();
    let (input, input_rx, _) = queue::bounded_with_debug(128, "first-record-input", &debugger);
    let (output, output_rx, _) = queue::bounded_with_debug(128, "first-record-output", &debugger);
    let module = ModuleConfig::default();
    let config: LogParserAccess =
        Map::new(Arc::new(ArcSwap::from_pointee(module)), |c| &c.log_parser);
    let (aggregator, counter) =
        SessionAggregator::new(input_rx, output, 0, config, Arc::new(AtomicI64::new(0)));
    let mut raw_heads = 0;
    for index in 1..=20 {
        let mut events = [packet(index, false), packet(index, true)];
        if index == 1 {
            events.reverse();
        }
        for event in &mut events {
            for info in fixture.parse(event) {
                let head = info.app_proto_head().unwrap();
                let item = MetaAppProto::new(&flow, event, info, head).unwrap();
                input.send(AppProto::MetaAppProto(Box::new(item))).unwrap();
                raw_heads += 1;
            }
        }
    }
    assert_eq!(raw_heads, 40, "Loss occurred before the Session queue");
    aggregator.start();
    let mut sessions = Vec::new();
    for _ in 0..20 {
        match output_rx.recv(Some(Duration::from_secs(2))) {
            Ok(item) => sessions.push(item),
            Err(_) => break,
        }
    }
    aggregator.stop();
    let counters = counter
        .get_counters()
        .into_iter()
        .map(|(name, _, value)| {
            let CounterValue::Unsigned(value) = value else {
                panic!("Expected unsigned Session counters");
            };
            (name, value)
        })
        .collect::<HashMap<_, _>>();
    assert_eq!(sessions.len(), 20, "Session counters: {counters:?}");
    assert_eq!(counters["receive"], 40);
    assert_eq!(counters["merge"], 20);
    assert_eq!(counters["throttle-drop"], 0);
    let mut paths = std::collections::BTreeSet::new();
    for session in sessions {
        assert_eq!(
            session.data.base_info.head.msg_type,
            LogMessageType::Session
        );
        assert_eq!(session.data.base_info.flow_id, FLOW_ID);
        assert_eq!(session.data.base_info.process_id_1, PID);
        let L7ProtocolInfo::HttpInfo(info) = &session.data.l7_info else {
            panic!("Expected HTTP");
        };
        assert_eq!(info.status_code, Some(200));
        paths.insert(info.path.clone());
    }
    assert_eq!(
        paths,
        (1..=20).map(|index| format!("/cold/{index:02}")).collect()
    );
}
