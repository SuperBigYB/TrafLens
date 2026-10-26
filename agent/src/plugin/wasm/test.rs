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

use core::panic;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::rc::Rc;
use std::time::Duration;

use flate2::read::GzDecoder;
use public::enums::IpProtocol;
use public::l7_protocol::{CustomProtocol, LogMessageType};

use crate::common::ebpf::EbpfType;
use crate::common::flow::PacketDirection;
use crate::common::l7_protocol_info::L7ProtocolInfo;
use crate::common::l7_protocol_log::L7PerfCache;

use crate::config::handler::{L7LogDynamicConfigBuilder, LogParserConfig};
use crate::config::{
    config::{
        ExtraLogFields, ExtraLogFieldsInfo, Iso8583ParseConfig, NetSignParseConfig,
        WebSphereMqParseConfig,
    },
    OracleConfig,
};
use crate::flow_generator::protocol_logs::pb_adapter::L7ProtocolSendLog;
use crate::flow_generator::protocol_logs::{get_wasm_parser, L7ResponseStatus, WasmLog};
use crate::{
    common::l7_protocol_log::{L7ProtocolParserInterface, ParseParam},
    HttpLog,
};

use super::WasmVm;

fn get_req_param<'a>(
    vm: Rc<RefCell<Option<WasmVm>>>,
    rrt_cache: Rc<RefCell<L7PerfCache>>,
) -> ParseParam<'a> {
    ParseParam {
        l4_protocol: IpProtocol::TCP,
        ip_src: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        ip_dst: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        port_src: 12345,
        port_dst: 8080,
        flow_id: 1234567,
        direction: PacketDirection::ClientToServer,
        ebpf_type: EbpfType::TracePoint,
        #[cfg(feature = "libtrace")]
        ebpf_param: Some(crate::common::l7_protocol_log::EbpfParam {
            is_tls: false,
            is_req_end: false,
            is_resp_end: false,
            process_kname: "test_wasm",
        }),
        packet_start_seq: 9999999,
        packet_end_seq: 9999999,
        time: 12345678,
        parse_perf: true,
        parse_log: true,
        parse_config: None,
        obfuscate_cache: None,
        l7_perf_cache: Some(rrt_cache.clone()),
        wasm_vm: vm,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        so_func: Default::default(),
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 999,
        captured_byte: 999,
        oracle_parse_conf: OracleConfig::default(),
        iso8583_parse_conf: Iso8583ParseConfig::default(),
        web_sphere_mq_parse_conf: WebSphereMqParseConfig::default(),
        net_sign_parse_conf: NetSignParseConfig::default(),
        icmp_data: None,
        process_id: 0,
        socket_role: 0,
    }
}

fn get_resq_param<'a>(
    vm: Rc<RefCell<Option<WasmVm>>>,
    rrt_cache: Rc<RefCell<L7PerfCache>>,
) -> ParseParam<'a> {
    ParseParam {
        l4_protocol: IpProtocol::TCP,
        ip_src: IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8)),
        ip_dst: IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        port_src: 8080,
        port_dst: 12345,
        flow_id: 1234567,
        direction: PacketDirection::ServerToClient,
        ebpf_type: EbpfType::TracePoint,
        #[cfg(feature = "libtrace")]
        ebpf_param: Some(crate::common::l7_protocol_log::EbpfParam {
            is_tls: false,
            is_req_end: false,
            is_resp_end: false,
            process_kname: "test_wasm",
        }),
        packet_start_seq: 9999999,
        packet_end_seq: 9999999,
        time: 12345678,
        parse_perf: true,
        parse_log: true,
        parse_config: None,
        obfuscate_cache: None,
        l7_perf_cache: Some(rrt_cache.clone()),
        wasm_vm: vm,
        #[cfg(any(target_os = "linux", target_os = "android"))]
        so_func: Default::default(),
        stats_counter: None,
        rrt_timeout: Duration::from_secs(10).as_micros() as usize,
        buf_size: 999,
        captured_byte: 999,
        oracle_parse_conf: OracleConfig::default(),
        iso8583_parse_conf: Iso8583ParseConfig::default(),
        web_sphere_mq_parse_conf: WebSphereMqParseConfig::default(),
        net_sign_parse_conf: NetSignParseConfig::default(),
        icmp_data: None,
        process_id: 0,
        socket_role: 0,
    }
}

fn load_module() -> WasmVm {
    #[cfg(feature = "libtrace")]
    let path = "resources/test/plugins/wasm-fixture/wasm_test_native.wasm.gz";
    #[cfg(not(feature = "libtrace"))]
    let path = "resources/test/plugins/wasm-fixture/wasm_test_packet.wasm.gz";
    load_fixture(path)
}

fn load_fixture(path: &str) -> WasmVm {
    let mut f = File::open(path).unwrap();
    let mut gz_prog = vec![];
    f.read_to_end(&mut gz_prog).unwrap();

    let mut d = GzDecoder::new(gz_prog.as_slice());
    let mut prog = vec![];
    d.read_to_end(&mut prog).unwrap();

    let mut vm = WasmVm::new::<&str, &[u8]>(&[]);
    vm.append_prog("vm0", &prog)
        .expect("the checked-in WASM fixture must instantiate");
    vm
}

#[test]
fn test_wasm_http_req() {
    let vm = Rc::new(RefCell::new(Some(load_module())));
    let mut config = LogParserConfig::default();
    // Header logging stays opt-in. The SDK adapter must see the captured values.
    config.l7_log_dynamic = L7LogDynamicConfigBuilder {
        extra_log_fields: ExtraLogFields {
            http: ["user-agent", "referer"]
                .into_iter()
                .map(|field_name| ExtraLogFieldsInfo {
                    field_name: field_name.into(),
                })
                .collect(),
            ..Default::default()
        },
        ..Default::default()
    }
    .into();
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let mut param = get_req_param(vm.clone(), rrt_cache.clone());
    param.parse_config = Some(&config);

    let mut http = HttpLog::new_v1();
    let payload = "POST /test?a=1&b=2&c=test HTTP/1.1\r\nUser-Agent: deepflow\r\nreferer: aaa.com\r\nHost: abc.com\r\nContent-Type: application/json\r\n\r\n";
    let info = http.parse_payload(payload.as_bytes(), &param).unwrap();

    let kv: HashMap<&str, &str> = HashMap::from_iter([
        ("a", "1"),
        ("b", "2"),
        ("c", "test"),
        ("empty", ""),
        ("user_agent", "deepflow"),
        ("referer", "aaa.com"),
        // Zero configured error-snapshot limits preserve empty snapshot values.
        ("request_header", ""),
        ("request_payload", ""),
    ]);

    if let L7ProtocolInfo::HttpInfo(http) = info.unwrap_single() {
        let i: L7ProtocolSendLog = http.into();
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .trace_ids
                .first()
                .unwrap()
                .as_str(),
            "aaa"
        );
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .span_id
                .as_ref()
                .unwrap()
                .as_str(),
            "bbb"
        );

        assert_eq!(i.req.domain.as_str(), "rewrite domain");
        assert_eq!(i.req.resource.as_str(), "rewrite resource");
        assert_eq!(i.req.endpoint.as_str(), "/rewrite endpoint");

        let attr = i.ext_info.unwrap().attributes.unwrap();

        assert_eq!(attr.len(), kv.len(), "request attribute set: {attr:?}");
        let actual: HashMap<_, _> = attr
            .iter()
            .map(|entry| (entry.key.as_str(), entry.val.as_str()))
            .collect();
        assert_eq!(actual, kv);
    } else {
        unreachable!()
    };
}

#[test]
fn test_wasm_http_resp() {
    let vm = Rc::new(RefCell::new(Some(load_module())));
    let config = LogParserConfig::default();
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let mut param = get_resq_param(vm.clone(), rrt_cache.clone());
    param.parse_config = Some(&config);

    let mut http = HttpLog::new_v1();
    let payload = "HTTP/1.1 200 Ok\r\nContent-Type: application/json\r\n\r\n{\"data\":{\"user_id\":123, \"name\":\"kkk\"}}";
    let info = http.parse_payload(payload.as_bytes(), &param).unwrap();

    let kv: HashMap<&str, &str> = HashMap::from_iter([("user_id", "123"), ("username", "kkk")]);

    if let L7ProtocolInfo::HttpInfo(http) = info.unwrap_single() {
        let i: L7ProtocolSendLog = http.into();
        assert!(i.trace_info.as_ref().unwrap().trace_ids.is_empty());
        assert_eq!(
            i.trace_info
                .as_ref()
                .unwrap()
                .span_id
                .as_ref()
                .unwrap()
                .as_str(),
            ""
        );

        assert_eq!(i.resp.code.unwrap(), 599);
        assert_eq!(i.resp.status, L7ResponseStatus::ServerError);
        assert_eq!(i.resp.exception.as_str(), "rewrite exception");
        assert_eq!(i.resp.result, "rewrite result");

        let attr = i.ext_info.unwrap().attributes.unwrap();
        assert_eq!(attr.len(), kv.len());
        let actual: HashMap<_, _> = attr
            .iter()
            .map(|entry| (entry.key.as_str(), entry.val.as_str()))
            .collect();
        assert_eq!(actual, kv);
    } else {
        unreachable!()
    };
}

#[test]
fn test_check_payload() {
    let vm = Rc::new(RefCell::new(Some(load_module())));
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_req_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = WasmLog::default();
    let payload: [u8; 34] = [
        10, 6, 100, 111, 109, 97, 105, 110, 18, 8, 114, 101, 115, 111, 117, 114, 99, 101, 26, 4,
        116, 121, 112, 101, 34, 8, 101, 110, 100, 112, 111, 105, 110, 116,
    ];
    assert_eq!(
        wasm_log.check_payload(&payload[..], &param),
        Some(LogMessageType::Request)
    );
    assert_eq!(
        wasm_log.custom_protocol().unwrap(),
        CustomProtocol::Wasm(1, "test".to_string())
    );
}

#[test]
fn test_wasm_parse_payload_req() {
    let vm = Rc::new(RefCell::new(Some(load_module())));

    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_req_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = get_wasm_parser(1, "".to_string());
    let payload: [u8; 34] = [
        10, 6, 100, 111, 109, 97, 105, 110, 18, 8, 114, 101, 115, 111, 117, 114, 99, 101, 26, 4,
        116, 121, 112, 101, 34, 8, 101, 110, 100, 112, 111, 105, 110, 116,
    ];
    let info1 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(0);
    if let L7ProtocolInfo::CustomInfo(ci) = info1 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.req.domain.as_str(), "domain");
        assert_eq!(ci.req.req_type.as_str(), "type");
        assert_eq!(ci.req.resource.as_str(), "resource");
        assert_eq!(ci.req.endpoint.as_str(), "endpoint");

        assert_eq!(ci.trace.trace_ids.first().unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k1");
        assert_eq!(attr1.val.as_str(), "");

        assert_eq!(attr2.key.as_str(), "k2");
        assert_eq!(attr2.val.as_str(), "v2");

        assert_eq!(ci.need_protocol_merge, true);
        assert_eq!(ci.is_req_end, true);
    } else {
        unreachable!()
    }

    let info2 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(1);

    if let L7ProtocolInfo::CustomInfo(ci) = info2 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.req.domain.as_str(), "domain");
        assert_eq!(ci.req.req_type.as_str(), "type");
        assert_eq!(ci.req.resource.as_str(), "resource");
        assert_eq!(ci.req.endpoint.as_str(), "endpoint");

        assert_eq!(ci.trace.trace_ids.first().unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k3");
        assert_eq!(attr1.val.as_str(), "v3");

        assert_eq!(attr2.key.as_str(), "k4");
        assert_eq!(attr2.val.as_str(), "v4");

        assert_eq!(ci.need_protocol_merge, true);
        assert_eq!(ci.is_req_end, true);
    } else {
        unreachable!()
    }
}

#[test]
fn test_wasm_parse_payload_resp() {
    let vm = Rc::new(RefCell::new(Some(load_module())));
    let rrt_cache = Rc::new(RefCell::new(L7PerfCache::new(100)));

    let param = get_resq_param(vm.clone(), rrt_cache.clone());

    let mut wasm_log = get_wasm_parser(1, "".to_string());
    let payload: [u8; 11] = [8, 231, 7, 18, 6, 114, 101, 115, 117, 108, 116];
    let info1 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(0);
    if let L7ProtocolInfo::CustomInfo(ci) = info1 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.resp.status, L7ResponseStatus::Ok);
        assert_eq!(ci.resp.code.unwrap(), 999);
        assert_eq!(ci.resp.result, "result");
        assert_eq!(ci.resp.exception, "exception");

        assert_eq!(ci.trace.trace_ids.first().unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k1");
        assert_eq!(attr1.val.as_str(), "v1");

        assert_eq!(attr2.key.as_str(), "k2");
        assert_eq!(attr2.val.as_str(), "v2");
    } else {
        unreachable!()
    }

    let info2 = wasm_log
        .parse_payload(&payload[..], &param)
        .unwrap()
        .unwrap_multi()
        .remove(1);
    if let L7ProtocolInfo::CustomInfo(ci) = info2 {
        assert_eq!(ci.req_len.unwrap(), 999);
        assert_eq!(ci.resp_len.unwrap(), 9999);
        assert_eq!(ci.request_id.unwrap(), 666);
        assert_eq!(ci.resp.status, L7ResponseStatus::Ok);
        assert_eq!(ci.resp.code.unwrap(), 999);
        assert_eq!(ci.resp.result, "result");
        assert_eq!(ci.resp.exception, "exception");

        assert_eq!(ci.trace.trace_ids.first().unwrap(), "11111");
        assert_eq!(ci.trace.span_id.unwrap(), "22222");
        assert_eq!(ci.trace.parent_span_id.unwrap(), "33333");

        let attr1 = ci.attributes.get(0).unwrap();
        let attr2 = ci.attributes.get(1).unwrap();
        assert_eq!(attr1.key.as_str(), "k3");
        assert_eq!(attr1.val.as_str(), "");

        assert_eq!(attr2.key.as_str(), "k4");
        assert_eq!(attr2.val.as_str(), "v4");
    } else {
        unreachable!()
    }
}

// the protobuf message use in test, it use the go plugin gen the go code: ​https://github.com/knqyf263/go-plugin
// compile commnad: protoc --go-plugin_out=. --go-plugin_opt=paths=source_relative proto.proto

/*
syntax = "proto3";
package proto;

option go_package = "./pb";


message Req {
  string domain = 1;
  string resource = 2;
  string type = 3;
  string endpoint = 4;
}


message Resp {
  uint32 status = 1;
  string result = 2;
}
*/

// The current Go fixture source, pinned SDK patch and reproducible build recipe
// live in resources/test/plugins/wasm-fixture/. The original 2023 binary remains
// unchanged for the independent legacy result compatibility test below.

#[cfg(feature = "libtrace")]
#[test]
fn original_sdk_custom_output_without_business_trailer_still_parses() {
    let vm = Rc::new(RefCell::new(Some(load_fixture(
        "resources/test/plugins/wasm_test.wasm.gz",
    ))));
    let cache = Rc::new(RefCell::new(L7PerfCache::new(100)));
    let request: &[u8] = &[
        10, 6, 100, 111, 109, 97, 105, 110, 18, 8, 114, 101, 115, 111, 117, 114, 99, 101, 26, 4,
        116, 121, 112, 101, 34, 8, 101, 110, 100, 112, 111, 105, 110, 116,
    ];
    let response: &[u8] = &[8, 231, 7, 18, 6, 114, 101, 115, 117, 108, 116];
    for (param, payload, direction) in [
        (
            get_req_param(vm.clone(), cache.clone()),
            request,
            PacketDirection::ClientToServer,
        ),
        (
            get_resq_param(vm.clone(), cache.clone()),
            response,
            PacketDirection::ServerToClient,
        ),
    ] {
        let mut parser = get_wasm_parser(1, "test".to_owned());
        let infos = parser
            .parse_payload(payload, &param)
            .unwrap()
            .unwrap_multi();
        assert_eq!(infos.len(), 2);
        for info in infos {
            let L7ProtocolInfo::CustomInfo(info) = info else {
                panic!("custom result expected")
            };
            assert_eq!(info.req_len, Some(999));
            assert_eq!(info.resp_len, Some(9999));
            assert_eq!(info.request_id, Some(666));
            assert_eq!(info.trace.trace_ids, ["11111"]);
            assert_eq!(info.biz_type, 0);
            assert!(info.need_protocol_merge);
            assert_eq!(
                info.is_req_end,
                direction == PacketDirection::ClientToServer
            );
            assert_eq!(
                info.is_resp_end,
                direction == PacketDirection::ServerToClient
            );
            if direction == PacketDirection::ClientToServer {
                assert_eq!(info.req.domain, "domain");
                assert_eq!(info.req.resource, "resource");
            } else {
                assert_eq!(info.resp.status, L7ResponseStatus::Ok);
                assert_eq!(info.resp.code, Some(999));
                assert_eq!(info.resp.result, "result");
            }
        }
    }
}
