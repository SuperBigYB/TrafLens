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

use std::collections::HashMap;

use public::l7_protocol::{CustomProtocol, L7Protocol, LogMessageType};

use crate::{
    common::{
        flow::L7PerfStats,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{L7ParseResult, L7ProtocolParserInterface, LogCacheKey, ParseParam},
    },
    flow_generator::{protocol_logs::set_captured_byte, Error, Result},
};

#[derive(Default)]
pub struct WasmLog {
    proto_num: Option<u8>,
    proto_str: String,
    perf_stats: Vec<L7PerfStats>,
}

impl L7ProtocolParserInterface for WasmLog {
    fn check_payload(&mut self, payload: &[u8], param: &ParseParam) -> Option<LogMessageType> {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return None;
        };

        let Some((proto_num, proto_str, message_type)) = vm.on_check_payload(&payload, &param)
        else {
            return None;
        };
        self.proto_num = Some(proto_num);
        self.proto_str = proto_str;

        Some(message_type)
    }

    fn parse_payload(&mut self, payload: &[u8], param: &ParseParam) -> Result<L7ParseResult> {
        let mut vm_ref = param.wasm_vm.borrow_mut();
        let Some(vm) = vm_ref.as_mut() else {
            return Err(Error::WasmParseFail);
        };
        self.perf_stats.clear();

        if let Some(mut infos) = vm.on_parse_payload(payload, param, self.proto_num.unwrap()) {
            // Preflight the complete external batch before any performance or
            // session-cache update. Keep existing requests intact on rejection.
            let mut merge_modes = HashMap::new();
            for info in &mut infos {
                info.proto = self.proto_num.unwrap();
                info.proto_str = self.proto_str.clone();
                info.msg_type = param.direction.into();
                info.validate_merge_cache(param)?;
                if !param.parse_perf || !info.needs_session_aggregation() {
                    continue;
                }
                let key = LogCacheKey::new(param, info.session_id(), info.is_reversed());
                let mode = info.need_merge();
                if merge_modes
                    .insert(key, mode)
                    .is_some_and(|previous| previous != mode)
                {
                    return Err(Error::WasmSerializeFail(
                        "plugin batch mixes merge modes for one session key".to_string(),
                    ));
                }
            }
            let l7_infos: Vec<L7ProtocolInfo> = infos
                .into_iter()
                .map(|mut i| {
                    set_captured_byte!(i, param);

                    if param.parse_perf {
                        let mut perf_stat = L7PerfStats::default();
                        if i.msg_type == LogMessageType::Response && i.resp.endpoint.is_empty() {
                            if let Some(endpoint) =
                                i.load_endpoint_from_cache(param, i.is_reversed())
                            {
                                i.resp.endpoint = endpoint.to_string();
                            }
                        }
                        if let Some(stats) = i.perf_stats(param) {
                            i.rrt = stats.rrt_sum;
                            perf_stat.sequential_merge(&stats);
                        }
                        self.perf_stats.push(perf_stat);
                    }

                    L7ProtocolInfo::CustomInfo(i)
                })
                .collect();
            Ok(L7ParseResult::Multi(l7_infos))
        } else {
            Err(Error::WasmParseFail)
        }
    }

    fn protocol(&self) -> L7Protocol {
        L7Protocol::Custom
    }

    fn custom_protocol(&self) -> Option<CustomProtocol> {
        Some(CustomProtocol::Wasm(
            self.proto_num.unwrap(),
            self.proto_str.clone(),
        ))
    }

    fn perf_stats(&mut self) -> Vec<L7PerfStats> {
        std::mem::take(&mut self.perf_stats)
    }
}

pub fn get_wasm_parser(p: u8, s: String) -> WasmLog {
    WasmLog {
        proto_num: Some(p),
        proto_str: s,
        perf_stats: vec![],
    }
}

#[cfg(test)]
mod identity_regression_tests {
    use std::{
        cell::RefCell,
        panic::{catch_unwind, AssertUnwindSafe},
        rc::Rc,
    };

    use prost::Message;
    use public::enums::IpProtocol;

    use super::*;
    use crate::{
        common::{
            l7_protocol_log::{L7PerfCache, LogCacheKey},
            MetaPacket,
        },
        plugin::wasm::{wasm_plugin as pb, WasmVm},
    };

    fn leb(mut value: usize) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 127) as u8;
            value >>= 7;
            out.push(byte | if value == 0 { 0 } else { 128 });
            if value == 0 {
                return out;
            }
        }
    }
    fn signed(mut value: i32) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let byte = (value & 127) as u8;
            value >>= 7;
            let end = (value == 0 && byte & 64 == 0) || (value == -1 && byte & 64 != 0);
            out.push(byte | if end { 0 } else { 128 });
            if end {
                return out;
            }
        }
    }
    fn name(out: &mut Vec<u8>, value: &str) {
        out.extend(leb(value.len()));
        out.extend(value.as_bytes());
    }
    fn section(out: &mut Vec<u8>, id: u8, body: Vec<u8>) {
        out.push(id);
        out.extend(leb(body.len()));
        out.extend(body);
    }
    fn constant(out: &mut Vec<u8>, value: i32) {
        out.push(0x41);
        out.extend(signed(value));
    }

    // Minimal actual guest binary. parse_payload forwards hand-encoded metadata
    // through the real host import; no SDK or replacement parser is involved.
    fn guest(infos: &[Vec<u8>]) -> WasmVm {
        let mut payload = Vec::new();
        for info in infos {
            payload.extend_from_slice(&(info.len() as u16).to_be_bytes());
            payload.extend(info);
        }
        let mut wasm = b"\0asm\x01\0\0\0".to_vec();
        section(
            &mut wasm,
            1,
            vec![
                3, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0, 0x60, 0, 1, 0x7f,
            ],
        );
        let mut imports = vec![1];
        name(&mut imports, "deepflow");
        name(&mut imports, "host_read_l7_protocol_info");
        imports.extend([0, 0]);
        section(&mut wasm, 2, imports);
        section(&mut wasm, 3, vec![6, 1, 2, 2, 2, 2, 2]);
        section(&mut wasm, 5, vec![1, 0, 1]);
        let mut exports = vec![7];
        name(&mut exports, "memory");
        exports.extend([2, 0]);
        for (index, export) in [
            "_start",
            "check_payload",
            "parse_payload",
            "on_http_req",
            "on_http_resp",
            "get_hook_bitmap",
        ]
        .iter()
        .enumerate()
        {
            name(&mut exports, export);
            exports.push(0);
            exports.extend(leb(index + 1));
        }
        section(&mut wasm, 7, exports);
        let mut parse = vec![0];
        constant(&mut parse, 1024);
        constant(&mut parse, payload.len() as i32);
        parse.extend([0x10, 0, 0x0b]);
        let mut bitmap = vec![0];
        constant(&mut bitmap, 512);
        bitmap.push(0x0b);
        let mut code = vec![6];
        for body in [
            vec![0, 0x0b],
            vec![0, 0x41, 0, 0x0b],
            parse,
            vec![0, 0x41, 0, 0x0b],
            vec![0, 0x41, 0, 0x0b],
            bitmap,
        ] {
            code.extend(leb(body.len()));
            code.extend(body);
        }
        section(&mut wasm, 10, code);
        let mut data = vec![2];
        for (offset, bytes) in [(512, [vec![0; 15], vec![1]].concat()), (1024, payload)] {
            data.push(0);
            constant(&mut data, offset);
            data.push(0x0b);
            data.extend(leb(bytes.len()));
            data.extend(bytes);
        }
        section(&mut wasm, 11, data);
        let vm = WasmVm::new(&[("identity-guest", wasm)]);
        assert_eq!(vm.len(), 1);
        vm
    }
    fn metadata(id: Option<u32>, merge: bool, asynchronous: bool, reversed: bool) -> Vec<u8> {
        let info = pb::AppInfo {
            request_id: id,
            is_end: merge.then_some(true),
            is_async: Some(asynchronous),
            is_reversed: Some(reversed),
            ..Default::default()
        };
        let mut bytes = b"PB".to_vec();
        bytes.extend(info.encode_to_vec());
        bytes
    }
    fn packet() -> MetaPacket<'static> {
        let mut packet = MetaPacket::default();
        packet.lookup_key.proto = IpProtocol::TCP;
        packet.flow_id = 42;
        packet
    }
    fn param<'a>(
        packet: &'a MetaPacket<'a>,
        cache: Rc<RefCell<L7PerfCache>>,
        infos: &[Vec<u8>],
    ) -> ParseParam<'a> {
        let mut param = ParseParam::new(
            packet,
            Some(cache),
            Rc::new(RefCell::new(Some(guest(infos)))),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        param.time = 100;
        param.rrt_timeout = 1000;
        param.direction = crate::common::flow::PacketDirection::ClientToServer;
        param
    }
    fn replace_guest(param: &ParseParam, infos: &[Vec<u8>]) {
        *param.wasm_vm.borrow_mut() = Some(guest(infos));
    }
    fn key(param: &ParseParam, id: u32, reversed: bool) -> LogCacheKey {
        LogCacheKey::new(param, Some(id), reversed)
    }

    #[test]
    fn missing_merge_identity_from_guest_is_rejected_without_panic() {
        let packet = packet();
        let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
        let param = param(
            &packet,
            cache.clone(),
            &[metadata(None, true, false, false)],
        );
        let mut parser = get_wasm_parser(1, "identity".into());
        let result = catch_unwind(AssertUnwindSafe(|| parser.parse_payload(b"", &param)));
        assert!(result.is_ok(), "untrusted missing merge ID panicked");
        assert!(result.unwrap().is_err());
        assert!(parser.perf_stats().is_empty());
        assert!(cache
            .borrow_mut()
            .rrt_cache
            .get(&key(&param, 0, false))
            .is_none());
    }

    #[test]
    fn mixed_modes_within_one_guest_batch_are_rejected_before_any_stats() {
        for first in [false, true] {
            let packet = packet();
            let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
            let param = param(
                &packet,
                cache.clone(),
                &[
                    metadata(Some(777), first, false, false),
                    metadata(Some(777), !first, false, false),
                ],
            );
            let mut parser = get_wasm_parser(1, "identity".into());
            let result = catch_unwind(AssertUnwindSafe(|| parser.parse_payload(b"", &param)));
            assert!(result.is_ok(), "mixed guest batch panicked");
            assert!(result.unwrap().is_err());
            assert!(parser.perf_stats().is_empty());
            assert!(cache
                .borrow_mut()
                .rrt_cache
                .get(&key(&param, 777, false))
                .is_none());
        }
    }

    #[test]
    fn incompatible_cached_mode_preserves_request_then_correct_response_closes() {
        for first in [false, true] {
            let packet = packet();
            let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
            let mut param = param(
                &packet,
                cache.clone(),
                &[metadata(Some(777), first, false, false)],
            );
            let mut parser = get_wasm_parser(1, "identity".into());
            parser.parse_payload(b"", &param).unwrap();
            assert_eq!(parser.perf_stats()[0].request_count, 1);
            let cache_key = key(&param, 777, false);
            replace_guest(&param, &[metadata(Some(777), !first, false, false)]);
            param.time = 130;
            param.direction = crate::common::flow::PacketDirection::ServerToClient;
            let result = catch_unwind(AssertUnwindSafe(|| parser.parse_payload(b"", &param)));
            assert!(result.is_ok(), "mode changed under active request panicked");
            assert!(result.unwrap().is_err());
            assert!(parser.perf_stats().is_empty());
            {
                let mut cache = cache.borrow_mut();
                let entry = cache.rrt_cache.get(&cache_key).unwrap();
                assert_eq!(entry.time, 100);
                assert_eq!(entry.multi_merge_info.is_some(), first);
            }
            assert_eq!(
                cache
                    .borrow_mut()
                    .timeout_cache
                    .get_or_insert_mut(42)
                    .in_cache[0],
                1
            );
            replace_guest(&param, &[metadata(Some(777), first, false, false)]);
            param.time = 150;
            parser.parse_payload(b"", &param).unwrap();
            let stats = parser.perf_stats();
            assert_eq!(
                (
                    stats[0].response_count,
                    stats[0].rrt_count,
                    stats[0].rrt_sum
                ),
                (1, 1, 50)
            );
            assert!(cache.borrow_mut().rrt_cache.get(&cache_key).is_none());
            assert_eq!(
                cache
                    .borrow_mut()
                    .timeout_cache
                    .get_or_insert_mut(42)
                    .in_cache[0],
                0
            );
        }
    }

    #[test]
    fn mode_rejection_respects_rrt_threshold_and_normal_closure() {
        // The threshold is inclusive and affects RTT/timeout accounting, not
        // entry expiration. Both plain and merged sessions retain this rule.
        for merged in [false, true] {
            for age in [999, 1000, 1001] {
                let packet = packet();
                let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
                let mut param = param(
                    &packet,
                    cache.clone(),
                    &[metadata(Some(777), merged, false, false)],
                );
                let mut parser = get_wasm_parser(1, "identity".into());
                parser.parse_payload(b"", &param).unwrap();
                assert_eq!(parser.perf_stats()[0].request_count, 1);
                param.time = 100 + age;
                param.direction = crate::common::flow::PacketDirection::ServerToClient;
                replace_guest(&param, &[metadata(Some(777), !merged, false, false)]);
                assert!(parser.parse_payload(b"", &param).is_err());
                assert!(parser.perf_stats().is_empty());
                assert_eq!(
                    cache
                        .borrow()
                        .rrt_cache
                        .peek(&key(&param, 777, false))
                        .unwrap()
                        .time,
                    100
                );
                {
                    let mut cache = cache.borrow_mut();
                    let timeout = cache.timeout_cache.get_or_insert_mut(42);
                    assert_eq!((timeout.in_cache[0], timeout.timeout[0]), (1, 0));
                }
                replace_guest(&param, &[metadata(Some(777), merged, false, false)]);
                parser.parse_payload(b"", &param).unwrap();
                let stats = parser.perf_stats();
                assert_eq!(stats[0].response_count, 1);
                assert_eq!(stats[0].rrt_count, u32::from(age <= 1000));
                assert_eq!(stats[0].rrt_sum, if age <= 1000 { age } else { 0 });
                assert!(cache
                    .borrow()
                    .rrt_cache
                    .peek(&key(&param, 777, false))
                    .is_none());
                {
                    let mut cache = cache.borrow_mut();
                    let timeout = cache.timeout_cache.get_or_insert_mut(42);
                    assert_eq!(
                        (timeout.in_cache[0], timeout.timeout[0]),
                        // Shared multi-merge accounting suppresses timeout
                        // after the request/response pair is marked merged.
                        // Preserve that existing distinction from plain mode.
                        (0, u64::from(age > 1000 && !merged))
                    );
                }
                // A completed session does not pin this ID's future mode.
                param.time += 1;
                param.direction = crate::common::flow::PacketDirection::ClientToServer;
                replace_guest(&param, &[metadata(Some(777), !merged, false, false)]);
                parser.parse_payload(b"", &param).unwrap();
                assert_eq!(parser.perf_stats()[0].request_count, 1);
            }
        }
    }

    #[test]
    fn flow_removal_preserves_timeout_then_allows_a_new_merge_mode() {
        for merged in [false, true] {
            let packet = packet();
            let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
            let mut param = param(
                &packet,
                cache.clone(),
                &[metadata(Some(777), merged, false, false)],
            );
            let mut parser = get_wasm_parser(1, "identity".into());
            parser.parse_payload(b"", &param).unwrap();
            assert_eq!(parser.perf_stats()[0].request_count, 1);
            param.time = 1101;
            replace_guest(&param, &[metadata(Some(777), !merged, false, false)]);
            assert!(parser.parse_payload(b"", &param).is_err());
            assert!(parser.perf_stats().is_empty());
            // This is FlowMap's flow_end accounting/removal sequence. The
            // rejection has not consumed or duplicated the pending timeout.
            assert_eq!(
                cache
                    .borrow_mut()
                    .timeout_cache
                    .pop_timeout_count(42, true, false),
                1
            );
            cache.borrow_mut().remove_flow(42);
            assert!(cache
                .borrow()
                .rrt_cache
                .peek(&key(&param, 777, false))
                .is_none());
            parser.parse_payload(b"", &param).unwrap();
            assert_eq!(parser.perf_stats()[0].request_count, 1);
            let mut cache = cache.borrow_mut();
            let timeout = cache.timeout_cache.get_or_insert_mut(42);
            assert_eq!((timeout.in_cache[0], timeout.timeout[0]), (1, 0));
        }
    }

    #[test]
    fn rejected_mode_does_not_refresh_cache_lru() {
        let packet = packet();
        let cache = Rc::new(RefCell::new(L7PerfCache::new(2)));
        let param = param(
            &packet,
            cache.clone(),
            &[metadata(Some(1), true, false, false)],
        );
        let mut parser = get_wasm_parser(1, "identity".into());
        parser.parse_payload(b"", &param).unwrap();
        parser.perf_stats();
        replace_guest(&param, &[metadata(Some(2), true, false, false)]);
        parser.parse_payload(b"", &param).unwrap();
        parser.perf_stats();
        replace_guest(&param, &[metadata(Some(1), false, false, false)]);
        let result = catch_unwind(AssertUnwindSafe(|| parser.parse_payload(b"", &param)));
        assert!(result.is_ok());
        assert!(result.unwrap().is_err());
        assert!(parser.perf_stats().is_empty());
        replace_guest(&param, &[metadata(Some(3), true, false, false)]);
        parser.parse_payload(b"", &param).unwrap();
        assert!(
            cache
                .borrow_mut()
                .rrt_cache
                .get(&key(&param, 1, false))
                .is_none(),
            "rejected lookup must not refresh oldest entry"
        );
        assert!(cache
            .borrow_mut()
            .rrt_cache
            .get(&key(&param, 2, false))
            .is_some());
        assert!(cache
            .borrow_mut()
            .rrt_cache
            .get(&key(&param, 3, false))
            .is_some());
    }

    #[test]
    fn asynchronous_and_reversed_guests_do_not_falsely_conflict() {
        let packet = packet();
        let cache = Rc::new(RefCell::new(L7PerfCache::new(4)));
        let param = param(
            &packet,
            cache.clone(),
            &[metadata(Some(777), true, false, false)],
        );
        let mut parser = get_wasm_parser(1, "identity".into());
        parser.parse_payload(b"", &param).unwrap();
        assert_eq!(parser.perf_stats()[0].request_count, 1);
        replace_guest(&param, &[metadata(Some(777), false, true, false)]);
        parser.parse_payload(b"", &param).unwrap();
        assert_eq!(parser.perf_stats()[0].request_count, 1);
        replace_guest(&param, &[metadata(Some(777), false, false, true)]);
        parser.parse_payload(b"", &param).unwrap();
        assert_eq!(parser.perf_stats()[0].request_count, 1);
        assert!(cache
            .borrow_mut()
            .rrt_cache
            .get(&key(&param, 777, false))
            .unwrap()
            .multi_merge_info
            .is_some());
        assert!(cache
            .borrow_mut()
            .rrt_cache
            .get(&key(&param, 777, true))
            .unwrap()
            .multi_merge_info
            .is_none());
    }
}
