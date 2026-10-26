// SPDX-License-Identifier: Apache-2.0

use std::{cell::RefCell, panic::catch_unwind, rc::Rc};

use prost::Message;

use crate::common::{
    flow::PacketDirection,
    l7_protocol_info::L7ProtocolInfoInterface,
    l7_protocol_log::{L7PerfCache, LogCache, LogCacheKey, ParseParam},
    MetaPacket,
};
use public::l7_protocol::LogMessageType;

use super::{pb, read_wasm_str, CustomInfo, L7ResponseStatus};

fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

// Independent hand encoding of the documented pre-Protobuf Go SDK layout.
// This deliberately does not use CustomInfo/prost serialization.
fn header(request_id: bool) -> Vec<u8> {
    let mut wire = 0x8000_007bu32.to_be_bytes().to_vec();
    wire.extend_from_slice(&0x8000_01c8u32.to_be_bytes());
    wire.push(u8::from(request_id));
    if request_id {
        wire.extend_from_slice(&777u32.to_be_bytes());
    }
    wire
}

fn message_prefix(direction: PacketDirection, request_id: bool) -> Vec<u8> {
    let mut wire = header(request_id);
    match direction {
        PacketDirection::ClientToServer => {
            for value in ["GET", "endpoint", "example.invalid", "/resource"] {
                string(&mut wire, value);
            }
        }
        PacketDirection::ServerToClient => {
            wire.extend_from_slice(&[0, 1]); // success, response code follows
            wire.extend_from_slice(&200u32.to_be_bytes());
            for value in ["result", "exception"] {
                string(&mut wire, value);
            }
        }
    }
    string(&mut wire, "legacy-example");
    wire.push(0x81); // merge and end of this direction
    wire
}

fn message(
    direction: PacketDirection,
    request_id: bool,
    attributes: bool,
    biz: Option<u8>,
) -> Vec<u8> {
    let mut wire = message_prefix(direction, request_id);
    wire.push(1); // trace: old single trace ID, span and parent span
    for value in ["trace", "span", "parent"] {
        string(&mut wire, value);
    }
    wire.push(u8::from(attributes));
    if attributes {
        for (key, value) in [("empty", ""), ("tag", "value")] {
            string(&mut wire, key);
            string(&mut wire, value);
        }
    }
    if let Some(biz) = biz {
        wire.push(biz);
    }
    wire
}

#[test]
fn old_request_and_response_without_biz_trailer_are_accepted() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        for request_id in [false, true] {
            let wire = message(direction, request_id, false, None);
            let info = CustomInfo::try_from((wire.as_slice(), direction)).unwrap();
            assert_eq!(info.req_len, Some(123));
            assert_eq!(info.resp_len, Some(456));
            assert_eq!(info.request_id, request_id.then_some(777));
            assert_eq!(info.proto_str, "legacy-example");
            assert_eq!(info.biz_type, 0);
            assert!(info.attributes.is_empty());
            assert_eq!(info.trace.trace_ids, ["trace"]);
            assert_eq!(info.trace.span_id.as_deref(), Some("span"));
            assert_eq!(info.trace.parent_span_id.as_deref(), Some("parent"));
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
                assert_eq!(info.req.resource, "/resource");
                assert_eq!(info.req.req_type, "GET");
            } else {
                assert_eq!(info.resp.status, L7ResponseStatus::Ok);
                assert_eq!(info.resp.code, Some(200));
                assert_eq!(info.resp.result, "result");
                assert_eq!(info.resp.exception, "exception");
            }
        }
    }
}

#[test]
fn complete_attributes_preserve_old_and_current_trailers() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        for biz in [None, Some(0), Some(7)] {
            let wire = message(direction, true, true, biz);
            let info = CustomInfo::try_from((wire.as_slice(), direction)).unwrap();
            assert_eq!(info.biz_type, biz.unwrap_or_default());
            assert_eq!(info.attributes.len(), 2);
            assert_eq!(info.attributes[0].key, "empty");
            assert_eq!(info.attributes[0].val, "");
            assert_eq!(info.attributes[1].key, "tag");
            assert_eq!(info.attributes[1].val, "value");
        }
    }
}

#[test]
fn malformed_attribute_pairs_are_not_reinterpreted_as_a_trailer() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        let mut prefix = message_prefix(direction, true);
        prefix.extend_from_slice(&[0, 1]); // no trace, attributes present
        for malformed in [
            &b"\0\0"[..], // empty key but missing value length
            &b"\0\x01k"[..],
            &b"\0\x01k\0"[..],
            &b"\0\x01k\0\x02x"[..],
            &b"\0\x09k\0\x01v"[..],
        ] {
            let mut wire = prefix.clone();
            wire.extend_from_slice(malformed);
            assert!(CustomInfo::try_from((wire.as_slice(), direction)).is_err());
        }
        // With no attribute count, one final byte is inherently ambiguous:
        // it is accepted as the optional business type, not guessed to be a
        // truncated next length prefix. Two or more bytes must form a full KV.
        let mut one_byte = prefix.clone();
        one_byte.push(7);
        let info = CustomInfo::try_from((one_byte.as_slice(), direction)).unwrap();
        assert_eq!(info.biz_type, 7);
        assert!(info.attributes.is_empty());
    }
}

#[test]
fn every_request_and_response_prefix_is_panic_free() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        for request_id in [false, true] {
            let wire = message(direction, request_id, true, Some(7));
            for length in 0..=wire.len() {
                assert!(
                    catch_unwind(|| CustomInfo::try_from((&wire[..length], direction))).is_ok(),
                    "direction={direction:?} request_id={request_id} length={length}"
                );
            }
        }
    }
}

#[test]
fn invalid_status_code_markers_and_unknown_extra_trailers_are_errors() {
    for response_fields in [&[9, 0][..], &[0, 3][..], &[0, 1, 0][..]] {
        let mut wire = header(false);
        wire.extend_from_slice(response_fields);
        assert!(CustomInfo::try_from((wire.as_slice(), PacketDirection::ServerToClient)).is_err());
    }
    let mut wire = message(PacketDirection::ClientToServer, false, false, Some(7));
    wire.push(8); // no attribute block; no known two-byte extension exists
    assert!(CustomInfo::try_from((wire.as_slice(), PacketDirection::ClientToServer)).is_err());
}

#[test]
fn failed_wasm_string_read_keeps_the_cursor() {
    let mut cursor = 0;
    assert_eq!(read_wasm_str(b"\0\x03a", &mut cursor), None);
    assert_eq!(cursor, 0);
    assert_eq!(
        read_wasm_str(b"\0\x01a\0", &mut cursor).as_deref(),
        Some("a")
    );
    assert_eq!(cursor, 3);
    assert_eq!(read_wasm_str(b"\0\x01a\0", &mut cursor), None);
    assert_eq!(cursor, 3);
}

#[test]
fn protobuf_magic_and_legacy_or_repeated_trace_ids_are_unchanged() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        for (legacy, repeated, expected) in [
            (Some("old"), vec![], vec!["old"]),
            (None, vec!["new", "second"], vec!["new", "second"]),
            (Some("old"), vec!["new", "old"], vec!["new", "old"]),
        ] {
            let mut info = pb::AppInfo {
                req_len: Some(123),
                resp_len: Some(456),
                request_id: Some(777),
                protocol_str: Some("protobuf-example".into()),
                biz_type: Some(7),
                is_end: Some(true),
                is_async: Some(true),
                is_reversed: Some(false),
                trace: Some(pb::AppTrace {
                    trace_id: legacy.map(str::to_string),
                    trace_ids: repeated.into_iter().map(str::to_string).collect(),
                    span_id: Some("span".into()),
                    parent_span_id: Some("parent".into()),
                    x_request_id: Some("request".into()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            info.info = Some(if direction == PacketDirection::ClientToServer {
                pb::app_info::Info::Req(pb::AppRequest {
                    resource: Some("/resource".into()),
                    ..Default::default()
                })
            } else {
                pb::app_info::Info::Resp(pb::AppResponse {
                    status: Some(pb::AppRespStatus::RespOk as i32),
                    code: Some(200),
                    ..Default::default()
                })
            });
            let mut wire = b"PB".to_vec();
            wire.extend_from_slice(&info.encode_to_vec());
            let actual = CustomInfo::try_from((wire.as_slice(), direction)).unwrap();
            assert_eq!(actual.trace.trace_ids, expected);
            assert_eq!(actual.biz_type, 7);
            assert_eq!(actual.is_async, Some(true));
            assert_eq!(actual.is_reversed, Some(false));
            assert_eq!(actual.request_id, Some(777));
            assert_eq!(actual.proto_str, "protobuf-example");
            if direction == PacketDirection::ClientToServer {
                assert_eq!(actual.trace.x_request_id_0.as_deref(), Some("request"));
                assert_eq!(actual.req.resource, "/resource");
            } else {
                assert_eq!(actual.trace.x_request_id_1.as_deref(), Some("request"));
                assert_eq!(actual.resp.code, Some(200));
            }
        }
    }
}

fn perf_message(protobuf: bool, direction: PacketDirection, end: bool) -> CustomInfo {
    let mut info = if protobuf {
        let pb_info = pb::AppInfo {
            request_id: Some(777),
            is_end: Some(end),
            ..Default::default()
        };
        let mut wire = b"PB".to_vec();
        wire.extend_from_slice(&pb_info.encode_to_vec());
        CustomInfo::try_from((wire.as_slice(), direction)).unwrap()
    } else {
        let mut wire = message(direction, true, false, None);
        let merge_byte = message_prefix(direction, true).len() - 1;
        wire[merge_byte] = if end { 0x81 } else { 0x80 };
        CustomInfo::try_from((wire.as_slice(), direction)).unwrap()
    };
    // The protocol wrapper assigns the request/response type after decoding.
    info.msg_type = if direction == PacketDirection::ClientToServer {
        LogMessageType::Request
    } else {
        LogMessageType::Response
    };
    info
}

fn cached_ends(cache: &Rc<RefCell<L7PerfCache>>, key: LogCacheKey) -> Option<(bool, bool, bool)> {
    cache.borrow_mut().rrt_cache.get(&key).and_then(|entry| {
        entry
            .multi_merge_info
            .as_ref()
            .map(|flags| (flags.req_end, flags.resp_end, flags.merged))
    })
}

#[test]
fn custom_log_cache_derives_completion_flags_for_legacy_and_protobuf() {
    for protobuf in [false, true] {
        for direction in [
            PacketDirection::ClientToServer,
            PacketDirection::ServerToClient,
        ] {
            for end in [false, true] {
                let mut info = perf_message(protobuf, direction, end);
                let cache = LogCache::from(&info);
                let flags = cache
                    .multi_merge_info
                    .expect("multi-message CustomInfo needs cache completion flags");
                assert_eq!(
                    flags.req_end,
                    end && direction == PacketDirection::ClientToServer
                );
                assert_eq!(
                    flags.resp_end,
                    end && direction == PacketDirection::ServerToClient
                );
                assert!(!flags.merged);
                info.need_protocol_merge = false;
                assert!(LogCache::from(&info).multi_merge_info.is_none());
            }
        }
    }
}

#[test]
fn custom_perf_counts_complete_messages_and_removes_closed_cache_entry() {
    for protobuf in [false, true] {
        for reversed in [false, true] {
            let packet = MetaPacket::default();
            let cache = Rc::new(RefCell::new(L7PerfCache::new(16)));
            let mut param = ParseParam::new(
                &packet,
                Some(cache.clone()),
                Default::default(),
                #[cfg(any(target_os = "linux", target_os = "android"))]
                Default::default(),
                true,
                true,
            );
            param.flow_id = 123;
            param.time = 100;
            param.rrt_timeout = 1000;
            param.direction = PacketDirection::ClientToServer;
            let key = LogCacheKey::new(&param, Some(777), reversed);
            let other_direction_key = LogCacheKey::new(&param, Some(777), !reversed);
            let mut first = perf_message(protobuf, param.direction, false);
            first.is_reversed = Some(reversed);
            let stats = first.perf_stats(&param).unwrap();
            assert_eq!(
                (stats.request_count, stats.response_count, stats.rrt_count),
                (0, 0, 0)
            );
            assert_eq!(cached_ends(&cache, key), Some((false, false, false)));
            assert!(cache
                .borrow_mut()
                .rrt_cache
                .get(&other_direction_key)
                .is_none());

            param.time = 110;
            let mut request_end = perf_message(protobuf, param.direction, true);
            request_end.is_reversed = Some(reversed);
            let stats = request_end.perf_stats(&param).unwrap();
            assert_eq!(
                (stats.request_count, stats.response_count, stats.rrt_count),
                (1, 0, 0)
            );
            assert_eq!(cached_ends(&cache, key), Some((true, false, false)));

            param.time = 150;
            param.direction = PacketDirection::ServerToClient;
            let mut response_end = perf_message(protobuf, param.direction, true);
            response_end.is_reversed = Some(reversed);
            let stats = response_end.perf_stats(&param).unwrap();
            assert_eq!(
                (stats.request_count, stats.response_count, stats.rrt_count),
                (0, 1, 1)
            );
            assert_eq!(stats.rrt_sum, 50); // First request chunk, not the final chunk.
            assert!(cache.borrow_mut().rrt_cache.get(&key).is_none());
        }
    }
}

#[test]
fn custom_async_completion_avoids_session_cache_and_retains_flags() {
    for protobuf in [false, true] {
        let packet = MetaPacket::default();
        let cache = Rc::new(RefCell::new(L7PerfCache::new(16)));
        let mut param = ParseParam::new(
            &packet,
            Some(cache.clone()),
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            true,
            true,
        );
        param.time = 100;
        param.flow_id = 456;
        let mut info = perf_message(protobuf, PacketDirection::ClientToServer, true);
        info.is_async = Some(true);
        info.is_reversed = Some(true);
        assert!(!info.needs_session_aggregation());
        assert!(info.is_reversed());
        let stats = info.perf_stats(&param).unwrap();
        assert_eq!(
            (stats.request_count, stats.response_count, stats.rrt_count),
            (1, 0, 0)
        );
        let key = LogCacheKey::new(&param, Some(777), true);
        assert!(cache.borrow_mut().rrt_cache.get(&key).is_none());
        assert_eq!(info.is_async, Some(true));
        assert_eq!(info.is_reversed, Some(true));
    }
}

// SDK 411f8d47 (2023-08-31) writes merge flags immediately after request or
// response fields: neither a protocol string nor a business-type trailer.
fn pre_protocol_string_message(
    direction: PacketDirection,
    trace: bool,
    attributes: bool,
    merge: bool,
) -> Vec<u8> {
    let mut wire = header(true);
    match direction {
        PacketDirection::ClientToServer => {
            for value in ["GET", "endpoint", "example.invalid", "/resource"] {
                string(&mut wire, value);
            }
        }
        PacketDirection::ServerToClient => {
            wire.extend_from_slice(&[0, 1]);
            wire.extend_from_slice(&200u32.to_be_bytes());
            for value in ["result", "exception"] {
                string(&mut wire, value);
            }
        }
    }
    wire.push(if merge { 0x81 } else { 0 });
    wire.push(u8::from(trace));
    if trace {
        for value in ["trace", "span", "parent"] {
            string(&mut wire, value);
        }
    }
    wire.push(u8::from(attributes));
    if attributes {
        for (key, value) in [("empty", ""), ("tag", "value")] {
            string(&mut wire, key);
            string(&mut wire, value);
        }
    }
    wire
}

#[test]
fn pre_protocol_string_request_response_and_all_prefixes_are_supported() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        for trace in [false, true] {
            for attributes in [false, true] {
                for merge in [false, true] {
                    let wire = pre_protocol_string_message(direction, trace, attributes, merge);
                    let info = CustomInfo::try_from((wire.as_slice(), direction)).unwrap();
                    assert_eq!(info.request_id, Some(777));
                    assert_eq!(info.req_len, Some(123));
                    assert_eq!(info.resp_len, Some(456));
                    assert!(info.proto_str.is_empty());
                    assert_eq!(info.biz_type, 0);
                    assert_eq!(info.need_protocol_merge, merge);
                    assert_eq!(
                        info.is_req_end,
                        merge && direction == PacketDirection::ClientToServer
                    );
                    assert_eq!(
                        info.is_resp_end,
                        merge && direction == PacketDirection::ServerToClient
                    );
                    assert_eq!(info.attributes.len(), if attributes { 2 } else { 0 });
                    assert_eq!(info.trace.trace_ids.len(), usize::from(trace));
                    if direction == PacketDirection::ClientToServer {
                        assert_eq!(info.req.resource, "/resource");
                    } else {
                        assert_eq!(info.resp.code, Some(200));
                        assert_eq!(info.resp.result, "result");
                    }
                    for length in 0..=wire.len() {
                        assert!(catch_unwind(|| CustomInfo::try_from((
                            &wire[..length],
                            direction
                        )))
                        .is_ok());
                    }
                }
            }
        }
    }
}

#[test]
fn pre_protocol_string_minimal_old_layout_has_no_optional_field_guessing() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        let mut wire = header(false);
        match direction {
            PacketDirection::ClientToServer => {
                for _ in 0..4 {
                    string(&mut wire, "");
                }
            }
            PacketDirection::ServerToClient => {
                wire.extend_from_slice(&[0, 0]);
                string(&mut wire, "");
                string(&mut wire, "");
            }
        }
        wire.extend_from_slice(&[0, 0, 0]); // no merge, no trace, no attributes
        let info = CustomInfo::try_from((wire.as_slice(), direction)).unwrap();
        assert!(
            !info.need_protocol_merge && info.request_id.is_none() && info.proto_str.is_empty()
        );
    }
}

#[test]
fn pre_protocol_string_fallback_rejects_noncanonical_flags_and_incomplete_tails() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        let wire = pre_protocol_string_message(direction, true, false, true);
        let merge_offset = wire.len() - (1 + 1 + 7 + 6 + 8 + 1);
        for bad in [1, 2, 0x82, 0xff] {
            let mut malformed = wire.clone();
            malformed[merge_offset] = bad;
            assert!(CustomInfo::try_from((malformed.as_slice(), direction)).is_err());
        }
        let mut malformed = wire.clone();
        malformed[merge_offset + 1] = 2;
        assert!(CustomInfo::try_from((malformed.as_slice(), direction)).is_err());
        let mut malformed = wire.clone();
        *malformed.last_mut().unwrap() = 2;
        assert!(CustomInfo::try_from((malformed.as_slice(), direction)).is_err());
        let mut malformed = wire;
        malformed.extend_from_slice(&[0xff, 0xff]);
        assert!(CustomInfo::try_from((malformed.as_slice(), direction)).is_err());
    }
}

#[test]
fn pre_protocol_string_2023_layout_rejects_a_business_trailer() {
    for direction in [
        PacketDirection::ClientToServer,
        PacketDirection::ServerToClient,
    ] {
        let mut minimal = header(false);
        match direction {
            PacketDirection::ClientToServer => {
                for _ in 0..4 {
                    string(&mut minimal, "");
                }
            }
            PacketDirection::ServerToClient => {
                minimal.extend_from_slice(&[0, 0]);
                string(&mut minimal, "");
                string(&mut minimal, "");
            }
        }
        minimal.extend_from_slice(&[0, 0, 0, 0]); // Old flags plus an invalid extra byte.
                                                  // This is truncated as current layout and has trailing data as 2023.
        assert!(CustomInfo::try_from((minimal.as_slice(), direction)).is_err());
        let mut attributes = pre_protocol_string_message(direction, true, true, true);
        attributes.push(7); // Old uncounted KV block must consume every byte.
        assert!(CustomInfo::try_from((attributes.as_slice(), direction)).is_err());
    }
}
