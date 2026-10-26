/*
 * Copyright (c) 2025 Yunshan Networks
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

use nom::FindSubstring;

use public::codecs::hessian2::{consts::*, Hessian2Decoder};

use super::consts::*;
use super::{DubboInfo, BODY_PARAM_MAX, BODY_PARAM_MIN};

use crate::config::handler::{L7LogDynamicConfig, TraceType};

cfg_if::cfg_if! {
if #[cfg(feature = "enterprise")] {
        use enterprise_utils::l7::custom_policy::{
            custom_field_policy::enums::{PayloadType, Source},
        };
        use super::CustomFieldContext;
    }
}

// Validate the complete envelope before calling the shared ASCII-only codec.
// Hessian lengths count UTF-16 units: bytes and units coincide only for ASCII.
// In particular, an R chunk must be followed by another complete string chunk.
fn complete_ascii_string_len(payload: &[u8], index: usize) -> Option<usize> {
    let mut start = index;
    loop {
        let tag = *payload.get(start)?;
        start = start.checked_add(1)?;
        let len = match tag {
            BC_STRING_DIRECT..=STRING_DIRECT_MAX => tag as usize,
            BC_STRING_SHORT..=BC_STRING_SHORT_MAX => {
                let low = *payload.get(start)? as usize;
                start = start.checked_add(1)?;
                (((tag - BC_STRING_SHORT) as usize) << 8) + low
            }
            BC_STRING_CHUNK | BC_STRING => {
                let high = *payload.get(start)? as usize;
                let low = *payload.get(start.checked_add(1)?)? as usize;
                start = start.checked_add(2)?;
                (high << 8) + low
            }
            _ => return None,
        };
        let end = start.checked_add(len)?;
        if !payload.get(start..end)?.is_ascii() {
            return None;
        }
        start = end;
        if tag != BC_STRING_CHUNK {
            return Some(start - index);
        }
    }
}

fn lookup_str(payload: &[u8], trace_type: &TraceType) -> Option<String> {
    let tag = match trace_type {
        TraceType::Sw3 | TraceType::Sw8 | TraceType::CloudWise | TraceType::Customize(_) => {
            trace_type.as_str()
        }
        _ => return None,
    };

    // Empty selectors would never advance the substring search. Non-ASCII
    // selectors cannot use the byte-length check of this best-effort lookup.
    if tag.is_empty() || !tag.is_ascii() || tag.len() > payload.len() {
        return None;
    }

    let mut start = 0;
    while start < payload.len() {
        if !payload[start].is_ascii() {
            break;
        }
        let Some(index) = (&payload[start..]).find_substring(tag) else {
            break;
        };
        // Keep the existing best-effort adjacent key/value search.
        if index == 0 || tag.len() != payload[start + index - 1] as usize {
            start += index + tag.len();
            continue;
        }

        let value_index = start + index + tag.len();
        if let Some(expected_len) = complete_ascii_string_len(payload, value_index) {
            if let Some((context, actual_len)) =
                Hessian2Decoder::decode_string(payload, value_index)
            {
                if actual_len == expected_len {
                    return Some(context);
                }
            }
        }
        start += index + tag.len();
    }
    return None;
}

// 注意 dubbo trace id 解析是区分大小写的
fn decode_trace_ids(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(trace_id) = lookup_str(payload, trace_type) {
        info.add_trace_id(trace_id, trace_type);
    }
}

fn decode_span_id(payload: &[u8], trace_type: &TraceType, info: &mut DubboInfo) {
    if let Some(span_id) = lookup_str(payload, trace_type) {
        info.set_span_id(span_id, trace_type);
    }
}

// 参考开源代码解析：https://github.com/apache/dubbo-go-hessian2/blob/master/decode.go#L289
// https://github.com/apache/dubbo-go-hessian2/blob/v2.0.0/string.go#L169
// 返回offset和数据length
fn get_req_param_len(payload: &[u8]) -> (usize, usize) {
    let tag = payload[0];
    match tag {
        BC_STRING_DIRECT..=STRING_DIRECT_MAX => (1, tag as usize),
        BC_STRING_SHORT..=BC_STRING_SHORT_MAX if payload.len() > 2 => {
            (2, ((tag as usize - 0x30) << 8) + payload[1] as usize)
        }
        BC_STRING_CHUNK | BC_STRING if payload.len() > 3 => {
            (3, ((payload[1] as usize) << 8) + payload[2] as usize)
        }
        _ => (0, 0),
    }
}

// 尽力而为的去解析Dubbo请求中Body各参数
// 解析逻辑：https://github.com/apache/dubbo-go/blob/v3.3.0/protocol/dubbo/impl/hessian.go
pub fn get_req_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    #[cfg(feature = "enterprise")] cf_ctx: CustomFieldContext<'_>,
) {
    let mut n = BODY_PARAM_MIN;
    let mut para_index = 0;
    let payload_len = payload.len();

    while n < BODY_PARAM_MAX && para_index < payload_len {
        let (offset, para_len) = get_req_param_len(&payload[para_index..]);
        para_index += offset;
        if para_len == 0 || para_len + para_index > payload_len {
            return;
        }

        match n {
            BODY_PARAM_DUBBO_VERSION => {
                info.dubbo_version =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned()
            }
            BODY_PARAM_SERVICE_NAME => {
                info.service_name =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            BODY_PARAM_SERVICE_VERSION => {
                info.service_version =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            BODY_PARAM_METHOD_NAME => {
                info.method_name =
                    String::from_utf8_lossy(&payload[para_index..para_index + para_len])
                        .into_owned();
            }
            _ => return,
        }

        para_index += para_len;
        if payload_len <= para_index {
            return;
        }
        n += 1;
    }

    if config.trace_types.is_empty() || para_index >= payload.len() {
        return;
    }

    for trace_type in config.trace_types.iter() {
        if trace_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_trace_ids(&payload[para_index..], &trace_type, info);
        if !config.multiple_trace_id_collection && !info.trace_ids.is_empty() {
            break;
        }
    }
    for span_type in config.span_types.iter() {
        if span_type.as_str().len() > u8::MAX as usize {
            continue;
        }

        decode_span_id(&payload[para_index..], &span_type, info);
        if info.span_id.get().len() != 0 {
            break;
        }
    }

    #[cfg(feature = "enterprise")]
    apply_custom_field_policies(payload, info, cf_ctx);
}

#[allow(unused_variables)]
pub fn get_resp_body_info(
    config: &L7LogDynamicConfig,
    payload: &[u8],
    info: &mut DubboInfo,
    #[cfg(feature = "enterprise")] cf_ctx: CustomFieldContext<'_>,
) {
    #[cfg(feature = "enterprise")]
    apply_custom_field_policies(payload, info, cf_ctx);
}

#[cfg(feature = "enterprise")]
fn apply_custom_field_policies(
    payload: &[u8],
    info: &DubboInfo,
    mut cf_ctx: CustomFieldContext<'_>,
) {
    if let Some(policies) = cf_ctx.policies {
        policies.apply(
            &mut cf_ctx.store,
            info,
            cf_ctx.direction.into(),
            Source::Payload(PayloadType::HESSIAN2, payload),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::flow_generator::protocol_logs::rpc::dubbo::TraceType;
    use crate::flow_generator::protocol_logs::DubboInfo;

    fn lookup(payload: &[u8]) -> Option<String> {
        super::lookup_str(payload, &TraceType::Customize("x-g-rid".to_string()))
    }

    #[test]
    fn decode_trace_id() {
        // Independently encoded Hessian2 untyped map: short key, 40-character value.
        let payload = b"H\x07x-g-rid\x30\x2838bafe668c2bedb6d3d2b50fcf17a7345210bf14Z";
        let trace_type = TraceType::Customize("x-g-rid".to_string());
        let mut info = DubboInfo::default();
        super::decode_trace_ids(payload, &trace_type, &mut info);
        assert_eq!(
            info.trace_ids.to_strings(),
            vec!["38bafe668c2bedb6d3d2b50fcf17a7345210bf14"]
        );
    }

    #[test]
    fn reject_java_string_encoding() {
        // Original failing vector: Java TC_STRING (0x74), not Hessian2.
        // dubbo::tests::decode_java_trace_id keeps the same vector's Java success contract.
        let payload =
            b"\x74\x00\x07x-g-rid\x74\x00\x2838bafe668c2bedb6d3d2b50fcf17a7345210bf14\x00\x00";
        assert_eq!(lookup(payload), None);
    }

    #[test]
    fn lookup_rejects_missing_value() {
        assert_eq!(lookup(b"\x07x-g-rid"), None);
    }

    #[test]
    fn lookup_rejects_truncated_strings() {
        let values: &[&[u8]] = &[
            b"\x30",
            b"\x30\x28",
            b"S",
            b"S\x00",
            b"S\x00\x05abc",
            b"\x05ab",
            b"R\x00\x03abc",
            b"R\x00\x03abcS\x00\x04xy",
            b"R\x00\x03abcZ",
            b"R\xff\xffa",
        ];
        for value in values {
            let mut payload = b"\x07x-g-rid".to_vec();
            payload.extend_from_slice(value);
            assert_eq!(lookup(&payload), None, "value={value:02x?}");
        }
    }

    #[test]
    fn lookup_accepts_complete_ascii_strings() {
        let values: &[(&[u8], &str)] = &[
            (b"\x05hello", "hello"),
            (b"\x30\x05hello", "hello"),
            (b"S\x00\x05hello", "hello"),
            (b"R\x00\x02he\x03llo", "hello"),
            (b"R\x00\x02heR\x00\x02ll\x01o", "hello"),
            (b"\x00", ""),
        ];
        for (value, expected) in values {
            let mut payload = b"\x07x-g-rid".to_vec();
            payload.extend_from_slice(value);
            assert_eq!(lookup(&payload).as_deref(), Some(*expected));
        }
    }

    #[test]
    fn lookup_key_length_and_next_pair() {
        for payload in [
            &b"H\x06x-g-rid\x05wrongZ"[..],
            &b"H\x30\x06x-g-rid\x05wrongZ"[..],
            &b"HS\x00\x06x-g-rid\x05wrongZ"[..],
            &b"H\x07x-g-ridN\x05other\x05wrongZ"[..],
        ] {
            assert_eq!(lookup(payload), None, "payload={payload:02x?}");
        }
        // A non-string value for one occurrence must not hide a later valid pair.
        assert_eq!(
            lookup(b"H\x07x-g-ridN\x05other\x05wrong\x07x-g-rid\x05rightZ").as_deref(),
            Some("right")
        );
    }

    #[test]
    fn lookup_unicode_values_remain_safely_unsupported() {
        // Lengths count UTF-16 units. These complete BMP/CESU-8 vectors are
        // valid Hessian, but the shared codec intentionally accepts ASCII only.
        for value in [
            &b"\x01\xc3\xa9"[..],
            &b"\x02\xed\xa0\xbd\xed\xb8\x80"[..],
            &b"R\x00\x01\xc3\xa9\x01a"[..],
        ] {
            let mut payload = b"\x07x-g-rid".to_vec();
            payload.extend_from_slice(value);
            assert_eq!(lookup(&payload), None);
        }
    }

    #[test]
    fn lookup_selector_bounds() {
        for selector in ["".to_string(), "x".repeat(65536), "\u{e9}".to_string()] {
            assert_eq!(
                super::lookup_str(b"\x07x-g-rid\x05hello", &TraceType::Customize(selector)),
                None
            );
        }
    }

    #[test]
    fn lookup_rejects_every_truncated_chunk_prefix() {
        let key = b"\x07x-g-rid";
        let value = b"R\x00\x02heR\x00\x02ll\x01o";
        let mut complete = key.to_vec();
        complete.extend_from_slice(value);
        for end in 0..complete.len() {
            assert_eq!(lookup(&complete[..end]), None, "prefix length {end}");
        }
        assert_eq!(lookup(&complete).as_deref(), Some("hello"));
    }
}
