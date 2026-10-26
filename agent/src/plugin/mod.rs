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

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod c_ffi;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod shared_obj;
pub mod wasm;

use prost::Message;
use public::{
    bytes::read_u32_be,
    counter::Countable,
    l7_protocol::{L7Protocol, LogMessageType},
};
use serde::Serialize;

use crate::{
    common::{
        flow::PacketDirection,
        l7_protocol_info::{L7ProtocolInfo, L7ProtocolInfoInterface},
        l7_protocol_log::{LogCache, MultiMergeInfo},
    },
    config::handler::LogParserConfig,
    flow_generator::{
        protocol_logs::{
            pb_adapter::{
                ExtendedInfo, KeyVal, L7ProtocolSendLog, L7Request, L7Response, MetricKeyVal,
                TraceInfo,
            },
            swap_if, L7ResponseStatus,
        },
        AppProtoHead, Error,
    },
};

use self::wasm::{read_wasm_str, wasm_plugin as pb};

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoRequest {
    pub version: String,
    pub req_type: String,
    pub domain: String,
    pub resource: String,
    pub endpoint: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoResp {
    pub status: L7ResponseStatus,
    pub code: Option<i32>,
    pub exception: String,
    pub result: String,
    pub req_type: String,
    pub endpoint: String,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfoTrace {
    pub trace_ids: Vec<String>,
    pub span_id: Option<String>,
    pub parent_span_id: Option<String>,
    pub x_request_id_0: Option<String>,
    pub x_request_id_1: Option<String>,
    pub http_proxy_client: Option<String>,
}

#[derive(Debug, Default, Serialize, Clone)]
pub struct CustomInfo {
    // fields populated by crate::flow_generator::protocol_logs::plugin::wasm::WasmLog
    #[serde(skip)]
    pub(super) proto: u8,
    pub(super) proto_str: String,
    pub(super) msg_type: LogMessageType,
    #[serde(skip)]
    pub(super) rrt: u64,

    pub captured_request_byte: u32,
    pub captured_response_byte: u32,

    // all the following fields are populated by data from wasm plugin
    pub req_len: Option<u32>,
    pub resp_len: Option<u32>,

    pub request_id: Option<u32>,

    pub req: CustomInfoRequest,

    pub resp: CustomInfoResp,

    pub trace: CustomInfoTrace,

    pub need_protocol_merge: bool,
    pub is_req_end: bool,
    pub is_resp_end: bool,

    #[serde(skip)]
    pub attributes: Vec<KeyVal>,

    #[serde(skip)]
    pub metrics: Vec<MetricKeyVal>,

    pub biz_type: u8,
    pub biz_code: Option<String>,
    pub biz_scenario: Option<String>,
    pub biz_response_code: Option<String>,

    #[serde(skip)]
    pub is_on_blacklist: bool,

    pub is_async: Option<bool>,
    pub is_reversed: Option<bool>,
}

impl CustomInfo {
    /*
        req len:        4 bytes: | 1 bit: is nil? | 31bit length |

        resp len:       4 bytes: | 1 bit: is nil? | 31bit length |

        has request id: 1 bytes:  0 or 1

        if has request id:

            request	id: 4 bytes

        if direction is c2s:

            ReqType, Endpoint, Domain, Resource
            (

                len:    2 bytes
                val:    $(len) bytes

            ) x 4

        if direction is s2c:

            status:     1 byte,
            has code:   1 byte, 0 or 1,

            if has code:

                code:   4 bytes,


            Result, Exception
            (

                len:    2 bytes
                val:    $(len) bytes

            ) x 2

        post-April-2024 layout only:
            l7_protocol_str len: 2 bytes
            l7_protocol_str: $(l7_protocol_str len) bytes
        older layout: these two fields are absent

        need_protocol_merge: 1 byte, the msb indicate is need protocol merge, the lsb indicate is end, such as 1 000000 1

        has trace: 1 byte

        if has trace:

            trace_id, span_id, parent_span_id
            (
                len: 2 bytes
                val: $(len) bytes
            ) x 3
            // The legacy layout carries one trace ID; protobuf also supports
            // repeated trace_ids.

        has kv:  1 byte
        if has kv
            (
                key len: 2 bytes
                key:     $(key len) bytes

                val len: 2 bytes
                val:     $(val len) bytes

            ) x len(kv)

        current layout: optional biz type, 1 byte (absent means 0)
        proven 2023 layout: no biz type; the KV section consumes through EOF

        The current-layout KV section has no pair count. After complete pairs, a single
        remaining byte is the business type. It cannot be distinguished from
        a truncated next string-length prefix; do not guess other extensions.
        Two or more remaining bytes must form another complete key/value pair
        when has kv is 1. Incomplete pairs are errors, not business-type data.
    */
    fn from_legacy_protocol(buf: &[u8], dir: PacketDirection) -> Result<Self, Error> {
        // The SDK added protocol_str in April 2024 without a format version.
        // Prefer that layout, then try the complete pre-2024 layout once.
        // A byte sequence valid under both is inherently ambiguous; current
        // layout wins. Each attempt validates all flags and consumes the tail.
        Self::from_legacy_protocol_layout(buf, dir, true)
            .or_else(|_| Self::from_legacy_protocol_layout(buf, dir, false))
    }

    fn from_legacy_protocol_layout(
        buf: &[u8],
        dir: PacketDirection,
        has_protocol_str: bool,
    ) -> Result<Self, Error> {
        let mut off = 0;
        let mut info = Self::default();
        if buf.len() < 9 {
            return Err(Error::WasmSerializeFail("buf len too short".to_string()));
        }

        if buf[off] >> 7 != 0 {
            let req_len = read_u32_be(&buf[off..off + 4]);
            info.req_len = Some(req_len & (i32::MAX as u32))
        }
        off += 4;

        if buf[off] >> 7 != 0 {
            let resp_len = read_u32_be(&buf[off..off + 4]);
            info.resp_len = Some(resp_len & (i32::MAX as u32))
        }
        off += 4;

        // parse request id
        match buf[off] {
            0 => off += 1,
            1 => {
                off += 1;
                if off + 4 > buf.len() {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse request id".to_string(),
                    ));
                }
                info.request_id = Some(read_u32_be(&buf[off..off + 4]));
                off += 4
            }
            _ => {
                return Err(Error::WasmSerializeFail(
                    "has request_id must 0 or 1".to_string(),
                ))
            }
        }

        match dir {
            PacketDirection::ClientToServer => {
                // parse req
                if read_wasm_str(buf, &mut off)
                    .and_then(|s| {
                        info.req.req_type = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.endpoint = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.domain = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.req.resource = s;
                        Some(())
                    })
                    .is_none()
                {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse request".to_string(),
                    ));
                }
            }
            PacketDirection::ServerToClient => {
                // parse resp
                let status = *buf.get(off).ok_or_else(|| {
                    Error::WasmSerializeFail(
                        "buf len too short when parse response status".to_string(),
                    )
                })?;
                match status {
                    0 => info.resp.status = L7ResponseStatus::Ok,
                    2 => info.resp.status = L7ResponseStatus::Timeout,
                    3 => info.resp.status = L7ResponseStatus::ServerError,
                    4 => info.resp.status = L7ResponseStatus::ClientError,
                    5 => info.resp.status = L7ResponseStatus::Unknown,
                    _ => {
                        return Err(Error::WasmSerializeFail(
                            "recv unexpected status ".to_string(),
                        ))
                    }
                }
                off += 1;
                let has_code = *buf.get(off).ok_or_else(|| {
                    Error::WasmSerializeFail(
                        "buf len too short when parse has response code".to_string(),
                    )
                })?;

                match has_code {
                    0 => off += 1,
                    1 => {
                        off += 1;
                        if off + 4 > buf.len() {
                            return Err(Error::WasmSerializeFail(
                                "buf len too short when parse response code".to_string(),
                            ));
                        }
                        info.resp.code = Some(read_u32_be(&buf[off..off + 4]) as i32);
                        off += 4;
                    }
                    _ => {
                        return Err(Error::WasmSerializeFail(
                            "recv unexpected has_code ".to_string(),
                        ))
                    }
                }

                if read_wasm_str(buf, &mut off)
                    .and_then(|s| {
                        info.resp.result = s;
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.resp.exception = s;
                        Some(())
                    })
                    .is_none()
                {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse exception and result".to_string(),
                    ));
                }
            }
        }

        if has_protocol_str {
            info.proto_str = read_wasm_str(buf, &mut off).ok_or_else(|| {
                Error::WasmSerializeFail("buf len too short when parse l7_protocol_str".to_string())
            })?;
        }

        // need_protocol_merge
        if off + 1 > buf.len() {
            return Err(Error::WasmSerializeFail(
                "buf len too short when parse need protocol merge".to_string(),
            ));
        }
        if !matches!(buf[off], 0 | 0x80 | 0x81) {
            return Err(Error::WasmSerializeFail(
                "invalid legacy merge flags".to_string(),
            ));
        }
        info.need_protocol_merge = buf[off] & 128 != 0;

        if info.need_protocol_merge {
            let is_end = buf[off] & 1 != 0;
            match dir {
                PacketDirection::ClientToServer => info.is_req_end = is_end,
                PacketDirection::ServerToClient => info.is_resp_end = is_end,
            }
        }
        off += 1;

        // trace info
        if off + 1 > buf.len() {
            return Err(Error::WasmSerializeFail(
                "buf len too short when parse has trace info".to_string(),
            ));
        }
        let has_trace = buf[off];
        off += 1;
        match has_trace {
            0 => {}
            1 => {
                if read_wasm_str(buf, &mut off)
                    .and_then(|s| {
                        merge_trace_ids(&mut info.trace.trace_ids, &vec![s]);
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.trace.span_id = Some(s);
                        read_wasm_str(buf, &mut off)
                    })
                    .and_then(|s| {
                        info.trace.parent_span_id = Some(s);
                        Some(())
                    })
                    .is_none()
                {
                    return Err(Error::WasmSerializeFail(
                        "buf len too short when parse trace info".to_string(),
                    ));
                }
            }
            _ => {
                return Err(Error::WasmSerializeFail(
                    "has trace return unexpected value".to_string(),
                ));
            }
        }

        // key val
        if off + 1 > buf.len() {
            return Err(Error::WasmSerializeFail(
                "buf len too short when parse key val".to_string(),
            ));
        }
        let has_kv = buf[off];
        off += 1;

        match has_kv {
            0 => {}
            1 => {
                // The proven 2023 layout has no business-type trailer.
                // Only the current layout may reserve a single final byte.
                let trailer_len = usize::from(has_protocol_str);
                while buf.len() - off > trailer_len {
                    let key = read_wasm_str(buf, &mut off).ok_or_else(|| {
                        Error::WasmSerializeFail(
                            "buf len too short when parse attribute key".to_string(),
                        )
                    })?;
                    let val = read_wasm_str(buf, &mut off).ok_or_else(|| {
                        Error::WasmSerializeFail(
                            "buf len too short when parse attribute value".to_string(),
                        )
                    })?;
                    info.attributes.push(KeyVal { key, val });
                }
            }
            _ => {
                return Err(Error::WasmSerializeFail(
                    "has kv return unexpected value".to_string(),
                ))
            }
        }

        // SDKs predating the business-type extension end immediately after
        // trace/KV data. Preserve their default rather than rejecting the log.
        match (has_protocol_str, &buf[off..]) {
            (_, []) => {}
            (true, [biz_type]) => info.biz_type = *biz_type,
            _ => {
                return Err(Error::WasmSerializeFail(
                    "unexpected trailing bytes after legacy attributes".to_string(),
                ))
            }
        }

        Ok(info)
    }

    fn from_protobuf(buf: &[u8], dir: PacketDirection) -> Result<Self, Error> {
        let pb_info = match pb::AppInfo::decode(buf) {
            Ok(info) => info,
            Err(e) => {
                return Err(Error::WasmSerializeFail(format!(
                    "decode protobuf failed: {e:?}"
                )))
            }
        };

        let mut info = Self {
            req_len: pb_info.req_len,
            resp_len: pb_info.resp_len,
            request_id: pb_info.request_id,
            proto_str: pb_info.protocol_str.unwrap_or_default(),
            need_protocol_merge: pb_info.is_end.is_some(),
            is_req_end: match pb_info.is_end {
                Some(true) => dir == PacketDirection::ClientToServer,
                _ => false,
            },
            is_resp_end: match pb_info.is_end {
                Some(true) => dir == PacketDirection::ServerToClient,
                _ => false,
            },
            attributes: pb_info
                .attributes
                .into_iter()
                .map(|k| KeyVal {
                    key: k.key,
                    val: k.val,
                })
                .collect(),
            biz_type: pb_info.biz_type.unwrap_or_default() as u8,
            biz_code: pb_info.biz_code,
            biz_scenario: pb_info.biz_scenario,
            biz_response_code: pb_info.biz_response_code,
            is_async: pb_info.is_async,
            is_reversed: pb_info.is_reversed,
            ..Default::default()
        };
        match pb_info.info {
            Some(pb::app_info::Info::Req(r)) => {
                info.req = CustomInfoRequest {
                    version: r.version.unwrap_or_default(),
                    req_type: r.r#type.unwrap_or_default(),
                    domain: r.domain.unwrap_or_default(),
                    resource: r.resource.unwrap_or_default(),
                    endpoint: r.endpoint.unwrap_or_default(),
                };
            }
            Some(pb::app_info::Info::Resp(r)) => {
                info.resp = CustomInfoResp {
                    status: match r.status.and_then(|s| pb::AppRespStatus::try_from(s).ok()) {
                        Some(pb::AppRespStatus::RespOk) => L7ResponseStatus::Ok,
                        Some(pb::AppRespStatus::RespTimeout) => L7ResponseStatus::Timeout,
                        Some(pb::AppRespStatus::RespServerError) => L7ResponseStatus::ServerError,
                        Some(pb::AppRespStatus::RespClientError) => L7ResponseStatus::ClientError,
                        Some(pb::AppRespStatus::RespUnknown) => L7ResponseStatus::Unknown,
                        _ => {
                            return Err(Error::WasmSerializeFail(
                                "unexpected resp status".to_string(),
                            ))
                        }
                    },
                    code: r.code,
                    result: r.result.unwrap_or_default(),
                    exception: r.exception.unwrap_or_default(),
                    req_type: r.r#type.unwrap_or_default(),
                    endpoint: r.endpoint.unwrap_or_default(),
                };
            }
            _ => (),
        }
        if let Some(t) = pb_info.trace {
            info.trace = CustomInfoTrace {
                trace_ids: t.trace_ids,
                span_id: t.span_id,
                parent_span_id: t.parent_span_id,
                http_proxy_client: t.http_proxy_client,
                ..Default::default()
            };
            // add trace_id to trace_ids
            if let Some(trace_id) = t.trace_id {
                if !info.trace.trace_ids.contains(&trace_id) {
                    info.trace.trace_ids.push(trace_id.to_string());
                }
            }
            match dir {
                PacketDirection::ClientToServer => {
                    info.trace.x_request_id_0 = t.x_request_id;
                }
                PacketDirection::ServerToClient => {
                    info.trace.x_request_id_1 = t.x_request_id;
                }
            }
        }
        Ok(info)
    }

    pub fn set_is_on_blacklist(&mut self, config: &LogParserConfig) {
        if let Some(t) = config.l7_log_blacklist_trie.get(&L7Protocol::Custom) {
            self.is_on_blacklist = t.request_type.is_on_blacklist(&self.req.req_type)
                || t.request_resource.is_on_blacklist(&self.req.resource)
                || t.endpoint.is_on_blacklist(&self.req.endpoint)
                || t.request_domain.is_on_blacklist(&self.req.domain);
        }
    }
}

impl TryFrom<(&[u8], PacketDirection)> for CustomInfo {
    type Error = Error;

    fn try_from(f: (&[u8], PacketDirection)) -> std::result::Result<Self, Self::Error> {
        let (buf, dir) = f;

        // the legacy protocol starts with
        //     req len:        4 bytes: | 1 bit: is nil? | 31bit length |
        //
        // so in the legacy protocol, the first byte will not have the first bit as 0 and other bits as 1
        // we put a magic `PB` in front to represent protobuf serialized data
        if buf.len() >= 2 && &buf[..2] == b"PB" {
            Self::from_protobuf(&buf[2..], dir)
        } else {
            Self::from_legacy_protocol(buf, dir)
        }
    }
}

fn merge_trace_ids(a: &mut Vec<String>, b: &Vec<String>) {
    for item in b {
        if !a.contains(item) {
            a.push(item.clone());
        }
    }
}

impl L7ProtocolInfoInterface for CustomInfo {
    fn session_id(&self) -> Option<u32> {
        self.request_id
    }

    fn merge_log(&mut self, other: &mut L7ProtocolInfo) -> crate::flow_generator::Result<()> {
        if let L7ProtocolInfo::CustomInfo(w) = other {
            // req merge
            swap_if!(self.req, version, is_empty, w.req);
            swap_if!(self.req, req_type, is_empty, w.req);
            swap_if!(self.req, domain, is_empty, w.req);
            swap_if!(self.req, resource, is_empty, w.req);
            swap_if!(self.req, endpoint, is_empty, w.req);

            if self.req_len.is_none() {
                self.req_len = w.req_len;
            }

            if w.is_req_end {
                self.is_req_end = true;
            }
            self.captured_request_byte += w.captured_request_byte;

            // resp merge
            if self.resp.status == L7ResponseStatus::default() {
                self.resp.status = w.resp.status;
            }

            if self.resp.code.is_none() {
                self.resp.code = w.resp.code;
            }

            swap_if!(self.resp, exception, is_empty, w.resp);
            swap_if!(self.resp, result, is_empty, w.resp);
            swap_if!(self.resp, req_type, is_empty, w.resp);
            swap_if!(self.resp, endpoint, is_empty, w.resp);

            if self.resp_len.is_none() {
                self.resp_len = w.resp_len;
            }

            if w.is_resp_end {
                self.is_resp_end = true;
            }
            self.captured_response_byte += w.captured_response_byte;

            // trace merge
            merge_trace_ids(&mut self.trace.trace_ids, &w.trace.trace_ids);
            swap_if!(self.trace, span_id, is_none, w.trace);
            swap_if!(self.trace, parent_span_id, is_none, w.trace);
            swap_if!(self.trace, x_request_id_0, is_none, w.trace);
            swap_if!(self.trace, x_request_id_1, is_none, w.trace);
            swap_if!(self.trace, http_proxy_client, is_none, w.trace);

            self.attributes.append(&mut w.attributes);

            swap_if!(self, biz_code, is_none, w);
            swap_if!(self, biz_scenario, is_none, w);
        }
        Ok(())
    }

    fn app_proto_head(&self) -> Option<AppProtoHead> {
        Some(AppProtoHead {
            proto: L7Protocol::Custom,
            msg_type: self.msg_type,
            rrt: self.rrt,
        })
    }

    fn needs_session_aggregation(&self) -> bool {
        // Returns true if `is_async` is None (not set) or Some(false).
        // Returns false only if `is_async` is explicitly set to Some(true).
        !self.is_async.unwrap_or(false)
    }

    fn is_tls(&self) -> bool {
        false
    }

    fn need_merge(&self) -> bool {
        self.need_protocol_merge
    }

    fn is_req_resp_end(&self) -> (bool, bool) {
        (self.is_req_end, self.is_resp_end)
    }

    fn get_endpoint(&self) -> Option<String> {
        if !self.req.endpoint.is_empty() {
            return Some(self.req.endpoint.clone());
        }
        if !self.resp.endpoint.is_empty() {
            return Some(self.resp.endpoint.clone());
        }
        return None;
    }

    fn get_biz_type(&self) -> u8 {
        self.biz_type
    }

    fn is_reversed(&self) -> bool {
        self.is_reversed.unwrap_or_default()
    }
}

impl From<CustomInfo> for L7ProtocolSendLog {
    fn from(w: CustomInfo) -> Self {
        Self {
            req_len: w.req_len,
            resp_len: w.resp_len,
            captured_request_byte: w.captured_request_byte,
            captured_response_byte: w.captured_response_byte,

            req: L7Request {
                req_type: if w.req.req_type.is_empty() {
                    w.resp.req_type
                } else {
                    w.req.req_type
                },
                domain: w.req.domain,
                resource: w.req.resource,
                endpoint: if w.req.endpoint.is_empty() {
                    w.resp.endpoint
                } else {
                    w.req.endpoint
                },
            },
            resp: L7Response {
                status: w.resp.status,
                code: w.resp.code,
                exception: w.resp.exception,
                result: w.resp.result,
            },
            trace_info: if !w.trace.trace_ids.is_empty()
                || w.trace.span_id.is_some()
                || w.trace.parent_span_id.is_some()
            {
                Some(TraceInfo {
                    trace_ids: w.trace.trace_ids,
                    span_id: w.trace.span_id,
                    parent_span_id: w.trace.parent_span_id,
                })
            } else {
                None
            },
            ext_info: Some(ExtendedInfo {
                request_id: w.request_id,
                attributes: Some(w.attributes),
                protocol_str: Some(w.proto_str),
                client_ip: w.trace.http_proxy_client,
                x_request_id_0: w.trace.x_request_id_0,
                x_request_id_1: w.trace.x_request_id_1,
                ..Default::default()
            }),
            biz_response_code: w.biz_response_code.unwrap_or_default(),
            version: if w.req.version.is_empty() {
                None
            } else {
                Some(w.req.version)
            },
            biz_code: w.biz_code.unwrap_or_default(),
            biz_scenario: w.biz_scenario.unwrap_or_default(),
            ..Default::default()
        }
    }
}

impl From<&CustomInfo> for LogCache {
    fn from(info: &CustomInfo) -> Self {
        LogCache {
            msg_type: info.msg_type,
            resp_status: info.resp.status,
            on_blacklist: info.is_on_blacklist,
            multi_merge_info: if info.need_merge() {
                Some(MultiMergeInfo {
                    req_end: info.is_req_end,
                    resp_end: info.is_resp_end,
                    merged: false,
                })
            } else {
                None
            },
            endpoint: info.get_endpoint(),
            ..Default::default()
        }
    }
}

pub struct PluginCounterInfo<'a> {
    pub plugin_name: &'a str,
    pub plugin_type: &'static str,
    pub function_name: &'static str,
    pub counter: Countable,
}

#[cfg(test)]
#[path = "legacy_protocol_regression.rs"]
mod legacy_protocol_regression;
