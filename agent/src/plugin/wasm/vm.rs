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

use std::mem::ManuallyDrop;
use std::net::IpAddr;

use crate::common::ebpf::EbpfType;
use crate::common::flow::PacketDirection;
use crate::common::l7_protocol_log::ParseParam;
use crate::flow_generator::protocol_logs::{HttpInfo, L7ResponseStatus};
use crate::flow_generator::{Error, Result};
use crate::plugin::wasm::host::WasmData;
use crate::plugin::CustomInfo;
use crate::wasm_error;

use log::error;
use public::bytes::{write_u16_be, write_u32_be, write_u64_be};
use public::enums::IpProtocol;

// result of the vm export function after serialize
#[derive(Debug)]
pub(super) enum VmResult {
    // result of parse_payload
    L7InfoResult(Vec<CustomInfo>),
    StringResult(String),
}

// vm parse ctx
pub(super) enum VmParseCtx {
    ParseCtx(VmCtxBase),
    OnCustomMessageCtx(VmOnCustomMessageCtx),
    HttpReqCtx(VmHttpReqCtx),
    HttpRespCtx(VmHttpRespCtx),
}

impl VmParseCtx {
    pub(super) fn get_ctx_base(&self) -> &VmCtxBase {
        match self {
            VmParseCtx::ParseCtx(c) => c,
            VmParseCtx::HttpReqCtx(c) => &c.base_ctx,
            VmParseCtx::HttpRespCtx(c) => &c.base_ctx,
            VmParseCtx::OnCustomMessageCtx(c) => &c.base_ctx,
        }
    }

    pub(super) fn get_ctx_base_mut(&mut self) -> &mut VmCtxBase {
        match self {
            VmParseCtx::ParseCtx(c) => c,
            VmParseCtx::HttpReqCtx(c) => &mut c.base_ctx,
            VmParseCtx::HttpRespCtx(c) => &mut c.base_ctx,
            VmParseCtx::OnCustomMessageCtx(c) => &mut c.base_ctx,
        }
    }

    pub(super) fn set_ins_name(&mut self, ins_name: String) {
        self.get_ctx_base_mut().instance_name = ins_name;
    }

    pub(super) fn get_ins_name(&self) -> &str {
        self.get_ctx_base().instance_name.as_str()
    }

    fn take_result(&mut self) -> Option<VmResult> {
        self.get_ctx_base_mut().result.take()
    }

    pub(super) fn take_l7_info_result(&mut self) -> Option<Vec<CustomInfo>> {
        self.take_result().map_or(None, |r| match r {
            VmResult::L7InfoResult(info) => Some(info),
            _ => {
                wasm_error!(
                    self.get_ins_name(),
                    "parse payload result with unexpect type",
                );
                None
            }
        })
    }

    pub(super) fn take_str_result(&mut self) -> Option<String> {
        self.take_result().map_or(None, |r| match r {
            VmResult::StringResult(s) => Some(s),
            _ => {
                wasm_error!(self.get_ins_name(), "str result with unexpect type",);
                None
            }
        })
    }

    pub(super) fn serialize_ctx_base(&self, buf: &mut [u8]) -> Result<usize> {
        self.get_ctx_base().serialize_to_bytes(buf)
    }
}

/*
    correspond to go struct ParseCtx:

    type ParseCtx struct {
        Src      net.IPAddr
        Dst      net.IPAddr
        l4       L4Protocol
        l7       uint16
        EbpfType EbpfType
        Time     uint64 // micro second
        Direction Direction
        ProcName string
        Payload  []byte
    }
*/
pub struct VmCtxBase {
    // parser ctx, set in check and parse payload
    pub(super) ip_src: IpAddr,
    pub(super) ip_dst: IpAddr,
    pub(super) port_src: u16,
    pub(super) port_dst: u16,
    pub(super) l4_protocol: IpProtocol,
    // proto is return from on_check_payload, when on_check_payload, it set to 0, other wise will set to non zero value
    pub(super) proto: u8,
    pub(super) ebpf_type: EbpfType,
    pub(super) time: u64,
    pub(super) direction: PacketDirection,
    pub(super) process_kname: Option<String>,
    pub(super) flow_id: u64,
    pub(super) buf_size: u16,

    /*
        payload is from the payload: &[u8] in L7ProtocolParserInterface::check_payload() and L7ProtocolParserInterface::parse_payload(),
        it can not modify and drop.
    */
    pub(super) payload: ManuallyDrop<Vec<u8>>,

    /*
        in every function call, traversal all instance and call correspond function in instance.
        it will set the current instance  name which calling the function, now only use for log.
    */
    instance_name: String,

    result: Option<VmResult>,
}

impl From<(&ParseParam<'_>, u8, &[u8])> for VmCtxBase {
    fn from(p: (&ParseParam<'_>, u8, &[u8])) -> Self {
        let (p, wasm_proto, payload) = p;

        #[cfg(feature = "libtrace")]
        let process_kname = if let Some(ebpf_param) = p.ebpf_param.as_ref() {
            Some(ebpf_param.process_kname.to_owned())
        } else {
            None
        };
        #[cfg(not(feature = "libtrace"))]
        let process_kname = None;
        Self {
            ip_src: p.ip_src,
            ip_dst: p.ip_dst,
            port_src: p.port_src,
            port_dst: p.port_dst,
            l4_protocol: p.l4_protocol,
            proto: wasm_proto,
            ebpf_type: p.ebpf_type,
            time: p.time,
            direction: p.direction,
            process_kname,
            flow_id: p.flow_id,
            buf_size: p.buf_size,
            /*
                it is safe to use unsafe because VmParseCtx use in check, parse or other place will drop before the function call finish.
                the lifetime of VmParseCtx always shorter than payload which from L7ProtocolParserInterface::check_payload() and L7ProtocolParserInterface::parse_payload().
                it will not modify in whole lifetime of VmParseCtx
            */
            payload: ManuallyDrop::new(unsafe {
                Vec::from_raw_parts(
                    payload.as_ptr() as usize as *mut u8,
                    payload.len(),
                    payload.len(),
                )
            }),
            instance_name: "".to_string(),

            result: None,
        }
    }
}

impl VmCtxBase {
    /*
        serial format as follow, be encode

        ip type:     1 byte, 4 and 6 indicate  ipv4/ipv6
        src_ip:      4/16 bytes
        dst_ip:      4/16 bytes
        src_port:    2 bytes
        dst_port:    2 bytes

        l4 protocol: 1 byte, 6/17 indicate udp/tcp
        l7 protocol: 1 byte

        ebpf type:   1 byte

        time:        8 bytes

        direction:   1 byte, 0/1 indicate c2s/s2c

        proc name len:  1 byte

        proc name: 		$(proc name len) len

        flow_id:     8 bytes

        buf_size:    2 bytes, the config of l7_log_packet_size
    */
    fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let serialize_len = if self.ip_src.is_ipv6() { 32 } else { 8 }
            + 28
            + if let Some(proc_name) = self.process_kname.as_ref() {
                proc_name.len()
            } else {
                0
            };
        if buf.len() < serialize_len {
            return Err(Error::WasmSerializeFail(format!(
                "serialize ctx base fail, need {} bytes but buf only {} bytes",
                serialize_len,
                buf.len()
            )));
        }

        let mut off = 0usize;

        buf[0] = if self.ip_src.is_ipv6() { 6u8 } else { 4u8 };
        match self.ip_src {
            IpAddr::V4(v4) => {
                buf[1..5].copy_from_slice(v4.octets().as_slice());
                off += 5;
            }
            IpAddr::V6(v6) => {
                buf[1..17].copy_from_slice(v6.octets().as_slice());
                off += 17;
            }
        }

        match self.ip_dst {
            IpAddr::V4(v4) => {
                buf[off..off + 4].copy_from_slice(v4.octets().as_slice());
                off += 4;
            }
            IpAddr::V6(v6) => {
                buf[off..off + 16].copy_from_slice(v6.octets().as_slice());
                off += 16;
            }
        }

        write_u16_be(&mut buf[off..off + 2], self.port_src);
        write_u16_be(&mut buf[off + 2..off + 4], self.port_dst);
        off += 4;

        match self.l4_protocol {
            IpProtocol::TCP => buf[off] = 6,
            IpProtocol::UDP => buf[off] = 17,
            _ => unreachable!(),
        }
        buf[off + 1] = self.proto;
        buf[off + 2] = self.ebpf_type as u8;
        off += 3;

        write_u64_be(&mut buf[off..off + 8], self.time);
        off += 8;

        buf[off] = self.direction as u8;
        off += 1;

        if let Some(proc_name) = self.process_kname.as_ref() {
            buf[off] = proc_name.len() as u8;
            off += 1;
            (&mut buf[off..off + proc_name.len()]).copy_from_slice(proc_name.as_bytes());
            off += proc_name.len();
        } else {
            buf[off] = 0;
            off += 1
        }

        write_u64_be(&mut buf[off..], self.flow_id);
        off += 8;

        write_u16_be(&mut buf[off..], self.buf_size);
        off += 2;

        Ok(off)
    }

    pub(super) fn set_result(&mut self, result: VmResult) {
        self.result = Some(result);
    }
}

/*
    correspond to go struct HttpReqCtx:

    type HttpReqCtx struct {
        BaseCtx    ParseCtx
        Path        string
        ContentType string
    }
*/
pub struct VmHttpReqCtx {
    pub base_ctx: VmCtxBase,

    pub path: String,
    pub host: String,
    pub user_agent: String,
    pub referer: String,
}

macro_rules! serialize_str_ctx {
    ($self: ident, $buf: expr, $off: ident, $field: ident) => {
        write_u16_be(&mut $buf[$off..$off + 2], $self.$field.len() as u16);
        $off += 2;
        $buf[$off..$off + $self.$field.len()].copy_from_slice($self.$field.as_bytes());
        $off += $self.$field.len();
    };
}

impl VmHttpReqCtx {
    /*
        path len:  2 byte
        path:      $(path len) byte

        host len:     2 byte
        host:         $(host len) byte

        ua len:     2 byte
        ua:         $(ua len) byte

        referer len:  2 byte
        referer:      $(referer) byte
    */
    pub(super) fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let need_size =
            8 + self.path.len() + self.host.len() + self.user_agent.len() + self.referer.len();
        if buf.len() < need_size {
            return Err(Error::WasmSerializeFail(format!(
                "serialize http req ctx fail, need at lease {} bytes but buf only {} bytes",
                need_size,
                buf.len()
            )));
        }

        let mut off = 0;

        serialize_str_ctx!(self, buf, off, path);
        serialize_str_ctx!(self, buf, off, host);
        serialize_str_ctx!(self, buf, off, user_agent);
        serialize_str_ctx!(self, buf, off, referer);
        Ok(off)
    }
}

impl From<(&ParseParam<'_>, &HttpInfo, &[u8])> for VmHttpReqCtx {
    fn from(value: (&ParseParam<'_>, &HttpInfo, &[u8])) -> Self {
        let (param, info, payload) = value;
        Self {
            base_ctx: VmCtxBase::from((param, info.proto as u8, payload)),
            path: info.path.clone(),
            host: info.host.clone(),
            user_agent: info
                .user_agent
                .as_deref()
                .or_else(|| info.captured_attribute("user_agent"))
                .unwrap_or_default()
                .to_owned(),
            referer: info
                .referer
                .as_deref()
                .or_else(|| info.captured_attribute("referer"))
                .unwrap_or_default()
                .to_owned(),
        }
    }
}

/*
    correspond to go struct HttpRespCtx:

    type HttpRespCtx struct {
        BaseCtx  ParseCtx
        Code     uint16
        Status   RespStatus
        Endpoint string
    }
*/
pub struct VmHttpRespCtx {
    pub base_ctx: VmCtxBase,
    pub code: u16,
    pub status: L7ResponseStatus,
    pub endpoint: String,
}

impl VmHttpRespCtx {
    /*
      code:         2 bytes
      status:       1 byte
      // appended when buf has room (>= 5 bytes), for backward compat with old wasm (3-byte buf):
      endpoint len: 2 bytes
      endpoint:     $(endpoint len) bytes
    */
    const MIN_BUF_SIZE: usize = 3;
    pub(super) fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.len() < Self::MIN_BUF_SIZE {
            return Err(Error::WasmSerializeFail(format!(
                "serialize http resp ctx fail, need at least {} bytes but buf only {} bytes",
                Self::MIN_BUF_SIZE,
                buf.len()
            )));
        }

        let mut off = 0;
        write_u16_be(buf, self.code);
        off += 2;
        buf[off] = self.status as u8;
        off += 1;

        // Only write endpoint if the buffer is large enough (old wasm allocates exactly 3 bytes)
        if buf.len() >= off + 2 + self.endpoint.len() {
            serialize_str_ctx!(self, buf, off, endpoint);
        }
        Ok(off)
    }
}

impl From<(&ParseParam<'_>, &HttpInfo, &[u8])> for VmHttpRespCtx {
    fn from(value: (&ParseParam, &HttpInfo, &[u8])) -> Self {
        let (param, info, payload) = value;
        Self {
            base_ctx: VmCtxBase::from((param, info.proto as u8, payload)),
            code: info.status_code.unwrap_or_default(),
            status: info.status,
            endpoint: info.endpoint.clone().unwrap_or_default(),
        }
    }
}

/*
    correspond to go struct OnCustomMessageCtx:

    type OnCustomMessageCtx struct {
        BaseCtx ParseCtx
        Payload string
    }
*/
pub struct VmOnCustomMessageCtx {
    pub base_ctx: VmCtxBase,
    pub wasm_data: WasmData,
}

impl VmOnCustomMessageCtx {
    pub(super) fn serialize_to_bytes(&self, buf: &mut [u8]) -> Result<usize> {
        let need_size = 2 + 4 + 4 + self.wasm_data.protobuf.len();
        if buf.len() < need_size {
            return Err(Error::WasmSerializeFail(format!(
                "serialize nats message ctx fail, need at lease {} bytes but buf only {} bytes",
                need_size,
                buf.len()
            )));
        }

        let mut off = 0;
        write_u16_be(buf, self.wasm_data.hook_point as u16);
        off += 2;
        write_u32_be(&mut buf[off..off + 4], self.wasm_data.type_code);
        off += 4;
        write_u32_be(&mut buf[off..off + 4], self.wasm_data.protobuf.len() as u32);
        off += 4;
        buf[off..off + self.wasm_data.protobuf.len()].copy_from_slice(&self.wasm_data.protobuf);
        off += self.wasm_data.protobuf.len();

        Ok(off)
    }
}

impl From<(&ParseParam<'_>, &[u8], WasmData)> for VmOnCustomMessageCtx {
    fn from(value: (&ParseParam<'_>, &[u8], WasmData)) -> Self {
        let (param, l7_payload, wasm_data) = value;
        Self {
            base_ctx: VmCtxBase::from((param, 0, l7_payload)),
            wasm_data,
        }
    }
}

#[cfg(test)]
mod abi_regression_tests {
    use super::*;
    use crate::plugin::wasm::abi_import::get_linker;
    use crate::plugin::wasm::host::{HookPoint, StoreDataType};
    use wasmtime::{Engine, Instance, Module, Store, StoreLimitsBuilder};
    use wasmtime_wasi::WasiCtxBuilder;

    const READS: [&str; 7] = [
        "vm_read_ctx_base",
        "vm_read_payload",
        "vm_read_http_req_info",
        "vm_read_http_resp_info",
        "vm_read_custom_message_info",
        "host_read_l7_protocol_info",
        "host_read_str_result",
    ];

    fn base() -> VmCtxBase {
        VmCtxBase {
            ip_src: "192.0.2.1".parse().unwrap(),
            ip_dst: "192.0.2.2".parse().unwrap(),
            port_src: 12345,
            port_dst: 8080,
            l4_protocol: IpProtocol::TCP,
            proto: 20,
            ebpf_type: EbpfType::None,
            time: 123,
            direction: PacketDirection::ClientToServer,
            process_kname: None,
            flow_id: 456,
            buf_size: 1024,
            payload: ManuallyDrop::new(Vec::new()),
            instance_name: "abi-regression".to_string(),
            result: None,
        }
    }

    fn guest(ctx: Option<VmParseCtx>, export_memory: bool) -> (Store<StoreDataType>, Instance) {
        let engine = Engine::default();
        let mut wat = "(module".to_string();
        for name in READS {
            wat.push_str(&format!(
                "(import \"deepflow\" \"{name}\" (func ${name} (param i32 i32) (result i32)))"
            ));
        }
        wat.push_str("(import \"deepflow\" \"wasm_log\" (func $log (param i32 i32 i32)))");
        wat.push_str(if export_memory {
            "(memory (export \"memory\") 1)"
        } else {
            "(memory 1)"
        });
        for name in READS {
            wat.push_str(&format!(
                "(func (export \"{name}\") (param i32 i32) (result i32) local.get 0 local.get 1 call ${name})"
            ));
        }
        wat.push_str("(func (export \"log\") (param i32 i32) (result i32) local.get 0 local.get 1 i32.const 0 call $log i32.const 1))");
        let module = Module::new(&engine, wat).unwrap();
        let mut store = Store::new(
            &engine,
            StoreDataType {
                parse_ctx: ctx,
                limiter: StoreLimitsBuilder::new().build(),
                wasi_ctx: WasiCtxBuilder::new().build(),
            },
        );
        let linker = get_linker(engine, &mut store);
        let instance = linker.instantiate(&mut store, &module).unwrap();
        (store, instance)
    }

    fn call(
        store: &mut Store<StoreDataType>,
        instance: &Instance,
        name: &str,
        b: u32,
        len: u32,
    ) -> i32 {
        instance
            .get_typed_func::<(i32, i32), i32>(&mut *store, name)
            .unwrap()
            .call(store, (b as i32, len as i32))
            .unwrap()
    }

    #[test]
    fn abi_guest_rejects_overflow_and_oob_then_keeps_context() {
        let (mut store, instance) = guest(Some(VmParseCtx::ParseCtx(base())), true);
        for name in READS {
            for (b, len) in [(u32::MAX, 2), (65535, 2), (65537, 0)] {
                assert_eq!(call(&mut store, &instance, name, b, len), 0, "{name}");
                assert!(store.data().parse_ctx.is_some(), "{name}");
            }
        }
        assert_eq!(call(&mut store, &instance, READS[0], 0, 128), 36);
    }

    #[test]
    fn abi_guest_calls_without_parse_context() {
        let (mut store, instance) = guest(None, true);
        for name in READS {
            assert_eq!(call(&mut store, &instance, name, 0, 64), 0, "{name}");
            assert_eq!(call(&mut store, &instance, name, u32::MAX, 2), 0, "{name}");
            assert!(store.data().parse_ctx.is_none());
        }
    }

    #[test]
    fn abi_guest_missing_memory_is_rejected() {
        let (mut store, instance) = guest(Some(VmParseCtx::ParseCtx(base())), false);
        for name in READS {
            assert_eq!(call(&mut store, &instance, name, 0, 64), 0, "{name}");
            assert!(store.data().parse_ctx.is_some());
        }
        assert_eq!(call(&mut store, &instance, "log", 0, 2), 1);
    }

    #[test]
    fn abi_guest_http_request_error_preserves_context_and_bytes() {
        let ctx = VmParseCtx::HttpReqCtx(VmHttpReqCtx {
            base_ctx: base(),
            path: "/x".to_string(),
            host: "example".to_string(),
            user_agent: String::new(),
            referer: String::new(),
        });
        let (mut store, instance) = guest(Some(ctx), true);
        assert_eq!(call(&mut store, &instance, READS[2], 0, 1), 0);
        assert!(store.data().parse_ctx.is_some());
        assert_eq!(call(&mut store, &instance, READS[2], 0, 64), 17);
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        assert_eq!(
            &memory.data(&store)[..17],
            b"\x00\x02/x\x00\x07example\x00\x00\x00\x00"
        );
    }

    #[test]
    fn abi_guest_http_response_error_preserves_context_and_bytes() {
        let ctx = VmParseCtx::HttpRespCtx(VmHttpRespCtx {
            base_ctx: base(),
            code: 200,
            status: L7ResponseStatus::Ok,
            endpoint: "/x".to_string(),
        });
        let (mut store, instance) = guest(Some(ctx), true);
        assert_eq!(call(&mut store, &instance, READS[3], 0, 2), 0);
        assert!(store.data().parse_ctx.is_some());
        assert_eq!(call(&mut store, &instance, READS[3], 0, 64), 7);
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        assert_eq!(&memory.data(&store)[..7], b"\x00\xc8\x00\x00\x02/x");
    }

    #[test]
    fn abi_guest_custom_error_preserves_context_and_bytes() {
        let ctx = VmParseCtx::OnCustomMessageCtx(VmOnCustomMessageCtx {
            base_ctx: base(),
            wasm_data: WasmData {
                hook_point: HookPoint::ProtocolParse,
                type_code: 7,
                protobuf: vec![1, 2, 3],
            },
        });
        let (mut store, instance) = guest(Some(ctx), true);
        assert_eq!(call(&mut store, &instance, READS[4], 0, 1), 0);
        assert!(store.data().parse_ctx.is_some());
        assert_eq!(call(&mut store, &instance, READS[4], 0, 64), 13);
        let memory = instance.get_memory(&mut store, "memory").unwrap();
        assert_eq!(
            &memory.data(&store)[..13],
            b"\x00\x00\x00\x00\x00\x07\x00\x00\x00\x03\x01\x02\x03"
        );
    }

    #[test]
    fn abi_guest_wrong_http_context_does_not_consume_base() {
        let (mut store, instance) = guest(Some(VmParseCtx::ParseCtx(base())), true);
        for name in &READS[2..5] {
            assert_eq!(call(&mut store, &instance, name, 0, 64), 0);
            assert!(store.data().parse_ctx.is_some());
        }
        assert_eq!(call(&mut store, &instance, READS[0], 0, 1), 0);
        assert!(store.data().parse_ctx.is_some());
        assert_eq!(call(&mut store, &instance, READS[0], 0, 128), 36);
    }

    #[test]
    fn abi_guest_log_rejects_huge_ranges_without_allocation() {
        let (mut store, instance) = guest(Some(VmParseCtx::ParseCtx(base())), true);
        for (b, len) in [
            (u32::MAX, 2),
            (0, u32::MAX),
            (u32::MAX, u32::MAX),
            (65536, 0),
            (0, 2),
        ] {
            assert_eq!(call(&mut store, &instance, "log", b, len), 1);
            assert!(store.data().parse_ctx.is_some());
        }
        assert_eq!(call(&mut store, &instance, READS[0], 0, 128), 36);
    }

    #[test]
    fn abi_guest_start_import_without_context() {
        let engine = Engine::default();
        let module = Module::new(
            &engine,
            r#"(module
                (import "deepflow" "vm_read_ctx_base" (func $read (param i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func $init i32.const 0 i32.const 64 call $read drop)
                (start $init))"#,
        )
        .unwrap();
        let mut store = Store::new(
            &engine,
            StoreDataType {
                parse_ctx: None,
                limiter: StoreLimitsBuilder::new().build(),
                wasi_ctx: WasiCtxBuilder::new().build(),
            },
        );
        let linker = get_linker(engine, &mut store);
        linker.instantiate(&mut store, &module).unwrap();
        assert!(store.data().parse_ctx.is_none());
    }

    #[test]
    fn abi_modern_tinygo_standard_wasi_imports_are_sandboxed() {
        // Modern TinyGo links these standard WASI runtime imports even for
        // pure parsers. The Store has no inherited descriptors or preopens.
        let engine = Engine::default();
        let module = Module::new(
            &engine,
            r#"(module
                (import "wasi_snapshot_preview1" "random_get" (func $random (param i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "sock_recv" (func $recv (param i32 i32 i32 i32 i32 i32) (result i32)))
                (import "wasi_snapshot_preview1" "poll_oneoff" (func $poll (param i32 i32 i32 i32) (result i32)))
                (memory (export "memory") 1)
                (func (export "random") (result i32) i32.const 0 i32.const 16 call $random)
                (func (export "recv") (result i32)
                    i32.const 42 i32.const 0 i32.const 0 i32.const 0 i32.const 16 i32.const 24 call $recv)
                (func (export "poll") (result i32)
                    i32.const 0 i32.const 0 i32.const 0 i32.const 16 call $poll))"#,
        )
        .unwrap();
        let mut store = Store::new(
            &engine,
            StoreDataType {
                parse_ctx: None,
                limiter: StoreLimitsBuilder::new().build(),
                wasi_ctx: WasiCtxBuilder::new().build(),
            },
        );
        let linker = get_linker(engine, &mut store);
        let instance = linker.instantiate(&mut store, &module).unwrap();
        for (name, errno) in [("random", 0), ("recv", 8), ("poll", 28)] {
            let call = instance
                .get_typed_func::<(), i32>(&mut store, name)
                .unwrap();
            assert_eq!(call.call(&mut store, ()).unwrap(), errno, "{name}");
        }
        assert!(store.data().parse_ctx.is_none());
    }
}

#[cfg(test)]
mod http_metadata_adapter_tests {
    use super::*;
    use crate::common::meta_packet::MetaPacket;
    use public::l7_protocol::L7LogAttribute;

    fn adapt(info: &HttpInfo) -> VmHttpReqCtx {
        let mut packet = MetaPacket::default();
        packet.lookup_key.proto = IpProtocol::TCP;
        let param = ParseParam::new(
            &packet,
            None,
            Default::default(),
            #[cfg(any(target_os = "linux", target_os = "android"))]
            Default::default(),
            false,
            true,
        );
        // Raw headers alone do not opt these fields into capture.
        let payload = b"GET / HTTP/1.1\r\nUser-Agent: raw-only\r\nReferer: raw.example\r\n\r\n";
        VmHttpReqCtx::from((&param, info, payload.as_slice()))
    }

    fn capture(info: &mut HttpInfo, key: &'static str, value: &'static str) {
        info.add_attribute(key.into(), value.into());
    }

    #[test]
    fn uncaptured_headers_stay_empty_despite_raw_payload() {
        let info = HttpInfo::default();
        let before = serde_json::to_value(&info).unwrap();
        let ctx = adapt(&info);
        assert_eq!(ctx.user_agent, "");
        assert_eq!(ctx.referer, "");
        assert!(info.user_agent.is_none() && info.referer.is_none());
        assert_eq!(serde_json::to_value(&info).unwrap(), before);
    }

    #[test]
    fn captured_attributes_supply_sdk_metadata_without_mutation() {
        let mut info = HttpInfo::default();
        capture(&mut info, "user_agent", "captured-agent");
        capture(&mut info, "referer", "captured.example");
        let before = serde_json::to_value(&info).unwrap();
        let ctx = adapt(&info);
        assert_eq!(ctx.user_agent, "captured-agent");
        assert_eq!(ctx.referer, "captured.example");
        assert!(info.user_agent.is_none() && info.referer.is_none());
        assert_eq!(serde_json::to_value(&info).unwrap(), before);
    }

    #[test]
    fn explicit_legacy_values_including_empty_take_priority() {
        let mut info = HttpInfo::default();
        info.user_agent = Some("legacy-agent".into());
        info.referer = Some(String::new());
        capture(&mut info, "user_agent", "captured-agent");
        capture(&mut info, "referer", "captured.example");
        let ctx = adapt(&info);
        assert_eq!(ctx.user_agent, "legacy-agent");
        assert_eq!(ctx.referer, "");
    }

    #[test]
    fn latest_normalized_captured_header_wins() {
        let mut info = HttpInfo::default();
        capture(&mut info, "user_agent", "first");
        capture(&mut info, "referer", "first.example");
        capture(&mut info, "user_agent", "last");
        capture(&mut info, "referer", "last.example");
        capture(&mut info, "user-agent", "not-normalized");
        let ctx = adapt(&info);
        assert_eq!(ctx.user_agent, "last");
        assert_eq!(ctx.referer, "last.example");
    }
}
