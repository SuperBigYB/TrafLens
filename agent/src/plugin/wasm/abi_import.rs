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

use std::ops::Range;

use crate::{
    plugin::{wasm::IMPORT_FUNC_WASM_LOG, CustomInfo},
    wasm_error,
};

use super::{
    read_wasm_str, StoreDataType, VmParseCtx, VmResult, IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
    IMPORT_FUNC_HOST_READ_STR_RESULT, IMPORT_FUNC_VM_READ_CTX_BASE,
    IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE, IMPORT_FUNC_VM_READ_HTTP_REQ,
    IMPORT_FUNC_VM_READ_HTTP_RESP, IMPORT_FUNC_VM_READ_PAYLOAD, LOG_LEVEL_ERR, LOG_LEVEL_INFO,
    LOG_LEVEL_WARN, WASM_MODULE_NAME,
};

use log::{error, info, warn};
use public::bytes::read_u16_be;
use wasmtime::{AsContext, AsContextMut, Caller, Engine, Linker, Memory, Store};
use wasmtime_wasi::snapshots::preview_1::add_wasi_snapshot_preview1_to_linker;

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export wasm_log
    func wasmLog(b *byte, length int, level uint8)

    note that the caller storeData.parse_ctx is Always None
*/
pub(super) fn wasm_log(mut caller: Caller<'_, StoreDataType>, b: u32, len: u32, level: u32) {
    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_WASM_LOG) else {
        return;
    };
    // Borrow validated guest bytes; never allocate from an unchecked guest length.
    let data = &mem.data(caller.as_context())[range];
    match std::str::from_utf8(data) {
        Ok(log_data) => {
            #[cfg(test)]
            {
                println!("wasm log: {}", log_data);
            }
            match level {
                LOG_LEVEL_INFO => info!("wasm log: {}", log_data),
                LOG_LEVEL_WARN => warn!("wasm log: {}", log_data),
                LOG_LEVEL_ERR => error!("wasm log: {}", log_data),
                _ => {
                    warn!("wasm log with unknown level: {}", level);
                }
            }
        }
        Err(err) => error!("in_fn: {}, log fail: {}", IMPORT_FUNC_WASM_LOG, err),
    }
}

// The end address is computed in the host's checked usize domain, never u32.
// A zero-length buffer at exactly memory_size is valid.
fn checked_memory_range(memory_size: usize, b: u32, len: u32) -> Option<Range<usize>> {
    let start = b as usize;
    let end = start.checked_add(len as usize)?;
    if end > memory_size {
        return None;
    }
    Some(start..end)
}

// Validate the exported memory and range before any read, write or allocation.
// Logging imports may run during initialization, with no ParseCtx installed.
fn check_memory(
    caller: &mut Caller<'_, StoreDataType>,
    b: u32,
    len: u32,
    func_name: &str,
) -> Option<(Memory, Range<usize>)> {
    let mem = caller
        .get_export("memory")
        .and_then(|export| export.into_memory());
    let ins_name = caller
        .data()
        .parse_ctx
        .as_ref()
        .map_or("", VmParseCtx::get_ins_name);
    let Some(mem) = mem else {
        wasm_error!(ins_name, func_name, "guest does not export memory");
        return None;
    };
    let mem_size = mem.data_size(caller.as_context());
    let Some(range) = checked_memory_range(mem_size, b, len) else {
        wasm_error!(
            ins_name,
            func_name,
            "invalid memory range: size {}, offset {}, length {}",
            mem_size,
            b,
            len
        );
        return None;
    };
    Some((mem, range))
}

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export vm_read_ctx_base
    func vmReadCtxBase(b *byte, length int) int
*/
pub(super) fn vm_read_ctx_base(mut caller: Caller<'_, StoreDataType>, b: u32, len: u32) -> i32 {
    /*
        wasm vm read the parse ctx, host need sesrialize the parse param to bytes and write to the vm.
        b is the wasm ptr indicate the addr bias from instance memory.
    */

    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_VM_READ_CTX_BASE) else {
        return 0;
    };

    let Some(ctx) = caller.data_mut().parse_ctx.take() else {
        return 0;
    };
    let mem_mut = mem.data_mut(caller.as_context_mut());

    let size = ctx.serialize_ctx_base(&mut mem_mut[range]);
    if let Err(err) = size {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_CTX_BASE,
            "serialize ctx base fail: {}",
            err
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    }

    let _ = caller.data_mut().parse_ctx.insert(ctx);
    size.unwrap() as i32
}

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export vm_read_payload
    func vmReadPayload(b *byte, length int) int
*/
pub(super) fn vm_read_payload(mut caller: Caller<'_, StoreDataType>, b: u32, len: u32) -> i32 {
    let Some((mem, _)) = check_memory(&mut caller, b, len, IMPORT_FUNC_VM_READ_PAYLOAD) else {
        return 0;
    };

    let Some(ctx) = caller.data_mut().parse_ctx.take() else {
        return 0;
    };
    let payload = ctx.get_ctx_base().payload.as_slice();
    let payload_size = payload.len();

    if payload_size > len as usize {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_CTX_BASE,
            "vm read payload fail: buffer length not enough, require {} but buffer size is {}",
            payload_size,
            len
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return -1;
    }

    if let Err(err) = mem.write(caller.as_context_mut(), b as usize, payload) {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_CTX_BASE,
            "vm read payload fail: {}",
            err
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return -1;
    }

    let _ = caller.data_mut().parse_ctx.insert(ctx);
    payload_size as i32
}

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export vm_read_http_req_info
    func vmReadHttpReqInfo(b *byte, length int) int
*/
pub(super) fn vm_read_http_req_info(
    mut caller: Caller<'_, StoreDataType>,
    b: u32,
    len: u32,
) -> i32 {
    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_VM_READ_HTTP_REQ) else {
        return 0;
    };

    let Some(ctx) = caller.data_mut().parse_ctx.take() else {
        return 0;
    };
    let mem_mut = mem.data_mut(caller.as_context_mut());

    let VmParseCtx::HttpReqCtx(ref req_ctx) = ctx else {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_HTTP_REQ,
            "ctx type incorrect"
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    };

    let size = req_ctx.serialize_to_bytes(&mut mem_mut[range]);
    if let Err(err) = size {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_HTTP_REQ,
            "serialize http req ctx fail: {}",
            err
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    }

    let _ = caller.data_mut().parse_ctx.insert(ctx);
    size.unwrap() as i32
}

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export vm_read_http_resp_info
    func vmReadHttpRespInfo(b *byte, length int) int
*/
pub(super) fn vm_read_http_resp_info(
    mut caller: Caller<'_, StoreDataType>,
    b: u32,
    len: u32,
) -> i32 {
    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_VM_READ_HTTP_RESP)
    else {
        return 0;
    };

    let Some(ctx) = caller.data_mut().parse_ctx.take() else {
        return 0;
    };
    let mem_mut = mem.data_mut(caller.as_context_mut());

    let VmParseCtx::HttpRespCtx(ref resp_ctx) = ctx else {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_HTTP_RESP,
            "ctx type incorrect"
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    };

    let size = resp_ctx.serialize_to_bytes(&mut mem_mut[range]);
    if let Err(err) = size {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_HTTP_RESP,
            "serialize http resp ctx fail: {}",
            err
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    }

    let _ = caller.data_mut().parse_ctx.insert(ctx);
    size.unwrap() as i32
}

/*
    import function, correspond to go func signature:

    //go:wasm-module deepflow
    //export vm_read_custom_message_info
    func vmReadCustomMessageInfo(b *byte, length int) int
*/
pub(super) fn vm_read_custom_message_info(
    mut caller: Caller<'_, StoreDataType>,
    b: u32,
    len: u32,
) -> i32 {
    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE)
    else {
        return 0;
    };

    let Some(ctx) = caller.data_mut().parse_ctx.take() else {
        return 0;
    };
    let mem_mut = mem.data_mut(caller.as_context_mut());

    let VmParseCtx::OnCustomMessageCtx(ref msg_ctx) = ctx else {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE,
            "ctx type incorrect"
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    };

    let size = msg_ctx.serialize_to_bytes(&mut mem_mut[range]);
    if let Err(err) = size {
        wasm_error!(
            ctx.get_ins_name(),
            IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE,
            "serialize custom message ctx fail: {}",
            err
        );
        let _ = caller.data_mut().parse_ctx.insert(ctx);
        return 0;
    }

    let _ = caller.data_mut().parse_ctx.insert(ctx);
    size.unwrap() as i32
}

/*
    import function, host read the serialized l7 protocol info and deserizlize to CustomInfo.

    correspond to go func signature:

    //go:wasm-module deepflow
    //export host_read_l7_protocol_info
    func hostReadL7ProtocolInfo(b *byte, length int) bool
*/
pub(super) fn host_read_l7_protocol_info(
    mut caller: Caller<'_, StoreDataType>,
    b: u32,
    len: u32,
) -> i32 {
    let Some((mem, range)) =
        check_memory(&mut caller, b, len, IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO)
    else {
        return 0;
    };
    let Some(ctx) = caller.data().parse_ctx.as_ref() else {
        return 0;
    };
    let dir = ctx.get_ctx_base().direction;

    let mem = mem.data(caller.as_context());
    let data = &mem[range];

    let mut infos = vec![];

    let mut off = 0;
    loop {
        if off + 2 > data.len() {
            let ins_name = caller.data().parse_ctx.as_ref().unwrap().get_ins_name();
            wasm_error!(
                ins_name,
                IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
                "CustomInfo deserilaize fail, length too short"
            );
            return 0;
        }

        let info_len = read_u16_be(&data[off..off + 2]) as usize;
        off += 2;
        if off + info_len > data.len() {
            let ins_name = caller.data().parse_ctx.as_ref().unwrap().get_ins_name();
            wasm_error!(
                ins_name,
                IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
                "CustomInfo deserilaize fail, info length incorrect"
            );
            return 0;
        }

        let info = CustomInfo::try_from((&data[off..off + info_len], dir));
        if info.is_err() {
            let ins_name = caller.data().parse_ctx.as_ref().unwrap().get_ins_name();
            wasm_error!(
                ins_name,
                IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
                "CustomInfo deserilaize fail: {}",
                info.unwrap_err()
            );
            return 0;
        }
        infos.push(info.unwrap());

        off += info_len;
        if off == data.len() {
            break;
        }
    }

    caller
        .data_mut()
        .parse_ctx
        .as_mut()
        .unwrap()
        .get_ctx_base_mut()
        .set_result(VmResult::L7InfoResult(infos));

    1
}

/*
    import function, host read the serialized http result and deserizlize to CustomInfo.

    correspond to go func signature:

    //go:wasm-module deepflow
    //export host_read_str_result
    func hostReadStrResult(b *byte, length int) bool
*/
pub(super) fn host_read_str_result(mut caller: Caller<'_, StoreDataType>, b: u32, len: u32) -> i32 {
    if caller.data().parse_ctx.is_none() {
        return 0;
    }

    let Some((mem, range)) = check_memory(&mut caller, b, len, IMPORT_FUNC_HOST_READ_STR_RESULT)
    else {
        return 0;
    };

    let mem = mem.data(caller.as_context());
    let data = &mem[range];
    let Some(str) = read_wasm_str(data, &mut 0) else {
        let ins_name = caller.data().parse_ctx.as_ref().unwrap().get_ins_name();
        wasm_error!(
            ins_name,
            IMPORT_FUNC_HOST_READ_STR_RESULT,
            "read str result fail"
        );
        return 0;
    };

    caller
        .data_mut()
        .parse_ctx
        .as_mut()
        .unwrap()
        .get_ctx_base_mut()
        .set_result(VmResult::StringResult(str));

    1
}

//  linker use for import func into wasm vm
pub(super) fn get_linker(e: Engine, store: &mut Store<StoreDataType>) -> Linker<StoreDataType> {
    let mut link = Linker::<StoreDataType>::new(&e);

    link.func_wrap(WASM_MODULE_NAME, IMPORT_FUNC_WASM_LOG, wasm_log)
        .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_VM_READ_CTX_BASE,
        vm_read_ctx_base,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_VM_READ_PAYLOAD,
        vm_read_payload,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_VM_READ_HTTP_REQ,
        vm_read_http_req_info,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_VM_READ_HTTP_RESP,
        vm_read_http_resp_info,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_VM_READ_CUSTOM_MESSAGE,
        vm_read_custom_message_info,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_HOST_READ_L7_PROTOCOL_INFO,
        host_read_l7_protocol_info,
    )
    .unwrap();

    link.func_wrap(
        WASM_MODULE_NAME,
        IMPORT_FUNC_HOST_READ_STR_RESULT,
        host_read_str_result,
    )
    .unwrap();

    link_wasi(&mut link, get_wasi_linker(e.clone()), store);
    link
}

fn link_wasi(
    link: &mut Linker<StoreDataType>,
    wasi_link: Linker<StoreDataType>,
    store: &mut Store<StoreDataType>,
) {
    // import the limit wasi_snapshot_preview1 api to linker, ensure can use protobuf serialize/deserialize
    // wasm in go can use protobuf decode/encode by https://github.com/knqyf263/go-plugin
    let link_func = [
        "clock_time_get",
        "args_sizes_get",
        "args_get",
        "environ_get",
        "environ_sizes_get",
        "fd_close",
        "fd_fdstat_get",
        "fd_filestat_get",
        "fd_pread",
        "fd_prestat_get",
        "fd_prestat_dir_name",
        "fd_read",
        "fd_seek",
        "fd_write",
        "path_open",
        "path_readlink",
        "proc_exit",
        // Modern TinyGo runtime imports these even for pure parser modules.
        // The existing empty WasiCtx grants no sockets, directories or env.
        "poll_oneoff",
        "random_get",
        "sched_yield",
        "sock_recv",
    ];

    for f in link_func {
        let func = wasi_link
            .get(&mut *store, "wasi_snapshot_preview1", f)
            .unwrap();
        link.define(&mut *store, "wasi_snapshot_preview1", f, func)
            .unwrap();
    }
}

fn get_wasi_linker(engine: Engine) -> Linker<StoreDataType> {
    let mut wasi_linker = Linker::<StoreDataType>::new(&engine);
    add_wasi_snapshot_preview1_to_linker(&mut wasi_linker, |b| &mut b.wasi_ctx).unwrap();
    wasi_linker
}

#[cfg(test)]
mod memory_range_tests {
    use super::checked_memory_range;

    #[test]
    fn checked_guest_pointer_boundaries() {
        assert_eq!(checked_memory_range(65536, 0, 65536), Some(0..65536));
        assert_eq!(checked_memory_range(65536, 65536, 0), Some(65536..65536));
        assert_eq!(checked_memory_range(65536, 65536, 1), None);
        assert_eq!(checked_memory_range(65536, 65537, 0), None);
        assert_eq!(checked_memory_range(65536, u32::MAX, 2), None);
        assert_eq!(checked_memory_range(65536, 0, u32::MAX), None);
        assert_eq!(checked_memory_range(0, 0, 0), Some(0..0));
    }
}
