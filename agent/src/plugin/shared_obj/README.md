# Native C plugin interface

`so_plugin.h` defines the C layout consumed by `agent/src/plugin/c_ffi.rs`.
Compile plugins against the header from the same Agent source revision. The
header now includes `check_result.direction` and `response.req_type/endpoint`,
which the Rust side already required. Rebuild plugins compiled with the earlier
incomplete header; their binary layouts are incompatible with these structures.

The `parse_ctx` payload and process name are borrowed for a synchronous callback.
Do not modify, free, or retain these pointers after the callback. A process name
is a readable NUL-terminated C string, including when empty. The Rust caller keeps
owned storage alive when a full-length kernel name has no terminator. Invalid
UTF-8 kernel names retain the Agent's existing empty-name fallback.

`parse_ctx.direction` uses `DIRECTION_C_TO_S`/`DIRECTION_S_TO_C` (0/1).
`check_result.direction` is a separate result convention: 0 means unknown,
1 means request, and 2 means response. Initialize every returned result field.

From the repository root, rebuild the native test fixture:

```sh
make -B -C agent/resources/test/plugins
```

Run the packet-mode contract gate with the pinned toolchain:

```sh
bash traflens/scripts/agent-packet.sh test-plugin
```

It executes the real shared object's callbacks and compares 55 independent
C/Rust size, alignment, and field-offset values. The fixture's exported
`traflens_test_abi_value` function is test-only; production plugins do not need
to export it. The libtrace feature adds a regression exercising actual eBPF
MetaPacket process-name inputs; packet-mode tests do not replace that gate.
