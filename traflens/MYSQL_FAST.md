# 显式无阶段等待的 MySQL 采集验收

此入口用于验证新 Agent 的有限、未加阶段等待的 MySQL 采集完整性。`fast` 是入口名称，不是吞吐、延迟或 DeepFlow 性能对等结论。默认 M14 `ebpf-mysql.py` 仍使用其已验收的 100ms paced 夹具；DNS 和旧 diagnostic 入口保持独立。

2026-10-29 的有限 M15 门禁已通过：真实生产核心 `e1daf16b1` / `0544bd9c...`、公开生命周期、18条完整Session、独立raw/API及实际headless Edge详情均有证据。详见 [匿名验收](evidence/2026-10-29/fast-mysql-qualified/README.md)。新运行仍须分别核构建、实际scope与完整人口，不能继承历史标签。

## 运行前提

- Linux x86_64/root，沿用已授权的 dev-79/dev-240 自有实验环境。源端和 peer 的工作父目录必须真实 owned、`0700`；每次运行使用全新目录和 nonce，禁止覆盖失败记录。
- 从**已提交的新核心代码**生产 default-libtrace release Agent，保存真实提交、构建日志、二进制 SHA 和运行库 provenance。`target/release/deps` 测试可执行文件不是部署产物。新目录的 `prepared.json` 包含真实 `source`、`binary_sha256`、缓存 `image_id` 及精确三个运行库 SHA。旧 `3dec20af5...` / `8dd5ec66...` 核心不能作为 fast 候选。
- 夹具固定为原始 unpaced 源码 SHA `d097917c05cfb5de5e8a0f5fe91cfc4181ae7653e4b3c11b4488333dab17c06f`、静态二进制 SHA `1c17c2cec2808c20c220e64e483a4ce5e213c1b2f37959b4dd6c42e0f7163136`。不补写 paced 字段或 `waits.jsonl`。
- 原生控制客户端固定 SHA `599d82f845e2d2e36f5fca86884780b447068affe182592445a4ef39a27ddd4b`。外层入口只在实际 owned Agent 的 namespace/root 下解析控制 socket，并验证 `SO_PEERCRED` 精确 PID/root 身份；不能连接主机上任意同名 socket。
- 使用正常许可 `[2,4,5]`、独立临时组/Agent、MySQL-only 18080、精确正向 namespace FD/inode/map。AF_PACKET、proc、onCPU、DWARF、OTLP 等仍禁用；不修改默认组、旧 Server、物理网口或路由。

以下变量均为实际核实的绝对路径/身份占位。`PEER_CONTROLLER_NEW` 必须全新，`PEER_CODE` 需部署当前公开 helper 并通过 SHA 预检；缓存镜像不拉取。

## 默认离线计划

从仓库根目录执行，以下命令不启动 Agent、流量或网络查询：

```sh
python3 traflens/lab/ebpf-mysql-fast.py
python3 traflens/lab/ebpf-mysql-fast-observed.py
python3 traflens/lab/verify-ebpf-mysql-fast.py
```

## 完整公开运行

```sh
python3 traflens/lab/ebpf-mysql-fast-observed.py --execute \
  --observer-output "$OBSERVER_NEW" --control-client "$CONTROL_CLIENT" -- \
  run --execute --work "$CAPTURE_NEW" \
  --backend-host dev-240 --backend-root "$PEER_LAB" \
  --backend-work "$PEER_CONTROLLER_NEW" --backend-code "$PEER_CODE" \
  --server-container traflens-lab-server \
  --controller-url http://127.0.0.1:20417 \
  --controller-ip "$CONTROLLER_IP" --ctrl-ip "$SOURCE_CTRL_IP" --ctrl-mac "$SOURCE_MAC" \
  --controller-port 20035 --ingester-port 20033 --forward-port 24017 \
  --image "$CACHED_RUNTIME_IMAGE" --artifacts "$NEW_ARTIFACTS/prepared.json" \
  --workload-bin "$ORIGINAL_UNPACED_BINARY" \
  --workload-sha256 1c17c2cec2808c20c220e64e483a4ce5e213c1b2f37959b4dd6c42e0f7163136 \
  --workload-source "$ORIGINAL_UNPACED_C" --observer-timeout-seconds 45
```

公开 coordinator 创建互相隔离的正、负 namespace。每个 namespace 内两个有限进程运行三条新 TCP 会话；真实 greeting/login/auth、query/result、QUIT 和 TCP EOF 全部保留。自有 server 的 `mysqld` comm 仅是原生方向提示，不代表实际数据库或 SQL 执行。四个 worker 的 Docker argv、实际 inspect、PID/start ticks/NET/PID namespace 和执行文件 SHA 均须符合原守卫。

任何 worker 创建前必须通过真实 collector、三监听器同步、Agent pinned FD、scope ARRAY 及零 AF_PACKET ready 门禁。`before-first-wire` gate 随后绑定这一代 Agent/PID/来源/namespace；外层 supervisor 开启有限原生 stdout observation，流式解析器仅保留有界 header 元数据、哈希和数字计数，不保存 payload。CLOSE 仍会被核对，不能用单协议过滤隐藏它。两个gate还从实际native merged INFO日志核对 MySQL/cache256/100ms/segmentation[]；raw Controller YAML不能替代。旧Server唯一只读 `/etc/server.yaml` bind内容仅计算SHA并前后比较。原生私有console可保留自有夹具payload，不能把解析器的metadata-only语义扩称为整次运行不保存payload。

夹具内部没有 100ms phase waits。运行时短暂停 server 的用途是取得客户端真实存活 PID 证明；后置 drain/statistics tail 用于收尾，不用于性能测量。`after-final-wire` gate 在四个 worker 全部完成后、Agent 仍存活时完成，随后显式关闭 observation 并公开清理资源。两个 ACK 只证明绑定的证据已收集，不能被解释为零丢包或计数器累计完整性。

捕获标识固定为 `traflens.ebpf-mysql-fast.capture.v1`；worker/scope 使用同一 `mysql-fast` stem，purpose 为 `traflens.ebpf-mysql-fast.worker`。旧 paced/diagnostic 的 schema 不回退接受。

## 独立存储和 API 验收

在 capture 清理完成后，使用既有公开有限 query/console runtime 和数字 loopback HTTP 地址。`CORE_COMMIT`/`CORE_SHA256` 必须来自独立新生产 artifact 的资格记录。使用真实事件时间选择覆盖窗口，最大为 60 个 inclusive 秒；不要用停后恢复等待的时长扩大数据窗口。

```sh
python3 traflens/lab/verify-ebpf-mysql-fast.py --execute \
  --capture-dir "$CAPTURE_NEW" --query-base "$QUERY_BASE" --console-base "$CONSOLE_BASE" \
  --from "$EVENT_FROM" --to "$EVENT_TO" --agent "$ACTUAL_AGENT_ID" \
  --native-source "$CORE_COMMIT" --native-sha256 "$CORE_SHA256" \
  --output "$ORACLE_NEW"
```

验收器先逐字节复算真实 classic wire、21 IO（18 data + 3 TCP EOF）、26 classic packets 和四个进程/namespace 收据，拒绝任何 paced 字段或 waits 文件。原始 unpaced source/binary、实际新 Agent 来源以及 capture/observer/验收阶段代码 SHA 也必须相符。

存储验收不以 HTTP ACK 为准：两次完整 Agent/时间人口必须保持同一批原始 ID/字段，包含 18 条 source3 Session（Login 6、COM_QUERY 6、空 resource 的 QUIT 6）。whole marker 是 12 条，`.my-...` 只用于六条 Query 子集。对照 namespace 零入库、source0/4 零对照、18 条实际详情、NULL 成功码和 ERR1064/server-status3 均须通过。缺 QUIT、孤立 Request、多余记录、响应失败或超限都失败，不缩小条件把它们滤掉。

只有完整应用/范围/恢复/存储/API 检查都通过，验收结果才可写 `unpaced_completeness_proven: true`；该结论限于本次有限夹具，不代表完整 MySQL 兼容性、真实数据库 SQL 或最大性能。

## 停止与失败续清

外层 supervisor 的 `finally` 会尝试显式 `off`、停止其精确 follower/parser，并调用公开 stop。中断或清理失败后可继续执行：

```sh
python3 traflens/lab/ebpf-mysql-fast.py stop --execute --work "$CAPTURE_NEW"
```

stop 沿原精确所有权恢复次序：worker → Agent/BPF/tracefs → namespace FD 租约 → Controller → 自有转发；未知资源不会删除，inspect 失败不等于不存在。重复 stop 追加清理证据，不把首个失败 `result.json` 改成成功。query runtime 和用户另建的转发按其各自公开入口停止。

保留 capture 的 `state.json`、`result.json`、`capture-source-sha256.json`、四角色 wire/runtime 收据、`scope-runtime.json`、真实 scope proof 和 restoration；observer 的 `observer-supervisor-result.json`、两个 gate request/manifest/ack 和元数据输出；oracle 的请求、原始响应与 `result.json`。没有 oracle 结果、仅 runtime pass、空查询结果或任一失败，都不能记为功能验收完成。先定位具体门禁或人口差异，再决定下一步，不自动重采、换旧核心或覆盖失败目录。
