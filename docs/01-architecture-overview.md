# 01. 系统总体架构与数据流设计

`llm-tracer` 是一个面向本机大模型应用、Agent 框架与 CLI 工具的**单二进制、零外部依赖、全运行时自适应**通信抓取与会话观测系统。它吸收了 `eCapture` 的内核 eBPF Uprobe 思想，并针对现代大模型客户端（静态内嵌 TLS、BoringSSL/`rustls`、Python `MemoryBIO`、JVM JSSE、剥离符号 Go/C/Rust 二进制）扩展了完整的非侵入式优先 + 侵入式自动回退体系。

---

## 一、端到端数据流拓扑

```text
+---------------------------------------------------------------------------------------------------+
|                            目标进程选择与子程序启动规划层 (ProcessTracker / LaunchPlan)               |
|   --pid (默认含子进程树 / --pid-only) | --exe/--binary | --cwd | --cmd | --host | -- <cmd> [args]   |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                  +-------------------------------+-------------------------------+
                  |                                                               |
                  v (优先：非侵入式内核态)                                         v (回退/自动补全：用户态与热注入)
+-----------------------------------+                           +-----------------------------------+
|   Linux 内核态 eBPF 引擎 (Layer 0) |                           |   多运行时自适应采集层 (Layer 1-7)   |
| - OpenSSL Uprobe/Uretprobe        |                           | - Layer 1: LD_PRELOAD ssl_hook.c  |
| - Static OpenSSL (.symtab) Uprobe |                           | - Layer 2: Socket writev/send Hook|
| - Python MemoryBIO Uprobe         |                           | - Layer 3: Python sitecustomize   |
| - GoTLS Write & Read-RET Uprobes  |                           | - Layer 4: Node/Bun node_hook.cjs |
|   (含 stripped .gopclntab 恢复)    |                           | - Layer 5: ptrace (Launch/SEIZE)  |
| - Syscall Tracepoints (write/     |                           | - Layer 6: LoopbackTap 动态 CA     |
|   writev/sendto/read/recvfrom)    |                           | - Layer 7: JVM Agent (pre/agent)  |
| - 16 MiB BPF_MAP_TYPE_RINGBUF     |                           | - Live Attach: jcmd / SIGUSR1     |
+-----------------+-----------------+                           +-----------------+-----------------+
                  |                                                               |
                  +-------------------------------+-------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                 Collector Source 统一输入源抽象 (source_ebpf / unixsock / pipe / tap)               |
|          [Magic: 0x4C4C4D54][PID: 4B][TID: 4B][ConnTag: 4B][Dir: 4B (0=W,1=R)][Len: 4B]           |
|        + tls.bin 读空即截断/64KB上限 + 严禁0666跨UID最小权限 + ancestryCache + userHookPIDs 去重     |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                         流重组、资源限额与隐私脱敏层 (parser/stream*.go)                            |
| - HTTP/1.1 Keep-Alive 分帧、Chunked 聚合、HTTP/2 HPACK 头解压与 DATA 帧重组 (单连接 256 流上限)     |
| - 单连接缓冲 8 MiB / 全局 64 MiB / 解压上限 16 MiB / 2 分钟空闲超时驱逐                            |
| - 默认剥离全部 Request/Response Headers，复用 selfmon 共享脱敏表自动掩码 URL Query 与 Matrix 参数    |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                         多协议识别与语义提取层 (parser/protocol_*.go - 8 大协议)                    |
|  systemone (TypeSafe JEV) | openai_chat | openai_responses | anthropic | gemini | bedrock |       |
|  ollama | mcp (JSON-RPC 2.0) + 未知协议按主机 LRU 限频告警与 --capture-unknown 可选录制            |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                  三级会话自动串联引擎 (Correlator)                                  |
|  - L1 (L1_explicit) : 显式 session_id / conversation_id / previous_response_id / prompt_cache_key |
|  - L2 (L2_context)  : messages 历史前缀指纹匹配（折叠重复上下文）+ systemone goal+recent_actions   |
|  - L3 (L3_proctree) : 同进程树活跃时间窗跨协议关联（如 Claude 主对话 <-> MCP Server 工具调用）      |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        本地文件缓存与可观测控制台 (Store + Selfmon + Web + TOTP)                    |
|  - 会话目录 sessions/<YYYY-MM-DD>/<session_id>/ (0700/0600 原子写 + OpenReadOnly + Lstat 防软链)   |
|  - 默认 10m 热窗驻留 + evictLoop (hotWindow/2) + 两层 LRU 贡献跟踪 (byID=4096, seenIDs=65536)      |
|  - 异步自监控 (4096 队列含 512 优先队列 + 按需 FlushWithTimeout) + /metrics + Web 鉴权矩阵与 IP 分桶 |
+---------------------------------------------------------------------------------------------------+
```

---

## 二、代码目录与模块职责边界

| 目录 / 包路径 | 核心文件 | 职责说明 |
| :--- | :--- | :--- |
| `cmd/llm-tracer` | `main.go` | CLI 入口（`capture`、`view`、`clean`、`status`、`totp`、`version` 六个子命令及 `--version` 开关，共用 `formatVersion`），执行先 `net.Listen` 再 `Serve` 的 Web 启动策略、`view` 子命令 `store.OpenReadOnly` 真只读打开、`clean --all` 清理 `hooks/` 已知产物 (`knownHookArtifacts`)、`webServer.RegisterOnShutdown` 与 `webServer.Close()` 优雅退出、单次 `PlanLaunchCommand` 规划与 `LaunchPlannedCommand` 子进程拉起。 |
| `internal/collector` | `collector.go`<br>`source_pipe.go`<br>`source_unixsock.go`<br>`source_tap.go`<br>`source_ebpf.go`<br>`source_perm_*.go`<br>`ebpf_engine_linux.go`<br>`ebpf_arch_amd64.go`<br>`ebpf_arch_arm64.go`<br>`ebpf_arch_other.go`<br>`elf_probe.go`<br>`live_attach.go`<br>`launch_plan*.go`<br>`preload_hook.go`<br>`runtime_hooks.go`<br>`java_agent.go`<br>`loopback_tap.go`<br>`proctree*.go`<br>`assets/{python,node,c,java}/` | **核心采集层**：统一 `Source` 输入源抽象（`pipe`/`unixsock`/`loopback_tap`/`ebpf`）、`tls.bin` 生命周期契约（仅读端 `initPipeFileNoFollow` 创建、4 个写端严禁 `O_CREAT`、排空即 `Truncate(0)` / `defaultMaxPipeFileSize = 64 KiB` 硬上限 / `findNextValidLLMTFrame` 重同步 `pipe_frame_resync`）、严禁 `0666` 的 `sanitizePrivateMode` (`cross_uid_channel_denied`)、基于 `procKey{pid, startTime}` 的 `ancestryCache` 祖先链缓存与导出方法 `IsInScope`、热注入范围门禁（`ErrPIDOutOfScope` / 403 / `pid_inject_out_of_scope_blocked`）、热注入失败按 PID 指数退避 (`inject_backoff` 与 `ResetInjectBackoff`)、三平台 `InspectProcess` 源头调用 `selfmon.RedactCmdArgs`、子进程环境变量透传（`IsSensitiveChildEnvKey` 仅剥离内部凭据，原样透传用户业务凭据）、Linux `amd64`/`arm64` 原生 eBPF 字节码加载与 `16 MiB` RingBuf 消费。 |
| `internal/parser` | `stream.go`<br>`stream_h1.go`<br>`stream_h2.go`<br>`protocol_detect.go`<br>`protocol_systemone.go`<br>`protocol_openai.go`<br>`protocol_anthropic.go`<br>`protocol_gemini.go`<br>`protocol_bedrock.go`<br>`protocol_ollama.go`<br>`protocol_mcp.go` | **流重组与多协议解析层**：`stream.go` 负责连接表预算（单连接 `8 MiB`、全局 `64 MiB`、4096 连接上限、2 分钟空闲超时驱逐）、Gzip/Deflate/Zstd 16 MiB 限额解压；`protocol_detect.go` 单向引用 `internal/selfmon` 导出的共享脱敏表（`SensitiveQueryKeys`、`IsSensitiveQueryKey`、`RedactQueryPairs`、`RedactPathMatrixParams`）完成 URL Query 与路径 Matrix 参数脱敏；`stream_h1.go` 负责 HTTP/1.1 Keep-Alive 与 Chunked 重组；`stream_h2.go` 负责 HTTP/2 帧与 HPACK 解码（单连接 256 并发流上限）；8 个 `protocol_*.go` 负责协议检测与结构化语义提取。 |
| `internal/correlator` | `correlator.go` | **三级会话串联层**：通过 `L1_explicit`、`L2_context`、`L3_proctree` 将离散的 HTTP 交互自动归并到同一逻辑会话（`sess_...`），并计算每轮新增消息（`NewMessages`）与历史折叠数（`PrefixCount`）。 |
| `internal/store` | `store.go` | **本地文件存储与热窗引擎**：提供读写模式 `Open` 与真只读模式 `OpenReadOnly`；按 `sessions/<YYYY-MM-DD>/<session_id>/{session.json,events.jsonl}` 分片落盘；`persistSessionEvent` 追加前通过 `ReadAt(size-1)` 检查末字节 `\n` 防粘连；`loadFromDisk` 启动通过 **`inspectAndHealEventsFile`** 自动截断损坏半行，缺失或损坏时通过 `rebuildSummaryFromEvents` 重建摘要；`OpenReadOnly` 纯只读模式下仅内存纠偏损坏尾部并重算摘要，严格保持磁盘零写盘；后台 `evictLoop` 按 `hotWindow / 2`（`100ms`~`30s`）执行 `EvictExpiredHot`，配合两层 LRU `sessionContribTracker`（`byID` 4096 + `seenIDs` 65536）实现新事件 ID $O(1)$ 免扫盘。 |
| `internal/selfmon` | `selfmon.go` | **异步自监控与统一脱敏管线**：记录 `probe`、`tracker`、`stream`、`parser`、`correlator`、`store`、`web`、`auth` 8 个阶段的事件，采用总容量 `DefaultWriteQueueSize = 4096`（预留 `DefaultPriorityQueueQuota = 512` 优先队列供 `warn`/`error`）+ 批量刷盘、`hotEvents` 保高优淘汰、`DroppedByStatus` 分级计数、按需 `FlushWithTimeout(200ms)`；通过 `RedactCmdline`、`RedactCmdArgs`、`RedactArgSlice` 统一处理命令行字符串与参数切片，覆盖 `--flag=value`、长短分离参数、`curl -u`、URL 内嵌凭据与敏感环境变量，并导出全局共享脱敏表 `SensitiveQueryKeys`、`IsSensitiveQueryKey`、`RedactQueryPairs`、`RedactPathMatrixParams`、`RedactSensitivePath`，统一脱敏为 `[REDACTED]`，并将主目录替换为 `~`。 |
| `internal/totp` | `totp.go` | **安全认证模块 (`totp.Guard`)**：纯标准库实现的 RFC 6238 TOTP（HMAC-SHA1 6 位动态码）、进程内存随机 Session Token（`"lt_" + base32(18B)`，`DefaultSessionTTL = 12h`，`CheckSession` 绝不计入失败次数）与按客户端 IP 分桶防爆破（`MaxClientBuckets = 4096`，`ClientBucketTTL = 10m`，连续 `MaxFailedAttempts = 5` 次失败锁定该 IP `LockoutDuration = 15s`）。 |
| `internal/web` | `server.go`<br>`static/index.html` | **Web 实时观测台与安全守卫**：提供 `/api/timeline` 等 REST API、监听 `s.done` 实现优雅退出的 `/api/stream` (`handleSSEStream`) SSE 实时流推送与退出退避清理（`ResetInjectBackoff`）、`handleAuthStatus` 下发 `window_ms` 供前端 `applyServerDefaultWindow` 生效、默认 `AllowWebHeaderToggle = false` 拦截未授权动态开启请求头（`--allow-web-header-toggle` 门禁 / 403 `scope_header_toggle_blocked`）、`POST /api/pid/inject` 范围门禁（不在监控范围拦截返回 403 `ErrPIDOutOfScope` / `pid_inject_out_of_scope_blocked`）、仅在回环下发的 32B CSPRNG 令牌、非回环写接口未开 TOTP 强制 `403`、Host/Origin/Sec-Fetch-Site 守卫与 `decodeJSONBody` (`415`/`413`) 校验。 |
| `internal/model` | `types.go` | **领域模型定义**：定义 `TraceEvent`、`SessionSummary`、`SystemOneStepSummary`、`ChatSummary`、`ProcessInfo`、`ScopeFilter` 等核心数据结构（`PIDAttachPlan` 与 `LaunchAttachPlan` 定义于 `internal/collector`）。 |

---

## 三、Collector `Source` 统一输入源抽象与内嵌资产体系

### 1. `Source` 接口与四个输入源适配器 (`internal/collector/source_*.go`)

`Collector` 将底层多通道采集统一抽象为 `Source` 生命周期接口（`Name() string`、`Start(ctx context.Context, sink Sink) error`、`Stop() error`），在 `Collector.Start()` 中按序启动并在 `Stop()` 中统一回收：

| 适配器实现 | 源码文件 | `Name()` | 工作机制与职责 |
| :--- | :--- | :--- | :--- |
| **`pipeSource`** | `internal/collector/source_pipe.go` | `"pipe"` | 创建 `<cache_dir>/hooks/tls.bin`（权限 `0600`），后台运行 `tailLoop` 持续读取 24 字节 `LLMT` 帧并调用 `RecordUserHookPID(pid)`；读到 EOF 即 `Truncate(0)` 清空，强制 `defaultMaxPipeFileSize = 64 KiB` 硬上限，遇损帧通过 `findNextValidLLMTFrame` 重同步（`pipe_frame_resync`），`Stop()` 时通过 `O_NOFOLLOW` 截断并删除文件。 |
| **`unixSockSource`** | `internal/collector/source_unixsock.go` | `"unixsock"` | 创建 `<cache_dir>/hooks/tls.sock` Unix 域流式套接字（当路径 `> 80` 字节超出 `sockaddr_un.sun_path` 安全阈值时，自动回退至 `/tmp/llmt-<pid>-<seq>.sock` 并在 `Stop()` 时清理），并发接收各语言 Hook 发来的 `LLMT` 帧。 |
| **`tapSource`** | `internal/collector/source_tap.go` | `"loopback_tap"` | 封装 `LoopbackTap` 本地动态 ECDSA P-256 CA MITM 代理（`127.0.0.1:<random_port>`），将解密后的明文双向流直接回调送入 `StreamReassembler.IngestChunk`。 |
| **`ebpfSource`** | `internal/collector/source_ebpf.go` | `"ebpf"` | 封装 Linux 内核态 `ebpfEngine`（`amd64` / `arm64`），管理 `BPF_PROG_LOAD`、19 个探针挂载与 `16 MiB` RingBuf 零拷贝读取协程。 |

### 2. D1 安全红线：`<cache_dir>/hooks/tls.bin` 完整生命周期、原子写帧与跨 UID 边界

**为什么 `tls.bin` 管道治理是安全红线**：`llm-tracer` 默认承诺不记录 HTTP 请求头（`--record-headers=false`），以防 `Authorization: Bearer sk-...`、`x-api-key`、`Cookie` 落盘。但在 `StreamReassembler` 与 `ParseExchange` 剥离头部之前，用户态 Hook 采集到的是包含完整 HTTP 请求头的原始 TLS 明文流。若回退通道 `<cache_dir>/hooks/tls.bin` 仅追加不清理或被放宽为 `0666` 全局可读写，原始明文 API Key 就会绕过脱敏层直接残留在磁盘文件上。为此，系统对 `tls.bin` 实施了全链路闭环保护：

1. **仅读端创建、写端严禁 `O_CREAT`、读空即 `Truncate(0)` 与退出 `O_NOFOLLOW` 销毁 (`internal/collector/source_pipe.go`)**：
   - **仅由读端创建 (`initPipeFileNoFollow`)**：`tls.bin` 仅由 Collector 读端 `pipeSource.Start` 调用 `initPipeFileNoFollow` 以 `O_CREATE|O_WRONLY|O_TRUNC|O_NOFOLLOW` 及 `0600` 权限安全创建；
   - **写端严禁 `O_CREAT`**：全部 4 个 Hook 写端（`ssl_hook.c`、`ptrace_helper.c`、`sitecustomize.py`、`node_hook.cjs`）打开 `tls.bin` 时**严禁携带 `O_CREAT`**。当 Collector 退出执行 `truncateAndRemovePipeNoFollow` 截断清零并删除 `tls.bin` 后，即使仍有脱离生命周期的孤儿/后台子进程存活，其写端 `open` 也会因 `ENOENT` 静默丢弃，绝不会以进程默认 umask（如 `0644`/`0666`）在磁盘上重新创建无人清理的明文残留文件；
   - 后台 `tailLoop` 定期调用 `drain()`（通过 `openReadWriteNoFollow` 与 `lockPipeFile` 加锁读取）；每次读到文件末尾（`afterInfo.Size() == s.offset`）即调用 `f.Truncate(0)` 将 `tls.bin` 截断为 `0` 字节并重置 `s.offset = 0`；
   - 当已消费偏移达到硬上限 `defaultMaxPipeFileSize = 64 * 1024`（`64 KiB`）且文件尾部仍有新追加字节时，自动将未消费尾部搬移至文件头、`f.Truncate(remLen)` 收缩文件并重置 `s.offset = 0`，确保磁盘文件绝不无限膨胀；
   - `pipeSource.Close()` 在排空最后一批帧后调用 `truncateAndRemovePipeNoFollow`，以 `O_NOFOLLOW` 安全截断清零并删除 `tls.bin`。
2. **写端原子写帧机制与并发保证 (`assets/c/`, `assets/python/`, `assets/node/`)**：
   - **C 写端 (`ssl_hook.c` 的 `send_tls_chunk` & `ptrace_helper.c` 的 `emit_llmt_frame`)**：以 `open(pipe_path, O_WRONLY | O_APPEND | O_CLOEXEC)` 打开（**不含 `O_CREAT`**），通过进程内 `pthread_mutex_t` (`pipe_write_mu`) 与跨进程 `flock(pfd, LOCK_EX)` 双重加锁，经单次 `writev(pfd, iov, 2)` 将 24 字节 `LLMT` 帧头与明文载荷原子写出；
   - **Python 写端 (`sitecustomize.py` 的 `_emit_chunk`)**：以 `os.open(pipe_path, os.O_WRONLY | os.O_APPEND)` 打开（**不含 `os.O_CREAT`**），在 `with _pipe_lock` 下通过 `fcntl.flock(fd, fcntl.LOCK_EX)` 加排他锁，单次 `os.write(fd, frame)` 原子写出；
   - **Node.js 写端 (`node_hook.cjs` 的 `emitChunk`)**：以 `fs.openSync(pipePath, fs.constants.O_WRONLY | fs.constants.O_APPEND)` 打开（**不含 `O_CREAT`**），通过 `Buffer.concat([hdr, slice])` 合并为单连续 Buffer 并执行单次同步 `fs.writeSync(fd, frame)`。据实说明：Node 标准库 `node:fs` 无原生 `flock(2)` 绑定，依赖 POSIX `O_APPEND` 单次 `write` 系统调用的内核原子追加防止帧内头体交错，若遇并发截断则依赖读端 `findNextValidLLMTFrame` 自愈重同步。
3. **读端损坏帧自动重同步 (`findNextValidLLMTFrame` & `pipe_frame_resync`)**：
   - 若目标进程在写帧中途被 `SIGKILL` 强杀导致残留半截或交错帧（`magic != 0x4c4c4d54`、`payloadLen > maxPipeFramePayloadSize` `512 KiB` 或 `!isCompleteUninterleavedFrame`），`drain()` 调用 `findNextValidLLMTFrame` 在缓冲区中向后扫描下一个合法 `"LLMT"` 魔数边界（同时校验 `dirVal <= 1`、`pid > 0`、`payloadLen <= maxPipeFramePayloadSize`），丢弃损坏字节并向 `selfmon` 记录 **`pipe_frame_resync`** 告警，保证后续正常流量持续消费。
4. **严禁 `0666` 的跨 UID 权限策略 (`source_perm_unix.go` & `cross_uid_channel_denied`)**：
   - `internal/collector/source_perm_unix.go` 的 `sanitizePrivateMode` 强制清除 `0o077` 权限位（默认 `0600`），`collector.go` 的 `ensureHookChannelPermissions` **严禁将 `tls.bin` 或 `tls.sock` 设为 `0666`**；
   - 默认通过 `ensureSafeHooksDir` 将 `hooks/` 目录设为 `0700`、`initPipeFileNoFollow` 将 `tls.sock` 与 `tls.bin` 设为 `0600`；当检测到单个跨 UID 目标进程且当前进程具备 `CAP_CHOWN`（root）时，通过 `setHooksDirModeNoFollow`（使用 `syscall.O_NOFOLLOW`）将 `hooks/` 设为 `0711`（仅允许路径穿越，禁止列目录），并通过 `applyPipePermissionsNoFollow` 与 `applySocketPermissionsNoFollow`（内部调用 `applyFdPermissions`）将 `tls.sock`/`tls.bin` `lchown` 给目标 UID 且严格保持 `0600`；
   - 当存在多个不同非特权 UID 目标或当前进程无 `CAP_CHOWN` 权限时，拒绝放宽通道权限，保持当前用户私有 `0600`，并向 `selfmon` `StageProbe` 记录 **`cross_uid_channel_denied`** 告警。
5. **`(pid, startTime)` 复合缓存键 `procKey`、短命进程归属与 PID 复用防串扰 (`internal/collector/proctree.go`)**：
   - 针对短生命周期子进程发送完 Hook 帧后立即退出、主进程收到帧时 `/proc/<pid>` 已消失的竞态，以及操作系统快速复用相同 PID 给无关新进程的串扰风险，`ProcessTracker`（`internal/collector/proctree.go`）的祖先链缓存 `ancestryCache`、进程元数据缓存 `procCache` 与用户态上报记录 `userHookPIDs` 均采用 **`procKey{pid, startTime}`** 复合键；
   - 结合三平台真实进程启动时间获取函数 **`readProcessStartTime`**（Linux 读取 `/proc/<pid>/stat` 第 22 字段 `starttime`、macOS 调用 `sysctl CTL_KERN KERN_PROC_PID` 获取 `P_starttime`、Windows 调用 `GetProcessTimes` 获取 `CreationTime`），配合 `resolveKeyForPID`、`syncLiveKeyLocked`、`evictPIDLocked` 与 `pruneDisappearedLocked`：
     - 短命子进程退出后，其已入队的 in-flight 管道帧仍能根据历史 `procKey` 命中缓存完成精确归因；
     - 操作系统快速复用同一 PID 给无关新进程时，由于实时 `startTime` 变化，`syncLiveKeyLocked` / `evictPIDLocked` 会立即驱逐旧代缓存，杜绝跨进程误归属；
   - 导出方法 **`ProcessTracker.IsInScope(pid int) bool`**，为在线热注入（`InjectRunningPID`）与流量接入提供统一范围判定门禁；对不在监控范围内的进程发来的帧，`Collector.recordOutOfScopeDrop` 按 PID 以 1 秒窗口限频（上限 4096 个 PID），向 `selfmon` `StageTracker` 记录 **`ingest_out_of_scope_dropped`** 告警并丢弃。

### 3. `//go:embed` 内嵌探针资产与校验机制 (`internal/collector/assets/`)

所有运行时注入源码与预编译字节码均通过 Go 标准库 `//go:embed` 编译进单一二进制，无需外部脚本文件：

| 内嵌资产路径 | 引用文件 | 说明与落地方式 |
| :--- | :--- | :--- |
| `internal/collector/assets/python/sitecustomize.py` | `internal/collector/runtime_hooks.go` | Python `SSLObject`/`SSLSocket`/`HTTPConnection` 钩子模板，启动时渲染写出至 `<cache_dir>/hooks/pyhook/sitecustomize.py`。 |
| `internal/collector/assets/node/node_hook.cjs` | `internal/collector/runtime_hooks.go` | Node.js / Bun `TLSSocket`、`net.Socket` 与 `globalThis.fetch` 钩子模板，写出至 `<cache_dir>/hooks/node_hook.cjs`。 |
| `internal/collector/assets/c/ssl_hook.c` | `internal/collector/preload_hook.go` | Linux/macOS `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` C 源码，运行时调用本机 `gcc`/`cc` 编译为 `libllmtracer_ssl.so`（或 `.dylib`）。 |
| `internal/collector/assets/c/ptrace_helper.c` | `internal/collector/runtime_hooks.go` | Linux `amd64` 跨进程树 `ptrace` 追踪器 C 源码（在 `EnsureRuntimeHooks` 中当 `currentArchCapabilities().PtraceUserspaceSupported` 为 `true` 时编译为 `<cache_dir>/hooks/llm_tracer_ptrace`）。 |
| `internal/collector/assets/java/LlmTracerAgent.java`<br>`internal/collector/assets/java/*.class`<br>`internal/collector/assets/java/checksums.sha256` | `internal/collector/java_agent.go`<br>`internal/collector/assets_test.go` | Java 8 (`class version 52.0`) 字节码 Agent。`EnsureJavaAgentJar` 在复用磁盘上已有的 `llm_tracer_java.jar` 前，先调用 `verifyJavaAgentJar` 校验文件大小（`>512B`）、ZIP 结构、`META-INF/MANIFEST.MF` 关键属性、无未知条目，以及 **2 个内嵌 `.class` 文件**（`LlmTracerAgent.class` 与 `LlmTracerAgent$TapProxySelector.class`）与 `assets/java/checksums.sha256` 的 SHA-256 一致性；若校验失败则记录 `verify_java_agent_jar` 告警、删除旧包并自动通过 `javac` 或内嵌预编译字节码重建。 |

---

## 四、统一 `LLMT` 二进制帧协议与多通道去重机制

### 1. 24 字节 `LLMT` 帧头格式

无论是内核 eBPF RingBuf、C `LD_PRELOAD` Hook、Python `sitecustomize.py`、Node.js `node_hook.cjs` 还是 `llm_tracer_ptrace`，所有采集探针输出的原始明文块均遵循相同的 24 字节小端序帧头：

| 偏移 (Bytes) | 字段名 | 类型 | 说明 |
| :--- | :--- | :--- | :--- |
| `0..3` | `Magic` | `uint32` | 固定魔数 `0x4C4C4D54`（ASCII `"LLMT"`） |
| `4..7` | `PID` | `uint32` | 产生流量的进程号 (`tgid`) |
| `8..11` | `TID` | `uint32` | 产生流量的线程号 (`pid`) |
| `12..15` | `ConnTag` | `uint32` | 连接唯一标识（如 `SSL*` 指针低 32 位、Socket FD + Keep-Alive 代数、或语言对象 ID） |
| `16..19` | `Direction` | `uint32` | `0` = `DirWrite`（客户端请求出向），`1` = `DirRead`（服务端响应入向） |
| `20..23` | `PayloadLen` | `uint32` | 紧随其后的有效明文载荷字节数（单帧上限 `512 KiB`，eBPF RingBuf 单帧上限 `4072 B`） |

### 2. 多层探针共存时的严格幂等与去重

当多个采集层同时存在时（例如 Root 模式下内核 eBPF 全局运行，同时某个子进程加载了用户态 Hook），系统通过四级机制保证**同一条流量绝不重复入库**：

1. **Collector 级 `userHookPIDs` 屏蔽**：一旦某个 `PID` 通过 Unix Socket (`tls.sock`) 或管道 (`tls.bin`) 上报了用户态 Hook 帧，`Collector` 立即标记 `userHookPIDs[pid] = true`，内核 eBPF 回调收到该 `PID` 的事件时直接丢弃。
2. **TLS 与明文 HTTP 拆分的跨层锁 (`LLM_TRACER_PY_TLS_ACTIVE=1` & `LLM_TRACER_NODE_PLAIN_ACTIVE=1`)**：
   - Python `sitecustomize.py` 与 Node/Bun `node_hook.cjs` 在挂载 TLS 钩子后设置 `LLM_TRACER_PY_TLS_ACTIVE=1`，同进程内的 `libllmtracer_ssl.so` 通过 `runtime_tls_hook_active()` 检测到后跳过 C 层 `SSL_write`/`SSL_read` 上报；
   - Node/Bun `node_hook.cjs` 在完成明文 `net.Socket.prototype._write`/`_writev`/`push`（或 Bun `globalThis.fetch`）挂载后独立设置 `LLM_TRACER_NODE_PLAIN_ACTIVE=1`，C 层 Socket 拦截器通过 `runtime_plain_http_hook_active()` 独立判断明文钩子是否已激活，避免 `LLM_TRACER_PY_TLS_ACTIVE` 一刀切关闭 C 层明文 HTTP 兜底。
3. **Node.js 钩子全局幂等锁 (`globalThis.__LLM_TRACER_NODE_HOOK_LOADED__`)**：即使同时通过命令行参数 `--require node_hook.cjs`、环境变量 `NODE_OPTIONS` 或 `SIGUSR1` V8 Inspector 注入，`node_hook.cjs` 也只会包裹 `tls.TLSSocket.prototype` 与 `net.Socket.prototype` 一次。
4. **Java `TapProxySelector` 幂等替换**：即使 `-javaagent` 与 `JAVA_TOOL_OPTIONS` 同时存在，`LlmTracerAgent.install()` 会检测 `ProxySelector.getDefault() instanceof TapProxySelector`，避免代理链嵌套循环。

---

## 五、文档导航索引

- [`docs/00-user-guide-and-cli-reference.md`](00-user-guide-and-cli-reference.md)：安装构建、6 个子命令与完整 CLI 参数参考、常见使用场景、Web 观测台使用指南与故障排查手册。
- [`docs/01-architecture-overview.md`](01-architecture-overview.md)（本文）：系统总体架构、模块职责边界、`Source` 输入源抽象、`//go:embed` 内嵌资产与 `LLMT` 帧去重协议。
- [`docs/02-capture-engine-and-ebpf.md`](02-capture-engine-and-ebpf.md)：八层自适应采集引擎、16 MiB eBPF RingBuf 与探针细节、6 平台（Linux/macOS/Windows × amd64/arm64）能力矩阵与测试矩阵。
- [`docs/03-process-selection-and-live-attach.md`](03-process-selection-and-live-attach.md)：进程选择模型、`.gopclntab` 剥离符号恢复、免重启热注入（JVM/Node/ptrace）与子程序启动参数纯函数规划。
- [`docs/04-protocols-and-session-correlation.md`](04-protocols-and-session-correlation.md)：HTTP/1.1 与 HTTP/2 流重组、Parser 资源上限与未知协议告警、8 大 LLM 协议解析与三级会话串联。
- [`docs/05-storage-web-security-and-ops.md`](05-storage-web-security-and-ops.md)：分片存储布局与热窗驱逐、`selfmon` 异步批量自监控与 `/metrics`、Web 鉴权模型与 CSRF/DNS Rebinding 防护、真实 REST API 路由表及 GA 验收标准。
