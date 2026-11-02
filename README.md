# llm-tracer

基于 eCapture / eBPF uprobe 与 OpenSSL / GoTLS 探针的本机大模型通信抓取、多协议识别、会话串联与实时 Web 观测工具（单二进制，纯本地文件缓存）。

## 文档体系导航

本项目提供完整的分层技术文档体系，涵盖从整体架构、内核 eBPF 字节码实现、免重启热注入到多协议会话串联的全部技术细节：

| 文档编号与路径 | 主题与涵盖内容 |
| :--- | :--- |
| **[00. 功能使用手册与命令行全参考](docs/00-user-guide-and-cli-reference.md)** | 安装编译、6 大子命令与全部参数速查（含 `--allow-web-header-toggle`、`--totp-secret` 默认值 `""` 运行时回退、`view` 只读回放 `-w` 时间窗联动、`clean --all` 清理 `hooks/` 产物、业务凭据原样透传与内部凭据剥离）、实战用法、Web 界面操作指南、常见故障排查（Troubleshooting） |
| **[01. 系统总体架构与数据流设计](docs/01-architecture-overview.md)** | 端到端数据流拓扑、模块职责边界、Collector `Source` 四通道抽象、`tls.bin` 管道生命周期契约（仅读端 `initPipeFileNoFollow` 创建、写端严禁 `O_CREAT`、排空即 `Truncate(0)`、`64KB` 上限、严禁 `0666` 跨 UID 最小权限）、4 写端原子写帧与 Node `findNextValidLLMTFrame` 重同步、`(pid, startTime)` 复合键 `procKey` 归因与 `IsInScope`、Store 崩溃断尾自愈与 Selfmon 统一脱敏 |
| **[02. 八层自适应采集引擎与内核 eBPF 深度解析](docs/02-capture-engine-and-ebpf.md)** | 为什么单一 `eCapture`/`LD_PRELOAD` 会漏抓、Linux 原生 11 程序/19 探针 eBPF 引擎（`16 MiB` RingBuf）、4 个 Hook 写端写 `tls.bin` 严禁 `O_CREAT` 与原子写机制（C 单次 `writev` + `flock`、Python `fcntl.flock`、Node 单次 `writeSync` + 读端自愈）、Node `_writev` 与 `LLM_TRACER_NODE_PLAIN_ACTIVE` 去重、跨平台与 `amd64`/`arm64` 能力矩阵 |
| **[03. 进程选择模型、免重启热注入与子程序自动参数补全](docs/03-process-selection-and-live-attach.md)** | 跨平台进程发现与 `InspectProcess` 源头 `RedactCmdArgs` 脱敏、`(pid, startTime)` 复合缓存键 `procKey` 与 PID 复用防串扰、导出 `IsInScope`、热注入范围门禁（`ErrPIDOutOfScope` / 403 / `pid_inject_out_of_scope_blocked`）、热注入按 PID 指数退避（`inject_backoff` 与自动重置）、Node Inspector inode 精确匹配、子程序业务凭据原样透传与内部敏感变量剥离（`IsSensitiveChildEnvKey` / `StripSensitiveEnvKeys`） |
| **[04. 多协议流重组、8 大 LLM 协议解析与三级会话串联](docs/04-protocols-and-session-correlation.md)** | HTTP/1.1 & HTTP/2 HPACK 流重组、缓冲区与解压防爆资源上限、复用 `selfmon` 共享脱敏表（覆盖 `x-goog-api-key`、`api%5Fkey`、`jwt`、`;key=`）、`record_headers` 动态开启门禁（`--allow-web-header-toggle`）、未知协议 LRU 限流告警、8 大协议解析与 `L1/L2/L3` 三级会话串联 |
| **[05. 存储引擎、自监控、Web 安全鉴权、API 契约与 GA 验收标准](docs/05-storage-web-security-and-ops.md)** | 分级目录权限与 `chmodNoFollow` 防符号链接、Store 崩溃断尾自愈（`persistSessionEvent` `ReadAt(size-1)` 末字节换行检查、`inspectAndHealEventsFile` 读写截断修复 / `rebuildSummaryFromEvents` 重建）、`OpenReadOnly` 纯内存纠偏只读零写盘、`evictLoop` 热窗驱逐、Selfmon 统一命令行脱敏管线（`RedactCmdline` / `RedactCmdArgs` / `RedactArgSlice`）、Web 动态开启请求头门禁（`--allow-web-header-toggle` / `AllowWebHeaderToggle` / 403）、Web `Close()` 优雅退出与 `ResetInjectBackoff`、C1 鉴权矩阵与 CI 零 SKIP 门禁 |

---

## 核心特性

- **多维范围抓取与模块化 `Source` 采集架构 (`internal/collector`)**
  - 支持按 `--pid`（默认抓取该 PID 及其所有后代子进程；加 `--pid-only` 则仅抓单个 PID 本身）、`--exe` / `--binary`、`--cwd`、`--cmd`、`--host` 过滤；三平台 `proctree_linux.go`、`proctree_darwin.go`、`proctree_windows.go` 的 `InspectProcess` 在采集源头调用 `selfmon.RedactCmdArgs` 将命令行中的敏感参数脱敏为 `[REDACTED]`。
  - **统一 `Source` 采集通道抽象与 `tls.bin` 安全生命周期契约 (`internal/collector/source_pipe.go`, `source_perm_unix.go`, `source_perm_windows.go`)**：内置 `pipe`（`<cache_dir>/hooks/tls.bin`）、`unixsock`（`tls.sock`，超 80 字节自动回退 `/tmp/llmt-<pid>-<seq>.sock`）、`loopback_tap`（支持 `--tap-insecure`）与 `ebpf` 四个适配器，并支持 `RegisterSource` 扩展。针对曾因明文落盘可能击穿“默认不记录请求头”承诺的 `tls.bin` 管道实施闭环安全契约：`tls.bin` **仅由 Collector 读端 `pipeSource.Start` 调用 `initPipeFileNoFollow` 以 `O_CREATE|O_WRONLY|O_TRUNC|O_NOFOLLOW` 及 `0600` 权限创建**；全部 4 个 Hook 写端（`ssl_hook.c` 的 `send_tls_chunk`、`ptrace_helper.c` 的 `emit_llmt_frame`、`sitecustomize.py` 的 `_emit_chunk`、`node_hook.cjs` 的 `emitChunk`）打开 `tls.bin` 时**严禁携带 `O_CREAT`**（C 写端采用单次 `writev` + `flock`/`pthread_mutex_t`；Python 采用 `_pipe_lock` + `fcntl.flock` + 单次 `os.write`；Node.js 采用单次 `fs.writeSync` 并在读端通过 `findNextValidLLMTFrame` 自愈重同步）。当 Collector 退出执行 `truncateAndRemovePipeNoFollow` 截断清零并删除 `tls.bin` 后，即使仍有脱离生命周期的孤儿/后台子进程存活，其写端 `open` 也会因 `ENOENT` 静默丢弃，绝不会以进程默认 umask（如 `0644`/`0666`）在磁盘上重新创建无人清理的明文残留文件；读端 `tailLoop` 排空到 EOF 立即 `Truncate(0)`、强制 `defaultMaxPipeFileSize = 64KB` 硬上限、损坏帧通过 `findNextValidLLMTFrame` 自动重同步并告警 `pipe_frame_resync`；`sanitizePrivateMode` 严禁 `0666` 全局可读写，跨 UID 且无 `CAP_CHOWN`（或多跨 UID）时拒绝放宽权限并记录 `cross_uid_channel_denied`。
  - **`(pid, startTime)` 复合缓存键 `procKey`、短命进程与 PID 复用防串扰、导出 `IsInScope` (`internal/collector/proctree.go`, `collector.go`)**：`ProcessTracker` 的祖先链缓存 `ancestryCache`、进程元数据缓存 `procCache` 与用户态上报记录 `userHookPIDs` 均采用 **`procKey{pid, startTime}`** 复合键（三平台 `readProcessStartTime`：Linux 读取 `/proc/<pid>/stat` 第 22 字段 `starttime`、macOS `sysctl CTL_KERN KERN_PROC_PID` `P_starttime`、Windows `GetProcessTimes CreationTime`），配合 `resolveKeyForPID`、`syncLiveKeyLocked`、`evictPIDLocked`、`pruneDisappearedLocked`，既保证短命子进程退出后其已入队的 in-flight 管道帧仍能命中缓存完成归属判定，又能在操作系统快速复用相同 PID 给无关新进程时因 `startTime` 变化立即驱逐旧缓存，杜绝跨进程误归属；导出方法 **`ProcessTracker.IsInScope(pid int) bool`** 供热注入与范围校验调用；对范围外进程流量通过 `recordOutOfScopeDrop` 按 PID 1 秒窗口限频聚合，记录 `ingest_out_of_scope_dropped` 告警。
  - **编译期 `//go:embed` 内嵌资产与运行时 JAR 完整性自愈 (`internal/collector/assets/`, `java_agent.go`)**：内嵌 `python/sitecustomize.py`、`node/node_hook.cjs`、`c/ssl_hook.c`、`c/ptrace_helper.c` 与 `java/LlmTracerAgent*.{java,class}`；`EnsureJavaAgentJar` 在无 `javac` 的纯 JRE 环境自动回退内嵌 Java 8 (class version `52.0`) 字节码，并在每次复用已有 `llm_tracer_java.jar` 前通过 `verifyJavaAgentJar` 按 `assets/java/checksums.sha256` 校验 ZIP 结构、`META-INF/MANIFEST.MF` 与 2 个 `.class` 文件的 SHA-256，校验失败时自动删除并重建。
  - **已运行进程免重启自动识别、在线热注入范围门禁与指数退避 (`internal/collector/live_attach.go`)**：对选中的运行中进程优先挂载非侵入式 eBPF Uprobe（含 `-ldflags="-s -w"` 剥离符号表的 `.gopclntab` 自动恢复）；当 eBPF 无法直接覆盖时生成含 `DegradationNotices` 的诊断计划，检查 `PtraceUserspaceSupported`（不支持如 `linux/arm64` 时跳过 ptrace 并告警 `ptrace_arch_unsupported`）。执行热注入前，`Collector.InjectRunningPID` 在入口最前端调用 `tracker.IsInScope(pid)` 校验目标 PID 是否属于当前监控范围；若不在范围内，立即记录 `selfmon` `StageProbe` 的 **`pid_inject_out_of_scope_blocked`** 告警并返回 **`ErrPIDOutOfScope`**，Web API `POST /api/pid/inject` 将其映射为 **`403 Forbidden`**，绝不触碰底层 `ptrace`/信号/JVMTI；对监控范围内的目标支持 JVM Dynamic Attach `agentmain`、基于 `/proc/<pid>/fd` + `/proc/net/tcp` socket inode 精确匹配端口的 Node.js `SIGUSR1` V8 Inspector、Linux `amd64` `PTRACE_SEIZE`；对注入失败的目标按 PID 执行 `1s`→`5min` 指数退避（`injectBackoffInitial` / `injectBackoffMax`），记录 `inject_backoff` 告警，并在 Collector 停止及 `web.Server.Close()` 时通过 `ResetInjectBackoff` 自动清空退避表。
  - **直接拉起子程序 (`-- <command> [args...]`) 自动参数补全与业务凭据原样透传 (`internal/collector/launch_plan.go`, `collector.go`)**：当目标子程序无法通过非侵入式 eBPF 覆盖时，默认（`--auto-intrusive`）自动补全目标命令行参数（Java `-javaagent` + `-Dhttps.proxyHost`、Node.js `--require`、Bun `--preload`、支持 ptrace 架构上的静态二进制 `llm_tracer_ptrace` 包装）与环境变量。启动规划与 `LaunchPlannedCommand` 执行时，`IsSensitiveChildEnvKey` 与导出的 `StripSensitiveEnvKeys` **仅剥离 `llm-tracer` 自身的内部敏感变量**（`LLM_TRACER_TOTP_SECRET`、`LLM_TRACER_INGEST_TOKEN`、`LLM_TRACER_LOCAL_TOKEN`、`LLM_TRACER_AUTH_TOKEN`、`LLM_TRACER_TOKEN` 等）；**用户的业务与模型认证环境变量**（例如 `OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`GEMINI_API_KEY`、`GITHUB_TOKEN`、`AWS_SESSION_TOKEN`、`HF_TOKEN` 等）在拉起子进程时**完整原样透传给被测程序**，确保各类 Agent CLI 与模型 SDK 正常鉴权（仅在 `/api/scope` 展示与 `selfmon` 日志落盘时通过 `redactEnvMap`/`RedactCmdArgs` 脱敏为 `[REDACTED]`）。
  - **八层全运行时自适应采集引擎**（详见 [`docs/02-capture-engine-and-ebpf.md`](docs/02-capture-engine-and-ebpf.md)）：
    0. **Linux 内核态零注入 eBPF 引擎 (`ebpf_engine_linux.go`)**：支持 `linux/amd64` 与 `linux/arm64`（`ebpf_arch_amd64.go` / `ebpf_arch_arm64.go`），内置 11 个原生 eBPF 程序、19 个 Uprobe/Uretprobe/Syscall Tracepoint 与 **`16 MiB` `BPF_MAP_TYPE_RINGBUF`**，通过 `active_ssl_read` 与 `active_sys_read` 双 LRU Hash Map 隔离 TLS 与系统调用读缓冲，支持动态/静态 OpenSSL、Go `crypto/tls` `RET` 探针与全静态二进制。
    1. **动态 `libssl.so` / `libssl.dylib` PLT 拦截 (`libllmtracer_ssl.so` / `libllmtracer_ssl.dylib`)**：拦截 `SSL_write` / `SSL_write_ex` / `SSL_read` / `SSL_read_ex`，覆盖 `curl`、系统 `python3`、常规 C/C++ 等动态链接 OpenSSL 程序。
    2. **Socket 系统调用函数拦截 (`send`/`recv`/`sendto`/`recvfrom`/`write`/`read`/`writev`/`close`)**：覆盖 Bun (`claude.exe` `uSockets`/`libuv` 分散 `writev`) 及明文 HTTP 网关流量，内置 `fstat(S_ISSOCK)`、Keep-Alive 请求代数隔离 (`tracked_http_gen[fd]`) 与 `runtime_plain_http_hook_active()` 独立去重判定。
    3. **Python 运行时 `ssl.SSLObject (MemoryBIO)` + `ssl.SSLSocket` + `HTTPConnection` 钩子 (`pyhook/sitecustomize.py`)**：覆盖 Astral `uv` / `hermes` 独立版 Python、`asyncio` (`httpx` / `aiohttp`) `MemoryBIO` 明文流及本地明文 HTTP（Ollama / vLLM / MCP）。
    4. **Node.js & Bun 运行时 TLS + 明文 HTTP 钩子 (`node_hook.cjs`)**：通过 `NODE_OPTIONS=--require` 拦截 Node.js 的 `tls.TLSSocket`（`_write`/`_writev`/`push`）与明文 `net.Socket`（`_write`/`_writev`/`push`），通过 `BUN_OPTIONS=--preload` 拦截 Bun (`claude.exe`) 的 `globalThis.fetch`，并设置 `LLM_TRACER_NODE_PLAIN_ACTIVE=1` 与 C 层明文钩子精确去重。
    5. **跨进程树 `ptrace` 系统调用追踪 (`llm_tracer_ptrace`)**：自动穿透包装脚本（如 `bin/codex`），基于 `PTRACE_GET_SYSCALL_INFO` + `process_vm_readv` 拦截 `static-pie`（如 `codex` Rust+`musl`）及 Go 原生二进制的底层 Socket 系统调用。
    6. **内置动态 CA 与 `LoopbackTap` (`internal/collector/loopback_tap.go`)**：为 Rust (`rustls` / `reqwest`)、C/C++ 剥离符号静态 TLS、Go (`crypto/tls`) 提供零 Root 跨平台 HTTPS 解密；默认校验非回环上游证书，可通过 `--tap-insecure` 跳过自签名/企业代理上游证书校验。
    7. **Java / JVM 零代码 `-javaagent` 字节码代理 (`internal/collector/java_agent.go`)**：自动构建 `llm_tracer_java.jar` 并通过 `JAVA_TOOL_OPTIONS` 注入 JVM，零侵入捕获 `Spring AI`、`LangChain4j`、`HttpClient` 等 JVM 客户端的 HTTPS/HTTP 流量。
- **多协议识别、流重组与严格资源边界 (`internal/parser`)**
  - 模块化拆分为 `stream.go`、`stream_h1.go`、`stream_h2.go` 与 `protocol_detect.go`、`protocol_systemone.go`、`protocol_openai.go`、`protocol_anthropic.go`、`protocol_gemini.go`、`protocol_bedrock.go`、`protocol_ollama.go`、`protocol_mcp.go`，支持 HTTP/1.1 & HTTP/2（HPACK 帧重组）、gzip/deflate/zstd 解压、SSE 流式实时拼接。
  - **严格内存与解压防爆上限**：单连接单缓冲上限 `8 MiB`、全局总缓冲预算 `64 MiB`（最旧连接优先驱逐）、每连接并发 HTTP/2 流上限 `256`、空闲连接超时 `2m` 自动回收并落盘 `incomplete` 事件、解压输出上限 `16 MiB`（防 Zip/Zstd 炸弹）、未知协议告警按 Host 10 秒限流并维护 `256` 容量 LRU 表。
  - 内置识别 8 大协议：**TypeSafe JEV (`systemone`)**、**OpenAI Chat Completions (`openai_chat`)**、**OpenAI Responses API (`openai_responses`)**、**Anthropic Messages (`anthropic`)**、**Google Gemini (`gemini`)**、**AWS Bedrock (`bedrock`)**、**Ollama (`ollama`)**、**Model Context Protocol (`mcp` JSON-RPC 2.0)**；支持 `--capture-unknown` 保留未识别协议的 HTTP 通信。
  - **默认不记录 HTTP 请求/响应头**（防止 `Authorization` / `Cookie` 等凭据泄露），仅在显式指定 `--record-headers` 时记录；`parser/protocol_detect.go` 的 `RedactSensitivePath` 直接引用 `selfmon` 导出的共享脱敏表 `SensitiveQueryKeys`、`IsSensitiveQueryKey`、`RedactQueryPairs` 与 `RedactPathMatrixParams`（包依赖方向：`parser` → `selfmon`），将 `?key=...`、`x-goog-api-key`、百分号编码 `api%5Fkey`、`jwt` 及路径矩阵参数 `;key=...` 统一脱敏为 `[REDACTED]`。
- **三级会话自动串联 (`internal/correlator`)**
  - **L1 (`L1_explicit`)**：显式 `session_id` / `conversation_id` / `previous_response_id` / `prompt_cache_key`。
  - **L2 (`L2_context`)**：对话协议 `messages` 前缀指纹匹配（自动折叠历史重复上下文，高亮本轮新增消息）与 `systemone` 的 `goal + recent_actions` 步进串联。
  - **L3 (`L3_proctree`)**：同进程树活跃时间窗跨协议关联（如 JEV 单步决策后调用 `/v1/chat/completions` 辅助生成填写文本）。
- **按日分片原子存储、只读回放、`evictLoop` 热窗驱逐与两层 LRU 增量统计 (`internal/store`)**
  - 会话数据按 UTC 日期分片存储于 `<cache_dir>/sessions/<YYYY-MM-DD>/<session_id>/{session.json,events.jsonl}`：**仅 `sessions` 子目录树强制为 `0700`、会话与自监控事件文件为 `0600`**（缓存根目录、`selfmon/`、`pyhook/`、`java_build/` 目录为 `0755`，编译产物 `.so`/`.dylib`/`llm_tracer_ptrace` 通过 `chmodArtifactNoFollow` 强制为 `0755`，`.jar`/`.py`/`.cjs`/`.pem` 通过 `writeArtifactNoFollow`/`chmodArtifactNoFollow` 强制为 `0644`，不受 umask 影响）。`persistSessionEvent` 在追加写入前通过 `ReadAt(size-1)` 检查 `events.jsonl` 末字节，若非 `\n` 则先补齐换行防止粘连；`loadFromDisk` 启动恢复时通过 **`inspectAndHealEventsFile`** 逐行校验 `events.jsonl`，若发现崩溃导致的半截损坏行或缺失 `session.json`，在读写模式下自动截断修复并调用 `rebuildSummaryFromEvents` 重建摘要，而在 **`OpenReadOnly`** 只读模式（如 `llm-tracer status` / `view`）下仅在内存中丢弃损坏尾部并重算摘要，严格保持磁盘文件零写入；启动时通过 `chmodNoFollow` + `os.Lstat` 防符号链接攻击并执行 `migrateSessionDirPermissions`；`clean --all` 按 `knownHookArtifacts` 同步清理 `hooks/` 探针产物。
  - 默认仅在内存保留 **最近 10 分钟 (`--window 10m`)** 的非流式热事件，后台 `evictLoop` 按 `hotWindow/2`（下限 `100ms`、上限 `30s`）及每 `defaultEvictSweepOps = 256` 次写入执行 `EvictExpiredHot` 热窗驱逐，拖动时间轴滑块时按需从磁盘 `events.jsonl` 懒加载并合并。
  - 通过 `sessionContribTracker` 维护两层 `lruIDSet`（第一层 `byID` 容量 `DefaultMaxTrackedEvents = 4096` 保存事件贡献，第二层 `seenIDs` 容量 `DefaultMaxSeenEventIDs = 65536` 记录已见事件 ID）：新事件 ID 以 $O(1)$ 直接判定无需扫盘，仅对已见过但被逐出第一层 `byID` 的旧事件更新回退扫描磁盘 `events.jsonl`。
- **异步批量自监控 (`internal/selfmon`)、Prometheus `/metrics` 与纵深 Web 安全 (`internal/web`, `internal/totp`)**
  - **统一命令行与凭据脱敏管线**：`selfmon` 通过 `RedactCmdline`、`RedactCmdArgs`、`RedactArgSlice` 统一处理命令行字符串与参数切片，覆盖 `--flag=value`、长短分离参数（`-p <secret>` / `--api-key <secret>`）、`curl -u user:pass`、URL 内嵌 `scheme://user:pass@host` 凭据以及 `KEY=VALUE` 环境变量；`selfmon` 采用 `DefaultWriteQueueSize = 4096` 异步写入队列（预留 `DefaultPriorityQueueQuota = 512` 优先队列专供 `warn`/`error`）、`hotEvents` 保高优淘汰、按状态分级丢弃统计 `DroppedByStatus`、基于 `hotCoveredFrom` 的按需 `FlushWithTimeout(200ms)`、用户主目录脱敏为 `~`，并通过 `GET /metrics` 导出 `llm_tracer_selfmon_*` Prometheus 指标。
  - **多层 Web 安全、动态请求头门禁与优雅退出**：`web.Server` 默认 `AllowWebHeaderToggle = false`（可通过 CLI 参数 `--allow-web-header-toggle` 显式开启），未开启时通过 `PUT /api/scope` 将 `record_headers` 从 `false` 翻转为 `true` 会被拦截并返回 `403 Forbidden`，同时记录 `selfmon` `StageWeb` 的 `scope_header_toggle_blocked` 告警（关闭方向始终放行）；`web.Server` 提供 `done` / `Close()` 并绑定 `httpServer.RegisterOnShutdown`，使 SSE (`handleSSEStream`) 在退出时立即中断返回并重置注入退避（`ResetInjectBackoff`）；`handleAuthStatus` 下发 `window_ms` 供前端 `applyServerDefaultWindow` 应用服务端默认时间窗；32 字节 CSPRNG 令牌（Header `X-LLM-Tracer-Token` / `X-LLM-Tracer-Ingest`，Cookie `llm_tracer_token` `HttpOnly: true` + `SameSite=Strict`）仅在回环地址下发；DNS Rebinding 拦截记录 `host_rejected`；`POST /api/pid/inject` 强制回环来源 + Header Token + 无 `Origin` 头且必须在监控范围内（范围外返回 403 `ErrPIDOutOfScope`）；`totp.Guard` 支持内存 `lt_...` 会话（`CheckSession` 不计失败）与按客户端 IP 分桶防爆破（`MaxClientBuckets = 4096`，连续 5 次失败锁定该 IP 15 秒）。

## 构建与常用命令

```bash
# 使用 mise 管理的 Go 1.26.5 构建测试
mise exec go@1.26.5 -- go test -v -count=1 ./...
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run TestCompatibilityMatrixAllRuntimeScenarios
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run 'TestPolyglotLanguagesCapture|TestAgentFrameworksAndAgentCLIsScenarios'
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run TestCrossPlatform
mise exec go@1.26.5 -- go build -o bin/llm-tracer ./cmd/llm-tracer
./bin/llm-tracer --version

# 交叉编译 Linux / macOS / Windows (amd64 & arm64) 发行二进制
GOOS=linux GOARCH=amd64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-linux-amd64 ./cmd/llm-tracer
GOOS=linux GOARCH=arm64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-linux-arm64 ./cmd/llm-tracer
GOOS=darwin GOARCH=amd64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-darwin-amd64 ./cmd/llm-tracer
GOOS=darwin GOARCH=arm64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-darwin-arm64 ./cmd/llm-tracer
GOOS=windows GOARCH=amd64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-windows-amd64.exe ./cmd/llm-tracer
GOOS=windows GOARCH=arm64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-windows-arm64.exe ./cmd/llm-tracer

# 1. 直接拉起命令并抓取（含所有子进程）
./bin/llm-tracer capture --listen 127.0.0.1:8787 -- uv run jev-release ripgrep --storybook 40-full --no-interactive

# 2. 抓取已运行中的进程（优先 eBPF Uprobe；若需免重启热注入可加 --inject-live）
./bin/llm-tracer capture --pid 12345
./bin/llm-tracer capture --pid 12345 --inject-live
./bin/llm-tracer capture --pid 12345 --pid-only --exe /usr/bin/python3
./bin/llm-tracer capture --cmd SpringBootAgent --cwd /srv/agent --inject-live

# 3. 开启 TOTP 登录认证、请求头记录、保留未知协议或跳过上游证书校验
./bin/llm-tracer totp
./bin/llm-tracer capture --totp-secret <SECRET> --record-headers
./bin/llm-tracer capture --capture-unknown --tap-insecure -- ./my-custom-client

# 4. 清理缓存、查看自监控状态与抓取 Prometheus 指标
./bin/llm-tracer clean --older-than 24h --dry-run
./bin/llm-tracer clean --all --yes
./bin/llm-tracer status
curl -s http://127.0.0.1:8787/metrics
```
