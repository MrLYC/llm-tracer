# 01. 系统总体架构与数据流设计

`llm-tracer` 是一个面向本机大模型应用、Agent 框架与 CLI 工具的**单二进制、零外部依赖、全运行时自适应**通信抓取与会话观测系统。它吸收了 `eCapture` 的内核 eBPF Uprobe 思想，并针对现代大模型客户端（静态内嵌 TLS、BoringSSL/`rustls`、Python `MemoryBIO`、JVM JSSE、剥离符号 Go/C/Rust 二进制）扩展了完整的非侵入式优先 + 侵入式自动回退体系。

---

## 一、端到端数据流拓扑

```text
+---------------------------------------------------------------------------------------------------+
|                                     目标进程选择层 (ProcessTracker)                                 |
|   --pid (默认含子进程树 / --pid-only) | --exe/--binary | --cwd | --cmd | --host | -- <cmd> [args]   |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                  +-------------------------------+-------------------------------+
                  |                                                               |
                  v (优先：非侵入式内核态)                                         v (回退/自动补全：用户态与热注入)
+-----------------------------------+                           +-----------------------------------+
|   Linux 内核态 eBPF 引擎 (Layer 0) |                           |     多运行时自适应采集层 (Layer 1-7) |
| - OpenSSL Uprobe/Uretprobe        |                           | - Layer 1: LD_PRELOAD libssl.so   |
| - Static OpenSSL (.symtab) Uprobe |                           | - Layer 2: Socket writev/send Hook|
| - Python MemoryBIO Uprobe         |                           | - Layer 3: Python sitecustomize   |
| - GoTLS Write & Read-RET Uprobes  |                           | - Layer 4: Node/Bun node_hook.cjs |
|   (含 stripped .gopclntab 恢复)    |                           | - Layer 5: ptrace (Launch/SEIZE)  |
| - Syscall Tracepoints (write/     |                           | - Layer 6: LoopbackTap 动态 CA     |
|   writev/sendto/read/recvfrom)    |                           | - Layer 7: JVM Agent (pre/agent)  |
| - 8 MiB BPF_MAP_TYPE_RINGBUF      |                           | - Live Attach: jcmd / SIGUSR1     |
+-----------------+-----------------+                           +-----------------+-----------------+
                  |                                                               |
                  +-------------------------------+-------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                        统一 24 字节 LLMT 帧总线 (Unix Socket / Append Pipe / RingBuf)               |
|          [Magic: 0x4C4C4D54][PID: 4B][TID: 4B][ConnTag: 4B][Dir: 4B (0=W,1=R)][Len: 4B]           |
|                              + 按 PID 自动去重 (userHookPIDs / 环境变量锁)                          |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                 流重组与隐私脱敏层 (StreamReassembler)                              |
| - HTTP/1.1 Keep-Alive 分帧、Chunked 聚合、HTTP/2 HPACK 头解压与 DATA 帧重组                         |
| - Gzip / Deflate / Zstd 自动解压、SSE (text/event-stream) 增量事件流拼接                            |
| - 默认剥离全部 Request/Response Headers（防 API Key 泄露），URL Query ?key= 自动脱敏                |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                              多协议识别与语义提取层 (ProtocolParser - 8 大协议)                     |
|  systemone (TypeSafe JEV) | openai-chat | openai-responses | anthropic | gemini | bedrock |       |
|  ollama | mcp (JSON-RPC 2.0) —— 统一提取 SystemPrompt / Reasoning / ToolCalls / TokenUsage        |
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
|  - 默认仅加载最近 10 分钟 (--window 10m) 数据，时间轴滑块按需从磁盘 .jsonl 分片懒加载               |
|  - 全链路自监控 (selfmon/events.jsonl) + 可选 RFC 6238 TOTP 登录保护 + SSE 实时推送                 |
+---------------------------------------------------------------------------------------------------+
```

---

## 二、代码目录与模块职责边界

| 目录 / 包路径 | 核心文件 | 职责说明 |
| :--- | :--- | :--- |
| `cmd/llm-tracer` | `main.go` | CLI 入口（`capture`、`view`、`clean`、`status`、`totp` 子命令），管理信号生命周期、进程选择器诊断交互与 `-- <cmd>` 子进程拉起。 |
| `internal/collector` | `collector.go`<br>`ebpf_engine_linux.go`<br>`elf_probe.go`<br>`live_attach.go`<br>`preload_hook.go`<br>`runtime_hooks.go`<br>`java_agent.go`<br>`loopback_tap.go`<br>`proctree*.go` | **核心采集层**：二进制 ELF/Mach-O/PE 与 `.gopclntab` 符号探测、Linux 原生 eBPF 字节码加载与 RingBuf 消费、动态/静态 OpenSSL 与 Python/Node/Bun/JVM 运行时 Hook、`ptrace` 追踪器、`LoopbackTap` 本地动态 CA MITM 代理、跨平台进程树扫描、已运行 PID 免重启热注入与子程序启动参数自动补全。 |
| `internal/parser` | `reassembler.go`<br>`protocol.go` | **流重组与协议解析层**：按 `ConnKey` 重组双向字节流，处理 HTTP/1.1、Chunked、HTTP/2 HPACK、Gzip/Deflate/Zstd 解压、SSE 流拼接，并将请求/响应解析为 8 种大模型协议的结构化字段。 |
| `internal/correlator` | `correlator.go` | **三级会话串联层**：通过 `L1_explicit`、`L2_context`、`L3_proctree` 将离散的 HTTP 交互自动归并到同一逻辑 `Session`，并计算每轮新增消息（`NewMessages`）与历史折叠数（`ContextMessagesCount`）。 |
| `internal/store` | `store.go` | **本地文件存储与时间窗引擎**：维护内存热索引与磁盘 `<cache_dir>/sessions.json` + `<cache_dir>/events/<session_id>.jsonl`，实现默认 10 分钟时间窗过滤、时间轴游标分页与 `clean` 缓存清理。 |
| `internal/selfmon` | `monitor.go` | **自监控模块**：记录 `probe`、`tracker`、`stream`、`parser`、`correlator`、`store`、`web`、`auth` 各阶段的成功（`ok`）、告警（`warn`）与错误（`error`）事件及累计指标。 |
| `internal/totp` | `totp.go` | **安全认证模块**：纯标准库实现的 RFC 6238 TOTP（HMAC-SHA1 6 位动态码）、HMAC 会话 Cookie 签发与防暴力破解窗口锁定。 |
| `internal/web` | `server.go`<br>`static/index.html` | **Web 实时观测台**：提供 REST API、`/api/stream` SSE 实时流推送、TOTP 登录界面、时间轴双滑块、多协议卡片渲染（JEV 决策卡片、Thinking 折叠、ToolCall 展示）、动态 Scope 更新与运行中 PID 一键热注入。 |
| `internal/model` | `types.go` | **领域模型定义**：定义 `TraceEvent`、`Session`、`SystemOneData`、`ChatSummary`、`ProcessInfo`、`ScopeFilter` 等核心数据结构。 |

---

## 三、统一 `LLMT` 二进制帧协议与多通道去重机制

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
2. **Python/C 跨层锁 (`LLM_TRACER_PY_TLS_ACTIVE=1`)**：Python `sitecustomize.py` 激活后写入该环境变量，同进程内的 `libllm_tracer_ssl.so` 检测到后自动跳过 C 层 `SSL_write`/`SSL_read` 上报。
3. **Node.js 钩子全局幂等锁 (`globalThis.__LLM_TRACER_NODE_HOOK_LOADED__`)**：即使同时通过命令行参数 `--require node_hook.cjs`、环境变量 `NODE_OPTIONS` 或 `SIGUSR1` V8 Inspector 注入，`node_hook.cjs` 也只会包裹 `tls.TLSSocket.prototype` 一次。
4. **Java `TapProxySelector` 幂等替换**：即使 `-javaagent` 与 `JAVA_TOOL_OPTIONS` 同时存在，`LlmTracerAgent.install()` 会检测 `ProxySelector.getDefault() instanceof TapProxySelector`，避免代理链嵌套循环。
