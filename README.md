# llm-tracer

基于 eCapture / eBPF uprobe 与 OpenSSL / GoTLS 探针的本机大模型通信抓取、多协议识别、会话串联与实时 Web 观测工具（单二进制，纯本地文件缓存）。

## 文档体系导航

本项目提供完整的分层技术文档体系，涵盖从整体架构、内核 eBPF 字节码实现、免重启热注入到多协议会话串联的全部技术细节：

| 文档编号与路径 | 主题与涵盖内容 |
| :--- | :--- |
| **[00. 功能使用手册与命令行全参考](docs/00-user-guide-and-cli-reference.md)** | 安装编译、5 大子命令与全部参数速查、`-- <cmd>` 与 `--pid`/`--cmd`/`--cwd` 实战用法、Web 界面各项功能操作指南、离线回放与 TOTP 配置 |
| **[01. 系统总体架构与数据流设计](docs/01-architecture-overview.md)** | 端到端数据流拓扑图、代码模块职责边界、统一 24 字节 `LLMT` 二进制帧协议、多层探针共存幂等去重机制 |
| **[02. 八层自适应采集引擎与内核 eBPF 深度解析](docs/02-capture-engine-and-ebpf.md)** | 为什么单一 `eCapture` / `LD_PRELOAD` 会漏抓、Linux 原生 11 程序/19 探针 eBPF 引擎、四 Map 防嵌套隔离、动态/静态 OpenSSL、Python `MemoryBIO`、Node/Bun、`ptrace`、`LoopbackTap`、JVM Agent |
| **[03. 进程选择模型、免重启热注入与子程序自动参数补全](docs/03-process-selection-and-live-attach.md)** | `--pid`/`--exe`/`--cwd`/`--cmd` 跨平台进程发现、stripped Go `.gopclntab` 符号恢复、运行中 JVM (`jcmd`/Socket) / Node (`SIGUSR1`) / Native (`PTRACE_SEIZE`) 免重启热注入、`-- <cmd>` 启动参数自动补全 |
| **[04. 多协议流重组、8 大 LLM 协议解析与三级会话串联](docs/04-protocols-and-session-correlation.md)** | HTTP/1.1 & HTTP/2 HPACK 流重组、默认防凭据泄露脱敏、8 大协议（含 `systemone` TypeSafe JEV、OpenAI、Anthropic、Gemini、Bedrock、Ollama、MCP）解析、`L1/L2/L3` 三级会话自动串联与上下文折叠 |
| **[05. 存储引擎、10 分钟时间窗、Web 观测台、TOTP 安全与 CI/CD](docs/05-storage-web-security-and-ops.md)** | 本地 JSONL 分片存储、10 分钟热窗口与时间轴滑块懒加载、`clean` 缓存清理、`selfmon` 全链路自监控、RFC 6238 TOTP 认证、REST/SSE API 契约与 GoReleaser Tag 自动发布 |
| **[附：完整采集兼容矩阵与测试场景详述](docs/capture-architecture.md)** | 6 大运行时兼容测试矩阵、Root 内核态 eBPF 15 大实测场景、多语言 (`Java`/`C++`/`Rust`) 与主流 Agent CLI (`claude`/`codex`/`gemini`) 专项说明 |

---

## 核心特性

- **多维范围抓取 (`internal/collector`)**
  - 支持按 `--pid`（默认抓取该 PID 及其所有后代子进程；加 `--pid-only` 则仅抓单个 PID 本身）、`--exe` / `--binary`、`--cwd`、`--cmd`、`--host` 过滤。
  - **已运行进程免重启自动识别与热注入**：对通过 `--pid`、`--exe`、`--cwd`、`--cmd` 选中的运行中进程，优先挂载非侵入式 eBPF Uprobe（含 `go build -ldflags="-s -w"` 剥离符号表的 `.gopclntab` 自动恢复）；当 eBPF 无法直接覆盖时自动诊断原因，支持通过 `--inject-live`、交互确认或 Web API 执行免重启热注入（JVM Dynamic Attach `agentmain`、Node.js `SIGUSR1` V8 Inspector、Linux `PTRACE_SEIZE`）。
  - **直接拉起子程序 (`-- <command> [args...]`) 自动侵入式参数补全**：当目标子程序无法通过非侵入式 eBPF 覆盖时，默认（`--auto-intrusive`）自动补全目标命令行参数（Java `-javaagent` + `-Dhttps.proxyHost`、Node.js `--require`、Bun `--preload`、静态二进制 `llm_tracer_ptrace` 包装）与环境变量，首包零丢失。
  - **八层全运行时自适应采集引擎**（详见 [`docs/capture-architecture.md`](docs/capture-architecture.md)）：
    0. **Linux 内核态零注入 eBPF 引擎 (`ebpf_engine_linux.go`)**：11 个原生 eBPF 程序、19 个 Uprobe/Uretprobe/Syscall Tracepoint 与 `8 MiB` `BPF_MAP_TYPE_RINGBUF`，支持动态/静态 OpenSSL、Python `MemoryBIO`、Go `crypto/tls` `RET` 探针与全静态二进制。
    1. **动态 `libssl.so` PLT 拦截 (`libllm_tracer_ssl.so`)**：拦截 `SSL_write` / `SSL_write_ex` / `SSL_read` / `SSL_read_ex`，覆盖 `curl`、系统 `python3`、常规 C/C++ 等动态链接 OpenSSL 程序。
    2. **Socket 全族函数拦截 (`write`/`writev`/`read`/`readv`/`send`/`sendto`/`recv`/`recvfrom`)**：覆盖 Bun (`claude.exe` `uSockets`/`libuv` 分散 `writev`) 及明文 HTTP 网关流量，内置 `fstat(S_ISSOCK)` 与 Keep-Alive 请求代数隔离 (`tracked_http_gen[fd]`)。
    3. **Python 运行时 `ssl.SSLObject (MemoryBIO)` + `ssl.SSLSocket` + `HTTPConnection` 钩子 (`pyhook/sitecustomize.py`)**：覆盖 Astral `uv` / `hermes` 独立版 Python、`asyncio` (`httpx` / `aiohttp`) `MemoryBIO` 明文流及本地明文 HTTP（Ollama / vLLM / MCP）。
    4. **Node.js & Bun 运行时 TLS + 明文 HTTP 钩子 (`node_hook.cjs`)**：通过 `NODE_OPTIONS=--require` 拦截 Node.js 的 `tls.TLSSocket` 与明文 `net.Socket`，通过 `BUN_OPTIONS=--preload` 拦截 Bun (`claude.exe`) 的 `globalThis.fetch`。
    5. **跨进程树 `ptrace` 系统调用追踪 (`llm_tracer_ptrace`)**：自动穿透包装脚本（如 `bin/codex`），基于 `PTRACE_GET_SYSCALL_INFO` + `process_vm_readv` 拦截 `static-pie`（如 `codex` Rust+`musl`）及 Go 原生二进制的底层 Socket 系统调用。
    6. **内置动态 CA 与 `LoopbackTap` (`internal/collector/loopback_tap.go`)**：为 Rust (`rustls` / `reqwest`)、C/C++ 剥离符号静态 TLS、Go (`crypto/tls`) 提供零 Root 跨平台 HTTPS 解密。
    7. **Java / JVM 零代码 `-javaagent` 字节码代理 (`internal/collector/java_agent.go`)**：自动构建 `llm_tracer_java.jar` 并通过 `JAVA_TOOL_OPTIONS` 注入 JVM，零侵入捕获 `Spring AI`、`LangChain4j`、`HttpClient`、`OkHttp`、`Apache HttpClient` 的 HTTPS/HTTP 流量。
- **多协议识别与流重组 (`internal/parser`)**
  - 支持 HTTP/1.1 & HTTP/2（HPACK 帧重组）、gzip/deflate/zstd 解压、SSE 流式实时拼接。
  - 内置识别 8 大协议：**TypeSafe JEV (`systemone`)**、**OpenAI Chat Completions**（含 Azure OpenAI、DeepSeek/QwQ `reasoning_content`、`developer` 角色）、**OpenAI Responses API**（Codex CLI / Agents SDK `function_call` & `reasoning_summary`）、**Anthropic Messages**（Claude Code `thinking` & `tool_use`）、**Google Gemini**（Gemini CLI `streamGenerateContent`、`thought`、`functionCall`）、**AWS Bedrock Converse/Invoke (`bedrock`)**、**Ollama (`ollama`)**、**Model Context Protocol (`mcp` JSON-RPC 2.0)**。
  - **默认不记录 HTTP 请求/响应头**（防止 `Authorization` / `Cookie` 等凭据泄露），仅在显式指定 `--record-headers` 时记录。
- **三级会话自动串联 (`internal/correlator`)**
  - **L1 (`L1_explicit`)**：显式 `session_id` / `conversation_id` / `previous_response_id` / `prompt_cache_key`。
  - **L2 (`L2_context`)**：对话协议 `messages` 前缀指纹匹配（自动折叠历史重复上下文，高亮本轮新增消息）与 `systemone` 的 `goal + recent_actions` 步进串联。
  - **L3 (`L3_proctree`)**：同进程树活跃时间窗跨协议关联（如 JEV 单步决策后调用 `/v1/chat/completions` 辅助生成填写文本）。
- **10 分钟默认时间窗与缓存清理 (`internal/store`)**
  - 启动与 Web 界面默认仅加载 **最近 10 分钟 (`--window 10m`)** 的消息，拖动顶部时间轴滑块时按需从磁盘 `.jsonl` 分片懒加载历史数据。
  - 提供 `llm-tracer clean` 命令（`--older-than` / `--all` / `--dry-run`）与 Web 端一键清理。
- **全链路自监控 (`internal/selfmon`) 与可选 TOTP 认证 (`internal/totp`)**
  - 记录 `probe` / `tracker` / `stream` / `parser` / `correlator` / `store` / `auth` 各阶段成功（`ok`）与异常（`warn` / `error`）事件并持久化至 `<cache_dir>/selfmon/`。
  - 支持 `--totp-secret`（或 `LLM_TRACER_TOTP_SECRET`）开启 Web 界面及 API 的 6 位 TOTP 动态码登录保护。

## 构建与常用命令

```bash
# 使用 mise 管理的 Go 1.26.5 构建测试
mise exec go@1.26.5 -- go test -v -count=1 ./...
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run TestCompatibilityMatrixAllRuntimeScenarios
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run 'TestPolyglotLanguagesCapture|TestAgentFrameworksAndAgentCLIsScenarios'
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run TestCrossPlatform
mise exec go@1.26.5 -- go build -o bin/llm-tracer ./cmd/llm-tracer

# 交叉编译 Linux / macOS / Windows 发行二进制
GOOS=linux GOARCH=amd64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-linux-amd64 ./cmd/llm-tracer
GOOS=darwin GOARCH=arm64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-darwin-arm64 ./cmd/llm-tracer
GOOS=windows GOARCH=amd64 mise exec go@1.26.5 -- go build -o dist/llm-tracer-windows-amd64.exe ./cmd/llm-tracer

# 1. 直接拉起命令并抓取（含所有子进程）
./bin/llm-tracer capture --listen 127.0.0.1:8787 -- uv run jev-release ripgrep --storybook 40-full --no-interactive

# 2. 抓取已运行中的进程（优先 eBPF Uprobe；若需免重启热注入可加 --inject-live）
./bin/llm-tracer capture --pid 12345
./bin/llm-tracer capture --pid 12345 --inject-live
./bin/llm-tracer capture --pid 12345 --pid-only --exe /usr/bin/python3
./bin/llm-tracer capture --cmd SpringBootAgent --cwd /srv/agent --inject-live

# 3. 开启 TOTP 登录认证与请求头记录
./bin/llm-tracer totp
./bin/llm-tracer capture --totp-secret <SECRET> --record-headers

# 4. 清理缓存与查看自监控状态
./bin/llm-tracer clean --older-than 24h --dry-run
./bin/llm-tracer clean --all --yes
./bin/llm-tracer status
```
