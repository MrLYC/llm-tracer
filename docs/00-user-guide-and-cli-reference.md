# 00. 功能使用手册与命令行全参考

本文档面向日常使用与运维排障场景，提供 `llm-tracer` 从源码构建、命令行子命令与参数全表、各类大模型客户端抓取实战、Web 实时观测界面操作指南，到常见故障排查（Troubleshooting）的完整参考（代码入口见 `cmd/llm-tracer/main.go`）。

---

## 一、构建与安装

### 1. 本地源码构建（支持 Linux / macOS / Windows）
```bash
# 使用 mise 管理的 Go 1.26.5 编译单二进制
mise exec go@1.26.5 -- go build -o bin/llm-tracer ./cmd/llm-tracer

# 带版本元数据编译（注入 main.version / main.commit / main.date）
mise exec go@1.26.5 -- go build \
  -ldflags="-s -w -X main.version=v0.2.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  -o bin/llm-tracer ./cmd/llm-tracer

# 查看版本与帮助信息
./bin/llm-tracer --version
./bin/llm-tracer version
./bin/llm-tracer --help
```

### 2. 六平台交叉编译（`linux` / `darwin` / `windows` × `amd64` / `arm64`）
```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/llm-tracer-linux-amd64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build -ldflags="-s -w" -o dist/llm-tracer-linux-arm64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=darwin  GOARCH=amd64 go build -ldflags="-s -w" -o dist/llm-tracer-darwin-amd64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/llm-tracer-darwin-arm64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/llm-tracer-windows-amd64.exe ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o dist/llm-tracer-windows-arm64.exe ./cmd/llm-tracer
```

---

## 二、六大子命令与完整参数说明

`llm-tracer` 在 `cmd/llm-tracer/main.go` 中提供 6 个子命令（直接运行 `llm-tracer [flags] [-- cmd]` 等同于 `llm-tracer capture`，同时根命令支持 `--version` / `-v`）：

| 子命令 | 用途说明 | 示例 |
| :--- | :--- | :--- |
| `capture` (默认) | 启动实时抓取引擎与 Web 观测界面（支持关联已运行进程或直接拉起子程序） | `llm-tracer capture --pid 12345`<br>`llm-tracer -- claude -p "hello"` |
| `view [dir]` | 以**真只读离线模式 (`store.OpenReadOnly`)** 打开已有缓存目录进行历史时间轴回放（不启动探针、不创建目录、不修改权限、不删除 `.tmp`） | `llm-tracer view ./traces -l 127.0.0.1:8787 -w 1h` |
| `clean` | 按时间阈值或全量清理本地缓存文件（`--all` 同步清理 `hooks/` 探针产物，支持 `--dry-run` 预览与交互式二次确认） | `llm-tracer clean --older-than 24h --dry-run` |
| `status` | 检查本机 OpenSSL/GoTLS 探针符号解析状态、时间轴概览与自监控指标摘要 | `llm-tracer status -d ./traces` |
| `totp` | 生成新的 RFC 6238 TOTP Base32 密钥、当前 6 位动态码与 `otpauth://` 绑定 URI | `llm-tracer totp` |
| `version` | 输出二进制版本号、Git Commit 与构建时间（等同于 `llm-tracer --version`） | `llm-tracer version` |

### 1. `capture`（及根命令）参数完整速查表

| 参数 | 简写 | 默认值 | 功能说明 |
| :--- | :--- | :--- | :--- |
| `--listen` | `-l` | `127.0.0.1:8787` | Web 界面与 API 监听地址（传 `off`、`none` 或空字符串 `""` 可禁用 Web 仅落盘采集） |
| `--cache-dir` | `-d` | `./traces` | 本地文件缓存目录路径 |
| `--window` | `-w` | `10m` | 打开 Web 时默认预加载的最近时间窗口（支持 `10m`、`30m`、`1h`、`24h`、`7d` 等） |
| `--pid` | `-p` | 空 (不限) | 指定抓取的 PID 列表（如 `--pid 1234,5678`），**默认自动包含其所有后代子进程** |
| `--pid-only` | 无 | `false` | 与 `--pid`、`--exe`、`--cwd`、`--cmd` 配合，仅抓匹配进程本身，不追踪其子进程 |
| `--exe` / `--binary` | 无 | 空 (不限) | 按可执行文件路径或程序名过滤（如 `--exe /usr/bin/python3` 或 `--binary java`） |
| `--cwd` | 无 | 空 (不限) | 按进程当前工作目录（及其子目录）过滤（如 `--cwd /workspace/my-agent`） |
| `--cmd` | 无 | 空 (不限) | 按进程名 (`comm`) 或完整命令行 (`cmdline`) 子串过滤（如 `--cmd claude`） |
| `--host` | 无 | 空 (不限) | 按目标大模型服务器域名过滤（如 `--host api.anthropic.com`） |
| `--inject-live` | 无 | `false` | 针对已运行进程：当非侵入式 eBPF 无法直接解密时，自动执行免重启侵入式热注入 |
| `--auto-intrusive` | 无 | `true` | 针对 `-- <cmd>` 直接拉起的子程序：当无法使用非侵入式方式时，自动通过参数完成侵入式方案 |
| `--exit-with-child` | 无 | `false` | 使用 `-- <cmd>` 拉起子程序时，子程序运行结束后自动刷新缓冲并退出 `llm-tracer` |
| `--tap-insecure` | 无 | `false` | 跳过 `LoopbackTap` 对非回环上游 HTTPS 服务端证书的校验（适用于自签名网关或企业代理后） |
| `--capture-unknown` | 无 | `false` | 保留未识别协议 (`unknown`) 的 HTTP 通信事件（默认 `false` 时在未指定 `--host` 下丢弃未知协议流量） |
| `--record-headers` | 无 | `false` | 是否记录 HTTP 请求头与响应头（**默认关闭**以防 API Key / Cookie 泄露） |
| `--allow-web-header-toggle` | 无 | `false` | 允许通过 Web 界面动态翻转 `record_headers` 红线开关（默认关闭；未开启时禁止通过 Web API 将 `record_headers` 从 `false` 切换为 `true`） |
| `--totp-secret` | 无 | `""` (空) | 可选 TOTP Base32 密钥，开启 Web 登录保护（默认空串；未指定时由 `resolveTOTPSecret` 运行时读取环境变量 `LLM_TRACER_TOTP_SECRET`，避免 `--help` 输出泄露密钥） |
| `--yes` | `-y` | `false` | 跳过免重启热注入或清理操作的交互式 `[y/N]` 确认提示 |
| `--version` | `-v` | `false` | 打印版本信息并退出 |

> **非回环监听安全告警 (`warnIfNonLoopbackWithoutTOTP`)**：当 `capture` 或 `view` 的 `--listen` 参数绑定在非回环地址（如 `0.0.0.0:8787`、`192.168.1.10:8787` 或 `:8787`，即非 `127.0.0.1`、`::1`、`localhost`、`*.localhost`）且未启用 `--totp-secret` 时，程序启动时会在终端输出：
> `[WARNING] 监听地址 <addr> 非回环地址且未开启 TOTP 认证，Web 界面可被同网段访问；建议增加 --totp-secret 参数开启登录保护`
> 并同步向 `selfmon` 的 `web` 阶段写入 `non_loopback_without_totp` 告警事件。

### 2. `view` / `clean` / `status` 子命令参数表

| 子命令 | 参数 | 简写 | 默认值 | 功能说明 |
| :--- | :--- | :--- | :--- | :--- |
| `view [cache-dir]` | `--listen` | `-l` | `127.0.0.1:8787` | 离线回放 Web 监听地址 |
| `view [cache-dir]` | `--window` | `-w` | `10m` | 默认加载时间窗口（支持 `d` 天单位，如 `7d`） |
| `view [cache-dir]` | `--totp-secret` | 无 | `""` (空) | 可选 TOTP Base32 密钥（未指定时由 `resolveTOTPSecret` 运行时读取环境变量 `LLM_TRACER_TOTP_SECRET`，避免帮助信息泄露明文） |
| `clean` | `--cache-dir` | `-d` | `./traces` | 缓存目录路径 |
| `clean` | `--older-than` | 无 | 空 | 清理早于指定时长的会话（如 `10m`、`1h`、`24h`、`7d`） |
| `clean` | `--all` | 无 | `false` | 清理全部缓存会话，并同步清理 `<cache_dir>/hooks/` 下的已知探针与通道产物 (`knownHookArtifacts`) |
| `clean` | `--dry-run` | 无 | `false` | 仅预览将被删除的会话数、文件数和释放字节数，不实际删除 |
| `clean` | `--include-selfmon` | 无 | `false` | 清理时同时删除 `<cache_dir>/selfmon/*.jsonl` 自监控日志 |
| `clean` | `--yes` | `-y` | `false` | 跳过 `--all` 全量清理时的交互式 `yes` 确认 |
| `status` | `--cache-dir` | `-d` | `./traces` | 检查指定缓存目录的探针、时间轴与自监控状态 |

### 3. CLI 启动、版本输出与 Web 监听生命周期契约 (`cmd/llm-tracer/main.go`)

1. **`version` 子命令与 `--version` / `-v` 输出格式完全一致 (`formatVersion`)**：
   - 编译期变量默认为 `version = "dev"`、`commit = "none"`、`date = "unknown"`。
   - `llm-tracer version` 与 `llm-tracer --version`（或 `-v`）共用 `formatVersion()`：当注入了 `commit` 或 `date` 元数据时，输出格式为 `llm-tracer version <version> (<commit>, <date>)`；当 `commit` 与 `date` 均为默认值（`""`、`"none"`、`"unknown"`）时优雅降级为 `llm-tracer version <version>`（如 `llm-tracer version dev`）。
2. **Web 服务先同步 `net.Listen` 再异步 `Serve`**：
   - 在 `runCapture` 与 `runView` 中，当未禁用 Web 监听时，主流程先同步调用 `net.Listen("tcp", listen)` 绑定端口，成功后才启动后台协程执行 `httpServer.Serve(ln)`（HTTP Server 默认 `defaultReadHeaderTimeout = 10s`、`defaultIdleTimeout = 120s`）。
   - 若端口冲突或监听地址非法导致 `net.Listen` 失败，程序立即向 `selfmon` 的 `web` (`StageWeb`) 阶段记录 `http_listen` 错误，向 `stderr` 打印 `Error: failed to listen on <addr>: <err>`，完成采集器/存储层清理并以退出码 `1` 退出（`exitCodeError{code: 1}`）。
3. **`-l off` / `none` / 空字符串禁用 Web UI (`isWebListenDisabled`)**：
   - 当 `-l` / `--listen` 传入 `off`、`none` 或 `""`（不区分大小写）时，`isWebListenDisabled` 返回 `true`，不创建监听器与 HTTP Server，且启动横幅打印 `LLM-Tracer Web UI : Web UI 已禁用`（不会打印 `http://off`）。
4. **单次 `capture -- <cmd>` 仅产生 1 条 `plan_launch_command` 自监控事件**：
   - 拉起目标子程序时，`runCapture` 先调用一次 `col.PlanLaunchCommand(launchArgs)` 生成 `LaunchAttachPlan`（若包含架构降级通知 `DegradationNotices`，则在终端输出 `[!] 降级提示: ...`），随后直接调用 `col.LaunchPlannedCommand(ctx, plan, env)` 复用已生成的 `plan` 启动子进程，保证单次 `capture` 全程只记录 1 条 `plan_launch_command` 自监控事件。
5. **真只读 `view` 模式与 SSE 优雅退出 (`store.OpenReadOnly` & `web.Server.Close`)**：
   - `runView` 调用 `store.OpenReadOnly(cacheDir, window)` 打开历史目录：若目录不存在直接报错返回，绝不调用 `os.MkdirAll`、`migrateSessionDirPermissions` 或删除 `.tmp` 文件，支持对只读挂载卷安全回放。
   - `runCapture` 与 `runView` 均通过 `webServer.RegisterOnShutdown` 注册关闭钩子，并在收到退出信号时先调用 `webServer.Close()` 关闭 `s.done` 通道，使所有活跃的 `/api/stream` (`handleSSEStream`) 长连接立即退出循环，避免 `httpServer.Shutdown` 被 SSE 连接拖延超时。

---

## 三、核心功能使用实战指南

### 场景 1：直接拉起子程序并抓取 (`-- <cmd> [args...]`)

在命令末尾加上 `-- <你的程序命令>`，`llm-tracer` 会在启动子进程前自动探测其技术栈：若内核 eBPF 可直接覆盖则走零侵入 eBPF；若不能（如非 root 环境、JVM JSSE、Node/Bun/Python 特殊 TLS、Rust `rustls` 或静态二进制），**会自动向子程序补全所需的启动参数与环境变量**，无需手动配置任何代理或证书。

> **子进程环境变量透传契约 (`IsSensitiveChildEnvKey` / `StripSensitiveEnvKeys`)**：
> - `IsSensitiveChildEnvKey` **仅剥离 `llm-tracer` 自身的内部敏感变量**（如 `LLM_TRACER_TOTP_SECRET`、`LLM_TRACER_INGEST_TOKEN`、`LLM_TRACER_LOCAL_TOKEN`、`LLM_TRACER_AUTH_TOKEN`、`LLM_TRACER_TOKEN` 以及以 `LLM_TRACER_` 开头且带敏感后缀的内部变量）；
> - **用户的业务与模型认证环境变量**（例如 `OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`GEMINI_API_KEY`、`GITHUB_TOKEN`、`AWS_SESSION_TOKEN`、`HF_TOKEN` 等）在拉起子进程时**完整原样透传给被测程序**，确保 Claude Code、Codex、各类 Agent CLI 与模型 SDK 能够正常完成上游鉴权（仅在 `/api/scope` 展示与 `selfmon` 日志落盘时通过 `redactEnvMap`/`RedactCmdArgs` 脱敏为 `[REDACTED]`）。

```bash
# 1. 抓取 Claude Code CLI 启动与对话全过程（自动识别 Bun/Node 并完成参数注入，子进程退出后自动结束）
./bin/llm-tracer capture --exit-with-child -- claude -p "用一句话解释 eBPF uprobe"

# 2. 抓取 OpenAI Codex CLI（自动穿透 bin/codex 包装脚本，识别 static-pie 并启用 ptrace/LoopbackTap）
./bin/llm-tracer capture -- codex "检查当前项目的目录结构"

# 3. 抓取 Hermes / TypeSafe JEV 自动化任务（自动识别 uv Python MemoryBIO 并串联每一步 DOM 决策）
./bin/llm-tracer capture -- uv run jev-release ripgrep --storybook 40-full --no-interactive

# 4. 抓取 Java (Spring AI / LangChain4j) 应用（自动前置注入 -javaagent:... 与 -Dhttps.proxyHost 参数）
./bin/llm-tracer capture -- java -jar my-spring-ai-agent.jar

# 5. 抓取 Node.js Agent 脚本（自动前置注入 --require node_hook.cjs 参数）
./bin/llm-tracer capture -- node agent.js

# 6. 抓取 Rust (reqwest/rustls) 或 C/C++ 编译产物
./bin/llm-tracer capture -- ./target/release/my-rust-agent

# 7. 抓取连接企业自签名网关的自定义 HTTP 客户端（开启 --tap-insecure 与 --capture-unknown）
./bin/llm-tracer capture --tap-insecure --capture-unknown -- ./my-custom-agent
```

---

### 场景 2：抓取已在运行中且不允许重启的进程 (`--pid` / `--cmd` / `--cwd` / `--exe`)

针对线上或本地已经启动的服务/Agent，`llm-tracer` **无需重启目标进程**，按“**eBPF 优先 -> 失败或不支持时提示并免重启热注入**”的流程工作：

#### 方式 A：Linux Root 下优先使用零侵入 eBPF Uprobe
```bash
# 指定 PID（默认包含该 PID 底下的所有子进程），自动识别 GoTLS（含 -ldflags="-s -w" strip 二进制）与 OpenSSL
sudo ./bin/llm-tracer capture --pid 28410
```
- 若目标进程是 **Go 程序（含 strip 后的 `ollama` 等）** 或 **C/C++/Python/Node 动态/静态 OpenSSL 程序**，终端会直接输出：
  `[PID 28410 (my-go-app)] 自动识别: gotls | 挂载模式: ebpf_uprobe (免重启零侵入)`

#### 方式 B：eBPF 无法覆盖时执行免重启热注入（交互式确认或 `--inject-live`）
当目标进程是 **Java/JVM (`jvm-jsse`)**，或在**非特权（无 root）环境**下抓取运行中的 **Node.js / 原生进程**时：

```bash
# 1. 交互式模式：自动输出 eBPF 无法覆盖的原因，并询问是否执行免重启热注入 [y/N]
./bin/llm-tracer capture --pid 31052
# 输出示例：
# [!] [PID 31052 (java)] 自动识别: jvm-jsse | eBPF 状态: unavailable
#   ├─ 诊断原因: Java/JVM 默认使用 JSSE 纯字节码/JIT 执行 TLS 加解密...
#   └─ 候选侵入式方案: [jvm_dynamic_attach] 通过 JVM Dynamic Attach API 动态加载 LlmTracerAgent
#   ? 是否立即对运行中 PID 31052 (java) 执行 [jvm_dynamic_attach] 免重启侵入式热注入？[y/N]: y
#   [+] PID 31052 已完成免重启热注入 (模式: jvm_dynamic_attach)

# 2. 非交互自动模式：加上 --inject-live 直接完成免重启热注入
./bin/llm-tracer capture --pid 31052 --inject-live
```

#### 方式 C：不知道 PID？直接按工作目录 (`--cwd`)、命令行 (`--cmd`) 或程序名 (`--exe`) 选择运行中进程
```bash
# 自动扫描主机上在 /workspace/agent-service 目录下运行的进程并热注入
./bin/llm-tracer capture --cwd /workspace/agent-service --inject-live

# 自动扫描命令行含 "SpringBootAgent" 的运行中进程并热注入
./bin/llm-tracer capture --cmd SpringBootAgent --inject-live

# 仅抓取指定 PID 本身，不追踪其派生的子进程
./bin/llm-tracer capture --pid 31052 --pid-only
```

---

### 场景 3：Web 实时观测界面功能操作指南

启动 `llm-tracer capture`（或离线回放 `llm-tracer view ./traces`）后，在浏览器打开 `http://127.0.0.1:8787`：

1. **顶部时间轴与 10 分钟默认热窗口**
   - **服务端默认窗口下发与动态生效 (`window_ms` & `applyServerDefaultWindow`)**：前端初始化调用 `GET /api/auth/status`（`handleAuthStatus`）获取服务端配置的 `window_ms`（对应 CLI `--window` / `-w`，默认 `10m`），并通过 `static/index.html` 的 `applyServerDefaultWindow` 自动设置初始时间窗口和激活对应预设按钮（例如启动时传入 `-w 1h`，打开页面即默认展示最近 1 小时数据）。
   - **快捷窗口切换**：点击顶部 `10m`、`30m`、`1h`、`6h`、`24h`、`All` 按钮可快速切换时间跨度。
   - **时间轴滑块与平移**：拖动顶部时间轴滑块，或点击两侧 `◀` / `▶` 按钮，即可通过 `GET /api/timeline` 与 `GET /api/sessions/{id}/events` 按需从本地 `<cache_dir>/sessions/<YYYY-MM-DD>/<session_id>/events.jsonl` 懒加载任意历史时间段的通信记录；直方图实时展示各时间分桶的请求密度。
2. **左侧会话列表与多维检索**
   - **自动会话串联展示**：每条会话卡片展示主模型名称、协议类型徽标（`systemone`、`openai_chat`、`openai_responses`、`anthropic`、`gemini`、`bedrock`、`ollama`、`mcp`、`unknown`）、进程名 (`Comm [PID]`)、串联依据徽标（`L1_explicit` / `L2_context` / `L3_proctree` / `root`）、累计轮次 (`Turns` / `Steps`) 与总 Token 消耗。
   - **协议过滤与全文搜索**：可通过下拉框按协议筛选，或在搜索框输入 Prompt 关键词、模型名、Action 名称实时过滤会话。
3. **中间多协议对话与决策时间线**
   - **上下文去重折叠**：在多轮对话中，前几轮重复携带的历史消息（`PrefixCount`）自动折叠为 **`[+ 已折叠 N 条上文历史消息，点击展开]`**，卡片默认只高亮展示本轮新增的用户输入（`NewMessages`）、工具返回与模型响应。
   - **`systemone` (TypeSafe JEV) 专属卡片**：直观展示自动化任务目标 `Goal`、决策动作徽标（如 `CLICK` / `TYPE_TEXT` / `SELECT` / `DONE`）、目标元素 `SelectedTarget` / `SelectedElement`、输入文本 `SelectedText`、置信度百分比、页面摘要 `Page` 与 `RecentActions` 历史动作序列。
   - **Agent 思考与工具调用展示**：独立渲染 `System Prompt`、可折叠的 `Thinking / Reasoning`（Claude Thinking / DeepSeek `reasoning_content` / Gemini `thought` / Codex `reasoning_summary`）以及 `Tool Calls` 参数列表。
4. **右侧报文详情检查器 (Inspector)**
   - 点击任意一轮请求卡片，右侧面板展示完整进程信息（`PID`、`PPID`、`Exe`、`Cwd`、`Cmdline`、`TLSMode` 采集通道）、结构化解析 JSON，以及支持：
     - **「复制脱敏 cURL (`Copy Sanitized cURL`)」**：一键生成剥离了敏感认证头的复现 `curl` 命令；
     - **「导出会话 JSON (`Export Session JSON`)」**：将当前完整串联会话及所有轮次导出为本地 `.json` 文件。
5. **顶部管理弹窗：动态范围修改、自监控与在线清理**
   - **「范围过滤 (Scope)」**：无需重启程序，调用 `PUT /api/scope` 在线修改监听的 `PIDs`、`PIDOnly`、`Exes`、`Cwds`、`Cmds`、`Hosts` 与 `RecordHeaders`，并查看当前已挂载的 eBPF/用户态探针与 `PIDAttachPlan`。
   - **「自监控 (Self-Monitor)」**：通过 `/api/selfmon/stats` 与 `/api/selfmon/events` 查看 `probe` / `tracker` / `stream` / `parser` / `correlator` / `store` / `auth` / `web` 各阶段的成功数、告警数、错误数、异步队列深度、丢弃数及实时日志明细。
   - **「清理缓存 (Clean)」**：通过 `POST /api/cache/clean` 输入时长（如 `1h`、`24h`）或勾选全量清理，先点击 **「预览 (Dry-Run)」** 查看预计删除的会话数与释放磁盘空间，确认无误后再执行删除。

---

### 场景 4：隐私保护、TOTP 登录认证、Prometheus 指标与离线回放

```bash
# 1. 生成 TOTP 密钥（用 Google Authenticator / 1Password / Authy 扫描或录入 Secret）
./bin/llm-tracer totp

# 2. 启动带 TOTP 登录认证的采集服务（或设置环境变量 LLM_TRACER_TOTP_SECRET）
./bin/llm-tracer capture --listen 0.0.0.0:8787 --totp-secret JBSWY3DPEHPK3PXP

# 3. 调试需要查看完整 HTTP 请求/响应头时，显式开启 --record-headers（默认关闭）
./bin/llm-tracer capture --record-headers -- python3 my_agent.py

# 4. 抓取 Prometheus 格式自监控指标（回环地址免密，或传入 TOTP / Local Token）
curl -s http://127.0.0.1:8787/metrics

# 5. 事后离线回放历史抓取目录（不启动任何探针，纯只读浏览）
./bin/llm-tracer view ./traces --listen 127.0.0.1:8787

# 6. 命令行检查探针与缓存状态
./bin/llm-tracer status --cache-dir ./traces
```

---

## 四、常见故障排查指南 (Troubleshooting)

### 1. 无内核 eBPF 权限（`ebpf_status: "unavailable"` 或 `perf_event_open` 报 `EACCES`/`EPERM`）
- **现象**：Linux 下启动时报 `TryAttachKernelUprobe` 失败，或 `status` 显示 `Attached: false`，回退至用户态 Hook / `LoopbackTap`。
- **原因**：Linux 内核加载 `BPF_PROG_TYPE_KPROBE`/`TRACEPOINT` 及 `perf_event_open` 需要 `root`（或 `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`），且要求挂载 `tracefs`/`debugfs`。
- **诊断与解决命令**：
  ```bash
  # 检查当前内核版本、tracefs 挂载与 perf_event_paranoid 设置
  uname -r
  mount | grep -E 'tracefs|debugfs'
  sysctl kernel.perf_event_paranoid kernel.kptr_restrict

  # 挂载 tracefs 并放开 perf_event 限制后，使用 sudo 启动
  sudo mount -t tracefs none /sys/kernel/tracing || true
  sudo sysctl -w kernel.perf_event_paranoid=-1
  sudo ./bin/llm-tracer capture --pid <target_pid>
  ```

### 2. 宿主机无 `gcc` / `cc` 编译器
- **现象**：`selfmon` 的 `probe` 阶段出现 `build_ssl_hook` 告警 `c compiler not found`。
- **影响与自动降级**：无法现场编译 `<cache_dir>/hooks/libllmtracer_ssl.so`（macOS 为 `.dylib`）和 Linux `llm_tracer_ptrace`；但内核 eBPF、Python `sitecustomize.py`、Node/Bun `node_hook.cjs`、Java `llm_tracer_java.jar`（使用内嵌 `.class` 字节码）与 `LoopbackTap` 仍正常工作。
- **诊断与解决命令**：
  ```bash
  # 检查 C 编译器是否存在
  which gcc || which cc
  # Ubuntu/Debian 安装 build-essential；Alpine 安装 build-base；macOS 安装 Xcode CLT
  sudo apt-get update && sudo apt-get install -y gcc libc6-dev
  ```

### 3. 宿主机无 `python3` 或仅有 JRE（无 `javac`）
- **现象**：
  - 环境无 `python3` 时，`CanUsePtrace()` 探测返回 `false`（`internal/collector/runtime_hooks.go`），拉起静态二进制时会自动注入 `HTTP_PROXY`/`HTTPS_PROXY` 走 `LoopbackTap` 兜底；
  - 环境仅有 Java JRE 而无 `javac` 时，`EnsureJavaAgentJar`（`internal/collector/java_agent.go`）会自动回退使用二进制内嵌的预编译 Java 8 字节码（`assets/java/LlmTracerAgent.class` 与 `LlmTracerAgent$TapProxySelector.class`）打包生成 `llm_tracer_java.jar`。
- **诊断命令**：
  ```bash
  python3 --version
  java -version
  unzip -l ./traces/hooks/llm_tracer_java.jar
  ```

### 4. `--cache-dir` 路径过长导致 Unix Domain Socket 创建失败
- **现象**：深层目录下 `AF_UNIX` 路径超过操作系统 `108` 字节限制。
- **自动恢复与 `tls.bin` 零残留机制**：`Collector.Start`（`internal/collector/collector.go`）在检测到 `<cache_dir>/hooks/tls.sock` 长度 `> 80` 字节时，会自动将 Socket 路径缩短重定向至 `/tmp/llmt-<pid>-<seq>.sock`；若 `net.Listen("unix", ...)` 仍因文件系统限制失败，`unixSockSource` 会自动记录 `listen_unix_sock_fallback_pipe` 告警并无缝回退至文件管道 `<cache_dir>/hooks/tls.bin`（`pipeSource` 的 `tailLoop` 每次读到 EOF 且全部完整帧消费完毕后立即 `Truncate(0)` 清空文件，单文件硬上限 `defaultMaxPipeFileSize = 64 KiB`，并在 `Stop()` 时通过 `O_NOFOLLOW` 截断并删除 `tls.bin`，杜绝原始明文头部残留磁盘）。
- **诊断命令**：
  ```bash
  ls -la /tmp/llmt-*.sock ./traces/hooks/
  curl -s http://127.0.0.1:8787/api/selfmon/events?stage=probe | jq .
  ```

### 5. 跨 UID 进程抓取或免重启热注入失败（权限不足 / Yama `ptrace_scope`）
- **现象**：以 `root` 运行 `llm-tracer` 抓取普通用户（或容器/服务账户）进程时，目标进程无法写入 `tls.sock`/`tls.bin`，或非 root 下 `ptrace_seize` / `jvm_dynamic_attach` 报 `EPERM`。
- **内部机制与排查**：
  - **严禁 `0666` 全局可写的跨 UID 最小权限策略**：`ensureHookChannelPermissions`（`internal/collector/collector.go` 与 `source_perm_unix.go` 的 `ensureSafeHooksDir`、`setHooksDirModeNoFollow`、`initPipeFileNoFollow`、`applyPipePermissionsNoFollow`、`applySocketPermissionsNoFollow`、`applyFdPermissions`、`sanitizePrivateMode`）检测到单个跨 UID 目标进程且当前进程具备 `CAP_CHOWN`（root）时，通过 `setHooksDirModeNoFollow`（使用 `syscall.O_NOFOLLOW`）将 `<cache_dir>/hooks` 设为 `0711`（仅可遍历不可列目录），通过 `applyPipePermissionsNoFollow` 与 `applySocketPermissionsNoFollow` 将 `tls.sock`/`tls.bin` `lchown` 给该目标 UID 并严格保持 `0600`。**若存在多个不同非特权 UID 目标或当前无 `CAP_CHOWN` 权限，系统绝不回退 `0666`**，而是保持当前用户私有 `0600` 并向 `selfmon` `StageProbe` 记录 `cross_uid_channel_denied` 告警。
  - **热注入失败按 PID 指数退避 (`inject_backoff`)**：`live_attach.go` 对热注入失败的 PID 执行指数退避（初始 `injectBackoffInitial = 1s`，每次翻倍直至上限 `injectBackoffMax = 5m`，通过 `recordInjectFailure` 与 `checkInjectBackoff` 维护 `pidInjectBackoffState` 并记录 `inject_backoff` 告警），避免每 `200ms` 重复向目标进程发送 `SIGUSR1` 或拉起 `jcmd`。
  - 若 `--cache-dir` 位于 `/root/...` 等父目录本身禁止其他 UID 遍历（`0700`）的路径下，请将 `-d` 指定到公共可遍历路径（如 `/tmp/llm-traces`）。
  - 若 `ptrace_seize` 报 `check kernel.yama.ptrace_scope or root privileges`，需检查 Yama LSM 配置。
- **诊断与解决命令**：
  ```bash
  # 检查目标进程 UID 与 Yama ptrace_scope
  ps -o pid,uid,user,comm -p <target_pid>
  sysctl kernel.yama.ptrace_scope

  # 允许跨进程 ptrace 并使用公共缓存目录
  sudo sysctl -w kernel.yama.ptrace_scope=0
  sudo ./bin/llm-tracer capture -d /tmp/llm-traces --pid <target_pid> --inject-live
  ```

### 6. Web API 请求被安全守卫拦截（`403 Forbidden` / `401 Unauthorized` / `415 Unsupported Media Type`）
- **原因对照（详见 `internal/web/server.go`）**：
  - **`403 Forbidden` (`{"error": "forbidden host"}`)**：请求 `Host` 头既非回环地址（`127.0.0.1`、`localhost`、`[::1]`），也不匹配 `--listen` 显式绑定的地址（触发 `isAllowedRequestHost` DNS Rebinding 防护，自监控记录 `host_rejected`）。
  - **`403 Forbidden` (`{"error": "cross-site request forbidden"}` / `"forbidden origin"` / `"origin and host mismatch"`)**：浏览器跨站请求被 `withOriginAndHostGuard` 的 `Sec-Fetch-Site: cross-site` 或 `isValidSameOrigin` 同源守卫拦截（自监控记录 `csrf_origin_rejected`）。
  - **`403 Forbidden` (`{"error": "enabling record_headers via Web API requires --allow-web-header-toggle"}`)**：未指定 CLI 参数 `--allow-web-header-toggle` 时，通过 `PUT /api/scope` 试图将 `record_headers` 从 `false` 动态开启为 `true` 会被拒绝并返回 `403`（记录 `selfmon` `StageWeb` 的 `scope_header_toggle_blocked` 告警）；而将 `record_headers` 设为 `false`（关闭方向）或保持原值始终放行。
  - **`403 Forbidden` (`{"error": "pid is outside the configured capture scope"}`)**：调用 `POST /api/pid/inject` 时，`Collector.InjectRunningPID` 在入口最前端通过 `tracker.IsInScope(pid)` 校验目标 PID 是否在当前监控范围内，若不在监控范围内立即拒绝并返回 `403`（记录 `selfmon` `StageProbe` 的 `pid_inject_out_of_scope_blocked` 告警），绝不触发底层 ptrace/信号/JVMTI。
  - **`403 Forbidden` (`{"error": "非回环地址访问需启用 --totp-secret", "totp_enabled": false}`)**：未启用 `--totp-secret` 时，从非回环地址访问 `POST /api/auth/bootstrap`、`POST /api/auth/login`、`PUT /api/scope`、`POST /api/cache/clean`、`POST /api/ingest/exchange`、`POST /api/ingest/tls` 等写接口会被一律拒绝（记录 `write_non_loopback_forbidden` / `ingest_non_loopback_forbidden`）。
  - **`403 Forbidden`（调用 `POST /api/pid/inject`）**：`withPIDInjectAuth` 无论是否开启 TOTP，均强制要求请求来自本机回环地址（非回环返回 `403`，`protection: "loopback_header_token_only"`，记录 `pid_inject_non_loopback_blocked`）且禁止携带任何 `Origin` 请求头（携带 `Origin` 返回 `403`，`protection: "header_token_only_no_origin"`，记录 `pid_inject_browser_blocked`），仅接受通过 HTTP 请求头（`X-LLM-Tracer-Token`、`X-LLM-Tracer-Ingest` 或 `Authorization: Bearer`）传入的本机 Token。
  - **`401 Unauthorized`**：调用写接口（`PUT /api/scope`、`POST /api/cache/clean`、`POST /api/pid/inject`、`POST /api/ingest/*`）未携带有效 Token / Cookie，或开启 TOTP 后未登录（注：系统已彻底移除 URL 查询参数令牌鉴权，且本机 Token 与 `llm_tracer_token` Cookie 仅在回环地址下发）。
  - **`415 Unsupported Media Type`**：调用 JSON 写接口时 `decodeJSONBody` 检测到未携带 `Content-Type: application/json` 请求头。
- **可执行诊断与正确调用示例**：
  ```bash
  # 从本地首页提取进程启动生成的本机 Token（未开启 TOTP 时）
  LOCAL_TOKEN=$(curl -s http://127.0.0.1:8787/ | sed -n 's/.*name="llm-tracer-token" content="\([^"]*\)".*/\1/p')

  # 携带 Content-Type: application/json 与 X-LLM-Tracer-Token 调用写接口
  curl -i -X PUT http://127.0.0.1:8787/api/scope \
    -H "Content-Type: application/json" \
    -H "X-LLM-Tracer-Token: $LOCAL_TOKEN" \
    -d '{"pids":[12345],"record_headers":false}'

  # 触发运行中 PID 热注入（无 Origin 头 + 显式 X-LLM-Tracer-Token 请求头）
  curl -i -X POST http://127.0.0.1:8787/api/pid/inject \
    -H "Content-Type: application/json" \
    -H "X-LLM-Tracer-Token: $LOCAL_TOKEN" \
    -d '{"pid":12345}'
  ```

### 7. `LoopbackTap` 上游 TLS 证书校验失败或私有协议流量被丢弃
- **现象 1**：`selfmon` 出现 `loopback_tap_upstream_tls` 告警（`upstream TLS verify/dial failed... hint: use --tap-insecure`）。
  - **解决**：目标上游使用了自签名证书或处于企业内网 MITM 代理后，启动时添加 `--tap-insecure`。
- **现象 2**：`selfmon` 出现 `unknown_protocol_dropped` 告警，自定义 HTTP 接口未出现在会话列表中。
  - **解决**：默认情况下未匹配 8 大内置协议且未设置 `--host` 的流量会被自动过滤；启动时添加 `--capture-unknown`（或指定 `--host <domain>`）即可完整保留。
