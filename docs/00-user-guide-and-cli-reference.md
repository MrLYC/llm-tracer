# 00. 功能使用手册与命令行全参考

本文档面向日常使用场景，提供 `llm-tracer` 从安装构建、命令行子命令与参数说明、各类大模型客户端抓取实战，到 Web 实时观测界面各项功能的完整操作指南。

---

## 一、构建与安装

### 1. 本地源码构建（支持 Linux / macOS / Windows）
```bash
# 使用 mise 管理的 Go (或本机 Go 1.22+) 编译单二进制
mise exec go@1.26.5 -- go build -o bin/llm-tracer ./cmd/llm-tracer

# 查看版本与帮助信息
./bin/llm-tracer --help
```

### 2. 跨平台交叉编译
```bash
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o dist/llm-tracer-linux-amd64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o dist/llm-tracer-darwin-arm64 ./cmd/llm-tracer
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/llm-tracer-windows-amd64.exe ./cmd/llm-tracer
```

---

## 二、五大子命令与完整参数说明

`llm-tracer` 提供 5 个子命令（直接运行 `llm-tracer [flags] [-- cmd]` 等同于 `llm-tracer capture`）：

| 子命令 | 用途说明 | 示例 |
| :--- | :--- | :--- |
| `capture` (默认) | 启动实时抓取引擎与 Web 观测界面（支持关联已运行进程或直接拉起子程序） | `llm-tracer capture --pid 12345`<br>`llm-tracer -- claude -p "hello"` |
| `view [dir]` | 以**只读离线模式**打开已有缓存目录进行历史时间轴回放（不启动采集探针） | `llm-tracer view ./traces -l 127.0.0.1:8787` |
| `clean` | 按时间阈值或全量清理本地缓存文件（支持 `--dry-run` 预览与交互式二次确认） | `llm-tracer clean --older-than 24h --dry-run` |
| `status` | 检查本机 OpenSSL/GoTLS 探针符号解析状态、缓存占用统计与自监控指标摘要 | `llm-tracer status -d ./traces` |
| `totp` | 生成新的 RFC 6238 TOTP Base32 密钥、当前 6 位动态码与 `otpauth://` 绑定链接 | `llm-tracer totp` |

### `capture` 参数完整速查表

| 参数 | 简写 | 默认值 | 功能说明 |
| :--- | :--- | :--- | :--- |
| `--listen` | `-l` | `127.0.0.1:8787` | Web 界面与 API 监听地址（传 `off` 或 `none` 可关闭 Web 仅落盘采集） |
| `--cache-dir` | `-d` | `./traces` | 本地文件缓存目录路径 |
| `--window` | `-w` | `10m` | 打开 Web 时默认预加载的最近时间窗口（支持 `10m`、`30m`、`1h`、`24h`、`7d`） |
| `--pid` | `-p` | 空 (不限) | 指定抓取的 PID 列表（如 `--pid 1234,5678`），**默认自动包含其所有后代子进程** |
| `--pid-only` | 无 | `false` | 与 `--pid`、`--exe`、`--cwd`、`--cmd` 配合，仅抓匹配进程本身，不追踪其子进程 |
| `--exe` / `--binary` | 无 | 空 (不限) | 按可执行文件路径或程序名过滤（如 `--exe /usr/bin/python3` 或 `--binary java`） |
| `--cwd` | 无 | 空 (不限) | 按进程当前工作目录（及其子目录）过滤（如 `--cwd /workspace/my-agent`） |
| `--cmd` | 无 | 空 (不限) | 按进程名 (`comm`) 或完整命令行 (`cmdline`) 子串过滤（如 `--cmd claude`） |
| `--host` | 无 | 空 (不限) | 按目标大模型服务器域名过滤（如 `--host api.anthropic.com`） |
| `--inject-live` | 无 | `false` | 针对已运行进程：当非侵入式 eBPF 无法直接解密时，自动执行免重启侵入式热注入 |
| `--auto-intrusive` | 无 | `true` | 针对 `-- <cmd>` 直接拉起的子程序：当无法使用非侵入式方式时，自动通过参数完成侵入式方案 |
| `--exit-with-child` | 无 | `false` | 使用 `-- <cmd>` 拉起子程序时，子程序运行结束后自动刷新缓冲并退出 `llm-tracer` |
| `--record-headers` | 无 | `false` | 是否记录 HTTP 请求头与响应头（**默认关闭**以防 API Key / Cookie 泄露） |
| `--totp-secret` | 无 | `$LLM_TRACER_TOTP_SECRET` | 开启 Web 界面与 API 的 TOTP 6 位动态口令登录保护 |
| `--yes` | `-y` | `false` | 跳过免重启热注入或清理操作的交互式 `[y/N]` 确认提示 |

---

## 三、核心功能使用实战指南

### 场景 1：直接拉起子程序并抓取 (`-- <cmd> [args...]`)

在命令末尾加上 `-- <你的程序命令>`，`llm-tracer` 会在启动子进程前自动探测其技术栈：若内核 eBPF 可直接覆盖则走零侵入 eBPF；若不能（如非 root 环境、JVM JSSE、Node/Bun/Python 特殊 TLS、Rust `rustls` 或静态二进制），**会自动向子程序补全所需的启动参数与环境变量**，无需手动配置任何代理或证书。

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
   - **默认保护**：页面初次加载仅拉取最近 **10 分钟 (`10m`)** 内的会话与消息，避免历史缓存过大导致浏览器卡顿。
   - **快捷窗口切换**：点击顶部 `10m`、`30m`、`1h`、`6h`、`24h`、`All` 按钮可快速切换时间跨度。
   - **时间轴滑块与平移**：拖动顶部时间轴滑块，或点击两侧 `◀` / `▶` 按钮，即可按需从本地 `.jsonl` 分片懒加载任意历史时间段的通信记录；直方图实时展示各时间分桶的请求密度与异常分布。
2. **左侧会话列表与多维检索**
   - **自动会话串联展示**：每条会话卡片展示主模型名称、协议类型徽标（如 `systemone`、`anthropic`、`openai-responses`、`gemini`、`mcp`）、进程名 (`Comm [PID]`)、串联依据徽标（`L1_explicit` / `L2_context` / `L3_proctree`）、累计轮次 (`Turns`) 与总 Token 消耗。
   - **协议过滤与全文搜索**：可通过下拉框按协议筛选，或在搜索框输入 Prompt 关键词、模型名、Action 名称实时过滤会话。
3. **中间多协议对话与决策时间线**
   - **上下文去重折叠**：在多轮对话中，前几轮重复携带的历史消息自动折叠为 **`[+ 已折叠 N 条上文历史消息，点击展开]`**，卡片默认只高亮展示本轮新增的用户输入（`NewMessages`）、工具返回与模型响应。
   - **`systemone` (TypeSafe JEV) 专属卡片**：直观展示自动化任务目标 `Goal`、决策动作徽标（如 `CLICK` / `FILL` / `DONE`）、目标选择器 `Target`、输入值 `Value`、置信度百分比、可折叠的 `DOM Summary` 与 `Recent Actions` 历史动作序列。
   - **Agent 思考与工具调用展示**：独立渲染 `System Prompt`、可折叠的 `Thinking / Reasoning`（Claude Thinking / DeepSeek `reasoning_content` / Gemini `thought` / Codex `reasoning_summary`）以及 `Tool Calls` 参数列表。
4. **右侧报文详情检查器 (Inspector)**
   - 点击任意一轮请求卡片，右侧面板展示完整进程信息（`PID`、`PPID`、`Exe`、`Cwd`、`Cmdline`、`TLSMode` 采集通道）、结构化解析 JSON，以及支持：
     - **「复制脱敏 cURL (`Copy Sanitized cURL`)」**：一键生成剥离了敏感认证头的复现 `curl` 命令；
     - **「导出会话 JSON (`Export Session JSON`)」**：将当前完整串联会话及所有轮次导出为本地 `.json` 文件。
5. **顶部管理弹窗：动态范围修改、自监控与在线清理**
   - **「范围过滤 (Scope)」**：无需重启程序，在线修改监听的 `PIDs`、`Exes`、`Cwds`、`Cmds`、`Hosts` 与 `RecordHeaders`，并查看当前已挂载的 eBPF/用户态探针与 `PIDAttachPlan`。
   - **「自监控 (Self-Monitor)」**：查看 `probe` / `tracker` / `stream` / `parser` / `correlator` / `store` / `auth` 各阶段的成功数、告警数、错误数及实时日志明细。
   - **「清理缓存 (Clean)」**：输入时长（如 `1h`、`24h`）或勾选全量清理，先点击 **「预览 (Dry-Run)」** 查看预计删除的会话数与释放磁盘空间，确认无误后再执行删除。

---

### 场景 4：隐私保护、TOTP 登录认证与离线回放

```bash
# 1. 生成 TOTP 密钥（用 Google Authenticator / 1Password / Authy 扫描或录入 Secret）
./bin/llm-tracer totp

# 2. 启动带 TOTP 登录认证的采集服务（或设置环境变量 LLM_TRACER_TOTP_SECRET）
./bin/llm-tracer capture --listen 0.0.0.0:8787 --totp-secret JBSWY3DPEHPK3PXP

# 3. 调试需要查看完整 HTTP 请求/响应头时，显式开启 --record-headers（默认关闭）
./bin/llm-tracer capture --record-headers -- python3 my_agent.py

# 4. 事后离线回放历史抓取目录（不启动任何探针，纯只读浏览）
./bin/llm-tracer view ./traces --listen 127.0.0.1:8787

# 5. 命令行检查探针与缓存状态
./bin/llm-tracer status --cache-dir ./traces
```
