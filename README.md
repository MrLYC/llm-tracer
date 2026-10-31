# llm-tracer

基于 eCapture / eBPF uprobe 与 OpenSSL / GoTLS 探针的本机大模型通信抓取、多协议识别、会话串联与实时 Web 观测工具（单二进制，纯本地文件缓存）。

## 核心特性

- **多维范围抓取 (`internal/collector`)**
  - 支持按 `--pid`（默认抓取该 PID 及其所有后代子进程；加 `--pid-only` 则仅抓单个 PID 本身）、`--exe` / `--binary`、`--cwd`、`--cmd`、`--host` 过滤。
  - 支持 `-- <command> [args...]` 直接拉起目标子进程并同步纳入追踪，不漏首包。
  - 自动解析本机 `libssl.so`（`SSL_write`/`SSL_read`/`SSL_write_ex`/`SSL_read_ex`）及 Go 二进制 `crypto/tls.(*Conn).Write/Read` 偏移，同时提供零 root 的 `libllmtracer_ssl.so` 透明钩子。
- **多协议识别与流重组 (`internal/parser`)**
  - 支持 HTTP/1.1 & HTTP/2（HPACK 帧重组）、gzip/deflate/zstd 解压、SSE 流式实时拼接。
  - 内置识别 **TypeSafe JEV (`systemone`)**、**OpenAI Chat Completions**、**OpenAI Responses API**、**Anthropic Messages**、**Gemini**、**Ollama**。
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
mise exec go@1.26.5 -- go build -o bin/llm-tracer ./cmd/llm-tracer

# 1. 直接拉起命令并抓取（含所有子进程）
./bin/llm-tracer capture --listen 127.0.0.1:8787 -- uv run jev-release ripgrep --storybook 40-full --no-interactive

# 2. 指定 PID 抓取（默认包含子进程；加 --pid-only 仅抓该 PID）
./bin/llm-tracer capture --pid 12345
./bin/llm-tracer capture --pid 12345 --pid-only --exe /usr/bin/python3

# 3. 开启 TOTP 登录认证与请求头记录
./bin/llm-tracer totp
./bin/llm-tracer capture --totp-secret <SECRET> --record-headers

# 4. 清理缓存与查看自监控状态
./bin/llm-tracer clean --older-than 24h --dry-run
./bin/llm-tracer clean --all --yes
./bin/llm-tracer status
```
