# 04. 多协议流重组、8 大 LLM 协议解析与三级会话串联

---

## 一、双向流重组、资源限额与隐私脱敏 (`internal/parser/stream*.go`)

流重组层已按职责拆分为三个核心文件：`internal/parser/stream.go`（连接表生命周期、全局/单连接内存预算、压缩解压、头部与路径脱敏）、`internal/parser/stream_h1.go`（HTTP/1.1 Keep-Alive、Chunked 与 SSE 流式响应分帧）与 `internal/parser/stream_h2.go`（HTTP/2 帧解析与 HPACK 动态表解码）。

### 1. HTTP/1.1、HTTP/2 与压缩解压能力

1. **HTTP/1.1 分帧与 Keep-Alive 复用 (`internal/parser/stream_h1.go`)**：
   - 解析请求行（`POST /v1/messages HTTP/1.1`）与响应状态行（`HTTP/1.1 200 OK`）；
   - 支持 `Content-Length` 定长体、`Transfer-Encoding: chunked` 分块传输及 `text/event-stream` SSE 流式响应；
   - 同一 Keep-Alive 连接上连续完成的多个请求/响应对按 FIFO 队列精确配对。
2. **HTTP/2 (h2) 帧重组 (`internal/parser/stream_h2.go`)**：
   - 检测 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 连接序言或合法 H2 帧头；
   - 按 9 字节帧头 (`Length[24] | Type[8] | Flags[8] | StreamID[31]`) 拆分多路复用 `StreamID`，使用 `golang.org/x/net/http2/hpack` 解码 `HEADERS` / `CONTINUATION` 帧（`:method`、`:path`、`:authority`、`:status`、`content-encoding`）并拼接 `DATA` 帧直至 `END_STREAM (0x1)` 或 `RST_STREAM (0x3)`。
3. **压缩编码安全解压 (`DecompressBody` in `internal/parser/protocol_detect.go`)**：
   - 支持 `Content-Encoding: gzip`、`deflate`（含 raw deflate 回退）与 `zstd`（`github.com/klauspost/compress/zstd`），并支持根据魔数 (`\x1f\x8b` / `\x28\xb5\x2f\xfd`) 自动嗅探解压；
   - 解压流通过 `readBounded(r, MaxDecompressedBodyBytes)` 强制包裹 `io.LimitReader`（**上限 `MaxDecompressedBodyBytes = 16 MiB`**），且 Zstd 解码器额外设置 `zstd.WithDecoderMaxMemory(uint64(MaxDecompressedBodyBytes))`，防止压缩炸弹耗尽进程内存。
4. **默认防凭据泄露脱敏策略与 Web 动态开启门禁 (`internal/parser/protocol_detect.go` `ParseExchange` & `RedactSensitivePath`)**：
   - **默认不记录任何 HTTP 请求头与响应头**（`RecordHeaders = false`）：`ParseExchange` 在 `!ev.HeadersRecorded` 时直接清空 `ev.RequestHeaders = nil`、`ev.ResponseHeaders = nil`，彻底避免 `Authorization: Bearer sk-...`、`x-api-key`、`Cookie` 落盘；仅当用户显式传入 `--record-headers` 时才保留请求与响应头。
   - **Web API 动态翻转红线门禁 (`--allow-web-header-toggle` / `AllowWebHeaderToggle`)**：若要在运行时通过 Web API（`PUT /api/scope`）将 `record_headers` 从 `false` 动态切换为 `true`，必须在服务端启动时显式指定 CLI 参数 `--allow-web-header-toggle`（或 `web.WithAllowWebHeaderToggle(true)`）；否则该切换会被拦截并返回 `403 Forbidden`，同时向 `selfmon` `StageWeb` 记录 **`scope_header_toggle_blocked`** 告警；而将 `record_headers` 设为 `false`（关闭方向）或保持原值始终放行。
   - **共享脱敏表与 URL Query / Matrix 参数全覆盖 (`parser` → `selfmon`)**：`internal/selfmon/selfmon.go` 导出全局共享敏感参数表 `SensitiveQueryKeys` 及辅助函数 `IsSensitiveQueryKey`、`RedactQueryPairs`、`RedactPathMatrixParams`，由 `internal/parser/protocol_detect.go` 的 `RedactSensitivePath` 直接复用（依赖方向：`parser` → `selfmon`）：
     - 覆盖键名：`key`、`api_key`、`apikey`、`api-key`、`x-api-key`、`x-goog-api-key`、`goog-api-key`、`token`、`access_token`、`refresh_token`、`id_token`、`session_token`、`auth`、`authorization`、`bearer`、`jwt`、`secret`、`client_secret`、`private_key`、`password`、`passwd`、`pwd`、`sig`、`signature`、`code`、`x-amz-signature`、`x-amz-security-token`、`x-amz-credential`、`x-goog-signature`、`x-goog-credential`（以及任何含 `api_key`、`apikey`、`secret`、`token`、`password`、`signature`、`credential` 子串的键名）；
     - 支持对百分号编码键名（如 `api%5Fkey`）先 `url.QueryUnescape` 再归一化匹配，自动将敏感查询参数替换为 `<param>=[REDACTED]`；
     - 同时通过 `RedactPathMatrixParams` 识别并脱敏 URL 路径段中的分号矩阵参数（如 `/v1/models;key=AIza...` 替换为 `/v1/models;key=[REDACTED]`）。

### 2. Parser 资源上限、超时驱逐与未知协议 LRU 限频告警 (`internal/parser/stream.go`)

为保证在长时间、高吞吐或异常大流量场景下内存严格有界，`StreamReassembler` 与协议解析层实施了以下硬性上限与自监控策略：

| 常量 / 机制 | 源码位置 | 默认阈值 | 触发后的行为与自监控事件 (`selfmon`) |
| :--- | :--- | :--- | :--- |
| **`MaxConnBufferBytes`** | `internal/parser/stream.go` (`enforceConnBufferLimitsLocked`) | **`8 MiB`** (`8 * 1024 * 1024`) | 单个连接单向缓冲区超过 `8 MiB` 时拒绝继续膨胀，若存在未完成请求则立即输出 `Status = "incomplete"`、`Error = "buffer_truncated: <bufName> exceeded 8388608 bytes"` 的终止事件，清空该方向缓冲并通过 `recordBufferTruncatedWarnLocked` 记录 `stream` 阶段 `warn` (`buffer_truncated`)。 |
| **`MaxTotalBufferBytes`** | `internal/parser/stream.go` (`enforceGlobalBufferBudgetLocked`) | **`64 MiB`** (`64 * 1024 * 1024`) | 所有活跃连接缓冲总和超过 `64 MiB`（或连接数超过 **`MaxTrackedConns = 4096`**）时，循环调用 `evictConnLocked(oldest, nowMs, "global_buffer_budget_exceeded")` 淘汰最老连接，输出 `Error = "global_buffer_budget_exceeded: ..."` 的 `incomplete` 事件，并记录 `stream` 阶段 `warn` (`conn_evicted`, `reason: "global_buffer_budget_exceeded"`)。 |
| **`MaxH2StreamsPerConn`** | `internal/parser/stream.go` & `stream_h2.go` (`evictOldestH2StreamLocked`) | **`256`** 并发流/连接 | 单条 HTTP/2 连接上活跃 `StreamID` 达到 `256` 时，自动调用 `evictOldestH2StreamLocked` 淘汰该连接上最老的流，并输出 `Status = "incomplete"`、`Error = "h2_stream_limit_evicted: max concurrent streams exceeded"` 的终止事件。 |
| **`ConnIdleTimeout`** | `internal/parser/stream.go` (`EvictIdleConns`) | **`2m`** (`2 * time.Minute`) | 后台定时调用 `EvictIdleConns(nowMs)`（或每 `connSweepInterval = 64` 次写入）清理超过 2 分钟无读写的空闲连接；若连接上有半截未闭合的请求，自动生成 `Status = "incomplete"`、`Error = "idle_timeout: ..."` 的终止事件，并记录 `stream` 阶段 `warn` (`conn_evicted`, `reason: "idle_timeout"`)。 |
| **`MaxNonHTTPPrefixBytes`** | `internal/parser/stream.go` | **`4 KiB`** (`4096` B) | 非 HTTP 杂音流超过 `4 KiB` 仍未出现 HTTP 方法行或 H2 序言时，直接丢弃前缀并仅保留末尾 16 字节滑动窗口。 |
| **`MaxDecompressedBodyBytes`** | `internal/parser/protocol_detect.go` (`DecompressBody` / `ParseExchange`) | **`16 MiB`** (`16 * 1024 * 1024`) | 单次请求体或响应体 Gzip/Deflate/Zstd 解压后的最大字节数上限；同时 `ParseExchange` 通过 `truncateBytesToString` 将落盘的 `RequestRaw` / `ResponseRaw` 截断为 **`256 KiB`** (`256 * 1024`)。 |
| **未知协议按主机 LRU 限频告警** | `internal/parser/stream.go` (`recordUnknownProtocolWarnLocked` / `evictUnknownWarnHostLocked`) | **`UnknownProtocolWarnInterval = 10s`** / Host<br>（LRU 上限 **`MaxUnknownWarnHosts = 256`**） | 当捕获到无法匹配 8 大协议的 HTTP 交互时：默认不入库，并通过 `recordUnknownProtocolWarnLocked` 按 Host 限频（同一 Host 每 `10s` 最多告警一次，最多维护 `MaxUnknownWarnHosts = 256` 个主机条目，超限由 `evictUnknownWarnHostLocked` 淘汰最久未告警 Host）向 `parser` 阶段发送 `warn` (`unknown_protocol_dropped`，路径经 `RedactSensitivePath` 脱敏)。若开启 CLI `--capture-unknown`（`Collector.SetCaptureUnknown(true)` -> `StreamReassembler.SetDropUnknown(false)`），则将其作为 `ProtocolUnknown ("unknown")` 事件保留入库。 |

---

## 二、8 大协议识别与语义解析 (`internal/parser/protocol_*.go`)

协议解析器已按协议族拆分为 8 个独立实现文件（位于 `internal/parser/`），由 `protocol_detect.go` 中的 `DetectProtocol(path, reqBody, respBody)` 与 `ParseExchange` 统一调度：

| 协议枚举 (`ProtocolType`) | 实现文件 | 典型端点 / 识别特征 | 提取的核心结构化字段 (`ChatSummary` / `SystemOneStepSummary`) |
| :--- | :--- | :--- | :--- |
| **`systemone`**<br>(TypeSafe JEV) | `protocol_systemone.go` | `/api/jev/decide`、`/api/v1/step` 或 JSON 含页面元素与多题概率分布 | `Model`、`Goal`、`Page` (`SystemOnePageSummary`)、`RecentActionCount`、`RecentActions`、`SelectedOp`、`SelectedTarget`、`SelectedElement`、`SelectedText`、`OpConfidence`、`TargetConfidence`、`Questions` (`[]SystemOneQuestion`)；当响应仅返回概率分布 `probabilities` 而无显式 `answer_choice` 时，**自动执行 `argmax`（`UsedArgmax = true`）兜底推断最优动作**。 |
| **`openai_chat`** | `protocol_openai.go` | `/v1/chat/completions`、`/openai/deployments/{model}/chat/completions` | 支持 `system` / `developer` 角色提取 `SystemPrompt`；支持 DeepSeek R1 / QwQ 的 `reasoning_content` 与 `reasoning`（含 SSE `delta.reasoning_content`）；支持 `tool_calls` 流式分片按 `index` 聚合；支持 Azure URL 路径提取模型名。 |
| **`openai_responses`** | `protocol_openai.go` | `/v1/responses`（OpenAI Codex CLI、OpenAI Agents SDK） | 提取顶层 `instructions` 为 `SystemPrompt`，归一化 `input`（字符串或 `message`/`function_call_output` 数组）；从响应或 SSE (`response.output_text.delta`、`response.reasoning_summary_text.delta`、`response.completed`) 提取 `ResponseID` (`resp_...`)、`PreviousResponseID`、`ReasoningText` 与 `function_call`。 |
| **`anthropic`** | `protocol_anthropic.go` | `/v1/messages`（Claude Code CLI、Anthropic SDK） | 提取顶层 `system`（字符串或内容块数组）；从内容块及 SSE (`content_block_start` / `thinking_delta` / `text_delta` / `input_json_delta`) 提取 `thinking` 推理过程、`text` 回复与 `tool_use` / `tool_result`；统计 `cache_read_input_tokens` + `cache_creation_input_tokens`。 |
| **`gemini`** | `protocol_gemini.go` | `/v1beta/models/{model}:generateContent`、`:streamGenerateContent`（Gemini CLI） | 提取 `systemInstruction`；归一化 `contents`（`role: "model" -> "assistant"`）；识别 Gemini 2.5 Thinking 块 (`part.thought == true` -> `ReasoningText`)、`functionCall` / `functionResponse`；提取 `usageMetadata`（含 `thoughtsTokenCount`）。 |
| **`bedrock`** | `protocol_bedrock.go` | `/model/{modelId}/converse`、`/converse-stream`、`/invoke`（Spring AI、AWS SDK） | 从 URL 提取解码后的 `modelId`；解析 Converse `system`、`messages`、`reasoningContent.reasoningText`、`toolUse` / `toolResult` 及 `usage` (`inputTokens`/`outputTokens`/`cacheReadInputTokens`)。 |
| **`ollama`** | `protocol_ollama.go` | `/api/chat`、`/api/generate`（本地 Ollama 实例） | 支持 NDJSON 流式响应拼接，提取 `model`、`messages`、`message.content`、`prompt_eval_count` 与 `eval_count`。 |
| **`mcp`** | `protocol_mcp.go` | JSON-RPC 2.0 (`"jsonrpc":"2.0"` + `tools/list`、`tools/call`、`resources/read`、`prompts/get`、`initialize`) | 提取 MCP 方法名（如 `mcp:tools/call`）、工具名称与参数摘要、JSON-RPC 结果文本及关联 `mcp-session-id`。 |

---

## 三、三级会话自动串联算法 (`internal/correlator/correlator.go`)

在无状态 HTTP 通信中，客户端往往不会在每次请求中携带统一的 Session ID。`Correlator.Correlate(ev)` 通过三级递进策略自动将多轮请求串联为完整会话（新会话 ID 格式为 `"sess_" + 12位UUID前缀`）：

### 1. 第一级：显式会话键匹配 (`L1_explicit`)
- `extractExplicitSessionKeys` 提取请求头（`x-session-id`、`x-conversation-id`、`x-thread-id`、`openai-conversation-id`、`mcp-session-id`、`x-claude-session-id`、`x-codex-session-id`、`x-agent-session-id`、`x-langsmith-trace-id`）与请求体中的显式会话标识（`session_id`、`conversation_id`、`thread_id`、`metadata.session_id`、`prompt_cache_key`）并索引至 `explicitIdx`；
- OpenAI Responses API 的链式响应 ID：第 $N$ 轮响应通过 `extractResponseObjectID` 提取 `id = "resp_abc"` 注册至 `explicitIdx["resp:resp_abc"] = sessionID`，第 $N+1$ 轮请求携带 `previous_response_id: "resp_abc"` 时直接精确命中同一会话。

### 2. 第二级：上下文前缀指纹与状态步进匹配 (`L2_context`)
- **多轮对话协议 (`matchChatPrefixLocked` `messages` 前缀指纹，活跃窗口 `activeWindow = 15m`)**：
  - 对话每推进一轮，`messages` 数组会在上一轮历史消息（User + Assistant + Tool）基础上追加新消息。
  - `recordChatSnapshotLocked` 为每轮对话计算每条消息的 SHA-256 前 8 字节哈希序列（`reqHashes` 与追加了助手回复的 `fullHashes`，单会话最多保留 64 条 `msgSnapshot`）；下一轮请求到来时，`matchChatPrefixLocked` 通过 `hasPrefixHashes` 在活跃会话中查找最长匹配前缀。
  - 命中后自动设置 `ev.Chat.PrefixCount = prefixCount`（前端默认折叠展示为“已折叠 N 条历史上下文”），并将 `ev.Chat.NewMessages = ev.Chat.Messages[prefixCount:]` 提取为本轮新增输入，彻底消除多轮抓包中满屏重复历史消息的噪音。
- **`systemone` (TypeSafe JEV) 目标步进匹配 (`matchSystemOneLocked`)**：
  - 在 `activeWindow (15m)` 内按相同 `Goal` 匹配最近活跃会话，将单步浏览器 DOM 决策串联为连续的动作轨迹（`StepIndex` 递增）。

### 3. 第三级：同进程树活跃时间窗跨协议关联 (`L3_proctree`)
- 当未携带显式会话键的请求在 **5 分钟 (`5 * time.Minute`)** 活跃时间窗内满足同进程（`same_pid`）、父子进程（`child_of_pid`：`st.pids[ev.Process.PPID]` 或 `st.rootPID == ev.Process.PPID`）或同工作目录活跃步进（`same_cwd` 且 `st.stepCount > 0`）时，`matchProcessTreeLocked` 自动将不同协议的调用（如 JEV `systemone` 决策后调用 `openai_chat` 辅助生成填写文本，或主 Agent 调用 `mcp` 工具）归入同一个逻辑会话时间线中展示。

---

## 四、功能使用：在 Web 与 API 中查看多协议与串联会话

1. **按协议筛选会话**：
   - 在 Web 界面左侧「协议过滤」下拉框选择 `systemone`、`openai_chat`、`openai_responses`、`anthropic`、`gemini`、`bedrock`、`ollama` 或 `mcp`（开启 `--capture-unknown` 时还可筛选 `unknown`）；
   - 或调用 API：`curl -s "http://127.0.0.1:8787/api/sessions?protocol=systemone&limit=20"`。
2. **查看串联方式与折叠上下文**：
   - 会话列表与事件卡片右上角会标注串联等级徽标：
     - `L1_explicit`：通过显式 `session_id` / `previous_response_id` 串联；
     - `L2_context`：通过多轮 `messages` 前缀指纹或 `systemone` `goal+recent_actions` 自动串联；
     - `L3_proctree`：通过同进程树活跃时间窗跨协议串联（如主对话与 MCP 工具调用）。
   - 点击对话卡片顶部的 **`[+ 已折叠 N 条上文历史消息]`** 即可展开或收起前序轮次携带的完整历史上下文。
3. **查看 `systemone` (TypeSafe JEV) 决策流**：
   - 选中 `systemone` 会话后，每一步卡片直观展示 `Goal`、动作类型（`CLICK` / `FILL` / `SCROLL` / `DONE`）、目标元素 `Target`、填充值 `Value`、模型推理 `Reasoning` 与置信度百分比，点击 `DOM Summary` 可展开当步完整的页面 DOM 快照摘要。
4. **开启未知 HTTP 协议捕获 (`--capture-unknown`)**：
   ```bash
   # 当目标 Agent 调用私有网关或自定义 REST 接口时，将未识别 HTTP 交互也落盘展示
   ./bin/llm-tracer capture --capture-unknown -- python3 my_custom_agent.py
   ```
