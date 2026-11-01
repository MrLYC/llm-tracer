# 04. 多协议流重组、8 大 LLM 协议解析与三级会话串联

---

## 一、双向流重组与隐私脱敏 (`internal/parser/reassembler.go`)

`StreamReassembler` 按 `ConnKey = "<pid>:<conn_id>"` 维护独立的连接缓冲区，处理以下底层传输特性：

1. **HTTP/1.1 分帧与 Keep-Alive 复用**：
   - 解析请求行（`POST /v1/messages HTTP/1.1`）与响应状态行（`HTTP/1.1 200 OK`）；
   - 支持 `Content-Length` 定长体、`Transfer-Encoding: chunked` 分块传输及 `text/event-stream` SSE 流式响应；
   - 同一 Keep-Alive 连接上连续完成的多个请求/响应对按 FIFO 队列精确配对。
2. **HTTP/2 (h2) 帧重组**：
   - 检测 `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` 连接序言；
   - 按 9 字节帧头 (`Length[24] | Type[8] | Flags[8] | StreamID[31]`) 拆分多路复用 `StreamID`，使用 `golang.org/x/net/http2/hpack` 解码 `HEADERS` 帧（`:method`、`:path`、`:authority`、`:status`）并拼接 `DATA` 帧直至 `END_STREAM (0x1)`。
3. **压缩编码自动解压 (`DecompressBody`)**：
   - 支持 `Content-Encoding: gzip`、`deflate`（含 raw deflate 回退）与 `zstd`（`github.com/klauspost/compress/zstd`），并支持根据魔数 (`\x1f\x8b` / `\x28\xb5\x2f\xfd`) 自动嗅探解压。
4. **默认防凭据泄露脱敏策略**：
   - **默认不记录任何 HTTP 请求头与响应头**（`RecordHeaders = false`），彻底避免 `Authorization: Bearer sk-...`、`x-api-key`、`Cookie` 落盘；仅当用户显式传入 `--record-headers` 时才保存头部（且仍对敏感认证头值做掩码保护）。
   - **URL Query 参数自动脱敏 (`redactPathSecrets`)**：对 URL 路径中的 `?key=...`、`?api_key=...`（如 Google Gemini `:streamGenerateContent?alt=sse&key=AIza...`）自动替换为 `key=[REDACTED]`。

---

## 二、8 大协议识别与语义解析 (`internal/parser/protocol.go`)

`DetectProtocol(path, reqBody, respBody)` 与 `ParseExchange` 支持以下 8 种大模型与 Agent 协议：

| 协议枚举 (`ProtocolType`) | 典型端点 / 识别特征 | 提取的核心结构化字段 (`ChatSummary` / `SystemOneData`) |
| :--- | :--- | :--- |
| **`systemone`**<br>(TypeSafe JEV) | `/api/jev/decide`、`/api/v1/step` 或 JSON 含 `dom_summary` + `recent_actions` / `action_probs` | `Goal`、`DOMSummary`、`RecentActions`、`Action`、`Target`、`Value`、`Reasoning`、`Confidence`；当响应仅返回 `action_probs` 概率分布而无显式 `action` 时，**自动执行 `argmax(action_probs)` 兜底推断最优动作**。 |
| **`openai-chat`** | `/v1/chat/completions`、`/openai/deployments/{model}/chat/completions` | 支持 `system` / `developer` 角色提取 `SystemPrompt`；支持 DeepSeek R1 / QwQ 的 `reasoning_content` 与 `reasoning`（含 SSE `delta.reasoning_content`）；支持 `tool_calls` 流式分片按 `index` 聚合；支持 Azure URL 路径提取模型名。 |
| **`openai-responses`** | `/v1/responses`（OpenAI Codex CLI、OpenAI Agents SDK） | 提取顶层 `instructions` 为 `SystemPrompt`，归一化 `input`（字符串或 `message`/`function_call_output` 数组）；从响应或 SSE (`response.output_text.delta`、`response.reasoning_summary_text.delta`、`response.completed`) 提取 `ResponseID` (`resp_...`)、`PreviousResponseID`、`ReasoningText` 与 `function_call`。 |
| **`anthropic`** | `/v1/messages`（Claude Code CLI、Anthropic SDK） | 提取顶层 `system`（字符串或内容块数组）；从内容块及 SSE (`content_block_start` / `thinking_delta` / `text_delta` / `input_json_delta`) 提取 `thinking` 推理过程、`text` 回复与 `tool_use` / `tool_result`；统计 `cache_read_input_tokens` + `cache_creation_input_tokens`。 |
| **`gemini`** | `/v1beta/models/{model}:generateContent`、`:streamGenerateContent`（Gemini CLI） | 提取 `systemInstruction`；归一化 `contents`（`role: "model" -> "assistant"`）；识别 Gemini 2.5 Thinking 块 (`part.thought == true` -> `ReasoningText`)、`functionCall` / `functionResponse`；提取 `usageMetadata`（含 `thoughtsTokenCount`）。 |
| **`bedrock`** | `/model/{modelId}/converse`、`/converse-stream`、`/invoke`（Spring AI、AWS SDK） | 从 URL 提取解码后的 `modelId`；解析 Converse `system`、`messages`、`reasoningContent.reasoningText`、`toolUse` / `toolResult` 及 `usage` (`inputTokens`/`outputTokens`/`cacheReadInputTokens`)。 |
| **`ollama`** | `/api/chat`、`/api/generate`（本地 Ollama 实例） | 支持 NDJSON 流式响应拼接，提取 `model`、`messages`、`message.content`、`prompt_eval_count` 与 `eval_count`。 |
| **`mcp`** | JSON-RPC 2.0 (`"jsonrpc":"2.0"` + `tools/list`、`tools/call`、`resources/read`、`prompts/get`、`initialize`) | 提取 MCP 方法名（如 `mcp:tools/call`）、工具名称与参数摘要、JSON-RPC 结果文本及关联 `mcp-session-id`。 |

---

## 三、三级会话自动串联算法 (`internal/correlator/correlator.go`)

在无状态 HTTP 通信中，客户端往往不会在每次请求中携带统一的 Session ID。`Correlator.Correlate(ev)` 通过三级递进策略自动将多轮请求串联为完整会话（`Session`）：

### 1. 第一级：显式会话键匹配 (`L1_explicit`)
- 提取请求或响应中的显式会话标识：
  - `session_id`、`conversation_id`、`thread_id`、`metadata.session_id`、`prompt_cache_key`；
  - OpenAI Responses API 的链式响应 ID：第 $N$ 轮响应产生 `ResponseID = "resp_abc"` 注册至 `byRespID["resp_abc"] = sessionID`，第 $N+1$ 轮请求携带 `previous_response_id: "resp_abc"` 时直接精确命中同一 `Session`。

### 2. 第二级：上下文前缀指纹与状态步进匹配 (`L2_context`)
- **多轮对话协议 (`messages` 前缀指纹)**：
  - 对话每推进一轮，`messages` 数组会在上一轮历史消息（User + Assistant + Tool）基础上追加新消息。
  - `Correlator` 为每轮对话计算全量消息指纹 `fullHash = H(messages[0..n])`，并尝试用当前请求的规范化历史前缀 `H(messages[0..k])` ($k < n$) 在 `byMsgHash` 索引中查找最近活跃的父会话。
  - 命中后自动计算 `ContextMessagesCount = prevLen`（前端默认折叠展示为“已折叠 N 条历史上下文”），并将 `NewMessages = messages[prevLen:]` 提取为本轮新增输入，彻底消除多轮抓包中满屏重复历史消息的噪音。
- **`systemone` (TypeSafe JEV) 步进匹配**：
  - 按 `(RootPID, Goal)` 匹配同一自动化任务目标且 `len(RecentActions) >= prevActionCount` 的活跃会话，将单步浏览器 DOM 决策串联为连续的动作轨迹。

### 3. 第三级：同进程树活跃时间窗跨协议关联 (`L3_proctree`)
- 当同一个 Agent 进程树（共享 `RootPID` 或 `PID`，时间间隔 $\le 90\text{s}$）在执行过程中混合调用不同协议时（例如：Claude Code 主进程调用 `anthropic` `/v1/messages` 产生 `tool_use` 后，立即拉起或调用本地/远端 `mcp` Server 执行 `tools/call`；或 JEV `systemone` 决策后调用 `openai-chat` 生成长文本），`L3_proctree` 自动将它们归入同一个逻辑会话时间线中展示。

---

## 四、功能使用：在 Web 与 API 中查看多协议与串联会话

1. **按协议筛选会话**：
   - 在 Web 界面左侧「协议过滤」下拉框选择 `systemone`、`openai-chat`、`openai-responses`、`anthropic`、`gemini`、`bedrock`、`ollama` 或 `mcp`；
   - 或调用 API：`curl -s "http://127.0.0.1:8787/api/sessions?protocol=systemone&limit=20"`。
2. **查看串联方式与折叠上下文**：
   - 会话列表与事件卡片右上角会标注串联等级徽标：
     - `L1_explicit`：通过显式 `session_id` / `previous_response_id` 串联；
     - `L2_context`：通过多轮 `messages` 前缀指纹或 `systemone` `goal+recent_actions` 自动串联；
     - `L3_proctree`：通过同进程树活跃时间窗跨协议串联（如主对话与 MCP 工具调用）。
   - 点击对话卡片顶部的 **`[+ 已折叠 N 条上文历史消息]`** 即可展开或收起前序轮次携带的完整历史上下文。
3. **查看 `systemone` (TypeSafe JEV) 决策流**：
   - 选中 `systemone` 会话后，每一步卡片直观展示 `Goal`、动作类型（`CLICK` / `FILL` / `SCROLL` / `DONE`）、目标元素 `Target`、填充值 `Value`、模型推理 `Reasoning` 与置信度百分比，点击 `DOM Summary` 可展开当步完整的页面 DOM 快照摘要。
