# 05. 存储引擎、10 分钟时间窗、Web 观测台、TOTP 安全与 CI/CD 发布

---

## 一、本地文件系统缓存与 10 分钟默认时间窗 (`internal/store/store.go`)

`llm-tracer` 采用纯本地文件系统缓存，无需额外部署数据库，目录结构如下：

```text
<cache_dir>/ (默认 ./traces)
├── sessions.json                 # 会话元数据索引（原子写临时文件 + rename 持久化）
├── events/
│   ├── ses_<id1>.jsonl           # 按会话分片的 TraceEvent 追加日志（JSON Lines）
│   └── ses_<id2>.jsonl
├── selfmon/
│   └── events.jsonl              # 自监控全链路成功/告警/错误事件日志
└── hooks/                        # 自动生成的运行时探针产物
    ├── libllm_tracer_ssl.so      # Linux/macOS 动态预加载库
    ├── llm_tracer_ptrace         # Linux 跨进程树 ptrace 追踪器
    ├── llm_tracer_java.jar       # Java 8+ 零代码字节码 Agent (premain + agentmain)
    ├── llm_tracer_ca_bundle.pem  # LoopbackTap 动态 ECDSA 根证书束
    ├── node_hook.cjs             # Node.js / Bun TLS & HTTP 钩子
    └── pyhook/sitecustomize.py   # Python MemoryBIO / SSLSocket / HTTPConnection 钩子
```

### 1. 默认仅加载 10 分钟热数据 (`--window 10m`)
- 为防止长时间采集后打开 Web 页面一次性加载海量数据导致卡顿，查询接口默认将时间窗起点设为 `from = now - 10m`（可通过 `--window 1h` 等参数调整）。
- 当用户在 Web 界面顶部**拖动双端时间轴滑块**（或点击“加载更早历史”按游标 `before=<timestamp>` 请求）时，后端才按需读取对应 `.jsonl` 分片中的历史事件。
- 若用户主动在左侧会话列表中点击某个早于 10 分钟的会话，`handleGetSession` 会自动将该会话的 `[CreatedAt, UpdatedAt]` 时间跨度纳入查询范围。

### 2. 缓存清理命令 (`llm-tracer clean`)
```bash
# 预览清理 24 小时前的历史会话及预计释放空间（不实际删除）
llm-tracer clean --cache-dir ./traces --older-than 24h --dry-run

# 清理 1 小时前的会话（带交互式二次确认，加 -y 跳过确认）
llm-tracer clean --cache-dir ./traces --older-than 1h -y

# 全量清空所有会话与自监控日志
llm-tracer clean --cache-dir ./traces --all --include-selfmon -y
```

---

## 二、全链路自监控模块 (`internal/selfmon/monitor.go`)

`selfmon.Monitor` 对采集全生命周期的 8 个阶段（`probe`、`tracker`、`stream`、`parser`、`correlator`、`store`、`web`、`auth`）进行实时打点与统计：
- **同时记录成功（`ok`）、告警（`warn`）与异常（`error`）**：不仅统计 `ok_count`、`warn_count`、`error_count`、`bytes_processed`，还保留最近 200 条内存环形缓冲明细并实时落盘至 `<cache_dir>/selfmon/events.jsonl`。
- 可通过 CLI `llm-tracer status` 或 Web 界面右上角 **「自监控」抽屉 (`/api/selfmon`)** 按阶段与状态过滤查看（如查看 eBPF 探针挂载数量、热注入结果、流重组解压状态或解析异常）。

---

## 三、可选 TOTP 双因素认证 (`internal/totp/totp.go`)

当在公网或共享开发机暴露 Web 观测端口时，可通过 `--totp-secret`（或环境变量 `LLM_TRACER_TOTP_SECRET`）启用标准 RFC 6238 TOTP 认证：

1. **生成密钥与二维码 URI**：
   ```bash
   llm-tracer totp
   # 输出 Base32 Secret、当前 6 位动态码及 otpauth://totp/llm-tracer:admin?secret=...
   ```
2. **认证机制与防暴力锁定**：
   - 校验当前 30 秒步长窗口及前后 $\pm 1$ 窗口（容忍 $\pm 30\text{s}$ 时钟漂移）；
   - 验证通过后签发 `HttpOnly`、`SameSite=Lax` 的 HMAC-SHA256 签名会话 Cookie（有效期 12 小时）；支持请求头 `X-LLM-Tracer-TOTP: <6位码>` 直接调用 API；
   - 同一 IP 连续 5 次验证码错误后自动触发 **5 分钟锁定 (`429 Too Many Requests`)**，并将成功/失败认证事件记录至 `selfmon` 的 `auth` 阶段。

---

## 四、Web 实时观测台与 REST API 速查 (`internal/web/server.go`)

| 方法与路径 | 功能说明 |
| :--- | :--- |
| `GET /api/overview` | 返回总览统计、时间轴分桶直方图、当前 10 分钟窗口会话列表、活跃探针与自监控摘要 |
| `GET /api/sessions` | 按 `from`、`to`、`protocol`、`q`（全文搜索）、`limit` 查询会话列表 |
| `GET /api/sessions/{id}` | 获取指定会话详情及时间窗内事件列表 |
| `GET /api/sessions/{id}/events` | 支持 `from`、`to`、`before`（历史游标懒加载）、`limit` 获取事件流 |
| `GET /api/stream` | SSE (`text/event-stream`) 实时推送新捕获的 `TraceEvent` |
| `GET /api/scope` | 查看当前生效的进程过滤范围 (`scope`)、已挂载探针 (`probes`)、运行中进程诊断 (`pid_plans`) 与子进程启动计划 (`launch_plan`) |
| `POST /api/scope` | 动态更新抓取范围（`pids`、`pid_only`、`exes`、`cwds`、`cmds`、`hosts`、`record_headers`），立即触发进程发现与探针更新 |
| `POST /api/pid/inject` | 对运行中进程执行免重启侵入式热注入（传 `{"pid": 1234}` 注入单进程，或 `{"all": true}` 批量注入所有匹配进程） |
| `GET /api/selfmon` | 查询自监控阶段统计及事件明细（支持 `?status=error&stage=probe` 过滤） |
| `POST /api/clean` | 在线预览 (`dry_run: true`) 或执行缓存清理 (`older_than` / `all`) |

---

## 五、CI 自动化验证与 GoReleaser 发布流水线

1. **三端跨平台与内核 eBPF 持续集成 (`.github/workflows/ci.yml`)**：
   - 每次 Push / PR 在 GitHub Actions 的 `ubuntu-latest`（非特权模式 + Root 内核 eBPF 11 程序/19 探针/15 场景 + 免重启热注入 6 子场景）、`macos-latest`、`windows-latest` 上执行全量测试并校验 `.goreleaser.yaml`。
2. **打 Tag 自动多平台发布 (`.github/workflows/release.yml` & `.goreleaser.yaml`)**：
   - 推送符合 `v*` 格式的 Git Tag（如 `git tag v0.1.0 && git push origin v0.1.0`）时，自动运行全量测试并通过 GoReleaser v2 构建 `linux` / `darwin` / `windows` 的 `amd64` 与 `arm64` 共 6 个平台发行包、生成 `checksums.txt` 并发布至 GitHub Releases。
