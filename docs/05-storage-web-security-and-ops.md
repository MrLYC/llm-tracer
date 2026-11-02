# 05. 存储引擎、自监控、Web 安全鉴权、API 路由表与 GA 验收标准

---

## 一、本地分片存储引擎、原子持久化与两层 LRU 增量统计 (`internal/store/store.go`)

### 1. 磁盘缓存目录布局、分级权限矩阵、`OpenReadOnly` 与 `rebuildSummaryFromEvents`

`llm-tracer` 采用纯本地文件系统缓存，无需额外部署数据库。每个会话独立存储在按 UTC 日期分片的子目录中，**不使用任何全局索引文件**，并对不同目录和产物实施精确的分级权限控制（仅 `sessions/` 子目录树为 `0700`、会话与自监控事件文件为 `0600`）：

```text
<cache_dir>/ (默认 ./traces，缓存根目录权限 0755)
├── sessions/                               # 0700 (sessionDirPerm)
│   └── <YYYY-MM-DD>/                       # 按会话创建日期 (UTC) 分片 (0700)
│       └── <session_id>/                   # 单个会话目录 (如 sess_...，0700)
│           ├── session.json                # 会话元数据快照（.tmp -> Sync -> Rename 原子写，0600 sessionFilePerm）
│           └── events.jsonl                # 该会话的 TraceEvent 追加日志（JSON Lines，0600 sessionFilePerm）
├── selfmon/                                # 自监控目录 (0755)
│   └── <YYYY-MM-DD>.jsonl                  # 自监控全链路异步批量落盘日志（按天滚动，0600）
└── hooks/                                  # 运行时探针与回传通道目录（默认 0700；单跨 UID 有 CAP_CHOWN 时 0711）
    ├── tls.sock                            # Unix 域流式套接字（0600；超 80B 时移至 /tmp/llmt-<pid>-<seq>.sock）
    ├── tls.bin                             # 管道回退文件（0600；仅读端 initPipeFileNoFollow 创建，写端严禁 O_CREAT；排空即 Truncate(0)，上限 64KiB，退出 truncateAndRemovePipeNoFollow 删除）
    ├── libllmtracer_ssl.so                 # Linux/macOS 动态预加载库 (.so / .dylib，chmodArtifactNoFollow 强制权限 0755)
    ├── llm_tracer_ptrace                   # Linux amd64 跨进程树 ptrace 追踪器 (0755)
    ├── llm_tracer_java.jar                 # Java 8+ 字节码 Agent (chmodArtifactNoFollow 强制权限 0644；java_build/ 临时目录 0755)
    ├── llm_tracer_ca_bundle.pem            # LoopbackTap 动态 ECDSA P-256 根证书束 (0644)
    ├── node_hook.cjs                       # Node.js / Bun TLS & HTTP 钩子 (0644)
    └── pyhook/sitecustomize.py             # Python 钩子（pyhook/ 目录 0755，sitecustomize.py 文件 0644）
```

- **`session.json` 原子写与节流 `Sync` (`writeFileAtomicWithHook` & `renameReplace`)**：
  1. 每次持久化会话摘要时，先以 `os.O_CREATE|os.O_WRONLY|os.O_TRUNC` 与 `sessionFilePerm (0o600)` 打开临时文件 `session.json.tmp` 写入完整 JSON，并显式调用 `f.Chmod(0o600)`；
  2. 按 **`minSyncInterval = 50 * time.Millisecond`** 节流执行 `f.Sync()`：若距上次同步已达 `50ms` 则立即 `f.Sync()`；若在 `50ms` 高频窗口内跳过即时 `Sync`，则将该会话目录记入 `dirtySyncDirs`，在 `Store.Flush()` 或 `Close()` 时通过 `syncFilePath` 补齐 `fsync`；
  3. 关闭句柄后调用 `renameReplace(tmp, path)`：优先执行 `os.Rename(src, dst)` 原子替换；在 Windows 下若因目标文件已存在导致 `os.Rename` 失败，自动回退执行 `os.Remove(dst)` + `os.Rename(src, dst)`。
- **崩溃断尾自愈、追加防粘连 (`persistSessionEvent` & `inspectAndHealEventsFile`) 与摘要重建 (`rebuildSummaryFromEvents`)**：
  1. `persistSessionEvent` 在向 `events.jsonl` 追加写入新行前，先通过 `f.ReadAt(last[:], fi.Size()-1)` 检查文件末尾字节；若末字节非 `\n`，说明此前发生过未终止写入，自动先追加写入 `\n` 补齐换行，杜绝两行 JSON 粘连导致的解析损坏；
  2. `loadIndexAndHotWindow` 启动遍历会话目录时，先调用 **`inspectAndHealEventsFile(eventsPath, readOnly)`** 逐行流式校验 `events.jsonl`：统计合法事件行与唯一 ID 数；若检测到文件末尾半截损坏行（无换行符）或非法 JSON 乱码，标记 `eventsDamaged = true`。在读写模式下，自动过滤剔除损坏尾部并原子重写为仅包含完整合法换行行的新文件；
  3. 当检测到 `eventsDamaged`、`session.json` 缺失/损坏、或 `session.json` 中的 `EventCount` 与 `validUniqueCount` 不一致时，触发 **`rebuildSummaryFromEvents`** 流式扫描 `events.jsonl`，按 `ev.ID` 去重并保持事件顺序（支持同 ID 事件覆盖更新），重新计算 `Title`（`deriveSessionTitle`）、`PrimaryModel`（`extractEventModel`）、`EventCount`、`TurnCount`、`StepCount`、`ErrorCount`、`TotalTokens`、`TotalDurationMs`（`eventContributionFromEvent`）、`PIDs`、`Commands` 与 `CorrelationBasis`；重建成功后，在非只读且 `session.json` 非符号链接时通过 `writeFileAtomic` 自动将修复后的 `session.json` 原子写回磁盘；
  4. 权限收敛：启动时先通过 **`chmodNoFollow`**（先调用 `os.Lstat` 确认目标不是 `os.ModeSymlink` 软链接后再执行 `os.Chmod`）将 `sessions/` 与日期分片目录收敛为 `0700`，并对每个非软链接会话目录执行 **`migrateSessionDirPermissions(dirPath)`**：将会话目录设为 `0700`、清理残留的 `*.tmp` 临时文件、将目录下非软链接的常规文件（`session.json`、`events.jsonl`）收敛为 `0600`。
- **真只读打开模式 (`store.OpenReadOnly`)**：
  - 供 `llm-tracer view` 和 `llm-tracer status` 子命令使用。`OpenReadOnly` 设置 `readOnly: true`，仅检查 `baseDir` 存在性，**不创建任何目录、不调用 `chmodNoFollow` 或 `migrateSessionDirPermissions`、不删除 `.tmp` 文件、不写盘截断修复损坏文件、不启动后台 `evictLoop`**；在 `inspectAndHealEventsFile` 与 `rebuildSummaryFromEvents` 时仅在内存中剔除损坏尾部并纠偏元数据，**严格保持磁盘文件零修改、零写盘**，且对 `SaveEvent` / `CleanSessions` 直接返回 `ErrReadOnly`。
- **Hook 管道文件 `tls.bin` 生命周期契约 (`initPipeFileNoFollow` & `truncateAndRemovePipeNoFollow`)**：
  - `tls.bin` **仅由 Collector 读端 `pipeSource.Start` 调用 `initPipeFileNoFollow`**（使用 `os.O_CREATE|os.O_WRONLY|os.O_TRUNC` 配合 `syscall.O_NOFOLLOW`）以 `0600` 专用私有权限独占创建；
  - 全部 4 个 Hook 写端（`ssl_hook.c`、`ptrace_helper.c`、`sitecustomize.py`、`node_hook.cjs`）打开 `tls.bin` 时**严禁携带 `O_CREAT`**（仅使用 `O_WRONLY | O_APPEND`）；
  - 当 Collector 退出或调用 `truncateAndRemovePipeNoFollow` 销毁管道时，先截断为 0 字节再执行删除；即使此时仍有脱离生命周期的孤儿/后台子进程存活并尝试写管道，其写端 `open` 也会因 `ENOENT` 静默丢弃，绝不会以进程默认 umask（如 `0644`/`0666`）在磁盘上重新创建无人清理的明文残留文件。

### 2. 默认 10 分钟热窗与后台热事件驱逐 (`evictLoop` & `EvictExpiredHot`)

- **深拷贝隔离 (`cloneEventForHot`)**：写入内存热缓存 `hotEvents[sessionID]` 的 `TraceEvent` 均经过深拷贝，避免与调用方切片共享底层数组。
- **热窗定期驱逐 (`evictLoop` / `EvictExpiredHot` / `evictExpiredHotLocked`)**：
  - `store.Open` 启动后台协程 **`evictLoop`**，其定时器间隔为 **`evictTick = hotWindow / 2`**（下限 **`100 * time.Millisecond`**，上限 **`30 * time.Second`**），周期性调用 `EvictExpiredHot()`；同时每次累计写入达到 **`defaultEvictSweepOps = 256`** 次时也会同步触发 `evictExpiredHotLocked`。
  - 驱逐逻辑扫描 `hotEvents` 并剔除 `Timestamp < now - hotWindow`（默认 `DefaultHotWindow = 10 * time.Minute`）的过期内存事件，释放后的切片重新分配收缩底层数组容量，确保常驻内存仅与当前热窗口流量成正比。
- **冷数据按需磁盘回源 (`readEventsFile`)**：
  - 当用户在 Web 界面拖动时间轴滑块查询早于热窗口的历史区间，或点击某个已冷化的历史会话时，`Store` 自动打开对应的 `sessions/<day>/<id>/events.jsonl` 流式读取并按时间窗过滤返回。

### 3. 两层 LRU `sessionContribTracker`（`byID` 4096 + `seenIDs` 65536，新事件 ID O(1) 免扫盘）

当流式响应或重试逻辑以相同 `Event.ID` 覆盖更新已有事件时，需要先扣除该事件旧版本的累计贡献（`totalTokens`、`durationMs`、`isError`、`isStep`、`isTurn`），再累加新版本贡献。为同时保证内存严格有界与超长会话写入吞吐，每个会话内置一个基于双向链表 `lruIDSet` 的两层 LRU 结构 `sessionContribTracker`：

1. **第一层：活跃事件贡献表 `byID map[string]eventContribution` + `contribLRU *lruIDSet`（容量 `DefaultMaxTrackedEvents = 4096`）**：
   - 缓存单会话最近活跃的最多 `4096`（`maxSessionTrackedEvents = 4096`）条事件的精确贡献结构体 `eventContribution`；超出容量时按 LRU 淘汰最久未访问的事件条目。
2. **第二层：已见事件 ID 过滤器 `seenIDs *lruIDSet`（容量 `DefaultMaxSeenEventIDs = 65536`）**：
   - 轻量级维护该会话最近见过的最多 `65536` 个事件 ID。
3. **O(1) 查找与按需磁盘回退 (`lookupEventContribLocked` & `recordEventContribLocked`)**：
   - **第一层命中（O(1)）**：`SaveEvent` 先查 `tracker.byID[ev.ID]`，命中则直接在内存更新贡献并刷新两层 LRU 顺序；
   - **全新事件 ID 判定（O(1) 零磁盘扫描）**：若 `byID` 未命中，立即检查 `!tracker.seenIDs.contains(ev.ID)`——若不在 `seenIDs` 中，说明这是全新到达的事件 ID（即使该会话总事件数早已超过 `4096`），**直接以 $O(1)$ 判定为新事件，完全不扫描磁盘 `events.jsonl`**；
   - **超 4096 旧事件更新回退**：仅当 `seenIDs.contains(ev.ID)` 为 `true` 但该 ID 已被逐出第一层 `byID`（即对 4096 条之前的旧事件再次发起同 ID 更新）时，才先查内存 `hotEvents`，未命中再调用 `findEventContribInFile(eventsPath, ev.ID)` 扫描该会话的 `events.jsonl` 恢复旧贡献并重新載入 `byID`。

### 4. 缓存清理命令 (`llm-tracer clean` / `POST /api/cache/clean`)
- 当传入 `--all`（即 `CleanOptions.All == true`）时，`Store.Clean` 除清理全部会话外，还会通过 `os.Lstat` 防符号链接检查 `<cache_dir>/hooks/` 并遍历 `knownHookArtifacts` 清理所有已知探针与通道产物（`tls.bin`、`tls.sock`、`libllmtracer_ssl.c`、`libllmtracer_ssl.so`、`libllmtracer_ssl.dylib`、`llm_tracer_ptrace.c`、`llm_tracer_ptrace`、`llm_tracer_java.jar`、`llm_tracer_ca_bundle.pem`、`node_hook.cjs`、`pyhook/sitecustomize.py`）。
```bash
# 预览清理 24 小时前的历史会话及预计释放空间（不实际删除）
llm-tracer clean --cache-dir ./traces --older-than 24h --dry-run

# 清理 1 小时前的会话（带交互式二次确认，加 -y 跳过确认）
llm-tracer clean --cache-dir ./traces --older-than 1h -y

# 全量清空所有会话、hooks/ 探针产物与自监控日志
llm-tracer clean --cache-dir ./traces --all --include-selfmon -y
```

---

## 二、异步批量自监控模块 (`internal/selfmon/selfmon.go`) 与 `/metrics`

### 1. 优先队列配额 (`512`/`4096`)、分级丢弃、保高优热窗与按需超时 Flush

`selfmon.Monitor` 对采集全生命周期的 8 个阶段（`probe`、`tracker`、`stream`、`parser`、`correlator`、`store`、`web`、`auth`）进行实时打点与统计：

1. **总队列 `4096` 与告警/错误优先队列配额 (`DefaultWriteQueueSize = 4096`, `DefaultPriorityQueueQuota = 512`)**：
   - 异步写队列总容量为 **`DefaultWriteQueueSize = 4096`**，内部切分为常规通道 `writeCh`（容量 `3584`）与高优通道 `prioCh`（容量 **`DefaultPriorityQueueQuota = 512`**，专供 `StatusWarn` 与 `StatusError` 事件）。
   - `Monitor.Record`（内部调用 `enqueue`）先尝试非阻塞写入 `writeCh`；当突发洪峰填满 `writeCh` 时，`warn` 与 `error` 事件自动溢入预留的 `prioCh`，后台 `writeLoop` 每次优先排空 `prioCh` 并按每批最多 **`maxWriteBatchSize = 256`** 条合并写入 `<cache_dir>/selfmon/<YYYY-MM-DD>.jsonl`（目录 `0755`，文件权限 `0600`）。
2. **按状态分级丢弃统计 (`DroppedByStatus`)**：
   - 当队列满发生丢弃时，`recordDrop` 除原子递增 `droppedEvents` 外，还按事件状态分别累加 `droppedOK`、`droppedWarn`、`droppedError`，并在 `Stats.DroppedByStatus`（`map[Status]int64{"ok": ..., "warn": ..., "error": ...}`）中完整返回。
3. **`hotEvents` 保高优淘汰与 `hotCoveredFrom` 边界追踪 (`appendHotLocked`)**：
   - 内存热窗口默认保留最近 **`defaultHotWindow = 10 * time.Minute`**、最多 **`maxHot = 4096`** 条事件。
   - 当 `len(hotEvents) > 4096` 需要淘汰时，若队首事件不是 `StatusOK`，`appendHotLocked` 会在前 64 条记录中优先查找并淘汰最老的 `StatusOK` 事件以保护 `warn`/`error` 记录不被冲掉，同时将 **`hotCoveredFrom`** 推进至被淘汰事件的时间戳 `+ 1`。
4. **按需 Flush 与 `FlushWithTimeout(200ms)` 超时降级 (`QueryEvents` & `needsDiskForQuery`)**：
   - 调用 `QueryEvents` 时，先通过 `needsDiskForQuery(q, hotCoveredFrom, hotCopy)` 检查内存 `hotEvents` 是否已完整覆盖查询起始时间（`hotCoveredFrom <= effectiveFrom`）或已满足 `q.Limit` 条数：若已满足，**直接从内存返回，不触发任何磁盘 Flush 或文件读取**；
   - 仅当查询范围早于 `hotCoveredFrom` 时，才调用 **`FlushWithTimeout(DefaultQueryFlushTimeout)`**（默认 **`200ms`**）。若磁盘 I/O 阻塞超时，原子递增 `flushTimeouts` 并返回 `ErrFlushTimeout`，查询自动降级读取已有磁盘文件并与内存 `hotEvents` 去重合并返回，绝不卡死 Web 查询接口。
5. **统一命令行与 URL 凭据脱敏管线 (`RedactCmdline` / `RedactCmdArgs` / `RedactArgSlice` / `RedactSensitivePath`)**：
   - `selfmon` 建立统一的凭据脱敏管线，通过 `RedactCmdline`、`RedactCmdArgs`、`RedactArgSlice` 统一处理命令行字符串与参数切片，深度覆盖 `--flag=value`（如 `--api-key=sk-...`）、长短分离参数（如 `-p <secret>`、`--token <secret>`、`--auth <secret>`）、`curl -u user:pass`、URL 内嵌 `scheme://user:password@host` 凭据，以及 `KEY=VALUE` 环境变量赋值；
   - 导出并维护全局敏感词表与脱敏函数契约：`SensitiveQueryKeys`、`IsSensitiveQueryKey`、`RedactQueryPairs`、`RedactPathMatrixParams`、`RedactSensitivePath`，并在 `sanitizeDetailMap` 中将 `secretDetailKeys`（`authorization`、`cookie`、`set-cookie`、`x-api-key`、`api_key`、`apikey`、`token`、`access_token`、`refresh_token`、`secret`、`password`、`totp_secret`）对应的值替换为 **`[REDACTED]`**；
   - 通过 `redactHomeDir` 将宿主机用户主目录路径前缀（含 `file:///home/...`）统一替换为 `~`（或 `file://~`），杜绝本地用户名与私有路径外泄。

### 2. `GET /metrics` 真实 Prometheus 指标暴露 (`internal/web/server.go` `handleMetrics`)

Web 服务通过 `GET /metrics`（`text/plain; version=0.0.4; charset=utf-8`）导出 `selfmon.Monitor.Stats()` 快照中的真实指标：

| Prometheus 指标名 | 类型 | 标签 / 说明 |
| :--- | :--- | :--- |
| `llm_tracer_selfmon_started_at_timestamp_ms` | `gauge` | 自监控器启动时间戳（Unix 毫秒） |
| `llm_tracer_selfmon_uptime_ms` | `gauge` | 自监控器累计运行毫秒数 |
| `llm_tracer_selfmon_total_ok` | `counter` | 状态为 `ok` 的自监控事件累计总数 |
| `llm_tracer_selfmon_total_warn` | `counter` | 状态为 `warn` 的自监控事件累计总数 |
| `llm_tracer_selfmon_total_error` | `counter` | 状态为 `error` 的自监控事件累计总数 |
| `llm_tracer_selfmon_events_total` | `counter` | 所有状态的自监控事件累计总数 |
| `llm_tracer_selfmon_dropped_events_total` | `counter` | 因异步写队列（4096）满而丢弃的自监控事件数 |
| `llm_tracer_selfmon_disk_errors_total` | `counter` | 自监控日志文件写入错误次数 |
| `llm_tracer_selfmon_queue_length` | `gauge` | 当前异步写队列（`writeCh + prioCh`）待刷盘事件数 |
| `llm_tracer_selfmon_queue_capacity` | `gauge` | 异步写队列总容量（默认 `4096`） |
| `llm_tracer_selfmon_recent_events_per_sec` | `gauge` | 最近 60 秒平均每秒自监控事件速率 |
| `llm_tracer_selfmon_stage_events_total` | `counter` | `stage="<probe\|tracker\|stream\|parser\|correlator\|store\|web\|auth>", status="<ok\|warn\|error>"` |
| `llm_tracer_selfmon_metric_<name>` | `gauge` | 通过 `extractOptionalMonitorMetrics` 提取 `Monitor.Metrics()` 暴露的运行期动态指标 |

---

## 三、Web 鉴权模型、C1 鉴权矩阵与 TOTP IP 分桶防爆破 (`internal/web/server.go` & `internal/totp/totp.go`)

### 1. 单令牌初始化、Header/Cookie 契约、仅回环下发与 TOTP IP 分桶锁定

1. **进程级 32 字节 CSPRNG 令牌与真实 Header / Cookie 名称**：
   - `web.NewServer` 启动时调用 `generateIngestToken()` 生成一个 32 字节（64 位十六进制）高熵随机令牌，默认同时赋给 `localToken` 与 `ingestToken`（二者默认是**同一个 token**，也可通过 `WithLocalToken` / `WithIngestToken` 分别指定）。在拉起子进程或 `ptrace` 辅助进程时，`launch_plan.go` 导出的 **`StripSensitiveEnvKeys`**（配合 `IsSensitiveChildEnvKey`）会强制从子进程环境中剥离 `LLM_TRACER_TOTP_SECRET`、`LLM_TRACER_INGEST_TOKEN`、`LLM_TRACER_LOCAL_TOKEN`、`LLM_TRACER_AUTH_TOKEN`、`LLM_TRACER_TOKEN` 等敏感变量。
   - **子进程环境变量透传契约 (`StripSensitiveEnvKeys` / `IsSensitiveChildEnvKey`)**：
     - `StripSensitiveEnvKeys` 配合 `IsSensitiveChildEnvKey` **严格仅剥离 `llm-tracer` 自身的内部敏感变量**（`LLM_TRACER_TOTP_SECRET`、`LLM_TRACER_INGEST_TOKEN`、`LLM_TRACER_LOCAL_TOKEN`、`LLM_TRACER_AUTH_TOKEN`、`LLM_TRACER_TOKEN` 以及以 `LLM_TRACER_` 开头且带敏感后缀的内部变量）；
     - **用户的业务与模型认证环境变量**（例如 `OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`GEMINI_API_KEY`、`GITHUB_TOKEN`、`AWS_SESSION_TOKEN`、`HF_TOKEN` 等）在 `-- <command>` 拉起子进程或执行 `ptrace` 辅助进程时**完整原样透传给被测程序**，确保 Claude Code、Codex、OpenAI/Anthropic SDK 等被抓取进程正常完成上游鉴权（仅在 `/api/scope` 展示与 `selfmon` 日志落盘时通过 `redactEnvMap`/`RedactCmdArgs` 脱敏为 `[REDACTED]`）；
     - CLI `--totp-secret` 在 `--help` 中的默认值为空串 `""`（运行时由 `resolveTOTPSecret` 读取 `--totp-secret` 或环境变量 `LLM_TRACER_TOTP_SECRET`，避免 `--help` 输出直接暴露环境变量中的密钥明文）。
   - **请求头与 Cookie 常量（`internal/web/server.go`）**：
     - `LocalTokenHeaderName = "X-LLM-Tracer-Token"`
     - `IngestHeaderName = "X-LLM-Tracer-Ingest"`
     - `AuthCookieName = "llm_tracer_token"`（`setLocalAuthCookie` 与 `handleAuthLogin` 设置 Cookie 属性为 `Path: "/"`、`HttpOnly: true`、**`SameSite=Strict`** `http.SameSiteStrictMode`）
   - **已删除 URL 查询参数鉴权**：服务端仅从请求头（`X-LLM-Tracer-Token`、`X-LLM-Tracer-Ingest`、`X-LLM-Tracer-TOTP`、`Authorization: Bearer`）与 `llm_tracer_token` Cookie 提取凭证，**不支持任何 URL 查询参数传递 token**。
   - **Token 与 Cookie 仅在回环地址下发**：
     - 仅当未开启 TOTP 且客户端来自本机回环地址（`isLoopbackRemote(r.RemoteAddr, r) == true`）时，`GET /`（`handleStaticOrIndex`）、`GET /api/auth/status`、`POST /api/auth/bootstrap`、`POST /api/auth/login` 才会通过 `setLocalAuthCookie` 下发 `llm_tracer_token` Cookie，并在首页 HTML 中注入 `<meta name="llm-tracer-token">`；非回环地址访问时绝不下发本机 Token 或 Cookie。
   - **默认时间窗下发 (`window_ms`) 与 SSE 优雅退出 (`s.done` / `Close()` / `RegisterOnShutdown`)**：
     - `handleAuthStatus` 在响应 JSON 中始终下发 `"window_ms": s.defaultWin.Milliseconds()`，前端 `static/index.html` 启动时通过 `applyServerDefaultWindow` 应用该值，使 CLI `--window` 参数在浏览器端真实生效；
     - `web.Server` 维护 `done chan struct{}` 并提供 `Close()` 与 `RegisterOnShutdown(fn func())`：`handleSSEStream` 在 `select` 循环中同时监听 `<-r.Context().Done()` 与 `<-s.done`，当进程收到 `SIGINT`/`SIGTERM` 调用 `webServer.Close()` 时，所有 SSE 流立即退出，确保 `httpServer.Shutdown` 毫秒级完成。
   - **Web 动态开启请求头门禁 (`AllowWebHeaderToggle` / `--allow-web-header-toggle`)**：
     - `web.Server` 默认设置 `AllowWebHeaderToggle = false`（可通过 CLI 参数 `--allow-web-header-toggle` 或 `web.WithAllowWebHeaderToggle(true)` / `SetAllowWebHeaderToggle` 显式开启）；
     - 默认情况下，通过 `PUT /api/scope` 将 `record_headers` 从 `false` 切换为 `true` 会被拦截并返回 `403 Forbidden`，同时向 `selfmon` `StageWeb` 记录 **`scope_header_toggle_blocked`** 告警；而将 `record_headers` 设为 `false`（关闭方向）或保持原值始终放行。
   - **在线热注入范围门禁 (`IsInScope` / `ErrPIDOutOfScope`) 与退避自动清理 (`ResetInjectBackoff`)**：
     - `ProcessTracker` 采用 **`procKey{pid, startTime}`** 复合键（结合三平台 `readProcessStartTime`），防短命进程 in-flight 帧漏归属并彻底防范操作系统 PID 复用串扰，导出方法 **`ProcessTracker.IsInScope(pid int) bool`**；
     - `Collector.InjectRunningPID` 在入口最前端调用 `tracker.IsInScope(pid)` 校验目标 PID 是否属于当前监控范围；若不在范围内，立即记录 `selfmon` `StageProbe` 的 **`pid_inject_out_of_scope_blocked`** 告警并返回 **`ErrPIDOutOfScope`**，Web API `POST /api/pid/inject` 将其映射为 **`403 Forbidden`**（`{"error": "pid is outside the configured capture scope"}`），绝不触碰底层 `ptrace`/信号/JVMTI；
     - 针对注入失败维护按 PID 的指数退避表（`inject_backoff`）；`Collector` 停止时后台协程监听 `stopCh` 自动清理 `injectBackoffMap`，`web.Server.Close()` 亦调用 `collector.ResetInjectBackoff()`。
2. **RFC 6238 TOTP (`totp.Guard`)、不计失败的 `CheckSession` 与按客户端 IP 分桶防爆破 (`internal/totp/totp.go`)**：
   - 通过 `--totp-secret`（或环境变量 `LLM_TRACER_TOTP_SECRET`）启用 `totp.NewGuard`（`DefaultStepSeconds = 30`、`DefaultDigits = 6`、`DefaultWindow = 1`）。
   - **进程内存会话 (`Guard.CheckSession`)**：`LoginFrom` 验证 6 位动态码通过后，生成 `"lt_" + base32(18字节随机)` 会话令牌存入内存 `sessions` 表（上限 **`MaxActiveSessions = 4096`**，有效期 **`DefaultSessionTTL = 12 * time.Hour`**，进程重启即失效），并写入 `llm_tracer_token` Cookie（`SameSite=Strict`）。调用 **`Guard.CheckSession(tok)` 仅查询内存会话表并清理过期项，绝不计入失败次数或触发锁定**。
   - **按客户端 IP 分桶防爆破 (`Guard.CheckCodeFrom(client, code)` / `Guard.LoginFrom(client, code, ttl)`)**：
     - 通过 `normalizeClientKey(client)` 提取客户端 IP（剥离端口），在 `clients` 表中按客户端 IP 分桶记录失败次数，最多维护 **`MaxClientBuckets = 4096`** 个客户端桶（空闲过期时间 **`ClientBucketTTL = 10 * time.Minute`**，超限时优先淘汰过期桶或最久未访问桶）；
     - 单个客户端 IP 连续 **`MaxFailedAttempts = 5`** 次 6 位动态码验证失败后，仅锁定该客户端 IP **`LockoutDuration = 15 * time.Second`**（返回 `401 Unauthorized`，不影响其他客户端 IP），并将认证事件记录至 `selfmon` 的 `auth` (`StageAuth`) 阶段。

### 2. C1 完整鉴权矩阵（接口 × 来源地址 × 是否开启 TOTP → 允许/拒绝）

所有请求首先经过全局最外层 `withOriginAndHostGuard`（校验 `isAllowedRequestHost`、拒绝 `Sec-Fetch-Site: cross-site`、校验非空 `Origin` 必须满足 `isValidSameOrigin`），随后按各路由鉴权包装器执行如下矩阵判定：

| 接口 / 路由组 | 包装器 / 处理器 | 来源：本机回环 (`isLoopbackRemote=true`)<br>未开启 TOTP | 来源：非回环 (`isLoopbackRemote=false`)<br>未开启 TOTP | 来源：本机回环 (`isLoopbackRemote=true`)<br>已开启 `--totp-secret` | 来源：非回环 (`isLoopbackRemote=false`)<br>已开启 `--totp-secret` |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`GET /` 及静态资源** | `handleStaticOrIndex` | **允许 (`200`)**：种 `llm_tracer_token` Cookie (`SameSite=Strict`) 并注入 `<meta name="llm-tracer-token">` | **允许 (`200`)**：返回前端外壳，但**不下发 Cookie、不注入 `<meta>` Token** | **允许 (`200`)**：返回前端外壳（不注入 `<meta>` Token，前端弹窗要求 TOTP 登录） | **允许 (`200`)**：返回前端外壳（不注入 `<meta>` Token，前端弹窗要求 TOTP 登录） |
| **`GET /api/auth/status`** | `handleAuthStatus` | **允许 (`200`)**：种 Cookie，返回 `authenticated: true, auth_mode: "local_token"` | **允许 (`200`)**：不种 Cookie，返回 `authenticated: false, auth_mode: "loopback_only"` | **允许 (`200`)**：携带有效 `localToken` 或有效 TOTP 时 `authenticated: true`，否则 `false` (`auth_mode: "totp"`) | **允许 (`200`)**：携带有效 TOTP（`CheckSession` 或 Header 6 位码）时 `authenticated: true`，否则 `false` |
| **`POST /api/auth/bootstrap`** | `handleAuthBootstrap` | **允许 (`200`)**：种 `llm_tracer_token` Cookie，返回 `authenticated: true` | **拒绝 (`403`)**：返回 `{"error": "非回环地址访问需启用 --totp-secret", "totp_enabled": false}` | **拒绝 (`401`)**：返回 `{"error": "TOTP enabled; use /api/auth/login"}` | **拒绝 (`401`)**：返回 `{"error": "TOTP enabled; use /api/auth/login"}` |
| **`POST /api/auth/login`** | `handleAuthLogin` | **允许 (`200`)**：种 `llm_tracer_token` Cookie，返回 `authenticated: true` | **拒绝 (`403`)**：返回 `{"error": "非回环地址访问需启用 --totp-secret", "totp_enabled": false}` | **校验 TOTP (`200`/`401`)**：`guard.LoginFrom` 验证 6 位码通过则签发 `lt_...` Cookie (`SameSite=Strict`)，失败/锁定返回 `401` | **校验 TOTP (`200`/`401`)**：`guard.LoginFrom` 按客户端 IP 分桶校验 6 位码，通过种 `lt_...` Cookie，失败/锁定返回 `401` |
| **只读查询 API**<br>(`/api/timeline`, `/api/sessions*`, `/api/stream`, `GET /api/scope`, `/api/selfmon/*`) | `withAuth` | **允许 (`200`)**：直接放行 | **允许 (`200`)**：只读放行 | **需认证 (`200`/`401`)**：携带有效 `localToken`（Header/Cookie）或有效 TOTP（`CheckSession` / `CheckCodeFrom`）放行，否则 `401` | **需认证 (`200`/`401`)**：携带有效 TOTP（`llm_tracer_token` 会话或 Header 6 位码）放行，否则 `401` |
| **管理写接口**<br>(`PUT /api/scope`, `POST /api/cache/clean`) | `withWriteAuth` | **需本地 Token (`200`/`401`)**：必须携带有效 `localToken`（Header `X-LLM-Tracer-Token` 或 Cookie `llm_tracer_token`），否则 `401`（`PUT /api/scope` 若翻转 `record_headers` 为 `true` 需已开启 `--allow-web-header-toggle`，否则 `403` `scope_header_toggle_blocked`） | **一律拒绝 (`403`)**：返回 `{"error": "非回环地址访问需启用 --totp-secret", "totp_enabled": false}`（记录 `write_non_loopback_forbidden`） | **需认证 (`200`/`401`)**：携带有效 `localToken`（Header/Cookie）或有效 TOTP 放行，否则 `401`（同样受 `--allow-web-header-toggle` 约束） | **需 TOTP (`200`/`401`)**：携带有效 TOTP（Session Cookie 或 Header 6 位码）放行，否则 `401`（同样受 `--allow-web-header-toggle` 约束） |
| **数据上报写接口**<br>(`POST /api/ingest/exchange`, `POST /api/ingest/tls`) | `withIngestAuth` | **需令牌 (`200`/`401`)**：必须携带匹配 `ingestToken`/`localToken` 的 Header（`X-LLM-Tracer-Ingest` / `X-LLM-Tracer-Token` / `Bearer`）或 Cookie，否则 `401` | **一律拒绝 (`403`)**：返回 `{"error": "非回环地址访问需启用 --totp-secret", "totp_enabled": false}`（记录 `ingest_non_loopback_forbidden`） | **需认证 (`200`/`401`)**：携带有效 `ingestToken`/`localToken` 或有效 TOTP 放行，否则 `401` | **需 TOTP (`200`/`401`)**：携带有效 TOTP 放行，否则 `401` |
| **运行中进程热注入**<br>(`POST /api/pid/inject`) | `withPIDInjectAuth` | **仅限回环 + Header Token + 无 `Origin` + 范围门禁 (`200`/`401`/`403`)**：若带任何 `Origin` 头直接 `403` (`header_token_only_no_origin`，记录 `pid_inject_browser_blocked`)；必须通过请求头（`extractHeaderTokens`，不接受 Cookie）携带有效 `localToken`，否则 `401`；最前端通过 `tracker.IsInScope(pid)` 校验范围，范围外返回 `403`（`ErrPIDOutOfScope` / `pid_inject_out_of_scope_blocked`） | **一律拒绝 (`403`)**：返回 `protection: "loopback_header_token_only"`（记录 `pid_inject_non_loopback_blocked`） | **仅限回环 + Header Token + 无 `Origin` + 范围门禁 (`200`/`401`/`403`)**：带 `Origin` 头返回 `403`；必须通过请求头携带有效 `localToken`，否则 `401`；同样执行 `IsInScope` 范围门禁 | **一律拒绝 (`403`)**：即使开启 TOTP 也拒绝非回环调用（`protection: "loopback_header_token_only"`，记录 `pid_inject_non_loopback_blocked`） |
| **Prometheus 指标**<br>(`GET /metrics`) | `withMetricsAuth` | **允许 (`200`)**：未开启 TOTP 且来自回环地址直接放行 | **需令牌 (`200`/`401`)**：携带有效 `localToken` 放行，否则返回 `401` | **需认证 (`200`/`401`)**：携带有效 `localToken` 或有效 TOTP 放行，否则 `401` | **需认证 (`200`/`401`)**：携带有效 `localToken` 或有效 TOTP 放行，否则 `401` |

### 3. Host / Origin / Sec-Fetch-Site 守卫 (`withOriginAndHostGuard`)、`decodeJSONBody` (`415`/`413`) 与非回环告警

1. **DNS Rebinding 防护 (`withOriginAndHostGuard` -> `isAllowedRequestHost`)**：
   - 默认仅允许 `Host` 头为回环主机（`localhost`、`*.localhost`、`127.0.0.1`、`::1`）或与 `--listen` 显式绑定的非通配主机名一致；若恶意网页通过 DNS Rebinding 使用外部域名指向 `127.0.0.1`，请求将被立即拦截并返回 `403 Forbidden`（`{"error": "forbidden host"}`，自监控记录 `host_rejected`）。
2. **CSRF 跨站请求伪造防护 (`withOriginAndHostGuard` -> `isValidSameOrigin`)**：
   - 若请求携带 `Sec-Fetch-Site: cross-site`，直接拒绝并返回 `403 Forbidden`（`{"error": "cross-site request forbidden"}`）；
   - 若请求携带非空 `Origin` 头，`isValidSameOrigin` 强制校验其不为 `"null"`、Scheme 为 `http`/`https` 且 `Origin.Host` 与当前请求 `Host` 完全一致，否则返回 `403 Forbidden`（自监控记录 `csrf_origin_rejected`）。
3. **严格 `Content-Type: application/json` (`415`) 与请求体大小限制 (`413`) (`decodeJSONBody`)**：
   - 所有 JSON 写接口均调用 `decodeJSONBody`：首先检查 `Content-Type` 必须以 `application/json` 开头，不匹配则返回 **`415 Unsupported Media Type`**；
   - 随后使用 `http.MaxBytesReader` 将请求体限制为 **`MaxRequestBodyBytes = 8 << 20`（`8 MiB`）**，超出上限时捕获 `http.MaxBytesError` 并返回 **`413 Request Entity Too Large`**。
4. **非回环地址监听安全告警 (`cmd/llm-tracer/main.go` `warnIfNonLoopbackWithoutTOTP`)**：
   - 当 `--listen` 设置为非回环地址（如 `0.0.0.0:8787` 或局域网 IP）且未配置 `--totp-secret` 时，CLI 启动时输出 `[WARNING] 监听地址 <addr> 非回环地址且未开启 TOTP 认证...`，并在 `selfmon` 的 `web` (`StageWeb`) 阶段记录 `non_loopback_without_totp` 告警。

---

## 四、Web 实时观测台真实路由表 (`internal/web/server.go` `Handler`)

| 方法与路径 | 鉴权策略 | 处理器与功能说明 |
| :--- | :--- | :--- |
| `GET /` 及静态资源 | `withOriginAndHostGuard` -> `handleStaticOrIndex` | 返回内嵌单页观测台应用 (`internal/web/static/index.html`)；仅在未开 TOTP 且来自回环地址时种下 `llm_tracer_token` Cookie 并注入 `<meta name="llm-tracer-token">` |
| `GET /api/auth/status` | `withOriginAndHostGuard` -> `handleAuthStatus` | 返回 `{"totp_enabled": bool, "authenticated": bool, "auth_mode": "local_token"\|"loopback_only"\|"totp", "window_ms": int64}`（前端 `applyServerDefaultWindow` 消费 `window_ms`） |
| `POST /api/auth/bootstrap` | `withOriginAndHostGuard` -> `handleAuthBootstrap` | 未开启 TOTP 时供本机回环客户端显式初始化 `llm_tracer_token` Cookie（非回环返回 `403`，开启 TOTP 时返回 `401`） |
| `POST /api/auth/login` | `withOriginAndHostGuard` + JSON (`415`) -> `handleAuthLogin` | 6 位 TOTP 动态口令验证接口（调用 `guard.LoginFrom` 按客户端 IP 分桶校验，成功签发内存 `lt_...` 的 `llm_tracer_token` Cookie `SameSite=Strict`，连续 5 次失败锁定该 IP 15 秒并返回 `401`） |
| `GET /api/timeline` | `withAuth` -> `handleTimeline` | **核心时间轴与总览接口**：按 `from`、`to`、`buckets`（默认 `36` 桶）返回时间分桶直方图、窗口会话与事件统计、各协议分布、当前 `scope`、已挂载探针 (`probes`) 与 `selfmon` 摘要 |
| `GET /api/sessions` | `withAuth` -> `handleListSessions` | 按 `from`、`to`、`protocol`、`pid`、`q`（全文搜索）、`offset`、`limit`（默认 `200`）查询会话列表 |
| `GET /api/sessions/{id}` | `withAuth` -> `handleGetSession` | 获取指定会话摘要及其事件列表（当未指定 `from`/`before` 且 `sess.CreatedAt > 0` 时，自动将查询区间扩展至 `[sess.CreatedAt - 1000, max(to, sess.UpdatedAt + 1000)]`，默认 `limit = 500`） |
| `GET /api/sessions/{id}/events` | `withAuth` -> `handleGetSessionEvents` | 按 `from`、`to`、`before`、`after`、`limit`（默认 `500`）分页获取指定会话的事件列表 |
| `GET /api/stream` | `withAuth` -> `handleSSEStream` | SSE (`text/event-stream`) 实时推送新捕获的 `TraceEvent`（内置 15 秒 `: keepalive` 心跳帧，同时 select `<-s.done` 支持 `Server.Close()` 优雅退出） |
| `GET /api/scope` | `withAuth` -> `handleGetScope` | 查看当前生效的过滤范围 (`scope`)、活跃目标进程 (`processes`)、已挂载探针 (`probes`)、运行中进程诊断 (`pid_plans`) 与脱敏后的子程序启动计划 (`launch_plan`) |
| `PUT /api/scope` | `withWriteAuth` + JSON (`415`) -> `handleUpdateScope` | 动态更新抓取范围（`pids`、`pid_only`、`exes`、`cwds`、`cmds`、`hosts`、`record_headers`），立即触发进程重扫与探针同步；受 `--allow-web-header-toggle` 门禁约束（未开启时禁止将 `record_headers` 从 `false` 切换为 `true`，违规返回 `403` `scope_header_toggle_blocked`） |
| `POST /api/pid/inject` | `withPIDInjectAuth` + JSON (`415`) -> `handleInjectPID` | 对运行中进程执行免重启侵入式热注入（强制要求回环 + Header Token + 无 `Origin`；最前端先通过 `tracker.IsInScope(pid)` 校验监控范围，范围外直接返回 `403 Forbidden` `ErrPIDOutOfScope` 并记录 `pid_inject_out_of_scope_blocked`；传 `{"pid": 1234}` 注入单进程，或 `{"all": true}` 批量注入所有需侵入进程；失败按 PID 指数退避并在退出时 `ResetInjectBackoff`） |
| `POST /api/cache/clean` | `withWriteAuth` + JSON (`415`) -> `handleCacheClean` | 在线预览 (`dry_run: true`) 或执行缓存清理（支持 `older_than: "24h"`、`before_ms`、`all: true`、`include_selfmon: true`） |
| `GET /api/selfmon/stats` | `withAuth` -> `handleSelfmonStats` | 返回自监控 8 大阶段计数、队列长度、按状态分级丢弃数 (`dropped_by_status`)、磁盘错误数与动态指标 |
| `GET /api/selfmon/events` | `withAuth` -> `handleSelfmonEvents` | 查询自监控事件明细（支持 `from`、`to`、`stage`、`status`、`pid`、`q`、`limit`，内部按 `hotCoveredFrom` 智能触发 `FlushWithTimeout(200ms)`） |
| `POST /api/ingest/exchange` | `withIngestAuth` + JSON (`415`) -> `handleIngestExchange` | 接收结构化 HTTP 请求/响应交换并进入解析、串联与存储流水线 |
| `POST /api/ingest/tls` | `withIngestAuth` + JSON (`415`) -> `handleIngestTLS` | 接收原始明文分片（支持 Base64 `data_base64` 或 `data`）并送入 `StreamReassembler` |
| `GET /metrics` | `withMetricsAuth` -> `handleMetrics` | 暴露 Prometheus 文本格式监控指标（`llm_tracer_selfmon_*`） |

---

## 五、GA 验收标准与 CI/CD 发布流水线

### 1. 本地与 CI 必过构建、静态检查、测试与交叉编译命令

在提交或发布 GA 版本前，必须全部通过以下命令验证（对应 `.github/workflows/ci.yml`、`.github/workflows/release.yml` 与 `.goreleaser.yaml`）：

```bash
# 1. 格式与 go.mod 整洁度检查（零差异）
test -z "$(gofmt -l ./cmd ./internal)"
go mod tidy -diff

# 2. 跨架构静态分析（x86_64 与 ARM64 eBPF / 采集器代码均须零告警）
GOOS=linux GOARCH=amd64 go vet ./...
GOOS=linux GOARCH=arm64 go vet ./...

# 3. 全量单元测试与并发竞态检测 (-race)
go test -v -count=1 ./...
go test -race -count=1 ./...

# 4. 内嵌探针资产完整性与 Java .class SHA-256 校验专项测试
go test -v -count=1 -run "TestEmbeddedAssetsNonEmpty|TestEmbeddedJavaClassChecksums|TestJavaAgentJarFallbackWithoutJavac" ./internal/collector

# 5. Parser 流重组与协议解析 Fuzz 冒烟验证
go test -run=^$ -fuzz=FuzzIngestChunk -fuzztime=30s ./internal/parser
go test -run=^$ -fuzz=FuzzParseExchange -fuzztime=30s ./internal/parser

# 6. Linux Root 内核态 eBPF 15 场景与免重启热注入实测（断言无 SKIP）
go test -c -o /tmp/collector.test ./internal/collector
sudo /tmp/collector.test -test.v -test.count=1 -test.run "TestEBPFEngine|TestCompatibilityMatrix|TestPolyglot|TestAgentFrameworks"
sudo /tmp/collector.test -test.v -test.count=1 -test.run "^TestLivePIDAttachWithoutRestart$"

# 7. 六大目标平台（Linux/macOS/Windows × amd64/arm64）全量交叉编译验证
for goos in linux darwin windows; do
  for goarch in amd64 arm64; do
    ext=""
    [ "$goos" = "windows" ] && ext=".exe"
    CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch \
      go build -trimpath -ldflags="-s -w" \
      -o "/tmp/llm-tracer-${goos}-${goarch}${ext}" ./cmd/llm-tracer
  done
done
```

### 2. 核心功能 GA 验收清单

1. **存储与热窗验收**：
   - 抓包生成的磁盘目录中，缓存根目录、`selfmon/`、`pyhook/`、`java_build/` 权限为 `0755`，`sessions/<YYYY-MM-DD>/<session_id>/` 子目录树权限为 `0700`（`sessionDirPerm`），`session.json` 与 `events.jsonl` 权限为 `0600`（`sessionFilePerm`）；`session.json` 采用 `.tmp` -> `Sync` -> `Rename` 原子写，追加写入前通过 `persistSessionEvent` 用 `ReadAt(size-1)` 检查末字节 `\n` 防止粘连；
   - 启动加载时通过 `inspectAndHealEventsFile` 逐行校验修复损坏尾部行并自动触发 `rebuildSummaryFromEvents` 从 `events.jsonl` 完整重建；启动时通过 `chmodNoFollow`（`os.Lstat` 防符号链接）与 `migrateSessionDirPermissions` 自动收敛权限并清理残留 `.tmp`；
   - `llm-tracer view ./traces` 与 `status` 使用 `store.OpenReadOnly` 纯只读打开缓存目录（不建目录、不 `chmod`、不删 `.tmp`、不写盘截断修复损坏文件），仅在内存中剔除损坏尾部并重算摘要，严格保持磁盘文件零写入；且后台 `evictLoop` 在读写模式下按 `hotWindow / 2`（`100ms`~`30s`）定时执行 `EvictExpiredHot`；
   - 单会话超过 `DefaultMaxTrackedEvents = 4096` 条事件后，新事件 ID 通过 `seenIDs` (`DefaultMaxSeenEventIDs = 65536`) 实现 $O(1)$ 免扫盘判定，已见旧事件重复 ID 更新自动回退磁盘扫描，统计值零漂移。
   - `tls.bin` 生命周期契约：仅由 Collector 读端通过 `initPipeFileNoFollow` 以 `0600` 独占创建，全部 4 个 Hook 写端严禁 `O_CREAT`；Collector 退出执行 `truncateAndRemovePipeNoFollow` 截断清零并删除；孤儿写端 `open` 遇 `ENOENT` 静默丢弃，绝不重新创建明文残留文件。
2. **进程追踪与环境变量透传验收**：
   - `ProcessTracker` 采用 `procKey{pid, startTime}` 复合键（结合三平台 `readProcessStartTime`：Linux 读取 `/proc/<pid>/stat` 第 22 字段 `starttime`、macOS `sysctl CTL_KERN KERN_PROC_PID`、Windows `GetProcessTimes`），杜绝短命进程 in-flight 帧丢归属与 PID 快速复用跨进程误归属，并导出 `IsInScope(pid)` 为热注入与流量接入提供统一范围门禁；
   - 子进程环境变量透传契约：`IsSensitiveChildEnvKey` / `StripSensitiveEnvKeys` 严格仅剥离探针内部凭据，用户业务与模型 API Key（`OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`GEMINI_API_KEY` 等）在拉起子进程时完整原样透传。
3. **解析器资源保护验收**：
   - 单连接超 `8 MiB`、全局缓冲超 `64 MiB`、单连接 HTTP/2 流超 `256`、空闲超 `2m`、压缩包解压超 `16 MiB` 时，进程内存不失控并正确生成 `incomplete` 事件与 `selfmon` 告警；
   - 未识别协议按 Host 每 `10s` 限频告警（LRU 上限 `256`），开启 `--capture-unknown` 后可入库查看。
4. **自监控与指标验收**：
   - `selfmon` 统一凭据脱敏管线（`RedactCmdline`、`RedactCmdArgs`、`RedactArgSlice`）深度覆盖 `--flag=value`、长短分离参数、`curl -u`、URL 内嵌凭据、`KEY=VALUE` 环境变量，保持 `SensitiveQueryKeys`、`IsSensitiveQueryKey`、`RedactQueryPairs`、`RedactPathMatrixParams`、`RedactSensitivePath` 导出契约；
   - `selfmon` 4096 异步队列内预留 `DefaultPriorityQueueQuota = 512` 优先队列供 `warn`/`error`、维护 `DroppedByStatus` 分级丢弃计数、`QueryEvents` 依据 `hotCoveredFrom` 按需执行 `FlushWithTimeout(200ms)`，并将用户主目录脱敏为 `~`；
   - `GET /metrics` 返回真实的 `llm_tracer_selfmon_*` Prometheus 指标。
5. **安全与鉴权验收**：
   - Web 动态开启请求头门禁：默认 `AllowWebHeaderToggle = false`（CLI `--allow-web-header-toggle`），未开启时拦截 `record_headers` 翻转为 `true` 并返回 `403`（`scope_header_toggle_blocked`）；
   - 本机 Token 与 `llm_tracer_token` Cookie (`SameSite=Strict`) 仅在回环地址下发；未开启 TOTP 时非回环访问写接口一律返回 `403`（`非回环地址访问需启用 --totp-secret`）；`POST /api/pid/inject` 强制要求回环来源 + Header Token + 无 `Origin` 头；
   - 热注入范围门禁：`POST /api/pid/inject` 最前端通过 `IsInScope(pid)` 拦截范围外 PID 并返回 `403`（`ErrPIDOutOfScope` / `pid_inject_out_of_scope_blocked`），并在 Collector 停止与 Web 关闭时自动执行 `ResetInjectBackoff`；
   - 启用 `--totp-secret` 后，`Guard.CheckSession` 不计失败，`Guard.CheckCodeFrom` / `LoginFrom` 按客户端 IP 分桶（`MaxClientBuckets = 4096`），连续 5 次错误触发该 IP 15 秒锁定（返回 `401`），且进程重启后旧 `llm_tracer_token` 会话立即失效。
   - CLI `--totp-secret` 在 `--help` 中默认值脱敏为空串 `""`，运行时通过 `resolveTOTPSecret` 优先读取参数或环境变量。

### 3. CI/CD 与 GoReleaser 发布流水线 (`.github/workflows/ci.yml`、`release.yml` & `.goreleaser.yaml`)

1. **持续集成 5-Job 矩阵 (`.github/workflows/ci.yml`)**：
   - **`linux-ebpf-and-compat` (`ubuntu-latest`)**：先执行 **D4 依赖预检门禁**（逐项校验 `curl`、`openssl`、`gcc`、`g++`、`<openssl/ssl.h>` 头文件、`javac`、`rustc` 以及 `nm -D $(which node) | grep -qE ' SSL_(write|read)'` 动态符号存在性，缺失即自动安装或报错失败），随后执行 `gofmt -l ./cmd ./internal`、`go vet ./...`、`GOARCH=arm64 go vet ./...`、全量 `go test -v -count=1 ./...`、全模块 `go test -race -count=1 ./...`；在 Root 阶段以 `set -o pipefail` + `tee /tmp/ebpf-15-scenarios.log` 运行 `TestEBPFBytecodeBuilderAndJumpBounds|TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot|TestCompatibilityMatrixAllRuntimeScenarios|TestCrossPlatform|TestPolyglotLanguagesCapture|TestAgentFrameworksAndAgentCLIsScenarios` 并以 `tee /tmp/live-attach.log` 运行 `TestLivePIDAttachWithoutRestart`，**两步均通过 `if grep -q -- '--- SKIP' <logfile>; then exit 1; fi` 强制断言零 SKIP**（防止测试因环境缺失静默跳过冒充通过），最后执行 `goreleaser check` 与 6 平台交叉编译。
   - **`fuzz-smoke` (`ubuntu-latest`)**：分别运行 `FuzzIngestChunk` (`-fuzztime=30s`) 与 `FuzzParseExchange` (`-fuzztime=30s`)。
   - **`linux-arm64-ebpf` (`ubuntu-24.04-arm` 原生 ARM64 Runner)**：同样先执行 **D4 依赖与 Node `SSL_write`/`SSL_read` 符号预检门禁**，在真实 `aarch64` 硬件上运行 `go test -v -count=1 ./...`、`go test -race -count=1 ./...`，并在 Root 下以 `set -o pipefail` + `tee /tmp/ebpf-arm64.log` 运行 `TestEBPFArch|TestEBPFBytecodeBuilderAndJumpBounds|TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot|TestCompatibilityMatrixAllRuntimeScenarios|TestPolyglotLanguagesCapture`，**同样通过 `grep -q -- '--- SKIP' /tmp/ebpf-arm64.log` 强制断言零 SKIP**。
   - **`macos-scenarios` (`macos-latest`)**：在 macOS 上运行 `go vet ./...` 与 `go test -v -count=1 ./...`。
   - **`windows-scenarios` (`windows-latest`)**：在 Windows 上运行 `go vet ./...` 与 `go test -v -count=1 ./...`。
2. **带验证门禁的自动发布流水线 (`.github/workflows/release.yml` & `.goreleaser.yaml`)**：
   - 推送 `v*` Tag 时，先执行 **`verify` Job**：运行 `gofmt -l ./cmd ./internal`、`go vet ./...`、`GOOS=linux GOARCH=arm64 go vet ./...`、`go mod tidy -diff`、`go test -count=1 ./...`、`go test -race -count=1 ./...` 及 6 平台交叉编译；
   - **`release` Job 声明 `needs: verify`**：仅当 `verify` 全部通过后才调用 `goreleaser/goreleaser-action@v6` 执行 `release --clean`；
   - **`.goreleaser.yaml`**：`before.hooks` 执行 `go mod tidy -diff`（确保发布工作树无未提交依赖变更），构建 `linux`/`darwin`/`windows` × `amd64`/`arm64` 发行包并通过 `-ldflags` 注入 `-X main.version={{.Version}} -X main.commit={{.ShortCommit}} -X main.date={{.Date}}`，自动生成 `checksums.txt`。
