# 03. 进程选择模型、免重启热注入与子程序自动参数补全

`llm-tracer` 支持两类核心工作模式：
1. **针对已在运行中且不允许重启的进程**：通过 `--pid`、`--exe`/`--binary`、`--cwd`、`--cmd` 选择目标进程，自动识别其语言/TLS 栈，**优先使用零侵入内核 eBPF Uprobe**；若 eBPF 无法直接覆盖，则明确提示原因并支持免重启侵入式热注入（`--inject-live` 或交互确认 `[y/N]`）。
2. **针对直接拉起的子程序 (`-- <cmd> [args...]`)**：启动前自动探测目标二进制是否可由非侵入式 eBPF 覆盖；若不能，**自动通过命令行参数与环境变量完成侵入式方案**（`--auto-intrusive`，默认开启）。

---

## 一、全维度进程选择方式及统一发现机制 (`internal/collector/proctree.go`)

所有进程选择器均由 `ProcessTracker.DiscoverMatchingPIDs()` 与 `MatchAndEnrich()` 统一驱动，具备完全一致的自动识别、eBPF 挂载与热注入能力：

| 选择参数 | 作用域语义 | 子进程继承行为 | 运行中进程自动发现机制 |
| :--- | :--- | :--- | :--- |
| `--pid <p1,p2>` / `-p` | 指定一个或多个根 PID | **默认抓取该 PID 及其所有后代子进程**；加 `--pid-only` 则仅抓该 PID 本身 | 递归扫描 `/proc/<pid>/task/*/children` 与全局 `PPID` 树；若父进程为纯 Shell（`bash`/`sh`/`zsh`），自动聚焦其底下的业务子进程 |
| `--exe <path/name>` / `--binary` | 指定可执行文件路径或二进制名（如 `/usr/bin/java`、`node`、`./agent`） | 默认包含匹配进程派生的后代子进程（加 `--pid-only` 可限制仅匹配进程本身） | 自动通过 `PATH` 解析裸命令名并预挂载 ELF/GoTLS 探针；同时扫描主机上所有 `exe` 匹配的运行中进程 |
| `--cwd <dir>` | 指定工作目录前缀（如 `/workspace/my-agent`） | 默认包含该目录内进程及其派生子进程 | 扫描主机上 `cwd` 位于目标目录（含子目录，自动解析 macOS `/private/var/folders` 等软链接）的所有运行中进程 |
| `--cmd <substr>` | 按进程名 (`comm`) 或完整命令行 (`cmdline`) 子串匹配 | 默认包含匹配进程派生的后代子进程 | 扫描主机上命令行或进程名包含指定关键字的运行中进程（无需事先查 PID） |
| `--host <domain>` | 按目标大模型域名过滤（如 `api.anthropic.com`） | 作用于所有命中进程的网络流 | 在 HTTP/1.1 `Host` 头或 HTTP/2 `:authority` 伪头层执行精确/后缀匹配 |
| `-- <cmd> [args...]` | 直接拉起子程序并追踪其完整进程树 | 自动将子进程根 PID 注册进 `rootPIDs`，追踪全部后代进程 | 启动前执行 `PlanLaunchCommand` 完成探针预挂载与侵入式参数自动补全，首包零丢失 |

### 跨平台进程树扫描实现

- **Linux (`proctree_linux.go`)**：直接读取 `/proc/<pid>/stat`（解析 `ppid`）、`/proc/<pid>/task/*/children`、`/proc/<pid>/cmdline`、`/proc/<pid>/exe`、`/proc/<pid>/cwd`，全量扫描耗时 `< 2ms`。
- **macOS (`proctree_darwin.go`)**：通过 `unix.SysctlKinfoProcSlice("kern.proc.all")` 单次系统调用获取全表，非 root 下按 `Eproc.Ucred.Uid == os.Geteuid()` 过滤掉系统守护进程，再结合 `ps` 与 `lsof -n -P -a -p <pid> -d cwd,txt -Fn` 提取 `cwd` 和 `exe`。
- **Windows (`proctree_windows.go`)**：通过 Win32 API `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`、`Process32First/Next` 与 `QueryFullProcessImageName` 构建父子进程树。
- **D2 源头进程命令行凭据脱敏 (`InspectProcess` -> `selfmon.RedactCmdArgs`)**：在 `proctree_linux.go`、`proctree_darwin.go`、`proctree_windows.go` 三平台的 `InspectProcess`（及 `scanDarwinProcessTable`）中，从操作系统读取命令行参数数组后立即调用 `selfmon.RedactCmdArgs(args)` 生成 `ProcessInfo.Cmdline`（将 `--api-key`、`--token`、`--totp-secret`、`Authorization: Bearer ...`、`sk-...`、URL 查询参数中的敏感键值等统一替换为 `[REDACTED]`），仅在内部保留未导出的 `rawCmdline` 供 `--cmd` 子串匹配使用，确保落盘事件与 Web 响应中的 `Cmdline` 绝不泄露明文凭据。
- **D1 `(pid, startTime)` 复合缓存键 `procKey` 与短生命周期/PID 复用防串扰 (`internal/collector/proctree.go`)**：
  - `ProcessTracker` 维护祖先链缓存 `ancestryCache`、进程元数据缓存 `procCache` 与用户态上报记录 `userHookPIDs`，全部采用 **`procKey{pid, startTime}`** 复合键；
  - 结合三平台真实启动时间获取函数 **`readProcessStartTime`**（Linux 读取 `/proc/<pid>/stat` 第 22 字段 `starttime`、macOS `sysctl CTL_KERN KERN_PROC_PID` `P_starttime`、Windows `GetProcessTimes CreationTime`），配合 `resolveKeyForPID`、`syncLiveKeyLocked`、`evictPIDLocked` 与 `pruneDisappearedLocked`；
  - 当短命子进程在发送完 Hook 帧后已退出导致 `/proc/<pid>` 消失时，其已入队的 in-flight 管道帧仍能命中旧代 `procKey` 完成精确归属；若操作系统快速将相同 PID 分配给无关新进程，由于 `startTime` 变化，`syncLiveKeyLocked` / `evictPIDLocked` 会立即驱逐旧缓存，彻底杜绝跨进程串扰误归属；
  - 导出方法 **`ProcessTracker.IsInScope(pid int) bool`**，为在线热注入（`InjectRunningPID`）与流量接入提供统一范围判定门禁；对不在监控范围内的进程发来的帧，`Collector.recordOutOfScopeDrop` 按 PID 执行 1 秒窗口限频并记录 `selfmon` `ingest_out_of_scope_dropped` 告警。

---

## 二、已运行进程免重启自动识别与热注入 (`internal/collector/live_attach.go`)

当通过 `--pid`、`--exe`、`--cwd`、`--cmd` 选中正在运行的进程时，`Collector.AnalyzePIDPlans()` 会对每个目标 PID 生成 `PIDAttachPlan`：

### 1. 自动识别与分级决策流程

```text
选中运行中 PID (通过 --pid / --exe / --cwd / --cmd 或 Web 动态设置)
  │
  ├─► 识别为 Go 二进制 (.go.buildinfo)
  │     ├─ 解析 .symtab 或从 stripped 二进制的 .gopclntab (debug/gosym) 恢复
  │     │  crypto/tls.(*Conn).Write / Read 偏移及全部 RET 指令偏移
  │     ├─ 若内核 eBPF 可用 ──► [ebpf_uprobe] 免重启、零侵入直接挂载生效 (IntrusiveNeeded=false)
  │     └─ 若无 eBPF 权限   ──► 提示需 sudo 启用 GoTLS eBPF Uprobe 或回退 ptrace_seize
  │
  ├─► 识别为动态/静态 OpenSSL (进程映射 libssl.so 或自身含 SSL_write/SSL_read 符号)
  │     ├─ 若内核 eBPF 可用 ──► [ebpf_uprobe] 免重启、零侵入直接挂载生效，已建立连接也能抓
  │     └─ 若无 eBPF 权限   ──► 若为 Node.js 推荐 [node_inspector_sigusr1]，否则推荐 [ptrace_seize]
  │
  ├─► 识别为 Java / JVM (进程名为 java 或映射 libjvm.so -> jvm-jsse)
  │     └─ 诊断说明：JVM JSSE 在字节码/JIT 层执行 TLS，无固定 ELF 函数偏移，eBPF 仅能抓明文 HTTP
  │        ──► 推荐免重启热注入方案：[jvm_dynamic_attach]
  │
  ├─► 识别为 Node.js (无导出 OpenSSL 符号或非 Linux 环境 -> nodejs)
  │     └─ 推荐免重启热注入方案：[node_inspector_sigusr1]
  │
  └─► 识别为已 strip 符号表的原生二进制 (如 rustls / 静态 C/C++ -> stripped-native)
        └─ 诊断说明：eBPF Syscall Tracepoint 已挂载（可抓明文 HTTP/IPC），加密 TLS 需侵入式方案
           ──► 推荐免重启热注入方案：[ptrace_seize]
```

### 2. `.gopclntab` 剥离符号恢复技术 (`internal/collector/elf_probe.go`)

生产环境分发的 Go 二进制（如 `ollama`、各类编译型 Go Agent）通常使用 `go build -ldflags="-s -w"` 剥离了 `.symtab` 符号表。
`InspectGoTLSTarget` 在 `.symtab` 为空时，自动回退读取 ELF 的 `.gopclntab`（或 `.data.rel.ro.gopclntab`）节，通过 `debug/gosym.NewLineTable` + `gosym.NewTable` 重建函数表：
- 恢复 `crypto/tls.(*Conn).Write` 与 `crypto/tls.(*Conn).Read` 的起止虚拟地址 `[fn.Entry, fn.End)`；
- **双架构栈检查序言跳过**：
  - `x86_64 (EM_X86_64)`：`scanAMD64GoPrologueOffset` 在函数开头 32 字节窗口内定位 `push %rbp; mov %rsp, %rbp` (`55 48 89 e5`)，跳过 Go 栈扩容检查序言（`morestack`）；
  - `ARM64 (EM_AARCH64)`：`scanARM64GoPrologueOffset` 在函数开头 64 字节窗口内定位 `stp x29, x30, [sp, #-N]!` 帧保存及 `sub x29, sp, #8`（`0xd10023fd`）或 `mov x29, sp`（`0x910003fd`），跳过 `morestack` 序言；
- **双架构 `RET` 指令偏移扫描**：
  - `x86_64`：`scanAMD64ReturnOffsets`（由 `findGoAMD64RetOffsets` 调用）扫描 `[fn.Entry, fn.End)` 内的 `add $imm, %rsp; pop %rbp; ret` 序列（回退扫描全部 `0xc3`），提取全部 `RET` 指令的文件偏移；
  - `ARM64`：`scanARM64ReturnOffsets`（由 `findGoARM64RetOffsets` 调用）按 4 字节对齐扫描函数体内的 A64 `RET` (`0xd65f03c0`) 及 `RETAA` (`0xd65f0bff`) / `RETAB` (`0xd65f0fff`) 指令偏移，实现**对 stripped Go 二进制的零侵入 eBPF Uprobe 挂载**。

### 3. 三种免重启侵入式热注入机制 (`InjectRunningPID`)

当 eBPF 无法直接解密目标进程且用户确认注入（交互式输入 `y`、传入 `--inject-live` 参数、或调用 `POST /api/pid/inject`）时，`InjectRunningPID` 按目标栈执行免重启热挂载：

0. **热注入范围校验门禁、严禁 `0666` 跨 UID 权限与指数退避 (`live_attach.go` & `source_perm_unix.go`)**
   - **热注入范围校验门禁 (`ErrPIDOutOfScope` / 403)**：`Collector.InjectRunningPID` 在入口最前端调用 `tracker.IsInScope(pid)` 校验目标 PID 是否属于当前监控范围；若不在范围内，立即记录 `selfmon` `StageProbe` 的 **`pid_inject_out_of_scope_blocked`** 告警并返回 **`ErrPIDOutOfScope`**，Web API `POST /api/pid/inject` 将其映射为 **`403 Forbidden`**，绝不触碰底层 `ptrace`/信号/JVMTI；
   - **严禁 `0666` 的最小权限策略与 `cross_uid_channel_denied`**：默认 `<cache_dir>/hooks` 目录权限为 `0700`、`tls.sock` 与 `tls.bin` 为 `0600`（`sanitizePrivateMode` 强制屏蔽 `0o077` 权限位）。在执行运行中进程热注入前，`ensureHookChannelPermissions` 读取目标进程的 `UID`：若检测到单个跨 UID 目标进程且具备 `CAP_CHOWN`（root），通过 `setHooksDirModeNoFollow`（使用 `syscall.O_NOFOLLOW`）将 `<cache_dir>/hooks` 设为 `0711`（仅允许路径穿越，禁止目录列表），通过 `applyPipePermissionsNoFollow` 与 `applySocketPermissionsNoFollow`（内部调用 `applyFdPermissions`）将 `tls.sock` 与 `tls.bin` `lchown` 给目标 `UID` 且严格维持 `0600`，同时将 CA 证书与只读 Hook 脚本设为 `0644`。**若存在多个不同非特权跨 UID 目标或当前进程无 `CAP_CHOWN` 权限，系统绝不回退 `0666`**，而是保持 `0600` 并向 `selfmon` `StageProbe` 记录 **`cross_uid_channel_denied`** 告警；
   - **热注入失败按 PID 指数退避与自动清理 (`inject_backoff` & `ResetInjectBackoff`)**：`InjectRunningPID` 通过 `checkInjectBackoff`、`recordInjectFailure`、`clearInjectBackoff` 与 `ResetInjectBackoff` 维护每个 PID 的失败退避状态（`pidInjectBackoffState`）：当某个 PID 热注入失败时，退避间隔从 `injectBackoffInitial = 1 * time.Second` 起按指数翻倍直至上限 `injectBackoffMax = 5 * time.Minute`（`1s -> 2s -> 4s ... -> 5m`），并向 `selfmon` `StageProbe` 记录 **`inject_backoff`** 告警，防止在 `200ms` 轮询周期内对无权限或异常进程产生信号/子进程风暴；当 Collector 停止时后台协程监听 `stopCh` 自动清理 `injectBackoffMap`，`web.Server.Close()` 亦主动调用 `collector.ResetInjectBackoff()`。
1. **`jvm_dynamic_attach`（针对运行中 Java/JVM 进程）**
   - **运行时 Agent JAR SHA-256 校验与自动重建 (`EnsureJavaAgentJar` / `verifyJavaAgentJar`)**：在准备 `llm_tracer_java.jar` 时，若文件已存在，`verifyJavaAgentJar` 会严格校验文件大小（`>512B`）、ZIP 归档结构、`META-INF/MANIFEST.MF`（必须包含 `Premain-Class`、`Agent-Class`、`Can-Redefine-Classes`、`Can-Retransform-Classes`）以及 JAR 内的 `LlmTracerAgent.class` 和 `LlmTracerAgent$TapProxySelector.class` 是否与内嵌 `assets/java/checksums.sha256` 的 SHA-256 完全一致且无未知条目；校验失败时记录 `verify_java_agent_jar` 告警、删除旧文件并自动重建。
   - **防符号链接攻击与退出自动清理**：使用 `os.CreateTemp("/tmp", fmt.Sprintf("llm_tracer_agent_%d_*.jar", pid))` 在 `/tmp` 创建带随机后缀的独立 staging JAR（权限 `0644`），并将路径登记到 `Collector.stagedAgentJars`；当 `Collector.Stop()` 退出时自动遍历清理所有临时 staging JAR。
   - 优先调用 `jcmd <pid> JVMTI.agent_load <jarPath> <proxyURL>`；若环境无 `jcmd`，则直接通过 HotSpot POSIX Dynamic Attach 协议连接 `/proc/<pid>/root/tmp/.java_pid<pid>` Unix Socket（若 Socket 尚未初始化，则通过 `createJVMAttachTriggerFile` 以 `O_CREATE|O_EXCL|O_WRONLY|O_NOFOLLOW` 安全标志创建 `.attach_pid<pid>` 触发文件并发送 `SIGQUIT` 唤醒 JVM Attach Listener 线程，随后发送 `1\0load\0instrument\0false\0<jar>=<proxyURL>\0`）。
   - 目标 JVM 内部自动执行 `LlmTracerAgent.agentmain()`，动态替换全局 `SSLContext`、`HttpsURLConnection` 默认 SocketFactory 与 `ProxySelector`，立即接管该 JVM 后续新建的所有 HTTPS/HTTP 连接。
2. **`node_inspector_sigusr1`（针对运行中 Node.js 进程）**
   - 向目标 Node.js 进程发送 `SIGUSR1` 信号唤醒内置 V8 Inspector。
   - **基于 `/proc/<pid>/fd` + `/proc/net/tcp` Inode 的端口精确匹配与安全拒绝 (`resolveNodeInspectorWSURL`)**：
     - `discoverPIDInspectorEndpoints(pid)` 先通过 `collectPIDSocketInodes(pid)` 扫描 `/proc/<pid>/fd` 提取该进程持有的全部 `socket:[<inode>]`，再通过 `parseProcNetTCPFile` 比对 `/proc/<pid>/net/tcp` 与 `/proc/<pid>/net/tcp6`（回退 `/proc/net/tcp{,6}`）中状态为 `0A` (`TCP_LISTEN`) 的回环监听记录，精确找出属于目标 `pid` 的 Inspector 端口；
     - `selectNodeInspectorTarget` 对 `/json` 返回的目标执行多重归属验证：校验 `validateInspectorWSURL`（必须为本机回环 `ws://`/`wss://`）、核对显式 `pid` 字段或匹配命令行主脚本（`matchesNodeCmdline`），或要求 `socketInodeMatched == true` 且仅有唯一 1 个调试目标；
     - **安全优先拒绝盲注**：若无法通过 socket inode 或脚本特征确认调试端口归属，或存在多目标歧义，立即拒绝注入并向 `selfmon` `StageProbe` 记录 **`node_inspector_target_rejected`** 告警，防止误注入同机其他 Node 进程。
   - 确认目标后，通过内置 RFC 6455 WebSocket 客户端发送 `Runtime.evaluate`（开启 `includeCommandLineAPI: true`）：设置 `process.env.LLM_TRACER_SOCK` / `LLM_TRACER_PIPE`、动态 `require("<cache_dir>/hooks/node_hook.cjs")` 挂载 `tls.TLSSocket` 与 `net.Socket`（含 `_writev`）钩子，并立即调用 `require("node:inspector").close()` 关闭调试端口。
3. **`ptrace_seize`（针对运行中原生 C/C++/Rust/静态进程）**
   - **架构支持度门控 (`PtraceUserspaceSupported`)**：在生成 `PIDAttachPlan`（`applyPtraceLiveFallback`）与执行热注入（`injectRunningPtrace`）时，都会真实检查 `currentArchCapabilities().PtraceUserspaceSupported`（`linux/amd64` 为 `true`，`linux/arm64` 为 `false`）。若当前架构不支持用户态 ptrace 辅助器，自动跳过 `ptrace_seize`，在 `PIDAttachPlan.DegradationNotices` 中记录降级说明，并向 `selfmon` `StageProbe` 发送 **`ptrace_arch_unsupported`** 告警。
   - 拉起后台 `llm_tracer_ptrace -p <pid>`（通过 `StripSensitiveEnvKeys` 剥离父进程敏感环境变量后注入 `LLM_TRACER_SOCK`/`LLM_TRACER_PIPE`），遍历 `/proc/<pid>/task/*` 全部线程执行 `ptrace(PTRACE_SEIZE, tid, 0, PTRACE_O_TRACESYSGOOD | ...)` 与 `PTRACE_INTERRUPT` 注入系统调用追踪。
   - 当 `llm-tracer` 退出时，信号处理器对所有已挂载线程执行 `PTRACE_DETACH`，目标进程继续无感运行，绝不会被杀死。

---

## 三、直接拉起子程序 (`-- <cmd>`) 纯函数启动规划器 (`internal/collector/launch_plan*.go`)

当使用 `llm-tracer [flags] -- <cmd> [args...]` 直接拉起子程序时，`PlanLaunchCommand` 采用**两阶段纯函数架构**（`planLaunch(in launchPlanInput) LaunchAttachPlan` 生成无副作用规划，`applyLaunchPlan` 将规划应用到子进程参数与环境变量并输出 `LaunchAttachPlan`），按运行时拆分为 5 个专用模块：
- `internal/collector/launch_plan.go`：公共输入收集、环境变量合并与导出函数 **`StripSensitiveEnvKeys`**：
  - **仅剥离内部凭据**：配合 `IsSensitiveChildEnvKey` 严格仅剥离 `llm-tracer` 自身的内部敏感变量（`LLM_TRACER_TOTP_SECRET`、`LLM_TRACER_INGEST_TOKEN`、`LLM_TRACER_LOCAL_TOKEN`、`LLM_TRACER_AUTH_TOKEN`、`LLM_TRACER_TOKEN` 以及以 `LLM_TRACER_` 开头且带敏感后缀的内部变量）；`collector.go` 的 `LaunchPlannedCommand` 与 `live_attach.go` 的 `injectRunningPtrace` 均統一调用 `StripSensitiveEnvKeys`，防止子进程继承任何探针内部凭据；
  - **业务与模型认证环境变量完整原样透传**：用户的业务与模型认证环境变量（例如 `OPENAI_API_KEY`、`ANTHROPIC_API_KEY`、`ANTHROPIC_AUTH_TOKEN`、`GEMINI_API_KEY`、`GITHUB_TOKEN`、`AWS_SESSION_TOKEN`、`HF_TOKEN` 等）在拉起子进程时**完整原样透传给被测程序**，确保 Claude Code、Codex、各类 Agent CLI 与模型 SDK 能够正常完成上游鉴权（仅在 `/api/scope` 展示与 `selfmon` 日志落盘时通过 `redactEnvMap`/`RedactCmdArgs` 脱敏为 `[REDACTED]`）；
- `internal/collector/launch_plan_jvm.go`：Java/JVM (`java`/`javaw`) 参数注入规划（`planJVMLaunch`）；
- `internal/collector/launch_plan_node.go`：Node.js (`planNodeLaunch`) 与 Bun (`planBunLaunch`) 参数注入规划；
- `internal/collector/launch_plan_python.go`：Python (`python`/`python3`/`uv`) `PYTHONPATH` 与 CA 环境变量规划（`planPythonLaunch`）；
- `internal/collector/launch_plan_native.go`：Go (`gotls`)、静态/动态 OpenSSL 与 `static-pie` / `stripped-embedded-tls` 原生二进制规划（`planNativeLaunch` / `planNativePtraceWrap`）。当目标需要 `ptrace` 包装但 `in.PtraceUserspaceSupported == false`（如 `linux/arm64`）时，`planNativePtraceWrap` 自动跳过 `llm_tracer_ptrace` 包装，将原因记入 `LaunchAttachPlan.DegradationNotices`，并在 `applyLaunchPlan` 中记录 `selfmon` `StageProbe` 告警 **`ptrace_arch_unsupported`**（`mode: "ptrace_wrapper"`）。

此外，Web 接口 `GET /api/scope` 在返回 `launch_plan` 前会通过 `sanitizeLaunchPlan`（`internal/web/server.go`）调用 `sanitizeEnvMap` 与 `sanitizeArgSlice` 对 `InjectedEnv`、`InjectedArgs` 与 `ExecArgs` 进行脱敏，将包含敏感键名（`token`/`secret`/`password`/`key`/`auth` 等）或匹配内部令牌的值替换为 `"***"`，防止子进程命令行或环境中的凭据通过 API 泄露。

| 目标子程序类型 | `DetectedStack` | `NonIntrusiveOK` 判定条件 | 无法非侵入时自动补全的命令行参数 (`InjectedArgs`) 与包装器 | 自动补全的环境参数 (`InjectedEnv`) |
| :--- | :--- | :--- | :--- | :--- |
| **Java (`java` / `javaw`)** | `jvm-jsse` | `false`（JSSE 字节码 TLS 无固定 ELF 偏移） | 自动在主类/`-jar` 前置插入：<br>`-javaagent:<jar>=<proxyURL>`<br>`-Dhttp.proxyHost=<host>`<br>`-Dhttp.proxyPort=<port>`<br>`-Dhttps.proxyHost=<host>`<br>`-Dhttps.proxyPort=<port>`<br>`-Djdk.internal.httpclient.disableHostnameVerification=true` | `JAVA_TOOL_OPTIONS`、`LLM_TRACER_PROXY_HOST/PORT`、`SSL_CERT_FILE` |
| **Node.js (`node`)** | `nodejs` | `false`（需覆盖 `undici`/`TLSSocket` BIO 流与 CA） | 自动前置插入：<br>`--require <node_hook.cjs>` | `NODE_OPTIONS`、`NODE_EXTRA_CA_CERTS`、`LD_PRELOAD`/`DYLD_INSERT_LIBRARIES` |
| **Bun (`bun`)** | `bun-boringssl` | `false`（静态内嵌 strip BoringSSL） | 自动前置插入：<br>`--preload <node_hook.cjs>` | `BUN_OPTIONS`、`HTTPS_PROXY`、`SSL_CERT_FILE`、`NODE_EXTRA_CA_CERTS` |
| **Python (`python3` / `uv`)** | `python` | `false`（`httpx`/`aiohttp` 使用 `MemoryBIO` 或 `uv` 静态 SSL） | 保持原命令行参数 (`sys.argv` 不变) | `PYTHONPATH=<pyhook>` (`sitecustomize.py`)、`REQUESTS_CA_BUNDLE`、`SSL_CERT_FILE` |
| **Go 二进制 (`go` / 编译产物)** | `gotls` | Linux Root eBPF 下为 `true`；非特权/macOS/Windows 下为 `false` | `RequiresPtrace` 时自动包裹 `llm_tracer_ptrace <bin> <args...>` | 非 eBPF 下自动注入 `HTTPS_PROXY`、`SSL_CERT_FILE` |
| **动态/静态 OpenSSL 原生程序** | `dynamic-libssl` / `static-openssl` | Linux Root eBPF 下为 `true`；非特权/macOS/Windows 下为 `false` | 保持原命令行参数 | `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES`、`SSL_CERT_FILE`、`CURL_CA_BUNDLE` |
| **全静态 / Rust `rustls` (`codex` 等)** | `static-pie` / `stripped-embedded-tls` | `false`（无动态链接器或无 OpenSSL/GoTLS 符号） | `static-pie` 自动包裹 `llm_tracer_ptrace <bin> <args...>` | `HTTPS_PROXY`、`HTTP_PROXY`、`SSL_CERT_FILE`、`CARGO_HTTP_CAINFO` |

> 可通过 `--auto-intrusive=false` 显式关闭子程序启动参数自动注入（默认 `--auto-intrusive=true`）。

---

## 四、功能使用与命令示例

### 1. 按不同维度选择运行中进程
```bash
# (1) 指定 PID 并默认包含其所有后代子进程（如指定终端 bash PID 或 Supervisor PID）
sudo ./bin/llm-tracer capture --pid 18420

# (2) 仅抓取指定 PID 本身，不抓其派生的子进程
sudo ./bin/llm-tracer capture --pid 18420 --pid-only

# (3) 按二进制路径或命令名选择（支持多个 --exe）
./bin/llm-tracer capture --exe /usr/bin/python3 --exe node --inject-live

# (4) 按项目工作目录选择（抓取在该目录及其子目录下运行的所有 Agent 进程）
./bin/llm-tracer capture --cwd /home/user/my-agent-project --inject-live

# (5) 按进程名或命令行关键字选择 + 限制只抓特定大模型域名
./bin/llm-tracer capture --cmd LangGraphWorker --host api.openai.com --inject-live
```

### 2. 通过 Web API 动态修改范围与触发免重启热注入

> **鉴权说明**：
> - 所有写接口（`PUT /api/scope`、`POST /api/pid/inject`、`POST /api/cache/clean`）均要求 `Content-Type: application/json`（否则 `decodeJSONBody` 返回 `415 Unsupported Media Type`）。
> - `PUT /api/scope` 与 `POST /api/cache/clean`（`withWriteAuth`）：未开启 `--totp-secret` 时仅允许本机回环地址调用（非回环一律返回 `403`，提示 `非回环地址访问需启用 --totp-secret`），且须携带 `X-LLM-Tracer-Token: <localToken>` 请求头或回环下发的 `llm_tracer_token` Cookie（`SameSite=Strict`）；开启 `--totp-secret` 时支持已登录的 `llm_tracer_token` Cookie 或 `X-LLM-Tracer-TOTP: <6位码>` 请求头。
> - `POST /api/pid/inject`（`withPIDInjectAuth`）：**无论是否启用 TOTP，均强制要求请求来自本机回环地址 + 不携带任何 `Origin` 请求头 + 通过 HTTP 请求头（`X-LLM-Tracer-Token`、`X-LLM-Tracer-Ingest` 或 `Authorization: Bearer`）传入本机 Token**（不接受 Cookie，也不接受浏览器带 `Origin` 的直接调用）。

```bash
# 动态修改抓取范围（注意方法为 PUT /api/scope，无需重启 llm-tracer）
curl -X PUT http://127.0.0.1:8787/api/scope \
  -H "Content-Type: application/json" \
  -H "X-LLM-Tracer-Token: <从启动日志或同源页面获取的 local_token>" \
  -d '{"pids":[31052],"pid_only":false,"cwds":["/srv/agent"],"record_headers":false}'

# 查看当前匹配到的运行中进程诊断计划 (pid_plans)
curl -s http://127.0.0.1:8787/api/scope | jq .pid_plans

# 对指定运行中 PID 执行免重启热注入（或传 {"all":true} 一键注入全部需侵入进程）
curl -X POST http://127.0.0.1:8787/api/pid/inject \
  -H "Content-Type: application/json" \
  -H "X-LLM-Tracer-Token: <local_token>" \
  -d '{"pid":31052}'
```

### 3. 直接拉起子程序 (`-- <cmd>`) 并查看自动补全的参数计划
```bash
# 直接拉起 Java / Node / Python / Claude / Codex 子程序（自动补全侵入式参数）
./bin/llm-tracer capture --exit-with-child -- java -cp ./app MyAgentMain

# 运行期间可通过 /api/scope 查看脱敏后的 InjectedArgs 与 InjectedEnv 键列表
curl -s http://127.0.0.1:8787/api/scope | jq .launch_plan
```

### 4. 本地 HTTP/HTTPS 代理抓包 (`--proxy-listen`) 与最后兜底代理环境变量注入

- **显式 HTTP/HTTPS 代理模式**：
  - `llm-tracer capture` 启动时内置 `LoopbackTap` 本地 HTTP + HTTPS MITM 抓包代理，可通过 `--proxy-listen` 指定固定监听地址（默认随机回环端口 `127.0.0.1:0`），并在启动日志及 `GET /api/scope`（`proxy_url`、`ca_bundle` 字段）中输出代理地址与合并了系统根证书的本地 CA 证书束路径（`<cache-dir>/hooks/llm_tracer_ca_bundle.pem`）。
  - 外部程序或容器可直接配置 `HTTP_PROXY`、`HTTPS_PROXY` 与 `SSL_CERT_FILE` 接入该代理完成抓包。
- **拉起子进程 (`-- <cmd>`) 的最后兜底策略 (`shouldFallbackToProxyEnv`)**：
  - 当非侵入式 eBPF Uprobe 可直接覆盖目标（如动态/静态 OpenSSL 或 GoTLS 且内核 eBPF 激活），或对应运行时的专用 Hook 可用（Python `PYTHONPATH`、Node/Bun `--require`/`--preload`、JVM `-javaagent`、Linux/macOS 下 `dynamic-libssl` 的 `LD_PRELOAD`/`DYLD_INSERT_LIBRARIES`）时，**不改写**子进程的 `HTTP_PROXY`/`HTTPS_PROXY`，并完整保留父进程原有的 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY` 环境变量。
  - 仅当所有非侵入式与运行时专用 Hook 手段均无法注入时（如 `stripped-embedded-tls` / Rust `rustls`、无 eBPF 权限下的静态 Go/OpenSSL 二进制、或缺失对应运行时 Hook 文件），才将注入 `HTTP_PROXY`/`HTTPS_PROXY`（连同 `SSL_CERT_FILE`、`NODE_EXTRA_CA_CERTS`、`REQUESTS_CA_BUNDLE` 等）作为最后的兜底手段。
- **父进程代理配置遵从 (`UpstreamProxyConfig`)**：
  - `LoopbackTap` 启动及拉起子进程兜底时会自动解析父进程的 `HTTP_PROXY`/`http_proxy`、`HTTPS_PROXY`/`https_proxy`、`ALL_PROXY`/`all_proxy` 与 `NO_PROXY`/`no_proxy`。
  - 子进程流量进入本地 `LoopbackTap` 解密抓包后，出站请求（含明文 HTTP 转发与 HTTPS `CONNECT` 隧道）会严格遵从父进程代理配置向上游代理（支持 `http://`、`https://`、`socks5://`、`socks5h://` 及 Basic Auth `Proxy-Authorization`）串联转发，并按父进程 `NO_PROXY` 规则（域名后缀、精确主机、IP 与 CIDR）直连白名单目标，同时自动识别并剔除指向 `LoopbackTap` 自身的代理地址以防止死循环。
