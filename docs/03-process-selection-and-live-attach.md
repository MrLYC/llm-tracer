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
- 在函数开头 32 字节窗口内定位 `push %rbp; mov %rsp, %rbp` (`55 48 89 e5`)，跳过 Go 栈扩容序言（`morestack`）；
- 扫描 `[fn.Entry, fn.End)` 内的 `add $imm, %rsp; pop %rbp; ret` 序列，提取全部 `RET` (`0xc3`) 指令的文件偏移，实现**对 stripped Go 二进制的 100% 零侵入 eBPF Uprobe 挂载**。

### 3. 三种免重启侵入式热注入机制 (`InjectRunningPID`)

当 eBPF 无法直接解密目标进程且用户确认注入（交互式输入 `y`、传入 `--inject-live` 参数、或调用 `POST /api/pid/inject`）时，`InjectRunningPID` 按目标栈执行免重启热挂载：

1. **`jvm_dynamic_attach`（针对运行中 Java/JVM 进程）**
   - 将 `llm_tracer_java.jar` 复制到 `/tmp/llm_tracer_agent_<pid>.jar`（`0644` 权限，确保目标 JVM 可读）。
   - 优先调用 `jcmd <pid> JVMTI.agent_load <jarPath> <proxyURL>`；若环境无 `jcmd`，则直接通过 HotSpot POSIX Dynamic Attach 协议连接 `/proc/<pid>/root/tmp/.java_pid<pid>` Unix Socket（若 Socket 尚未初始化，则在目标工作目录创建 `.attach_pid<pid>` 并发送 `SIGQUIT` 唤醒 JVM Attach Listener 线程，发送 `1\0load\0instrument\0false\0<jar>=<proxyURL>\0`）。
   - 目标 JVM 内部自动执行 `LlmTracerAgent.agentmain()`，动态替换全局 `SSLContext`、`HttpsURLConnection` 默认 SocketFactory 与 `ProxySelector`，立即接管该 JVM 后续新建的所有 HTTPS/HTTP 连接。
2. **`node_inspector_sigusr1`（针对运行中 Node.js 进程）**
   - 向目标 Node.js 进程发送 `SIGUSR1` 信号（Node.js 原生内置信号处理器会在 `127.0.0.1:9229` 启动 V8 Inspector）。
   - 轮询 `http://127.0.0.1:9229/json` 获取 `webSocketDebuggerUrl`，通过内置的 RFC 6455 WebSocket 客户端发送 `Runtime.evaluate`（开启 `includeCommandLineAPI: true`）：
     设置 `process.env.LLM_TRACER_PIPE`、动态 `require("<cache_dir>/hooks/node_hook.cjs")` 挂载 `tls.TLSSocket` 与 `net.Socket` 钩子，并立即调用 `require("node:inspector").close()` 关闭调试端口。
3. **`ptrace_seize`（针对运行中原生 C/C++/Rust/静态进程）**
   - 拉起后台 `llm_tracer_ptrace -p <pid>`，遍历 `/proc/<pid>/task/*` 全部线程执行 `ptrace(PTRACE_SEIZE, tid, 0, PTRACE_O_TRACESYSGOOD | ...)` 与 `PTRACE_INTERRUPT` 注入系统调用追踪。
   - 当 `llm-tracer` 退出时，信号处理器对所有已挂载线程执行 `PTRACE_DETACH`，目标进程继续无感运行，绝不会被杀死。

---

## 三、直接拉起子程序 (`-- <cmd>`) 自动侵入式参数补全 (`PlanLaunchCommand`)

当使用 `llm-tracer [flags] -- <cmd> [args...]` 直接拉起子程序时，`PlanLaunchCommand` 在 `exec.CommandContext` 启动前自动生成 `LaunchAttachPlan`：

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
```bash
# 动态修改抓取范围（无需重启 llm-tracer）
curl -X POST http://127.0.0.1:8787/api/scope \
  -H "Content-Type: application/json" \
  -d '{"pids":[31052],"pid_only":false,"cwds":["/srv/agent"],"record_headers":false}'

# 查看当前匹配到的运行中进程诊断计划 (pid_plans)
curl -s http://127.0.0.1:8787/api/scope | jq .pid_plans

# 对指定运行中 PID 执行免重启热注入（或传 {"all":true} 一键注入全部需侵入进程）
curl -X POST http://127.0.0.1:8787/api/pid/inject \
  -H "Content-Type: application/json" \
  -d '{"pid":31052}'
```

### 3. 直接拉起子程序 (`-- <cmd>`) 并查看自动补全的参数计划
```bash
# 直接拉起 Java / Node / Python / Claude / Codex 子程序（自动补全侵入式参数）
./bin/llm-tracer capture --exit-with-child -- java -cp ./app MyAgentMain

# 运行期间可通过 /api/scope 查看实际自动注入的 InjectedArgs 与 InjectedEnv
curl -s http://127.0.0.1:8787/api/scope | jq .launch_plan
```
