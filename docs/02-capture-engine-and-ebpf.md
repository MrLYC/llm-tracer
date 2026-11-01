# 02. 八层自适应采集引擎与内核 eBPF 深度解析

本文档详细说明 `llm-tracer` 如何针对不同编译链接方式、TLS 协议栈与语言运行时的大模型客户端实现全覆盖采集（完整测试矩阵与更多细节亦同步维护于 [`docs/capture-architecture.md`](capture-architecture.md)）。

---

## 一、为什么单一 `eCapture` 或传统 `LD_PRELOAD` 会漏抓？

| 典型客户端 / 运行时 | 二进制链接特征 | TLS / 网络栈实现 | 单一 `eCapture` 默认表现 | 传统 `LD_PRELOAD` (`SSL_*` + `send/recv`) 表现 | `llm-tracer` 覆盖方案 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `curl`、系统 `python3` | 动态链接 `libc.so.6` + `libssl.so.3` | 系统 OpenSSL 3 (`SSL_write`/`SSL_read`) | 需 Root 抓 HTTPS；**明文 HTTP 漏抓** | 可抓 HTTPS；若用 `write`/`read` 发 HTTP 则漏抓 | Layer 0 (eBPF Uprobe + Tracepoint) / Layer 1+2 (`LD_PRELOAD`) |
| **Claude Code (`claude.exe`)** | Bun 单文件 ELF，动态链接 `libc.so.6` | **静态内嵌 BoringSSL（符号已 strip）** + `uSockets/libuv` (`writev`) | **完全失效**：无 `libssl.so` 依赖且符号已 strip | `SSL_write` 不触发；未拦 `writev` 则漏抓 | Layer 0 (`sys_enter_writev`) + Layer 2 (`writev` 展平) + Layer 4 (`BUN_OPTIONS`) |
| **Hermes / `uv` 独立版 Python** | `python-build-standalone` | **静态内嵌 OpenSSL（局部符号 `t`）** + `asyncio` `ssl.MemoryBIO` | **默认失效**：`MemoryBIO` 下 `SSL_get_fd(ssl) == -1` | **HTTPS 失效**：`SSL_write` 为模块内部局部调用 | Layer 0 (`_ssl_MemoryBIO_*` Uprobe) + Layer 3 (`sitecustomize.py`) |
| **Node.js (v20 ~ v24+)** | 动态链接 `libc.so.6` | **静态内嵌 OpenSSL 3** + `undici`/`TLSSocket` | **默认失效**：不经过系统 `libssl.so` | **HTTPS 失效**：内部静态调用 `SSL_write` | Layer 0 (静态 OpenSSL Uprobe) + Layer 4 (`--require node_hook.cjs` / `SIGUSR1`) |
| **OpenAI Codex CLI (`codex`)** | `node` 包装脚本拉起 **`static-pie` (`stripped`)** | **Rust `musl` 全静态链接 + `rustls` + 内联 `syscall`** | **完全失效**：不支持 `rustls` 且完全 `stripped` | **完全失效**：无 `PT_INTERP`，内核忽略 `LD_PRELOAD` | Layer 0 (Syscall Tracepoint) + Layer 5 (`ptrace`) + Layer 6 (`LoopbackTap`) |
| **Go 原生程序 (`ollama`、Go Agent)** | 无 `libc` 依赖（含 `-ldflags="-s -w"` strip） | **Go 原生 `crypto/tls` + 直接 `syscall`** | strip 后 `.symtab` 为空则失效 | **完全失效**：不经过 `libc.so` 与 `libssl.so` | Layer 0 (`.gopclntab` 符号恢复 + `RET` Uprobe) + Layer 5/6 |
| **Java / JVM (`Spring AI`、`LangChain4j`)** | JVM 字节码 + JIT | **JDK JSSE (`SSLSocketImpl` / `SSLEngineImpl`) 纯 Java 实现** | **完全失效**：TLS 在 JVM 字节码层完成 | **完全失效**：不经过 C 层 `SSL_write` | Layer 7 (`-javaagent` `premain` / 动态 Attach `agentmain`) + Layer 6 |
| **Rust (`reqwest` + `rustls`、`goose`)** | 动态 `libc` 或 `musl` 静态 | **Rust 原生 `rustls`（`ring` / `aws-lc-rs`）** | **完全失效**：无 OpenSSL 符号 | **HTTPS 失效**：Socket 层仅见 TLS 密文 | Layer 6 (`LoopbackTap` + `CARGO_HTTP_CAINFO`) + Layer 5 (`ptrace`) |

---

## 二、八层采集机制技术细节

### Layer 0：Linux 原生 eBPF 引擎 (`internal/collector/ebpf_engine_linux.go`)

1. **纯 Go 原生 BPF 指令集构造**：
   - 无需外部 `clang`/`llvm`/内核头文件，直接构建 11 个 eBPF 程序并通过 `unix.SYS_BPF` (`BPF_PROG_LOAD`) 注入内核。
   - 共挂载 **19 个内核探针**：
     - OpenSSL Uprobes/Uretprobes：`SSL_write`、`SSL_write_ex`、`SSL_read` (entry + ret)、`SSL_read_ex` (entry + ret + `size_t *readbytes` 二次解引用)；
     - Python MemoryBIO Uprobes：`_ssl_MemoryBIO_write`、`_ssl_MemoryBIO_read`；
     - GoTLS Uprobes：`crypto/tls.(*Conn).Write`（跳过 `morestack` 序言后读取 `RAX=conn, RBX=ptr, RCX=len`）、`crypto/tls.(*Conn).Read`（入口以 `(pid<<32)|uint32(R14)` 保存 `g` 指针上下文，并在函数所有 `RET` 指令偏移处挂载 Uprobe 读取返回值 `RAX=n`）；
     - Syscall Tracepoints：`sys_enter_write`、`sys_enter_writev`（内核态展开 `iov[0..1]`）、`sys_enter_sendto`、`sys_enter_read`、`sys_exit_read`、`sys_enter_recvfrom`、`sys_exit_recvfrom`。
2. **四 Map 隔离架构**：
   - `ringbuf` (`BPF_MAP_TYPE_RINGBUF`, `8 MiB`)：双倍虚拟内存镜像 `mmap` 零拷贝消费；
   - `active_ssl_read` (`BPF_MAP_TYPE_HASH`)：专供 `SSL_read` / `SSL_read_ex` 保存 `(conn_tag, buf_ptr, len_ptr)`；
   - `active_sys_read` (`BPF_MAP_TYPE_HASH`)：专供 `sys_enter_read` / `sys_enter_recvfrom` 使用，与 `active_ssl_read` 物理隔离，防止 `SSL_read` 内部触发系统调用 `read` 时覆盖外层明文缓冲区指针；
   - `active_gotls_read` (`BPF_MAP_TYPE_HASH`)：以 Goroutine 唯一键 `(pid<<32)|uint32(R14)` 关联 GoTLS 读缓冲区。
3. **多核 CPU `perf_event_open` 保活机制**：
   - 对每个在线 CPU 核心打开 `perf_event_open` 并执行 `PERF_EVENT_IOC_ENABLE`；当 CPU `1..N` 调用 `PERF_EVENT_IOC_SET_BPF` 返回 `EEXIST`（同一 `tracepoint` `tp_event` 已在 CPU 0 绑定 BPF 程序）时，保持 CPU `1..N` 的 `perf_event` FD 开启且处于 `ENABLED` 状态，确保进程跨核调度时 100% 捕获事件。

### Layer 1 & Layer 2：C 预加载 Hook (`internal/collector/preload_hook.go`)

- **动态 OpenSSL 拦截**：拦截 `SSL_write`、`SSL_write_ex`、`SSL_read`、`SSL_read_ex`，通过 `__thread int in_ssl_hook` 防重入。
- **Socket 全族系统调用拦截**：拦截 `write`、`writev`、`send`、`sendto`、`sendmsg`、`read`、`readv`、`recv`、`recvfrom`、`recvmsg`、`close`：
  - 仅在 `fstat(fd)` 确认为 `S_ISSOCK` 且首包匹配 HTTP 方法前缀时追踪该 `fd`；
  - 将 `writev` / `readv` 的分散 `struct iovec[]` 展平为连续字节块；
  - 通过 `tracked_http_gen[fd]` 维护 Keep-Alive 连接上的请求代数隔离（`0x80000000 | (gen << 16) | fd`）。

### Layer 3：Python 运行时钩子 (`internal/collector/runtime_hooks.go`)

- 自动生成 `<cache_dir>/hooks/pyhook/sitecustomize.py`，链式执行下游 `sitecustomize.py`；
- 同时 Hook `ssl.SSLObject.write/read`（覆盖 `asyncio` + `httpx` / `httpcore` / `aiohttp` 的 `MemoryBIO`）、`ssl.SSLSocket.write/send/read`（覆盖 `requests` / `urllib3`）与 `http.client.HTTPConnection`（覆盖本地明文 HTTP Ollama/vLLM/MCP）。

### Layer 4：Node.js 与 Bun 运行时钩子 (`internal/collector/runtime_hooks.go`)

- 自动生成 `<cache_dir>/hooks/node_hook.cjs`（内置 `globalThis.__LLM_TRACER_NODE_HOOK_LOADED__` 幂等锁）；
- Hook `tls.TLSSocket.prototype._write` / `_writev` / `push`（覆盖 Node.js HTTPS）与 `net.Socket.prototype._write` / `push`（覆盖明文 HTTP）；
- 针对 Bun 运行时 (`process.versions.bun`) 额外包装 `globalThis.fetch` 拦截内嵌 BoringSSL 的 HTTPS 请求与流式响应。

### Layer 5：跨进程树 `ptrace` 追踪器 (`llm_tracer_ptrace`)

- 支持两种模式：
  1. **拉起子进程模式 (`llm_tracer_ptrace <prog> [args...]`)**：通过 `PTRACE_TRACEME` + `PTRACE_O_TRACEFORK/VFORK/CLONE/EXEC` 穿透包装脚本（如 `bin/codex`），仅对未映射 `libllm_tracer_ssl.so` 的静态二进制或 Go 二进制启用 `PTRACE_GET_SYSCALL_INFO` + `process_vm_readv` 零拷贝提取；
  2. **热挂载运行中进程模式 (`llm_tracer_ptrace -p <pid>`)**：通过 `PTRACE_SEIZE` + `PTRACE_INTERRUPT` 挂载运行中进程所有线程，退出时通过 `PTRACE_DETACH` 安全分离。

### Layer 6：动态 ECDSA CA 与 `LoopbackTap` (`internal/collector/loopback_tap.go`)

- 内存态生成 P-256 临时根证书并与系统根证书合并为 `llm_tracer_ca_bundle.pem`；
- 针对 `CONNECT host:443` 按需动态签发域名证书，双向镜像明文流至 `StreamReassembler`，并在客户端半关闭 (`CloseWrite`) 时保持上游读取直至响应完整结束。

### Layer 7：Java / JVM 字节码代理 (`internal/collector/java_agent.go`)

- 自动生成兼容 Java 8+ (class version `52.0`) 的 `llm_tracer_java.jar`，同时实现 `premain`（启动时通过 `-javaagent` / `JAVA_TOOL_OPTIONS` 加载）与 `agentmain`（运行中通过 `jcmd` / `.java_pid<pid>` 动态加载）；
- 安装自定义 `X509ExtendedTrustManager`、`HostnameVerifier` 与 `TapProxySelector`，零代码修改接管 JVM 全局 HTTPS/HTTP 流量。
