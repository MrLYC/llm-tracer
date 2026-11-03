# 02. 八层自适应采集引擎与内核 eBPF 深度解析

本文档基于代码实现（`internal/collector/`）详细说明 `llm-tracer` 如何针对不同编译链接方式、TLS 协议栈、语言运行时与硬件架构的大模型客户端实现自适应采集，并汇总跨平台能力矩阵与自动化验证矩阵（原 `capture-architecture.md` 内容已完整合并至本文档）。

---

## 一、为什么单一 `eCapture` 或传统 `LD_PRELOAD` 会漏抓？

| 典型客户端 / 运行时 | 二进制链接特征 | TLS / 网络栈实现 | 单一 `eCapture` 默认表现 | 传统 `LD_PRELOAD` (`SSL_*` + `send/recv`) 表现 | `llm-tracer` 覆盖方案 |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `curl`、系统 `python3` | 动态链接 `libc.so.6` + `libssl.so.3` | 系统 OpenSSL 3 (`SSL_write`/`SSL_read`) | 需 Root 抓 HTTPS；明文 HTTP 走 syscall tracepoint | 可抓 HTTPS；明文 HTTP 依赖 `write`/`read` 等 Hook，覆盖面弱于内核 tracepoint | Layer 0 (eBPF Uprobe + Tracepoint) / Layer 1+2 (`LD_PRELOAD`) |
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
   - 无需外部 `clang`/`llvm`/内核头文件，直接在 Go 中按目标架构寄存器约定（`internal/collector/ebpf_arch_amd64.go` / `internal/collector/ebpf_arch_arm64.go`）通过指令构造器（`BuildWriteProbeProgram`、`BuildReadEnterProgram`、`BuildReadExitProgram`、`BuildWritevProbeProgram`、`BuildSendmsgProbeProgram`、`BuildConnectResetProgram`、`BuildGoTLSReadEnterProgram`、`BuildGoTLSReadExitProgram`）构建 eBPF 字节码程序（内核加载名含 `llmt_ssl_write`、`llmt_ssl_r_ent`、`llmt_ssl_rx_en`、`llmt_ssl_r_ext`、`llmt_gotls_w`、`llmt_gotls_re`、`llmt_gotls_rx`、`llmt_tp_write`、`llmt_tp_sendto`、`llmt_tp_writev`、`llmt_tp_sendmsg`、`llmt_tp_r_ent`、`llmt_tp_rf_ent`、`llmt_tp_r_ext`、`llmt_tp_rf_ext`、`llmt_tp_connect`），并通过 `unix.SYS_BPF` (`BPF_PROG_LOAD`) 注入内核。
   - 共挂载 **多组内核探针**：
     - OpenSSL Uprobes/Uretprobes：`SSL_write`、`SSL_write_ex`、`SSL_read` (entry + ret)、`SSL_read_ex` (entry + ret + `size_t *readbytes` 二次解引用)；
     - Python MemoryBIO Uprobes：`_ssl_MemoryBIO_write`、`_ssl_MemoryBIO_read`；
     - GoTLS Uprobes（含 OBI 风格三级符号恢复与 ABI 门禁）：校验目标二进制 `buildinfo.GoVersion`（`amd64 >= go1.17`、`arm64 >= go1.18` 才启用寄存器 ABI），通过 `.symtab` + DWARF `.debug_info` + `.gopclntab` 三级通道解析 `crypto/tls.(*Conn).Write` 与 `crypto/tls.(*Conn).Read`，并支持大栈帧序言（`sub %rsp; mov %rbp, off(%rsp)` / ARM64 `STP X29, X30`）与多种尾声（`add %rsp; pop %rbp; ret`、`pop %rbp; add %rsp; ret`、`leave; ret`、无帧指针 `add %rsp; ret`）的偏移扫描；
     - Syscall Tracepoints：`sys_enter_write`/`sys_exit_write`、`sys_enter_sendto`/`sys_exit_sendto`（在 `sys_exit` 复制用户缓冲，避免 `sys_enter` 时未缺页的 `.rodata` 让 `bpf_probe_read_user` 失败）、`sys_enter_writev`（内核态展开 `iov[0..1]`）、`sys_enter_read`、`sys_exit_read`、`sys_enter_recvfrom`、`sys_exit_recvfrom`（启动时通过 `ResolveSyscallTracepointOffsets` 自动读取 `/sys/kernel/tracing/events/syscalls/*/format` 动态解析内核字段偏移，无权限时回退架构默认值）；`sys_enter_sendmsg` 从 `user_msghdr` 读取前两个 iovec，`recvmsg` enter/exit 记录 `iov[0]` 并按实际返回长度发射，`sys_enter_connect` 仅重置 `plain_flow` 状态。`sendmsg` / `recvmsg` / `connect` 为非必需探针，加载或 attach 失败只记录 warning，不影响引擎启动。
   - **明文 HTTP/1.1 走 syscall tracepoint，而不是 `kprobe`/`fentry` `tcp_sendmsg`**：Ollama、vLLM、llama.cpp、内网网关这类 `http://` 直连不进入 `crypto/tls` 或 `SSL_write`，因此在套接字系统调用层捕获；HTTPS 仍保留 OpenSSL/GoTLS uprobe，不替换、不重复解析。同一 `pid+fd` 一旦在前两字节看到 TLS record（`0x14/0x15/0x16/0x17` 且第二字节 `0x03`），`plain_flow` 标记为 TLS 后直接丢弃后续密文分片；请求行/状态行，或前 64 字节中路径起点落在前 16 字节且命中目标 LLM 路径时标记为 HTTP，同一 `pid+fd` 后续拆包 body、SSE 分片继续发送到重组器。未知状态下，仅当本次缓冲以 `{`、`[` 或 `data:` 开头时把该分片送进 RingBuf 供重组，且不把 fd 升级成 HTTP；其余未知流量不进入 RingBuf。系统调用方向再按明文纠正：请求方法即使出现在 `read`/`recvfrom` 上也视为请求，`HTTP/` 状态行即使出现在 `write`/`sendto` 上也视为响应。因此对端把两次 `sendto` 一次 `recvfrom` 拼成完整请求后，仍能和随后写出的响应配成一对。
2. **四 Map 隔离架构与 16 MiB RingBuf (`internal/collector/ebpf_engine_linux.go` `StartEBPFEngine`)**：
   - `ringbuf` (`BPF_MAP_TYPE_RINGBUF`, **`16 MiB` = `16 << 20` 字节**)：采用双倍虚拟内存镜像 `mmap` 零拷贝消费，避免高并发 SSE 流式输出或大上下文 Prompt 突发写入导致 RingBuf 丢包；单次提交帧载荷上限 `ebpfMaxPayload = 4072` 字节，连同 24 字节头共 `ebpfEventSize = 4096` 字节对齐；
   - `active_ssl_read` (`BPF_MAP_TYPE_LRU_HASH`, `maxEntries = 16384`, Key `8B`, Value `24B`)：供 OpenSSL `SSL_read` / `SSL_read_ex`（以 `pid_tgid` 为 Key）与 GoTLS `crypto/tls.(*Conn).Read`（以 `(pid<<32)|uint32(g)` 为 Key）保存读缓冲区指针 `(conn_tag, buf_ptr, len_ptr)`；LRU 自动淘汰异常未闭合条目，彻底消除 Map 泄漏；
   - `active_sys_read` (`BPF_MAP_TYPE_LRU_HASH`, `maxEntries = 16384`, Key `8B`, Value `24B`)：专供 `sys_enter_read` / `sys_enter_recvfrom` 使用，与 `active_ssl_read` 物理隔离，防止 `SSL_read` 内部触发系统调用 `read` 密文时覆盖外层 TLS 明文缓冲区指针。
   - `plain_flow` (`BPF_MAP_TYPE_LRU_HASH`, 失败回退 `HASH`, `maxEntries = 32768`, Key `8B = (tgid<<32)|tagged_fd`，`tagged_fd = 0x80000000|fd`，与事件里的 conn tag 以及 `connect` 重置使用同一把钥匙, Value `4B`)：共享给写路径与读路径，保存 `0=unknown / 1=plain HTTP / 2=TLS skip` 状态；`sys_enter_connect` 删除旧状态以避免 fd 复用。
3. **明文 HTTP 边界**：`plain_flow` 状态机覆盖 `write`、`sendto`、`writev`、`sendmsg`、`read`、`recvfrom`、`recvmsg`。`writev` 与 `sendmsg` 用 `iov[0]` 分类，只有 HTTP（或该 fd 已是 HTTP）才发射 `iov[0]` 和 `iov[1]`，TLS 则两者都丢弃；`sendmsg` 的 iovec 从 `user_msghdr.msg_iov` 读取，而不是误把 syscall 第二参数当作 iovec。`plain_flow` 未命中时，`{`、`[` 或 `data:` 续包只发射、不写回 map，避免两次 `sendto` 拆开的 JSON body 或 SSE 分片因状态丢失进不了重组器。`sendfile`、`io_uring`、明文 HTTP/2 h2c 不支持。
4. **多核 CPU `perf_event_open` 保活机制**：
   - 对每个在线 CPU 核心打开 `perf_event_open` 并执行 `PERF_EVENT_IOC_ENABLE`；当 CPU `1..N` 调用 `PERF_EVENT_IOC_SET_BPF` 返回 `EEXIST`（同一 `tracepoint` `tp_event` 已在 CPU 0 绑定 BPF 程序）时，保持 CPU `1..N` 的 `perf_event` FD 开启且处于 `ENABLED` 状态，确保进程跨核调度时 100% 捕获事件。

### Layer 1 & Layer 2：C 预加载 Hook (`internal/collector/preload_hook.go` & `assets/c/ssl_hook.c`)

- **编译产物与内嵌源码**：从 `internal/collector/assets/c/ssl_hook.c` 提取源码（通过 `writeArtifactNoFollow` 写入 `0644`），使用宿主机 `gcc`/`cc` 编译为 `<cache_dir>/hooks/libllmtracer_ssl.so`（通过 `chmodArtifactNoFollow` 强制权限 `0755`，macOS 为 `libllmtracer_ssl.dylib`）。
- **单次 `writev` + `flock`/互斥锁原子写帧与 `tls.bin` 生命周期契约 (`send_tls_chunk`)**：
  - **写端严禁 `O_CREAT`**：`send_tls_chunk` 写入 `<cache_dir>/hooks/tls.bin` 时，以 `open(pipe_path, O_WRONLY | O_APPEND | O_CLOEXEC)` 打开（**严禁携带 `O_CREAT`**）。`tls.bin` **仅由 Collector 读端 `pipeSource.Start` 调用 `initPipeFileNoFollow` 以 `O_CREATE|O_WRONLY|O_TRUNC|O_NOFOLLOW` 及 `0600` 权限安全创建**；当 Collector 退出执行 `truncateAndRemovePipeNoFollow` 截断清零并删除 `tls.bin` 后，即使仍有脱离生命周期的孤儿/后台子进程存活，其写端 `open` 也会因 `ENOENT` 静默丢弃，绝不会以进程默认 umask（如 `0644`/`0666`）在磁盘上重新创建无人清理的明文残留文件；
  - **原子写帧与并发安全**：写端先获取进程内互斥锁 `pthread_mutex_t` (`pipe_write_mu`) 并对文件描述符加跨进程排他锁 `flock(pfd, LOCK_EX)`，再通过单次 `writev(pfd, iov, 2)` 将 24 字节 `LLMT` 帧头与明文载荷原子写出，写毕释放文件锁与互斥锁，彻底避免多线程或多进程写交错损坏帧结构。
- **动态 OpenSSL 拦截**：拦截 `SSL_write`、`SSL_write_ex`、`SSL_read`、`SSL_read_ex`，通过 `__thread int in_ssl_hook` 防重入，并通过 `runtime_tls_hook_active()` 检测 `LLM_TRACER_PY_TLS_ACTIVE=1` 自动让出语言运行时 TLS 层。
- **Socket 系统调用函数拦截**：拦截 `send`、`recv`、`sendto`、`recvfrom`、`write`、`read`、`writev`、`close`：
  - 通过 `runtime_plain_http_hook_active()` 独立判断运行时明文 HTTP 钩子是否已激活（优先检查 `LLM_TRACER_NODE_PLAIN_ACTIVE`；若未设置且 `LLM_TRACER_PY_TLS_ACTIVE=1`，则通过 `dlsym` 检测 `napi_module_register` / `uv_loop_init` 区分 Node.js 与 Python 进程，避免 `LLM_TRACER_PY_TLS_ACTIVE` 一刀切关闭 C 层明文 HTTP 兜底）；
  - 仅在 `fstat(fd)` 确认为 `S_ISSOCK` 且首包匹配 HTTP 方法前缀时追踪该 `fd`；
  - 将 `writev` 的分散 `struct iovec[]` 展平为连续字节块；
  - 通过 `tracked_http_gen[fd]` 维护 Keep-Alive 连接上的请求代数隔离（`0x80000000 | (gen << 16) | fd`）。

### Layer 3：Python 运行时钩子 (`internal/collector/runtime_hooks.go` & `assets/python/sitecustomize.py`)

- 自动生成 `<cache_dir>/hooks/pyhook/sitecustomize.py`（目录 `pyhook/` 权限 `0755`，脚本权限 `0644`），链式执行下游 `sitecustomize.py`；写 `tls.bin` 管道时通过 `os.open(pipe_path, os.O_WRONLY | os.O_APPEND)` 打开（**严禁携带 `os.O_CREAT`**），在 `with _pipe_lock` 下通过 `fcntl.flock(fd, fcntl.LOCK_EX)` 跨进程排他锁 + 单次 `os.write(fd, frame)` 保证帧原子性；当 Collector 退出删除 `tls.bin` 时捕获 `ENOENT` 静默丢弃；
- 同时 Hook `ssl.SSLObject.write/read`（覆盖 `asyncio` + `httpx` / `httpcore` / `aiohttp` 的 `MemoryBIO`）、`ssl.SSLSocket.write/send/read`（覆盖 `requests` / `urllib3`）与 `http.client.HTTPConnection`（覆盖本地明文 HTTP Ollama/vLLM/MCP）。

### Layer 4：Node.js 与 Bun 运行时钩子 (`internal/collector/runtime_hooks.go` & `assets/node/node_hook.cjs`)

- 自动生成 `<cache_dir>/hooks/node_hook.cjs`（内置 `globalThis.__LLM_TRACER_NODE_HOOK_LOADED__` 幂等锁）；
- **Node.js 管道写端原子追加与自愈契约 (`emitChunk`)**：写端通过 `fs.openSync(pipePath, fs.constants.O_WRONLY | fs.constants.O_APPEND)` 打开现有管道（**严禁携带 `O_CREAT`**，若 `err.code === "ENOENT"` 则静默返回）。通过 `Buffer.concat([hdr, slice])` 将 24 字节帧头与载荷合并为单连续 Buffer 并执行单次同步 `fs.writeSync(fd, frame)`。据实说明：Node 标准库 `node:fs` 无原生 `flock(2)` 绑定，依赖 POSIX `O_APPEND` 单次 `write` 系统调用的内核原子追加防止帧内头体交错；若遇极端并发截断则依赖读端 `findNextValidLLMTFrame` 扫描下一个合法 `"LLMT"` 魔数边界自动重同步；
- **Node.js HTTPS 拦截**：Hook `tls.TLSSocket.prototype._write`、`_writev` 与 `push`，完成后设置 `process.env.LLM_TRACER_PY_TLS_ACTIVE = "1"`；
- **Node.js 明文 HTTP 全路径拦截（含 `_writev`）**：同时 Hook `net.Socket.prototype._write`、**`net.Socket.prototype._writev`** 与 `net.Socket.prototype.push`。Node.js 的 `http.request` 及 `fetch` (`undici`) 在发送明文 HTTP 请求时，实际常通过 `_writev(chunks, cb)` 批量写出请求头与请求体分片；钩子仅在 `!this.encrypted && !(this.ssl || this._tlsOptions)` 时处理明文 Socket，并在首包匹配 HTTP 方法前缀或已标记 `__llm_plain_http` 时拼接 `chunks` 上报，避免将 `TLSSocket`（继承自 `net.Socket`）的密文或已解密流重复上报；
- **独立明文激活标志 `LLM_TRACER_NODE_PLAIN_ACTIVE` 与去重机制**：
  - `node_hook.cjs` 在成功挂载 `net.Socket.prototype._write` / `_writev` / `push`（以及 Bun `globalThis.fetch`）后，显式设置 `process.env.LLM_TRACER_NODE_PLAIN_ACTIVE = "1"`；
  - **为什么该去重机制必要**：一方面，若子进程同时挂载了 `LD_PRELOAD=libllmtracer_ssl.so`，Node 明文 HTTP 写出在经过 `net.Socket.prototype._write`/`_writev` 后仍会调用底层 libc `write`/`writev`，若 C 层不知晓 JS 明文钩子已就绪，同一请求会被 JS 层和 C 层重复捕获两次；另一方面，若沿用旧版仅靠 `LLM_TRACER_PY_TLS_ACTIVE=1` 一刀切关闭 C 层 Socket 钩子的做法，一旦 Node 明文钩子未覆盖某些原生插件或仅激活了 TLS 钩子，明文流量就会漏抓。通过拆分 `LLM_TRACER_NODE_PLAIN_ACTIVE` 与 C 侧 `runtime_plain_http_hook_active()`，实现了 TLS 与明文通道解耦及 JS/C 跨层零重复、零漏抓；
- 针对 Bun 运行时 (`process.versions.bun`) 额外包装 `globalThis.fetch`，同时覆盖 `https://` 与 `http://` 请求及流式响应，并同样设置 `LLM_TRACER_NODE_PLAIN_ACTIVE = "1"`。

### Layer 5：跨进程树 `ptrace` 追踪器 (`internal/collector/runtime_hooks.go` & `assets/c/ptrace_helper.c`)

- 支持两种模式（由 `EnsureRuntimeHooks` 在 `runtime.GOOS == "linux" && currentArchCapabilities().PtraceUserspaceSupported` 时编译 `<cache_dir>/hooks/llm_tracer_ptrace`，内部 `emit_llmt_frame` 以 `open(pipe_path, O_WRONLY | O_APPEND | O_CLOEXEC)` 打开且**严禁携带 `O_CREAT`**，同样通过 `flock(pfd, LOCK_EX)` + 单次 `writev(pfd, iov, 2)` 保证 `LLMT` 帧原子写入，`ENOENT` 时静默丢弃）：
  1. **拉起子进程模式 (`llm_tracer_ptrace <prog> [args...]`)**：通过 `PTRACE_TRACEME` + `PTRACE_O_TRACEFORK/VFORK/CLONE/EXEC` 穿透包装脚本（如 `bin/codex`），仅对未映射 `libllmtracer_ssl.so` 的静态二进制或 Go 二进制启用 `PTRACE_GET_SYSCALL_INFO` + `process_vm_readv` 零拷贝提取；
  2. **热挂载运行中进程模式 (`llm_tracer_ptrace -p <pid>`)**：通过 `PTRACE_SEIZE` + `PTRACE_INTERRUPT` 挂载运行中进程所有线程，退出时通过 `PTRACE_DETACH` 安全分离。

### Layer 6：动态 ECDSA CA 与 `LoopbackTap` (`internal/collector/loopback_tap.go`)

- 内存态生成 P-256 临时根证书并与系统根证书合并为 `llm_tracer_ca_bundle.pem`；
- 针对 `CONNECT host:443` 按需动态签发域名证书，双向镜像明文流至 `StreamReassembler`，并在客户端半关闭 (`CloseWrite`) 时保持上游读取直至响应完整结束；
- **上游证书强校验与 `--tap-insecure` 开关**：`LoopbackTap` 连接真实上游服务器时**默认强制校验上游 TLS 证书**（`InsecureSkipVerify: false`），防止中间人攻击；仅当调试本地自签名模型服务并显式传入 `--tap-insecure`（调用 `Collector.SetTapInsecure(true)`）时，才对上游连接设置 `InsecureSkipVerify: true`。

### Layer 7：Java / JVM 字节码代理 (`internal/collector/java_agent.go` & `assets/java/`)

- 自动生成兼容 Java 8+ (class version `52.0`) 的 `llm_tracer_java.jar`（编译临时目录 `java_build/` 通过 `ensureSafeSubDir` 设为 `0755`，产物 `llm_tracer_java.jar` 通过 `chmodArtifactNoFollow` 强制权限 `0644`），同时实现 `premain`（启动时通过 `-javaagent` / `JAVA_TOOL_OPTIONS` 加载）与 `agentmain`（运行中通过 `jcmd` / `.java_pid<pid>` 动态加载）；
- `EnsureJavaAgentJar` 在复用磁盘已有 `llm_tracer_java.jar` 前通过 `verifyJavaAgentJar` 校验 ZIP 结构、`META-INF/MANIFEST.MF` 以及 `LlmTracerAgent.class` 和 `LlmTracerAgent$TapProxySelector.class` 与 `assets/java/checksums.sha256` 的 SHA-256 指纹，校验失败时记录 `verify_java_agent_jar` 告警并自动通过 `javac` 或内嵌 `.class` 字节码重建；
- 安装自定义 `X509ExtendedTrustManager`、`HostnameVerifier` 与 `TapProxySelector`，零代码修改接管 JVM 全局 HTTPS/HTTP 流量。

---

## 三、跨平台与硬件架构能力矩阵（以代码为准）

以下能力矩阵严格依据 `internal/collector/ebpf_arch_amd64.go`、`internal/collector/ebpf_arch_arm64.go`、`internal/collector/ebpf_arch_other.go`、`internal/collector/ebpf_engine_linux.go` 与 `internal/collector/elf_probe.go` 整理：

### 1. 六大目标平台采集能力总表 (`Linux` / `macOS` / `Windows` × `amd64` / `arm64`)

| 采集能力 / 特性 | `linux/amd64` | `linux/arm64` | `darwin/amd64` & `darwin/arm64` | `windows/amd64` & `windows/arm64` |
| :--- | :--- | :--- | :--- | :--- |
| **Layer 0：OpenSSL / MemoryBIO eBPF Uprobe** | 完整支持（`PT_REGS` 偏移：`RDI=112, RSI=104, RDX=96, RCX=88, RAX=80`） | 完整支持（`user_pt_regs` 偏移：`X0=0, X1=8, X2=16, X3=24`） | 不支持（无 Linux BPF），自动降级为用户态 Hook + `LoopbackTap` | 不支持（无 Linux BPF），自动降级为用户态 Hook + `LoopbackTap` |
| **Layer 0：Syscall Tracepoints (`write`/`writev`/`sendto`/`read`/`recvfrom`)** | 完整支持 | 完整支持 | 不支持（通过 Layer 2/3/4/6 覆盖） | 不支持（通过 Layer 3/4/6 覆盖） |
| **Layer 0：GoTLS `Write` / `Read` eBPF Uprobe（含 `.gopclntab` 恢复）** | 完整支持（跳过 `55 48 89 e5` 序言；`RAX/RBX/RCX` + `R14(g)` + `0xc3 RET` 扫描） | 支持但有明确架构边界（跳过 A64 栈检查序言；`X0/X1/X2` + `R28(g)=224` + A64 `RET` `0xd65f03c0`/`RETAA`/`RETAB` 扫描；详见下方 `arm64` 边界说明） | 不支持（Go 子程序自动走 `HTTPS_PROXY` + `SSL_CERT_FILE` `LoopbackTap`） | 不支持（Go 子程序自动走 `HTTPS_PROXY` + `SSL_CERT_FILE` `LoopbackTap`） |
| **Layer 1 & 2：C 预加载库 (`libllmtracer_ssl`)** | 支持（`LD_PRELOAD=.../libllmtracer_ssl.so`，需 `gcc`/`cc`） | 支持（`LD_PRELOAD=.../libllmtracer_ssl.so`，需 `gcc`/`cc`） | 支持（`DYLD_INSERT_LIBRARIES=.../libllmtracer_ssl.dylib`，需非 SIP 受限二进制且有 `cc`） | 不支持（无 POSIX `LD_PRELOAD`） |
| **Layer 3：Python `sitecustomize.py` Hook** | 完整支持（Unix Socket `tls.sock` 优先，回退 `tls.bin`） | 完整支持 | 完整支持 | 完整支持（自动使用追加管道 `tls.bin`） |
| **Layer 4：Node.js / Bun `node_hook.cjs` + `SIGUSR1` 热注入** | 完整支持 | 完整支持 | 完整支持 | 完整支持（`--require` / `NODE_OPTIONS` 启动注入） |
| **Layer 5：`llm_tracer_ptrace` (`PTRACE_SEIZE` / Launch)** | 完整支持（`PtraceUserspaceSupported = true`，x86_64 寄存器约定） | **已降级**（`PtraceUserspaceSupported = false`）：`ptrace_helper.c` 仅针对 `x86_64` 构建，`arm64` 自动跳过 ptrace、写入 `DegradationNotices` 并记录 `ptrace_arch_unsupported`，回退至 eBPF Syscall Tracepoint 或 `LoopbackTap` | 不支持 | 不支持 |
| **Layer 6：`LoopbackTap` 动态 ECDSA P-256 MITM 代理** | 完整支持 | 完整支持 | 完整支持 | 完整支持 |
| **Layer 7：Java Agent (`premain` + `agentmain` 动态 Attach + JRE 预编译 `.class`)** | 完整支持（`jcmd` + POSIX `.java_pid<pid>`） | 完整支持（`jcmd` + POSIX `.java_pid<pid>`） | 完整支持（`jcmd` + POSIX `.java_pid<pid>`） | 支持 `-javaagent` 启动注入与 `jcmd` 动态 Attach |
| **进程树扫描 (`proctree_*.go`)** | `/proc/<pid>/stat` + `task/*/children` (`< 2ms`) | `/proc/<pid>/stat` + `task/*/children` (`< 2ms`) | `sysctl("kern.proc.all")` + `lsof` | Win32 `CreateToolhelp32Snapshot` + `QueryFullProcessImageName` |

### 2. `linux/arm64` 上的 eBPF 能力边界与降级说明 (`internal/collector/ebpf_arch_arm64.go`)

在 `linux/arm64` 架构下，`arm64PtRegsOffsets`（类型为 `archPtRegsOffsets`）使用 ARM64 `struct user_pt_regs` 偏移量：
- **通用参数与返回值寄存器**：`CArg0 = 0` (`regs[0] / x0`)、`CArg1 = 8` (`regs[1] / x1`)、`CArg2 = 16` (`regs[2] / x2`)、`CArg3 = 24` (`regs[3] / x3`)、`CRet = 0` (`regs[0] / x0`)、`SP = 248` (`sp`)、`PC = 256` (`pc`)。
- **Go Register ABI (Go 1.17+ arm64) 映射**：`GoArg0 = 0` (`X0`)、`GoArg1 = 8` (`X1`)、`GoArg2 = 16` (`X2`)、`GoRet = 0` (`X0`)、`GoGoroutine = 224` (`regs[28] / R28` 保存当前 Goroutine `g` 指针)。
- **GoTLS 序言跳过与 `RET` 扫描 (`internal/collector/elf_probe.go`)**：
  - `scanARM64GoPrologueOffset` 扫描函数入口前 64 字节，定位 `stp x29, x30, [sp, #-N]!` + `sub x29, sp, #8`（`0xd10023fd`）或 `mov x29, sp`（`0x910003fd`）帧建立指令，跳过 `runtime.morestack_noctxt` 栈分裂检查；
  - `scanARM64ReturnOffsets`（由 `findGoARM64RetOffsets` 调用）按 4 字节对齐扫描函数体内的 A64 `RET` (`0xd65f03c0`) 以及 PAC 签名返回指令 `RETAA` (`0xd65f0bff`) / `RETAB` (`0xd65f0fff`)。
- **代码定义的 3 项架构能力边界 (`arm64ArchCapabilities.DegradedFeatures`)**：
  1. **`gotls_native_uretprobe`**：Go 使用动态伸缩栈，内核原生 `uretprobe` 篡改返回地址栈帧会导致 Go 进程栈展开崩溃，因此 `arm64` 同样禁用原生 `uretprobe`，改用指令级 `RET` 偏移 Uprobe；若某个内联/特殊编译的 Go 二进制未能扫描出全部 `RET` 偏移，引擎记录 `selfmon` 告警 `ebpf_gotls_read_ret_degraded`（仅挂载 `Write` Uprobe，入向响应可配合 `LoopbackTap` 补全）。
  2. **`arm64_pac_bti_uretprobe`**：在开启指针认证（PAC）或分支目标识别（BTI）的 ARM64 内核/二进制上，对 OpenSSL 库函数挂载 `uretprobe` 可能受内核 `uprobe` 实现限制；引擎在启动时主动写入一条 `ebpf_arch_capability_boundary` 监控记录供排障确认。
  3. **`ptrace_userspace_inject`**：`arm64ArchCapabilities.PtraceUserspaceSupported` 为 `false`，用户态 `llm_tracer_ptrace` C 辅助程序（`assets/c/ptrace_helper.c`）仅针对 `__x86_64__` 编写（`internal/collector/runtime_hooks.go` 的 `EnsureRuntimeHooks` 在 `!currentArchCapabilities().PtraceUserspaceSupported` 时直接跳过编译）；规划器与热注入在 `linux/arm64` 上遇到需 ptrace 的目标时会自动跳过 `ptrace_seize` / `ptrace_wrapper`，在 `PIDAttachPlan.DegradationNotices` / `LaunchAttachPlan.DegradationNotices` 中填充降级说明并记录 `selfmon` `ptrace_arch_unsupported` 告警，改由内核 eBPF Syscall Tracepoints 与 `LoopbackTap` 采集。

---

## 四、自动化验证矩阵（单元 / 兼容性 / 内核 eBPF / 多语言实测）

### 1. 六大复杂二进制与运行时兼容性矩阵 (`internal/collector/compat_matrix_test.go`)

| 测试编号 | 模拟的真实世界硬核目标 | 覆盖验证点 |
| :--- | :--- | :--- |
| **Scenario 1** | **Go 原生 `crypto/tls` + `-ldflags="-s -w"` 剥离符号二进制** | 验证 `InspectGoTLSTarget` 通过 `.gopclntab` 恢复剥离后的 `Write`/`Read` 与 `RET` 偏移，以及非 Root 下 `LoopbackTap` 全链路捕获 |
| **Scenario 2** | **全静态 `static-pie` 且 `strip --strip-all` 二进制（模拟 `codex`）** | 验证内核忽略 `LD_PRELOAD` 时，`llm_tracer_ptrace` 通过 `PTRACE_O_TRACEFORK/EXEC` 与 `process_vm_readv` 100% 捕获 |
| **Scenario 3** | **Bun / Claude Code 形态：`writev` 分散-聚集 I/O + 分片 SSE 流** | 验证 `writev(fd, iov[4])` 请求展平与分片 SSE `content_block_delta` 响应重组 |
| **Scenario 4** | **Python `asyncio` + `ssl.MemoryBIO` 异步无 FD 内存 BIO（模拟 `httpx`/Hermes）** | 验证 `SSL_get_fd == -1` 时 `sitecustomize.py` 对 `ssl.SSLObject.write/read` 的拦截及与 C Hook 的去重 |
| **Scenario 5** | **Node.js `tls.TLSSocket` + `gzip` 压缩 JSON 响应** | 验证 `node_hook.cjs` 拦截 Node.js 内部静态 OpenSSL 的 TLS 明文并自动解压 `Content-Encoding: gzip` |
| **Scenario 6** | **HTTP/2 (h2) 多路复用并发流 + HPACK 头部压缩 (`--record-headers`)** | 验证单条连接上交错的 `HEADERS`/`DATA` 帧按 `StreamID` 独立重组，且敏感 `Authorization` 头自动掩码为 `Bearer sk-***...` |

### 2. Root 内核态 eBPF 16 场景全矩阵 (`internal/collector/ebpf_engine_test.go`)

在具备 Root / `CAP_BPF` 权限的 Linux 环境下，`TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot` 真实加载全部内置 eBPF 程序、挂载必需与非必需内核探针并执行多个子场景端到端验证（CI 通过 `tee` 保存日志并执行 `grep -q -- '--- SKIP'` 零跳过门禁断言）：
1. `EBPF_Scenario1_DynamicLibSSL_TLS13_MultiTurn_And_SSE`（动态 `libssl.so.3` TLS 1.3 多轮对话与 SSE 捕获）
2. `EBPF_Scenario2_PythonMemoryBIO_NoSocketFD_SystemOneJEV`（Python `_ssl` 模块 `_ssl_MemoryBIO_write/read` 无 FD 捕获 `systemone` JEV）
3. `EBPF_Scenario3_StaticLocalOpenSSLSymbols_InExecutable`（静态内嵌 OpenSSL 局部符号 `.symtab` Uprobe 捕获）
4. `EBPF_Scenario4_NodeJS_StaticEmbeddedOpenSSL_UnhookedHTTPS`（Node.js 静态内嵌 OpenSSL 零 Hook 内核 Uprobe 捕获）
5. `EBPF_Scenario5_NativeGoBinary_GoTLS_WriteAndReadRetUprobes`（Go 原生 `crypto/tls` 含 `-ldflags="-s -w"` `.gopclntab` 恢复与 `RET` Uprobe 捕获）
6. `EBPF_Scenario6_StrippedBinary_ScatterGatherWritevTracepoint`（stripped 二进制 `sys_enter_writev` 分散-聚集 I/O 内核捕获）
7. `EBPF_Scenario7_FullStaticStrippedBinary_SyscallTracepoint`（全静态 stripped 二进制 Syscall Tracepoint 捕获）
8. `EBPF_Scenario8_UnhookedSystemCurl_HTTPS_GeminiGenerateContent`（系统 `curl` HTTPS Gemini `generateContent` 零侵入捕获）
9. `EBPF_Scenario9_OpenSSL3_ExAPI_SSLWriteEx_And_SSLReadEx_PointerDereference`（OpenSSL 3 `SSL_write_ex` / `SSL_read_ex` `readbytes` 指针解引用捕获）
10. `EBPF_Scenario10_StrippedBinary_SendtoRecvfrom_Tracepoints`（`sys_enter_sendto` + `sys_enter_recvfrom`/`sys_exit_recvfrom` Tracepoint 捕获）
11. `EBPF_Scenario11_ProcessTreeScope_SubtreeInheritance_vs_PIDOnlyMode`（进程树子树自动继承与 `--pid-only` 模式对比验证）
12. `EBPF_Scenario12_GzipChunkedResponse_And_HeaderRedactionPrivacy`（`gzip` + `chunked` 响应解压与默认请求头剥离隐私验证）
13. `EBPF_Scenario13_ScopeFilters_Exe_Cwd_Cmd_And_HostFilter`（`--exe`、`--cwd`、`--cmd`、`--host` 组合范围过滤验证）
14. `EBPF_Scenario14_ConcurrentMultiProcess_ParallelTLSStreams_And_Correlation`（多进程高并发 TLS 流采集与三级会话串联验证）
15. `EBPF_Scenario15_LaunchCommand_SubprocessTree_And_SelfMonitoringAudit`（`LaunchPlannedCommand` 子进程树拉起与 `selfmon` 全链路审计验证）
16. `EBPF_Scenario16_PlainHTTPSplitWrite`（明文 HTTP/1.1 经 `send`/`recv` syscall tracepoint 捕获，两次 `sendto` 拆包后重组）

---

## 五、功能使用：如何确认当前生效的采集层与探针状态

1. **启动时查看终端探针摘要**：
   ```bash
   sudo ./bin/llm-tracer capture
   # 启动日志与状态面板会输出已挂载的探针列表，例如：
   # ebpf:ringbuf=16MiB,progs=11,kprobes=19 | preload:libllmtracer_ssl.so | loopback_tap:127.0.0.1:xxxxx
   ```
2. **通过 CLI 或 API 查询已挂载探针与自监控状态**：
   ```bash
   # 查看缓存目录与 probe 阶段自监控计数
   ./bin/llm-tracer status --cache-dir ./traces

   # 查看运行中实例的活跃探针列表与 PID 挂载计划
   curl -s http://127.0.0.1:8787/api/scope | jq '{probes: .probes, pid_plans: .pid_plans}'

   # 查看 probe 阶段的详细自监控事件（含 arm64 架构边界提示或 eBPF 挂载明细）
   curl -s "http://127.0.0.1:8787/api/selfmon/events?stage=probe&limit=50" | jq .
   ```
3. **调试本地自签名 HTTPS 模型服务时启用 `--tap-insecure`**：
   ```bash
   ./bin/llm-tracer capture --tap-insecure -- python3 my_local_https_agent.py
   ```
