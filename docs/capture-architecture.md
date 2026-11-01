# `llm-tracer` 采集架构与全运行时兼容原理

本文档详细说明 `llm-tracer` 如何针对不同编译链接方式、TLS 协议栈与语言运行时的大模型客户端实现全覆盖采集，以及仓库内 6 大场景自包含测试矩阵（`internal/collector/compat_matrix_test.go`）的构造方式。

---

## 一、为什么单一 eCapture 或传统 `LD_PRELOAD` 会漏抓？

在实际生产与开发环境中，主流大模型 CLI 与 SDK 的底层实现差异极大。单纯依赖 `eCapture`（默认挂载系统 `/lib/.../libssl.so.3` uprobe）或传统 `LD_PRELOAD`（仅拦截 `SSL_write`/`SSL_read` 与 `send`/`recv`）会在以下场景失效：

| 典型客户端 / 运行时 | 二进制链接特征 | TLS / 网络栈实现 | 单一 `eCapture` 默认表现 | 传统 `LD_PRELOAD` (`SSL_*` + `send/recv`) 表现 |
| :--- | :--- | :--- | :--- | :--- |
| `curl`、系统 `/usr/bin/python3` | 动态链接 `libc.so.6` + 动态链接 `libssl.so.3` | 系统 OpenSSL 3 (`SSL_write`/`SSL_read`) | 需 Root 权限可抓 HTTPS；**明文 HTTP 漏抓** | 可抓 HTTPS；若用 `write`/`read` 发 HTTP 则漏抓 |
| **Claude Code (`claude.exe`)** | Bun 单文件 ELF，动态链接 `libc.so.6` | **静态内嵌 BoringSSL（符号已 strip）** + `uSockets/libuv` (`writev`/`write`/`read`) | **完全失效**：无 `libssl.so` 依赖且内部 `SSL_write` 符号已 strip；走 HTTP 网关也不触发 TLS 探针 | `SSL_write` 不触发；若未拦截 `write`/`writev`/`read` 则明文 HTTP 也漏抓 |
| **Hermes / `uv` 独立版 Python (`python3.14`)** | `python-build-standalone`，动态链接 `libc.so.6` | **静态内嵌 OpenSSL（局部符号 `t`）** + `asyncio` `ssl.MemoryBIO` (`BIO_s_mem`) | **默认失效**：不经过系统 `libssl.so`；即便手动指定 `--libssl`，`MemoryBIO` 下 `SSL_get_fd(ssl) == -1` 导致 FD 关联失败 | **HTTPS 失效**：`SSL_write` 为模块内部局部调用（非 PLT 绑定），`LD_PRELOAD` 无法介入 |
| **Node.js (v24+)** | 动态链接 `libc.so.6` / `libstdc++.so.6` | **静态内嵌 OpenSSL 3**（符号在 `bin/node` 内） | **默认失效**：不经过系统 `libssl.so`，需手动传 `--libssl=/path/to/node` | **HTTPS 失效**：内部静态调用 `SSL_write`，不走动态符号表重定位 |
| **OpenAI Codex CLI (`codex`)** | `node` 包装脚本拉起 **`x86_64-unknown-linux-musl/bin/codex` (`static-pie`, `stripped`)** | **Rust `musl` 全静态链接 + `rustls` + 内联 `syscall`** | **完全失效**：`eCapture` 不支持 `rustls`，且二进制完全 `stripped` | **完全失效**：二进制无动态链接器 `PT_INTERP`，内核在 `execve` 时直接忽略 `LD_PRELOAD` |
| **Go 原生程序 (`ollama`、Go Agent)** | 无 `libc` 依赖（或仅 cgo 壳） | **Go 原生 `crypto/tls` + `runtime/internal/syscall` 直接系统调用** | 需 Root 权限且手动指定 `gotls --elfpath`；若二进制 strip 或走明文 HTTP 则失效 | **完全失效**：不经过 `libc.so` 与 `libssl.so` |
| **Java / JVM (`Spring AI`、`LangChain4j`)** | JVM 字节码 + `libnet.so` | **JDK JSSE (`sun.security.ssl.SSLSocketImpl` / `SSLEngineImpl`) 纯 Java 实现** | **完全失效**：TLS 握手与加解密在 JVM 字节码层完成，不调用 `libssl.so` | **完全失效**：HTTPS 明文不经过 C 层 `SSL_write`，底层 Socket 写出已加密密文 |
| **Rust (`reqwest` + `rustls`、`goose`)** | 动态链接 `libc.so.6` 或 `musl` 静态链接 | **Rust 原生 `rustls`（`ring` / `aws-lc-rs`）** | **完全失效**：无 OpenSSL 符号，`eCapture` 不支持 `rustls` | **HTTPS 失效**：不经过 `libssl.so`，Socket 层仅见 TLS 密文 |
| **C/C++ (`libcurl`、`cpp-httplib`、`llama.cpp`)** | 动态链接 `libssl.so`、静态内嵌 OpenSSL/BoringSSL 或 `gcc -s` 剥离符号 | OpenSSL / BoringSSL / mbedTLS | 仅未 strip 的 OpenSSL 可抓；静态 strip 或 BoringSSL 失效 | 静态内嵌 TLS 时 `LD_PRELOAD` `SSL_write` 失效 |

---

## 二、二进制画像与自动路由 (`internal/collector/elf_probe.go`)

当 `llm-tracer` 启动或通过 `-- <cmd>` 拉起子进程时，`InspectBinaryProfile` 会对目标文件执行静态分析并自动选择采集策略：

1. **包装脚本自动穿透 (`unwrapScriptTarget`)**：
   - 检查文件头是否为 `\x7fELF`；若为脚本（如 npm 全局安装的 `bin/codex` Node 包装脚本），自动定位其底层拉起的原生二进制（如 `vendor/x86_64-unknown-linux-musl/bin/codex`）。
2. **动态链接器检测 (`PT_INTERP`)**：
   - 遍历 ELF Program Headers：若不存在 `elf.PT_INTERP` 段（如 `/lib64/ld-linux-x86-64.so.2`），判定为 `LinkMode = "static-pie"`，标记 `RequiresPtrace = true`。
3. **Go 运行时识别 (`debug/buildinfo`)**：
   - 解析 `.go.buildinfo` 段提取 `GoVersion`，并在 `.symtab` 中定位 `crypto/tls.(*Conn).Write`、`crypto/tls.(*Conn).Read`、`crypto/tls.(*Conn).HandshakeContext` 的虚拟地址，通过 `PT_LOAD` 段公式 `file_offset = vaddr - prog.Vaddr + prog.Off` 计算文件偏移，标记 `TLSStack = "gotls"`、`RequiresPtrace = true`。
4. **OpenSSL 动态/静态/MemoryBIO 符号解析 (`ResolveOpenSSLSymbols`)**：
   - 同时扫描 `.dynsym`（动态符号表）和 `.symtab`（完整符号表，含 `STB_LOCAL` 局部符号 `t`），解析以下 6 个核心函数偏移：
     - `SSL_write`、`SSL_write_ex`、`SSL_read`、`SSL_read_ex`
     - `_ssl_MemoryBIO_write`、`_ssl_MemoryBIO_read`（Python `asyncio` 内存 BIO 通道）
   - 若 `DT_NEEDED` 包含 `libssl.so*`，归类为 `dynamic-libssl`；若无 `libssl.so*` 依赖但自身符号表包含上述符号（如 `uv python3.14`、`node`），归类为 `static-openssl`；若均不包含（如 `claude.exe`），归类为 `stripped-embedded-tls`。

---

## 三、八大采集机制原理详解（内核态 eBPF + 用户态七层自适应）

所有采集通道在提取到明文 HTTP/1.1 或 HTTP/2 载荷后，统一封装为 **24 字节定长 `LLMT` 二进制帧** 写入本地 Unix Domain Socket (`LLM_TRACER_SOCK`) 或追加管道文件 (`LLM_TRACER_PIPE`)，再交由 `StreamReassembler` 进行流重组：

```text
+-------------------+-------------------+-------------------+-------------------+-------------------+-------------------+
| Magic (4B, LE)    | PID (4B, LE)      | TID (4B, LE)      | ConnTag (4B, LE)  | Dir (4B: 0=W,1=R) | Len (4B, LE)      |
| 0x4C4C4D54 ("LLMT")| 进程号             | 线程号             | 连接/请求代数标识   | 0=Request,1=Resp  | Payload 字节长度    |
+-------------------+-------------------+-------------------+-------------------+-------------------+-------------------+
|                                           Payload (Len Bytes, Raw HTTP/1.1 or H2)                                     |
+-----------------------------------------------------------------------------------------------------------------------+
```

### 机制 0：纯 Go 内核态 eBPF 数据面 — Uprobe + Syscall Tracepoint + RingBuf (`internal/collector/ebpf_engine_linux.go`)

- **适用场景**：具备 `root` 或 `CAP_BPF` + `CAP_PERFMON` 权限时，对 **任意正在运行中的进程 (`--pid <pid>`、`--exe`、全局范围)** 进行零侵入内核态抓取，无需注入环境变量、无需重启目标进程、零 `ptrace` 停顿开销。
- **实现原理**：
  1. **零外部依赖字节码生成**：不依赖外部 `clang` / `llvm` 或内核头文件，直接在 `ebpf_engine_linux.go` 中构造通过 Linux eBPF Verifier 校验的原语指令序列（`BPFInsn`），通过 `unix.Syscall(unix.SYS_BPF, ...)` 完成 Map 创建与程序加载。
  2. **三内核 Map 隔离架构（防嵌套覆盖）**：
     - `BPF_MAP_TYPE_RINGBUF`（1 MiB 环形缓冲区）：各探针通过 `bpf_ringbuf_reserve`（Helper `#131`）分配 4096 字节槽位（24B `LLMT` 头 + 4072B 载荷），调用 `bpf_probe_read_user`（Helper `#112`）读取用户态明文后由 `bpf_ringbuf_submit`（Helper `#132`）提交；
     - `active_ssl_read`（`BPF_MAP_TYPE_HASH`，24B Value `{conn_tag, buf_ptr, len_ptr}`）：专供 `uprobe/SSL_read`、`uprobe/SSL_read_ex` 与 `uretprobe/SSL_read` 使用；支持自动解引用 OpenSSL 3 `SSL_read_ex` 的第 4 参数 `size_t *readbytes`（`RCX`）；
     - `active_sys_read`（`BPF_MAP_TYPE_HASH`，24B Value）：专供 `tracepoint/syscalls/sys_enter_read`、`sys_enter_recvfrom` 与 `sys_exit_read`、`sys_exit_recvfrom` 使用。将 TLS 读表与系统调用读表物理隔离，彻底防止 `SSL_read` 内部调用底层 Socket `read()` 系统调用时在同一 `pid_tgid` 上覆盖或提前删除外层 `SSL_read` 的明文缓冲区指针。
  3. **三类内核探针挂载 (`perf_event_open` + `PERF_EVENT_IOC_SET_BPF`)**：
     - **OpenSSL / 静态 OpenSSL Uprobe & Uretprobe**：自动挂载至系统 `libssl.so.3` 以及 `node`、`uv python3.14` 内部的静态 `SSL_write` / `SSL_write_ex` / `SSL_read` / `SSL_read_ex` 偏移（读取 `pt_regs->di/si/dx/cx/ax`），输出模式标记为 `ebpf_uprobe`；
     - **GoTLS 寄存器 ABI Uprobe**：自动挂载至 Go 二进制的 `crypto/tls.(*Conn).Write` 偏移（按 Go 1.17+ 寄存器 ABI 读取 `RAX=conn`、`RBX=slice.ptr`、`RCX=slice.len`）；
     - **内核 Syscall Tracepoints**：挂载 `syscalls/sys_enter_write`、`sys_enter_sendto`、`sys_enter_read`、`sys_enter_recvfrom`、`sys_exit_read`、`sys_exit_recvfrom`，在内核态直接捕获 `claude.exe`、`codex` 等进程的明文 Socket I/O，输出模式标记为 `ebpf_tracepoint`。
  4. **双映射零拷贝 RingBuf 消费 (`Flush` / `consumeRingBufLoop`)**：
     - 通过 `unix.Mmap` 映射可写 `consumer_pos` 页与只读 `producer_pos + 2*ringBytes` 双倍镜像数据区，使用原子操作无锁消费内核事件并自动按 `userHookPIDs` 去重。

### 机制 1：动态 `libssl.so` PLT 函数拦截 (`internal/collector/preload_hook.go`)

- **适用场景**：动态链接系统 `libssl.so.3` / `libssl.so.1.1` 的程序（如 `curl`、系统 `/usr/bin/python3`、常规 C/C++ 客户端）。
- **实现原理**：
  1. `EnsureSSLPreloadHook` 在启动时调用 `gcc -shared -fPIC -O2` 将内嵌 C 源码编译为 `libllm_tracer_ssl.so`，并通过 `LD_PRELOAD` 注入子进程。
  2. 导出同名符号 `SSL_write`、`SSL_write_ex`、`SSL_read`、`SSL_read_ex`，优先通过 `dlsym(RTLD_NEXT, ...)` 获取真实函数地址；若目标程序延迟 `dlopen` 加载 `libssl.so`，则回退 `dlopen("libssl.so.3", RTLD_LAZY | RTLD_NOLOAD)` 解析。
  3. 使用线程局部存储 `__thread int in_ssl_hook` 防止 `SSL_write_ex` 内部调用 `SSL_write` 时发生递归重复上报。
  4. 以 `(uint32_t)(uintptr_t)ssl`（`SSL*` 结构体指针低 32 位）作为 `ConnTag`，天然隔离同一进程内并发的多条 TLS 连接。

### 机制 2：Socket 全族系统调用函数级拦截 (`internal/collector/preload_hook.go`)

- **适用场景**：
  - 使用 `uSockets` / `libuv` 直接调用 `write`/`writev`/`read` 而非 `send`/`recv` 的运行时（如 **Claude Code `claude.exe` Bun 运行时**）；
  - 连接本机或内网明文 HTTP 大模型网关（如 `ANTHROPIC_BASE_URL=http://...`、`Ollama :11434`、`vLLM :8000`）的所有动态链接程序。
- **实现原理**：
  1. 同时拦截 `send`、`sendto`、`sendmsg`、`write`、`writev`（出向）与 `recv`、`recvfrom`、`recvmsg`、`read`、`readv`（入向）以及 `close`。
  2. **非网络 FD 零开销过滤**：由于进程对标准输出、日志文件和管道也会频繁调用 `write`/`read`，Hook 仅在出向缓冲区匹配 HTTP 请求行前缀（`POST `、`GET `、`PUT `、`PATCH `、`DELETE `）且 `fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode)` 确认为真实 Socket 时，才会激活该 `fd` 的追踪状态。
  3. **分散/聚集 I/O (`writev`/`readv`) 展平**：像 Bun (`claude.exe`) 发送请求时会将 HTTP Header 放在 `iov[0]`、JSON Body 放在 `iov[1]` 通过单次 `writev` 发送。Hook 会按实际写入字节数 `ret` 将 `struct iovec[]` 线性拼接后上报，确保 `StreamReassembler` 能一次性解析完整 HTTP 报文。
  4. **Keep-Alive 请求代数隔离 (`tracked_http_gen[fd]`)**：在 HTTP/1.1 连接复用下，同一个 Socket `fd` 会连续发送多轮请求。每次检测到新的 HTTP 请求行前缀时，递增 `tracked_http_gen[fd]` 并构造 `ConnTag = 0x80000000 | (gen << 16) | fd`；在 `close(fd)` 时立即清零 `tracked_http_gen[fd]`，彻底避免 FD 复用导致的响应串流。

### 机制 3：Python 运行时 `ssl.SSLObject (MemoryBIO)` 与 `ssl.SSLSocket` 钩子 (`internal/collector/runtime_hooks.go`)

- **适用场景**：
  - **Hermes / `uv` 独立版 Python (`python-build-standalone`)**：将 `_ssl` 和 OpenSSL 静态编译进 `bin/python3.x` 内部（`SSL_write` 为局部符号 `t`），绕过 `LD_PRELOAD`；
  - **Python 异步 HTTP 框架 (`httpx`、`httpcore`、`aiohttp`)**：在 `asyncio` 下使用 `ssl.MemoryBIO` + `ssl.SSLObject` 进行内存态 TLS 加解密，底层 C `SSL*` 对象不绑定任何操作系统 Socket FD（`SSL_get_fd == -1`）。
- **实现原理**：
  1. `EnsureRuntimeHooks` 自动在 `<cache_dir>/hooks/pyhook/sitecustomize.py` 生成轻量级启动钩子，并通过 `PYTHONPATH` 前置注入。
  2. **无损链式加载**：启动后自动遍历剩余 `sys.path`，若用户环境原本存在 `sitecustomize.py`，则继续 `exec` 加载，不破坏宿主 Python 环境。
  3. **双层 TLS 拦截**：
     - 拦截 `ssl.SSLObject.write` 与 `ssl.SSLObject.read`（精准捕获 `asyncio` + `httpx` / `aiohttp` 的 `MemoryBIO` 明文流）；
     - 拦截 `ssl.SSLSocket.write`、`send`、`read`、`recv`（捕获 `requests`、`urllib3`、`urllib.request` 同步 TLS 明文流）。
  4. **C/Python 去重协同**：钩子激活时设置环境变量 `LLM_TRACER_PY_TLS_ACTIVE=1`；同进程内的 `libllm_tracer_ssl.so` 检测到该标记后自动跳过 C 层 `SSL_write`/`SSL_read` 上报，确保在使用系统动态 Python 时也不会产生重复事件。

### 机制 4：Node.js 与 Bun 运行时 TLS 钩子 (`internal/collector/runtime_hooks.go`)

- **适用场景**：
  - **Node.js (v24+)**：二进制内部静态编译 OpenSSL 3，不走系统 `libssl.so.3`；
  - **Claude Code (`claude.exe`，Bun 单文件可执行程序)**：内部静态编译 BoringSSL 且符号表已完全 strip，直连官方 `https://api.anthropic.com` 时无法通过 C 层 `LD_PRELOAD` 获取明文。
- **实现原理**：
  1. 自动生成 `<cache_dir>/hooks/node_hook.cjs`，同时通过 `NODE_OPTIONS="--require .../node_hook.cjs"`（针对 Node.js）与 `BUN_OPTIONS="--preload .../node_hook.cjs"`（针对 Bun 单文件 ELF `claude.exe`）注入。
  2. **Node.js `tls.TLSSocket` 明文流拦截**：
     - 包装 `tls.TLSSocket.prototype._write`、`_writev`（明文写入 OpenSSL BIO 前）与 `tls.TLSSocket.prototype.push`（从 OpenSSL BIO 解密读出明文后），以 `WeakMap` 维护每个 `TLSSocket` 实例的唯一 `ConnTag`，透明支持 `https.request`、`axios`、`undici`/`fetch` 及 OpenAI/Anthropic Node SDK。
  3. **Bun `globalThis.fetch` HTTPS 拦截**：
     - 在 Bun 运行时中，`globalThis.fetch` 由底层 Zig 直接调用静态 BoringSSL，不经过 `tls.TLSSocket`。
     - 当检测到 `process.versions.bun` 且请求 URL 以 `https://` 开头时，包装 `globalThis.fetch`：提取请求方法、路径、Header 与 Body 序列化为 HTTP/1.1 请求帧上报；同时通过 `resp.clone().arrayBuffer()` 异步读取解密后的响应体（不影响上层业务流式消费 SSE）并组装为 HTTP/1.1 响应帧上报。
     - 若 URL 为 `http://` 明文请求，则直接放行交由机制 2（`libllm_tracer_ssl.so` 的 `writev`/`read`）捕获，保证零重复。

### 机制 5：跨进程树 `ptrace` 系统调用追踪器 (`llm_tracer_ptrace`)

- **适用场景**：
  - **全静态编译二进制 (`static-pie` / `gcc -static`)**：如 **OpenAI Codex CLI (`x86_64-unknown-linux-musl/bin/codex`)**，无动态链接器 `PT_INTERP`，内核直接忽略 `LD_PRELOAD`，且不经过 `glibc` 直接执行 `syscall` 汇编指令；
  - **Go 原生二进制 (`gotls`)**：Go 标准库通过 `runtime/internal/syscall` 直接发起系统调用，不经过 `libc.so`。
- **实现原理**：
  1. `EnsureRuntimeHooks` 将内嵌 C 源码编译为独立辅助程序 `<cache_dir>/hooks/llm_tracer_ptrace`。当 `InspectBinaryProfile` 判定目标 `RequiresPtrace == true` 时，`LaunchCommand` 自动通过 `llm_tracer_ptrace` 启动目标程序。
  2. **全进程树自动跟随**：启用 `PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL`。即使入口是 Node/Shell 包装脚本（如 `bin/codex`），也能自动跟随其 `fork`/`clone`/`execve` 出的静态子进程。
  3. **智能按进程去重 (`check_needs_capture`)**：在 `PTRACE_EVENT_EXEC` 时检查 `/proc/<tid>/maps` 与 `/proc/<tid>/exe`：
     - 若某个进程已映射 `libllm_tracer_ssl.so` 且不是 Go 二进制（例如外层 Node 包装器进程），则 `needs_capture = 0`，直接跳过其系统调用解析；
     - 若进程未映射 `libllm_tracer_ssl.so`（全静态二进制）或包含 `.go.buildinfo`（Go 二进制），则激活系统调用采集。
  4. **零拷贝内存提取 (`PTRACE_GET_SYSCALL_INFO` + `process_vm_readv`)**：
     - 利用 Linux 5.3+ 的架构无关接口 `PTRACE_GET_SYSCALL_INFO` 获取 `PTRACE_SYSCALL_INFO_ENTRY`（记录 `nr`、`fd`、缓冲区地址 `arg1`、`arg2`）与 `PTRACE_SYSCALL_INFO_EXIT`（获取实际读写字节数 `rval`）；
     - 针对 Socket FD（`/proc/<tid>/fd/<fd>` `S_ISSOCK`）上的 `SYS_write`、`SYS_sendto`、`SYS_writev`、`SYS_read`、`SYS_recvfrom`、`SYS_readv`，调用 `process_vm_readv` 直接从被追踪进程地址空间批量读取缓冲区并写入 `LLMT` 帧。
  5. **受限容器无感降级**：若在禁止 `ptrace` 的容器/沙盒内运行（`ptrace(PTRACE_TRACEME)` 返回 `-1 EPERM`），子进程不会发送 `SIGSTOP`，而是直接 `execvp` 正常执行，同时自动切换至机制 6（`LoopbackTap`）。

### 机制 6：内置动态 CA 与本地透明代理 (`internal/collector/loopback_tap.go`)

- **适用场景**：
  - `codex` / `goose`（Rust `rustls`）、Go 二进制（`crypto/tls`）、C/C++ 剥离符号静态 TLS 二进制在无 Root 权限下发起 **HTTPS** 请求；
  - 在禁用 `ptrace` 的容器环境运行全静态或 Go 二进制。
- **实现原理**：
  1. `NewLoopbackTap` 在内存中动态生成 ECDSA P-256 临时根证书（有效期 7 天），与系统 `/etc/ssl/certs/ca-certificates.crt` 合并写入 `<cache_dir>/hooks/llm_tracer_ca_bundle.pem`，并在 `127.0.0.1:0` 启动本地监听。
  2. 当拉起 `RequiresPtrace` 目标（静态二进制或 Go 二进制）或 `stripped-embedded-tls` 原生二进制（如 Rust `rustls`、C/C++ 静态 strip 二进制）且用户未自定义代理时，自动注入 `HTTPS_PROXY`、`SSL_CERT_FILE`、`CARGO_HTTP_CAINFO`、`CURL_CA_BUNDLE`、`REQUESTS_CA_BUNDLE`。
  3. 收到 `CONNECT host:443` 请求时，根据目标域名动态签发内存态 ECDSA 叶子证书完成本地 TLS 握手，在转发至真实上游的同时将解密后的明文双向镜像至 `StreamReassembler`（含客户端 `SHUT_WR` 半关闭等待上游响应读完保护）。

### 机制 7：Java / JVM 零代码注入 `-javaagent` 字节码代理 (`internal/collector/java_agent.go`)

- **适用场景**：
  - **Java / Kotlin / Scala 应用与 Agent 框架**：`Spring AI`、`LangChain4j`、AWS Bedrock Java SDK、OpenAI Java SDK（底层使用 `java.net.http.HttpClient`、`HttpsURLConnection`、`OkHttp`、`Apache HttpClient`、`Reactor Netty`）。
- **实现原理**：
  1. JVM 的 TLS 协议栈（JSSE `sun.security.ssl`）完全由 Java 字节码实现，既不调用 `libssl.so` 也不受系统环境变量 `SSL_CERT_FILE` 影响（默认只认 `$JAVA_HOME/lib/security/cacerts`）。
  2. `EnsureJavaAgentJar` 在启动时自动生成 `<cache_dir>/hooks/llm_tracer_java.jar`（若环境有 `javac` 则通过 `javac --release 8` 现场编译，若仅有 JRE 则直接使用内嵌的 Java 8 `.class` 字节码打包），并通过 `JAVA_TOOL_OPTIONS="-javaagent:.../llm_tracer_java.jar"` 零侵入注入所有子 JVM 进程。
  3. `LlmTracerAgent.premain` 在目标 `main()` 执行前完成三项初始化：
     - 注册全局 `X509ExtendedTrustManager` 至 `SSLContext.setDefault(...)` 与 `HttpsURLConnection.setDefaultSSLSocketFactory(...)`，使 JVM 无需修改系统 `cacerts` 即可信任 `LoopbackTap` 的动态证书；
     - 设置 `https.proxyHost` / `https.proxyPort`、`http.proxyHost` / `http.proxyPort` 及 `jdk.http.auth.tunneling.disabledSchemes=""`；
     - 安装自定义 `ProxySelector.setDefault(...)`（`TapProxySelector`），将 `http://` 与 `https://` 流量透明路由至本地 `LoopbackTap`（同时自动绕过回环地址本身防止递归死循环）。

---

## 四、仓库内 6 大场景自包含测试矩阵 (`internal/collector/compat_matrix_test.go`)

仓库在 `internal/collector/compat_matrix_test.go` 的 `TestCompatibilityMatrixAllRuntimeScenarios` 中直接通过 `gcc`、`go build`、`python3`、`node` 现场编译并构造了全部 6 类场景的真实可执行程序，无需依赖任何外部私有目录即可验证：

1. **`Scenario1_DynamicLibcAndDynamicLibSSL_PreloadSSLWrite`**
   - 现场编译 `libssl.so.3` 共享库与动态链接它的 C 客户端 `scen1_dyn_ssl`，验证 `InspectBinaryProfile` 识别为 `dynamic-libssl`，并通过 `LD_PRELOAD` `SSL_write`/`SSL_read` 完整捕获 `systemone` JEV 决策会话。
2. **`Scenario2_StrippedEmbeddedTLS_BunLikeWritevReadSocket`**
   - 使用 `gcc -O2 -s` 编译完全剥离符号表的二进制 `scen2_bun_like`（模拟 `claude.exe` Bun 运行时），使用 `writev(sv[0], iov, 2)` 将 HTTP Header 与 JSON Body 分散在两个 `iovec` 中发送，验证 `InspectBinaryProfile` 识别为 `stripped-embedded-tls` 且 `writev`/`read` Hook 成功重组会话。
3. **`Scenario3_StaticLocalOpenSSLSymbols_And_PythonMemoryBIOHook`**
   - 现场编译内含 `static int SSL_write` / `_ssl_MemoryBIO_write` 局部符号（`.symtab` `t` 符号）的 ELF，验证 `ResolveOpenSSLSymbols` 准确解析局部符号偏移；同时拉起 `python3` 通过 `ssl.MemoryBIO` (`ssl.SSLObject.write/read`) 完成 TLS 1.3 握手与收发，验证 `sitecustomize.py` 捕获明文且与 C 层去重。
4. **`Scenario4_NodeStaticOpenSSL_TLSSocket_And_BunFetchHTTPSHook`**
   - 拉起 `node` 子进程，通过 `tls.TLSSocket` 传输 Anthropic `/v1/messages` 报文，验证 `NODE_OPTIONS=--require node_hook.cjs` 在静态 OpenSSL 下成功捕获明文。
5. **`Scenario5_WrapperScript_And_StaticPIE_PtraceSyscallAndLoopbackTap`**
   - 构造 `bin/codex` 包装脚本与 `gcc -static -s -O2` 编译的全静态无符号 ELF `vendor/x86_64-unknown-linux-musl/bin/codex`（无 `PT_INTERP`，`LD_PRELOAD` 完全失效），验证包装脚本穿透识别、`llm_tracer_ptrace` 系统调用级捕获，以及 `LoopbackTap` 动态证书签发与内存态 TLS MITM 握手。
6. **`Scenario6_NativeGoBinary_GoTLSSymbols_And_DirectSyscallCapture`**
   - 现场调用 `go build` 编译包含 `crypto/tls` 与 `syscall.Socketpair` / `syscall.Write` / `syscall.Read` 的独立 Go 二进制 `scen6_go_client`，验证 `InspectGoTLSTarget` 解析出 `crypto/tls.(*Conn).Write` / `Read` 偏移，并通过 `llm_tracer_ptrace` 捕获其绕过 `libc` 的原生系统调用流量。

运行验证命令：

```bash
# 非特权模式运行 6 大运行时兼容矩阵 + eBPF 字节码与 RingBuf 单元测试
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run TestCompatibilityMatrixAllRuntimeScenarios

# Root 权限下运行真实 Linux 内核 eBPF Verifier (11 个程序) + 15 大零注入内核 eBPF 实测场景
sudo /path/to/go test -v -count=1 ./internal/collector -run 'TestEBPF|TestRealKernelEBPF'
```

---

## 五、Root 内核态 eBPF 15 大场景实测矩阵 (`internal/collector/ebpf_engine_test.go`)

在 Root (`CAP_BPF` + `CAP_PERFMON`) 环境下，`TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot` 在不注入任何用户态环境变量（无 `LD_PRELOAD`、无 `PYTHONPATH`、无 `NODE_OPTIONS`、无 `ptrace`）的条件下，端到端验证 11 个 eBPF 程序通过 Linux 内核 Verifier 并挂载 19 个内核探针（12 个 Uprobe/Uretprobe + 7 个 Syscall Tracepoint），覆盖以下 15 个真实场景：

1. **`EBPF_Scenario1_DynamicLibSSL_TLS13_MultiTurn_And_SSE`**：动态 `libssl.so.3` Uprobe/Uretprobe 抓取 TLS 1.3 多轮对话与 SSE 流式响应。
2. **`EBPF_Scenario2_PythonMemoryBIO_NoSocketFD_SystemOneJEV`**：抓取无底层 Socket FD (`SSL_get_fd == -1`) 的 Python `ssl.MemoryBIO` 内存态 TLS 流与 `systemone` TypeSafe JEV 协议（以 `SSL*` 指针作为连接键）。
3. **`EBPF_Scenario3_StaticLocalOpenSSLSymbols_InExecutable`**：动态解析可执行文件 `.symtab` 中的 `static` 局部符号 `SSL_write` / `SSL_read` (`STB_LOCAL`) 并挂载内核 Uprobe/Uretprobe。
4. **`EBPF_Scenario4_NodeJS_StaticEmbeddedOpenSSL_UnhookedHTTPS`**：零 `NODE_OPTIONS` 抓取静态内嵌 OpenSSL 3 的 Node.js v24 原生 HTTPS 客户端请求。
5. **`EBPF_Scenario5_NativeGoBinary_GoTLS_WriteAndReadRetUprobes`**：自动定位 Go `crypto/tls.(*Conn).Write` 与 `(*Conn).Read` 栈扩容检查（`morestack`）后的入口偏移及函数内所有 `RET` (`0xc3`) 指令偏移，以 `(pid<<32)|uint32(R14)`（Goroutine `g` 指针）关联寄存器 ABI 参数（`RAX`/`RBX`/`RCX`），避免传统 `uretprobe` 破坏 Go 动态栈导致崩溃。
6. **`EBPF_Scenario6_StrippedBinary_ScatterGatherWritevTracepoint`**：通过 `tp/syscalls/sys_enter_writev` 在内核态展开 `struct iovec iov[0..1]`，抓取剥离符号表二进制（如 Bun/`claude.exe`）的分散-聚集 `writev` 请求。
7. **`EBPF_Scenario7_FullStaticStrippedBinary_SyscallTracepoint`**：零 `ptrace` 抓取 `gcc -static -O2 -s` 全静态无符号 ELF（如 `codex` `static-pie`）的底层系统调用流量。
8. **`EBPF_Scenario8_UnhookedSystemCurl_HTTPS_GeminiGenerateContent`**：直接抓取系统原生 `/usr/bin/curl -k --http1.1` 的 HTTPS Google Gemini `generateContent` 通信。
9. **`EBPF_Scenario9_OpenSSL3_ExAPI_SSLWriteEx_And_SSLReadEx_PointerDereference`**：抓取显式调用 OpenSSL 3.x `SSL_write_ex` 与 `SSL_read_ex` 的 C 程序，验证 eBPF 在 `SSL_read_ex` 返回时对 `RCX` (`size_t *readbytes`) 用户态指针的二次解引用。
10. **`EBPF_Scenario10_StrippedBinary_SendtoRecvfrom_Tracepoints`**：通过 `sys_enter_sendto` / `sys_enter_recvfrom` / `sys_exit_recvfrom` 抓取使用 `sendto`/`recvfrom` 的剥离符号二进制。
11. **`EBPF_Scenario11_ProcessTreeScope_SubtreeInheritance_vs_PIDOnlyMode`**：验证默认后代子进程树自动继承抓取（`PIDOnly=false`）与 `--pid-only` 单 PID 严格隔离模式（`PIDOnly=true`）。
12. **`EBPF_Scenario12_GzipChunkedResponse_And_HeaderRedactionPrivacy`**：验证内核 Uprobe 下的 HTTP/1.1 `Transfer-Encoding: chunked` + `Content-Encoding: gzip` 自动解压，以及默认不记录请求头防凭据泄露（`RecordHeaders=false`）与 `--record-headers` 显式开启。
13. **`EBPF_Scenario13_ScopeFilters_Exe_Cwd_Cmd_And_HostFilter`**：验证 `--exe`、`--cwd`、`--cmd`、`--host` 四维范围过滤在内核 eBPF 采集链路下的命中与拦截。
14. **`EBPF_Scenario14_ConcurrentMultiProcess_ParallelTLSStreams_And_Correlation`**：验证多进程高并发 TLS 流并行抓取零串流与会话独立关联。
15. **`EBPF_Scenario15_LaunchCommand_SubprocessTree_And_SelfMonitoringAudit`**：验证 `LaunchCommand` (`-- <cmd>`) 包装脚本子进程树端到端抓取与 `selfmon` 自监控指标审计。

---

## 六、跨平台采集架构（Linux / macOS / Windows）与 GitHub Actions CI

`llm-tracer` 的流重组器（`internal/parser`）、多协议解析器（`systemone` / OpenAI / Anthropic / Gemini / Ollama）、三级会话串联器（`internal/correlator`）、10 分钟热窗文件存储（`internal/store`）、自监控（`internal/selfmon`）与 Web/TOTP 控制台（`internal/web`）均为 100% 纯 Go 跨平台实现；采集层（`internal/collector`）按操作系统提供原生适配：

| 能力维度 | Linux (`linux`) | macOS (`darwin`) | Windows (`windows`) |
|---|---|---|---|
| **内核态零注入采集** | `ebpf_engine_linux.go`（11 个原生 eBPF 程序、19 个 Uprobe/Uretprobe/Syscall Tracepoint，`8 MiB` `BPF_MAP_TYPE_RINGBUF`） | `ebpf_engine_other.go`（自动降级至用户态 Hook 与 `LoopbackTap`） | `ebpf_engine_other.go`（自动降级至用户态 Hook 与 `LoopbackTap`） |
| **进程树与范围过滤** | `proctree_linux.go`（`/proc/<pid>/stat`、`task/*/children`、`cmdline`、`exe`、`cwd`） | `proctree_darwin.go`（`sysctl kern.proc.all` / `kern.proc.pid` + `ps` / `lsof`） | `proctree_windows.go`（Win32 `CreateToolhelp32Snapshot`、`Process32First/Next`、`QueryFullProcessImageName`） |
| **多格式二进制符号解析** | `debug/elf`（`.dynsym` + `.symtab` + Go PCLNTAB 栈扩容跳过与 `RET` 扫描） | `debug/macho`（Mach-O 符号表与 `crypto/tls` 符号识别） | `debug/pe`（PE `.exe`/`.dll` 符号表与 `crypto/tls` 符号识别） |
| **Python / Node / Bun 零配置 Hook** | `PYTHONPATH` (`sitecustomize.py`)、`NODE_OPTIONS` / `BUN_OPTIONS` (`node_hook.cjs`)、`LD_PRELOAD` (`.so`) | `PYTHONPATH`、`NODE_OPTIONS` / `BUN_OPTIONS`、`DYLD_INSERT_LIBRARIES` (`.dylib`) | `PYTHONPATH`（`os.O_BINARY` 二进制帧管道）、`NODE_OPTIONS` / `BUN_OPTIONS` |
| **原生编译二进制 (`codex` / Go / `curl`)** | Root eBPF Uprobe/Tracepoint 或 `llm_tracer_ptrace` + `LoopbackTap` | `LoopbackTap` 本地动态 CA + `HTTPS_PROXY` / `SSL_CERT_FILE` 自动注入 | `LoopbackTap` 本地动态 CA + `HTTPS_PROXY` / `SSL_CERT_FILE` 自动注入 |

### GitHub Actions 自动化验证矩阵 (`.github/workflows/ci.yml`)

仓库内置三端 CI 流水线（`ubuntu-latest`、`macos-latest`、`windows-latest`）：

- **`linux-ebpf-and-compat` (`ubuntu-latest`)**：
  1. 非特权模式执行全量单元测试与跨平台场景测试（`go test -v -count=1 ./...`）；
  2. Root 权限下实测挂载 **11 个内核 eBPF 程序（19 个探针）** 并运行 **15 大真实内核 eBPF 场景**（`TestRealKernelEBPFVerifierAndRingBufCaptureWhenRoot`）与 **6 大运行时兼容场景**（`TestCompatibilityMatrixAllRuntimeScenarios`）；
  3. 交叉构建 `linux/amd64` 与 `linux/arm64` 二进制。
- **`macos-scenarios` (`macos-latest`)**：验证 Darwin `sysctl` 进程树过滤、ELF/Mach-O/PE 三格式符号解析、Python `ssl.SSLSocket`、Node.js `tls.TLSSocket` 多轮对话及原生 Mach-O Go HTTPS 客户端通过 `LoopbackTap` 的端到端抓取，并构建 `darwin/arm64` 与 `darwin/amd64` 二进制。
- **`windows-scenarios` (`windows-latest`)**：验证 Windows `Toolhelp32` 进程树过滤、ELF/Mach-O/PE 三格式符号解析、Python/Node.js TLS Hook（含 `O_BINARY` 管道帧）及原生 PE `.exe` Go HTTPS 客户端端到端抓取，并构建 `windows/amd64` 二进制。

---

## 七、多语言 (`Java` / `C/C++` / `Rust`)、主流 Agent 框架与常用 Agent CLI 全面支持矩阵 (`internal/collector/polyglot_agents_test.go`)

### 1. 多语言运行时覆盖矩阵

| 语言 / 运行时 | 典型 HTTP / TLS 栈 | Linux Root 采集通道 | Linux 非特权 / macOS / Windows 采集通道 | 自动化验证用例 |
|---|---|---|---|---|
| **Python** (`CPython` / `uv` / `conda`) | `httpx` (`ssl.MemoryBIO`)、`aiohttp`、`requests`、`urllib3`、`http.client`（含本地明文 HTTP） | eBPF `uprobe/SSL_*` + `sitecustomize.py` | `sitecustomize.py`（`SSLObject` + `SSLSocket` + `HTTPConnection`） | `Scenario3`、`EBPF_Scenario2`、`TestAgentFrameworksAndAgentCLIsScenarios` |
| **Node.js / TypeScript / Bun** | `undici`/`fetch`、`tls.TLSSocket`、`net.Socket`、Bun `globalThis.fetch` (BoringSSL) | eBPF `uprobe` / `sys_enter_writev` + `node_hook.cjs` | `NODE_OPTIONS` / `BUN_OPTIONS` (`node_hook.cjs`) | `Scenario2`、`Scenario4`、`EBPF_Scenario4` |
| **Go** (`crypto/tls` / `net/http`) | Go 原生 `crypto/tls` + 直接 `syscall` | eBPF `uprobe/crypto/tls.(*Conn).Write` & `RET` 探针 | `llm_tracer_ptrace` + `LoopbackTap` (`SSL_CERT_FILE`) | `Scenario6`、`EBPF_Scenario5`、`TestCrossPlatformNativeHTTPSClientViaLoopbackTap` |
| **Java / JVM** (JDK 8 ~ 25+) | JSSE (`HttpClient`、`OkHttp`、`Apache HttpClient`、`HttpsURLConnection`) | `JAVA_TOOL_OPTIONS="-javaagent:llm_tracer_java.jar"` + `LoopbackTap` | `JAVA_TOOL_OPTIONS="-javaagent:llm_tracer_java.jar"` + `LoopbackTap` | `TestPolyglotLanguagesCapture/1_Java_JVM_ZeroCode_Agent_Capture` |
| **C / C++** (`gcc` / `clang`) | 动态 `libssl.so`、静态 OpenSSL、或 stripped 静态 TLS (`libcurl`) | eBPF `uprobe/SSL_*` + `tp/syscalls/sys_enter_*` | `LD_PRELOAD` (`libllm_tracer_ssl.so`) + `LoopbackTap` (`CURL_CA_BUNDLE` / `SSL_CERT_FILE`) | `Scenario1`、`EBPF_Scenario1/3/9`、`TestPolyglotLanguagesCapture/2_Cpp_Native_Stripped_Binary_Capture` |
| **Rust** (`cargo` / `rustc`) | `reqwest` + `rustls`（默认无 OpenSSL 符号）或 `native-tls` | eBPF `tp/syscalls/sys_enter_*` (明文) + `LoopbackTap` (HTTPS) | `LoopbackTap` (`HTTPS_PROXY` + `SSL_CERT_FILE` + `CARGO_HTTP_CAINFO`) | `Scenario5`、`EBPF_Scenario7`、`TestPolyglotLanguagesCapture/3_Rust_Stripped_Binary_Capture` |

### 2. 主流 Agent CLI 与 Agent 框架协议特性支持

| Agent CLI / 框架 | 核心协议 (`protocol`) | 关键特性解析与会话串联支持 |
|---|---|---|
| **Claude Code (`claude`)** | `anthropic` (`/v1/messages`) + `mcp` (JSON-RPC 2.0) | 解析 `system` 数组、`thinking` 块、`tool_use` / `tool_result`、Prompt Cache Token (`cache_read_input_tokens`)；通过 `L3_proctree` 将 Claude 主对话与子进程/远端 **MCP Server (`tools/call`)** 自动串联至同一 Session |
| **OpenAI Codex CLI (`codex`) & OpenAI Agents SDK** | `openai-responses` (`/v1/responses`) | 解析 `instructions`、`reasoning` (`response.reasoning_summary_text.delta`)、`function_call` / `function_call_output`；从 SSE `response.completed` 提取 `resp_...` 并通过 `previous_response_id` 实现 **L1 精确串联** |
| **Google Gemini CLI (`gemini`) & Vertex AI** | `gemini` (`:generateContent` / `:streamGenerateContent?alt=sse`) | 解析 `systemInstruction`、Gemini 2.5 Thinking (`thought: true`)、`functionCall` / `functionResponse`、`usageMetadata`（含 `thoughtsTokenCount`）；自动脱敏 URL `?key=[REDACTED]`；归一化 `role: "model" -> "assistant"` 实现多轮 `L2_context` 串联 |
| **LangChain / LangGraph / LlamaIndex / AutoGen / CrewAI / Aider** | `openai-chat` (`/v1/chat/completions`) + `ollama` (`http://.../api/chat`) | 支持 `role: "developer"`、DeepSeek/QwQ `reasoning_content` / `reasoning`、Azure OpenAI `/openai/deployments/{model}/chat/completions` 模型名提取；支持 **云端 HTTPS + 本地明文 HTTP (`Ollama` / `vLLM`) 混合 Agent 循环** 同进程树自动串联 |
| **Spring AI / LangChain4j / AWS Agents** | `bedrock` (`/model/{id}/converse` & `/converse-stream`) | 解析 AWS Bedrock Converse `system`、`messages`、`reasoningContent`、`toolUse` / `toolResult` 及 `usage` (`inputTokens`/`outputTokens`) |
| **Hermes / TypeSafe JEV** | `systemone` (`/api/jev/decide`、`/api/v1/step`) | 解析 `goal`、`dom_summary`、`recent_actions`、`action/target/value/confidence` 并按 `goal + recent_actions` 步进串联 |

运行多语言与 Agent 场景验证命令：

```bash
mise exec go@1.26.5 -- go test -v -count=1 ./internal/collector -run 'TestPolyglotLanguagesCapture|TestAgentFrameworksAndAgentCLIsScenarios'
```
