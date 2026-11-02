#define _GNU_SOURCE
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif

typedef int (*ssl_rw_fn)(void *ssl, void *buf, int num);
typedef int (*ssl_rw_ex_fn)(void *ssl, void *buf, size_t num, size_t *processed);
typedef ssize_t (*send_fn)(int fd, const void *buf, size_t len, int flags);
typedef ssize_t (*recv_fn)(int fd, void *buf, size_t len, int flags);
typedef ssize_t (*sendto_fn)(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
typedef ssize_t (*recvfrom_fn)(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen);
typedef ssize_t (*write_fn)(int fd, const void *buf, size_t len);
typedef ssize_t (*read_fn)(int fd, void *buf, size_t len);
typedef ssize_t (*writev_fn)(int fd, const struct iovec *iov, int iovcnt);
typedef int (*close_fn)(int fd);

static __thread int in_ssl_hook = 0;
static uint16_t tracked_http_gen[65536];
static pthread_mutex_t pipe_write_mu = PTHREAD_MUTEX_INITIALIZER;

static void *resolve_ssl_sym(const char *name, void *self_fn) {
    void *fn = dlsym(RTLD_NEXT, name);
    if (fn && fn != self_fn) return fn;
    static void *ssl_handle = NULL;
    if (!ssl_handle) {
        const char *candidates[] = {
            "libssl.so.3",
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "libssl.so.1.1",
            "libssl.so",
            "/opt/homebrew/opt/openssl@3/lib/libssl.3.dylib",
            "/usr/local/opt/openssl@3/lib/libssl.3.dylib",
            "libssl.3.dylib",
            NULL
        };
        for (int i = 0; candidates[i] != NULL && !ssl_handle; i++) {
            ssl_handle = dlopen(candidates[i], RTLD_LAZY | RTLD_NOLOAD);
            if (!ssl_handle) {
                ssl_handle = dlopen(candidates[i], RTLD_LAZY);
            }
        }
    }
    if (ssl_handle) {
        fn = dlsym(ssl_handle, name);
        if (fn && fn != self_fn) return fn;
    }
    return NULL;
}

static void send_tls_chunk(void *ssl, const void *buf, size_t len, uint32_t dir) {
    if (!buf || len == 0) return;
    int saved_errno = errno;
    int prev_hook = in_ssl_hook;
    in_ssl_hook = 1;
    uint32_t capped = (uint32_t)(len > 262144 ? 262144 : len);
    uint32_t hdr[6];
    hdr[0] = 0x4c4c4d54U; /* "LLMT" */
    hdr[1] = (uint32_t)getpid();
#ifdef __APPLE__
    uint64_t tid64 = 0;
    pthread_threadid_np(NULL, &tid64);
    hdr[2] = (uint32_t)tid64;
#else
    hdr[2] = (uint32_t)syscall(SYS_gettid);
#endif
    hdr[3] = (uint32_t)((uintptr_t)ssl & 0xffffffffU);
    hdr[4] = dir;
    hdr[5] = capped;

    struct iovec iov[2];
    iov[0].iov_base = hdr;
    iov[0].iov_len = sizeof(hdr);
    iov[1].iov_base = (void *)buf;
    iov[1].iov_len = capped;

    const char *sock_path = getenv("LLM_TRACER_SOCK");
    if (sock_path && sock_path[0]) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                struct msghdr msg;
                memset(&msg, 0, sizeof(msg));
                msg.msg_iov = iov;
                msg.msg_iovlen = 2;
                (void)sendmsg(fd, &msg, MSG_NOSIGNAL);
                close(fd);
                in_ssl_hook = prev_hook;
                errno = saved_errno;
                return;
            }
            close(fd);
        }
    }
    const char *pipe_path = getenv("LLM_TRACER_PIPE");
    if (pipe_path && pipe_path[0]) {
        pthread_mutex_lock(&pipe_write_mu);
        int pfd = open(pipe_path, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (pfd >= 0) {
            (void)flock(pfd, LOCK_EX);
            (void)writev(pfd, iov, 2);
            (void)flock(pfd, LOCK_UN);
            close(pfd);
        }
        pthread_mutex_unlock(&pipe_write_mu);
    }
    in_ssl_hook = prev_hook;
    errno = saved_errno;
}

static int runtime_tls_hook_active(void) {
    const char *v = getenv("LLM_TRACER_PY_TLS_ACTIVE");
    return (v && v[0] == '1');
}

static int runtime_plain_http_hook_active(void) {
    const char *node_plain = getenv("LLM_TRACER_NODE_PLAIN_ACTIVE");
    if (node_plain && node_plain[0] != '\0') {
        return (node_plain[0] == '1');
    }
    if (runtime_tls_hook_active()) {
        static int is_node_proc = -1;
        if (is_node_proc < 0) {
            is_node_proc = (dlsym(RTLD_DEFAULT, "napi_module_register") != NULL ||
                            dlsym(RTLD_DEFAULT, "uv_loop_init") != NULL) ? 1 : 0;
        }
        if (is_node_proc) {
            return 0;
        }
        return 1;
    }
    return 0;
}

int SSL_write(void *ssl, const void *buf, int num) {
    static ssl_rw_fn real_fn = NULL;
    if (!real_fn) real_fn = (ssl_rw_fn)resolve_ssl_sym("SSL_write", (void *)SSL_write);
    if (!real_fn) return -1;
    if (in_ssl_hook || runtime_tls_hook_active()) return real_fn(ssl, (void *)buf, num);
    in_ssl_hook = 1;
    int ret = real_fn(ssl, (void *)buf, num);
    if (ret > 0) {
        send_tls_chunk(ssl, buf, (size_t)ret, 0);
    }
    in_ssl_hook = 0;
    return ret;
}

int SSL_write_ex(void *ssl, const void *buf, size_t num, size_t *written) {
    static ssl_rw_ex_fn real_fn = NULL;
    if (!real_fn) real_fn = (ssl_rw_ex_fn)resolve_ssl_sym("SSL_write_ex", (void *)SSL_write_ex);
    if (!real_fn) return 0;
    if (in_ssl_hook || runtime_tls_hook_active()) return real_fn(ssl, (void *)buf, num, written);
    in_ssl_hook = 1;
    int ret = real_fn(ssl, (void *)buf, num, written);
    if (ret == 1 && written && *written > 0) {
        send_tls_chunk(ssl, buf, *written, 0);
    }
    in_ssl_hook = 0;
    return ret;
}

int SSL_read(void *ssl, void *buf, int num) {
    static ssl_rw_fn real_fn = NULL;
    if (!real_fn) real_fn = (ssl_rw_fn)resolve_ssl_sym("SSL_read", (void *)SSL_read);
    if (!real_fn) return -1;
    if (in_ssl_hook || runtime_tls_hook_active()) return real_fn(ssl, buf, num);
    in_ssl_hook = 1;
    int ret = real_fn(ssl, buf, num);
    if (ret > 0) {
        send_tls_chunk(ssl, buf, (size_t)ret, 1);
    }
    in_ssl_hook = 0;
    return ret;
}

int SSL_read_ex(void *ssl, void *buf, size_t num, size_t *readbytes) {
    static ssl_rw_ex_fn real_fn = NULL;
    if (!real_fn) real_fn = (ssl_rw_ex_fn)resolve_ssl_sym("SSL_read_ex", (void *)SSL_read_ex);
    if (!real_fn) return 0;
    if (in_ssl_hook || runtime_tls_hook_active()) return real_fn(ssl, buf, num, readbytes);
    in_ssl_hook = 1;
    int ret = real_fn(ssl, buf, num, readbytes);
    if (ret == 1 && readbytes && *readbytes > 0) {
        send_tls_chunk(ssl, buf, *readbytes, 1);
    }
    in_ssl_hook = 0;
    return ret;
}

static int is_http_request_prefix(const void *buf, size_t len) {
    if (!buf || len < 5) return 0;
    const char *s = (const char *)buf;
    return (memcmp(s, "POST ", 5) == 0 ||
            memcmp(s, "GET ", 4) == 0 ||
            memcmp(s, "PUT ", 4) == 0 ||
            memcmp(s, "PATCH ", 6) == 0 ||
            memcmp(s, "DELETE ", 7) == 0);
}

static void record_http_tx(int fd, const void *buf, size_t len) {
    if (runtime_plain_http_hook_active()) return;
    if (fd <= 2 || fd >= 65536 || !buf || len == 0) return;
    if (is_http_request_prefix(buf, len)) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISSOCK(st.st_mode)) {
            tracked_http_gen[fd]++;
            if (tracked_http_gen[fd] == 0) tracked_http_gen[fd] = 1;
        }
    }
    if (tracked_http_gen[fd] > 0) {
        uint32_t tag = 0x80000000U | (((uint32_t)(tracked_http_gen[fd] & 0x7fffU)) << 16) | ((uint32_t)fd & 0xffffU);
        send_tls_chunk((void *)(uintptr_t)tag, buf, len, 0);
    }
}

static void record_http_rx(int fd, const void *buf, size_t len) {
    if (runtime_plain_http_hook_active()) return;
    if (fd <= 2 || fd >= 65536 || !buf || len == 0) return;
    if (tracked_http_gen[fd] > 0) {
        uint32_t tag = 0x80000000U | (((uint32_t)(tracked_http_gen[fd] & 0x7fffU)) << 16) | ((uint32_t)fd & 0xffffU);
        send_tls_chunk((void *)(uintptr_t)tag, buf, len, 1);
    }
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    static send_fn real_fn = NULL;
    if (!real_fn) real_fn = (send_fn)dlsym(RTLD_NEXT, "send");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len, flags);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len, flags);
    if (ret > 0) {
        record_http_tx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
    static recv_fn real_fn = NULL;
    if (!real_fn) real_fn = (recv_fn)dlsym(RTLD_NEXT, "recv");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len, flags);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len, flags);
    if (ret > 0) {
        record_http_rx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen) {
    static sendto_fn real_fn = NULL;
    if (!real_fn) real_fn = (sendto_fn)dlsym(RTLD_NEXT, "sendto");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len, flags, dest_addr, addrlen);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len, flags, dest_addr, addrlen);
    if (ret > 0) {
        record_http_tx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen) {
    static recvfrom_fn real_fn = NULL;
    if (!real_fn) real_fn = (recvfrom_fn)dlsym(RTLD_NEXT, "recvfrom");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len, flags, src_addr, addrlen);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len, flags, src_addr, addrlen);
    if (ret > 0) {
        record_http_rx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t write(int fd, const void *buf, size_t len) {
    static write_fn real_fn = NULL;
    if (!real_fn) real_fn = (write_fn)dlsym(RTLD_NEXT, "write");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len);
    if (ret > 0) {
        record_http_tx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t read(int fd, void *buf, size_t len) {
    static read_fn real_fn = NULL;
    if (!real_fn) real_fn = (read_fn)dlsym(RTLD_NEXT, "read");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len);
    if (ret > 0) {
        record_http_rx(fd, buf, (size_t)ret);
    }
    in_ssl_hook = 0;
    return ret;
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    static writev_fn real_fn = NULL;
    if (!real_fn) real_fn = (writev_fn)dlsym(RTLD_NEXT, "writev");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, iov, iovcnt);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, iov, iovcnt);
    if (ret > 0 && iov && iovcnt > 0 && fd > 2 && fd < 65536) {
        size_t rem = (size_t)ret;
        for (int i = 0; i < iovcnt && rem > 0; i++) {
            if (!iov[i].iov_base || iov[i].iov_len == 0) continue;
            size_t chunk = iov[i].iov_len < rem ? iov[i].iov_len : rem;
            record_http_tx(fd, iov[i].iov_base, chunk);
            rem -= chunk;
        }
    }
    in_ssl_hook = 0;
    return ret;
}

int close(int fd) {
    static close_fn real_fn = NULL;
    if (!real_fn) real_fn = (close_fn)dlsym(RTLD_NEXT, "close");
    if (!real_fn) return -1;
    if (!in_ssl_hook && fd >= 0 && fd < 65536) {
        tracked_http_gen[fd] = 0;
    }
    return real_fn(fd);
}
