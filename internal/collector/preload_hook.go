package collector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const sslHookCSource = `#define _GNU_SOURCE
#include <fcntl.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

typedef int (*ssl_rw_fn)(void *ssl, void *buf, int num);
typedef int (*ssl_rw_ex_fn)(void *ssl, void *buf, size_t num, size_t *processed);
typedef ssize_t (*send_fn)(int fd, const void *buf, size_t len, int flags);
typedef ssize_t (*recv_fn)(int fd, void *buf, size_t len, int flags);

static __thread int in_ssl_hook = 0;
static uint16_t tracked_http_gen[65536];

static void *resolve_ssl_sym(const char *name) {
    void *fn = dlsym(RTLD_NEXT, name);
    if (fn) return fn;
    static void *ssl_handle = NULL;
    if (!ssl_handle) {
        const char *candidates[] = {
            "libssl.so.3",
            "/lib/x86_64-linux-gnu/libssl.so.3",
            "/usr/lib/x86_64-linux-gnu/libssl.so.3",
            "libssl.so.1.1",
            "libssl.so",
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
    }
    return fn;
}

static void send_tls_chunk(void *ssl, const void *buf, size_t len, uint32_t dir) {
    if (!buf || len == 0) return;
    int saved_errno = errno;
    uint32_t capped = (uint32_t)(len > 262144 ? 262144 : len);
    uint32_t hdr[6];
    hdr[0] = 0x4c4c4d54U; /* "LLMT" */
    hdr[1] = (uint32_t)getpid();
    hdr[2] = (uint32_t)syscall(SYS_gettid);
    hdr[3] = (uint32_t)((uintptr_t)ssl & 0xffffffffU);
    hdr[4] = dir;
    hdr[5] = capped;

    const char *sock_path = getenv("LLM_TRACER_SOCK");
    if (sock_path && sock_path[0]) {
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd >= 0) {
            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                (void)send(fd, hdr, sizeof(hdr), MSG_NOSIGNAL);
                (void)send(fd, buf, capped, MSG_NOSIGNAL);
                close(fd);
                errno = saved_errno;
                return;
            }
            close(fd);
        }
    }
    const char *pipe_path = getenv("LLM_TRACER_PIPE");
    if (pipe_path && pipe_path[0]) {
        int pfd = open(pipe_path, O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0666);
        if (pfd >= 0) {
            (void)write(pfd, hdr, sizeof(hdr));
            (void)write(pfd, buf, capped);
            close(pfd);
        }
    }
    errno = saved_errno;
}

int SSL_write(void *ssl, const void *buf, int num) {
    static ssl_rw_fn real_fn = NULL;
    if (!real_fn) real_fn = (ssl_rw_fn)resolve_ssl_sym("SSL_write");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(ssl, (void *)buf, num);
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
    if (!real_fn) real_fn = (ssl_rw_ex_fn)resolve_ssl_sym("SSL_write_ex");
    if (!real_fn) return 0;
    if (in_ssl_hook) return real_fn(ssl, (void *)buf, num, written);
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
    if (!real_fn) real_fn = (ssl_rw_fn)resolve_ssl_sym("SSL_read");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(ssl, buf, num);
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
    if (!real_fn) real_fn = (ssl_rw_ex_fn)resolve_ssl_sym("SSL_read_ex");
    if (!real_fn) return 0;
    if (in_ssl_hook) return real_fn(ssl, buf, num, readbytes);
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

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    static send_fn real_fn = NULL;
    if (!real_fn) real_fn = (send_fn)dlsym(RTLD_NEXT, "send");
    if (!real_fn) return -1;
    if (in_ssl_hook) return real_fn(fd, buf, len, flags);
    in_ssl_hook = 1;
    ssize_t ret = real_fn(fd, buf, len, flags);
    if (ret > 0 && fd >= 0 && fd < 65536) {
        if (is_http_request_prefix(buf, (size_t)ret)) {
            tracked_http_gen[fd]++;
            if (tracked_http_gen[fd] == 0) tracked_http_gen[fd] = 1;
        }
        if (tracked_http_gen[fd] > 0) {
            uint32_t tag = 0x80000000U | (((uint32_t)(tracked_http_gen[fd] & 0x7fffU)) << 16) | ((uint32_t)fd & 0xffffU);
            send_tls_chunk((void *)(uintptr_t)tag, buf, (size_t)ret, 0);
        }
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
    if (ret > 0 && fd >= 0 && fd < 65536 && tracked_http_gen[fd] > 0) {
        uint32_t tag = 0x80000000U | (((uint32_t)(tracked_http_gen[fd] & 0x7fffU)) << 16) | ((uint32_t)fd & 0xffffU);
        send_tls_chunk((void *)(uintptr_t)tag, buf, (size_t)ret, 1);
    }
    in_ssl_hook = 0;
    return ret;
}
`

// EnsureSSLPreloadHook compiles libllmtracer_ssl.so into hooksDir if gcc is available.
func EnsureSSLPreloadHook(hooksDir string) (string, error) {
	if err := os.MkdirAll(hooksDir, 0o755); err != nil {
		return "", err
	}
	cPath := filepath.Join(hooksDir, "libllmtracer_ssl.c")
	soPath := filepath.Join(hooksDir, "libllmtracer_ssl.so")
	if existingC, err := os.ReadFile(cPath); err == nil && string(existingC) == sslHookCSource {
		if info, err := os.Stat(soPath); err == nil && info.Size() > 0 {
			return soPath, nil
		}
	}
	gccPath, err := exec.LookPath("gcc")
	if err != nil {
		return "", fmt.Errorf("gcc not found: %w", err)
	}
	if err := os.WriteFile(cPath, []byte(sslHookCSource), 0o644); err != nil {
		return "", err
	}
	cmd := exec.Command(gccPath, "-shared", "-fPIC", "-O2", "-o", soPath, cPath, "-ldl")
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("compile ssl hook: %w (%s)", err, string(out))
	}
	return soPath, nil
}
