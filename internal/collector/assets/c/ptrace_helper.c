#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define LLMT_MAGIC 0x4c4c4d54U
#define MAX_TRACKED_TIDS 1024
#define MAX_TRACKED_FDS  4096

typedef struct {
    pid_t tid;
    uint64_t nr;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    int active;
    int needs_capture; // -1 = unknown, 0 = preload handles it, 1 = static/Go needs ptrace capture
} tid_state_t;

static tid_state_t tid_table[MAX_TRACKED_TIDS];
static uint16_t fd_http_gen[MAX_TRACKED_FDS];
static pid_t attached_root_pid = 0;
static volatile sig_atomic_t g_stop = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop = 1;
}

static tid_state_t *get_tid_state(pid_t tid) {
    int empty_idx = -1;
    for (int i = 0; i < MAX_TRACKED_TIDS; i++) {
        if (tid_table[i].tid == tid) return &tid_table[i];
        if (empty_idx < 0 && tid_table[i].tid == 0) empty_idx = i;
    }
    if (empty_idx >= 0) {
        memset(&tid_table[empty_idx], 0, sizeof(tid_state_t));
        tid_table[empty_idx].tid = tid;
        tid_table[empty_idx].needs_capture = -1;
        return &tid_table[empty_idx];
    }
    return &tid_table[0];
}

static void clear_tid_state(pid_t tid) {
    for (int i = 0; i < MAX_TRACKED_TIDS; i++) {
        if (tid_table[i].tid == tid) {
            memset(&tid_table[i], 0, sizeof(tid_state_t));
            return;
        }
    }
}

// Check if process requires ptrace syscall capture:
// Returns 1 if process does NOT have libllm_tracer_ssl.so mapped (e.g. static-pie codex) OR is a Go binary.
static int check_needs_capture(pid_t tid) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/maps", tid);
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    int has_preload = 0;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "libllm_tracer_ssl.so")) {
            has_preload = 1;
            break;
        }
    }
    fclose(f);
    if (!has_preload) return 1; // static-pie binary (like codex)

    // Also check if exe is a Go binary (.go.buildinfo)
    snprintf(path, sizeof(path), "/proc/%d/exe", tid);
    int fd = open(path, O_RDONLY);
    if (fd >= 0) {
        char buf[65536];
        ssize_t n = read(fd, buf, sizeof(buf));
        close(fd);
        if (n > 16 && memmem(buf, (size_t)n, "\xff Go buildinf:", 14) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int is_remote_socket(pid_t tid, int fd) {
    if (fd <= 2 || fd >= MAX_TRACKED_FDS) return 0;
    char path[128];
    struct stat st;
    snprintf(path, sizeof(path), "/proc/%d/fd/%d", tid, fd);
    if (stat(path, &st) == 0 && S_ISSOCK(st.st_mode)) {
        return 1;
    }
    return 0;
}

static int is_http_req_prefix(const uint8_t *buf, size_t len) {
    if (!buf || len < 4) return 0;
    return (memcmp(buf, "POST ", 5) == 0 ||
            memcmp(buf, "GET ", 4) == 0 ||
            memcmp(buf, "PUT ", 4) == 0 ||
            memcmp(buf, "PATCH ", 6) == 0 ||
            memcmp(buf, "DELETE ", 7) == 0 ||
            memcmp(buf, "HEAD ", 5) == 0 ||
            memcmp(buf, "OPTIONS ", 8) == 0);
}

static void emit_llmt_frame(pid_t tid, int fd, const uint8_t *buf, size_t len, uint32_t dir) {
    if (!buf || len == 0 || fd <= 2 || fd >= MAX_TRACKED_FDS) return;
    if (dir == 0 && is_http_req_prefix(buf, len)) {
        if (is_remote_socket(tid, fd)) {
            fd_http_gen[fd]++;
            if (fd_http_gen[fd] == 0) fd_http_gen[fd] = 1;
        }
    }
    if (fd_http_gen[fd] == 0) return;

    size_t capped = len > 262144 ? 262144 : len;
    uint32_t tag = 0x90000000U | (((uint32_t)(fd_http_gen[fd] & 0xfffU)) << 16) | ((uint32_t)fd & 0xffffU);
    uint32_t hdr[6];
    hdr[0] = LLMT_MAGIC;
    hdr[1] = attached_root_pid > 0 ? (uint32_t)attached_root_pid : (uint32_t)getpid();
    hdr[2] = (uint32_t)tid;
    hdr[3] = tag;
    hdr[4] = dir;
    hdr[5] = (uint32_t)capped;

    const char *pipe_path = getenv("LLM_TRACER_PIPE");
    if (pipe_path && pipe_path[0]) {
        int pfd = open(pipe_path, O_WRONLY | O_APPEND | O_CLOEXEC);
        if (pfd >= 0) {
            struct iovec iov[2];
            iov[0].iov_base = hdr;
            iov[0].iov_len = sizeof(hdr);
            iov[1].iov_base = (void *)buf;
            iov[1].iov_len = capped;
            (void)flock(pfd, LOCK_EX);
            (void)writev(pfd, iov, 2);
            (void)flock(pfd, LOCK_UN);
            close(pfd);
        }
    }
}

static void read_and_emit_buf(pid_t tid, int fd, uint64_t remote_addr, size_t len, uint32_t dir) {
    if (len == 0 || remote_addr == 0) return;
    size_t capped = len > 262144 ? 262144 : len;
    uint8_t *buf = (uint8_t *)malloc(capped);
    if (!buf) return;
    struct iovec local_iov = { .iov_base = buf, .iov_len = capped };
    struct iovec remote_iov = { .iov_base = (void *)(uintptr_t)remote_addr, .iov_len = capped };
    ssize_t n = process_vm_readv(tid, &local_iov, 1, &remote_iov, 1, 0);
    if (n > 0) {
        emit_llmt_frame(tid, fd, buf, (size_t)n, dir);
    }
    free(buf);
}

static void read_and_emit_iov(pid_t tid, int fd, uint64_t iov_addr, size_t iovcnt, size_t total_len, uint32_t dir) {
    if (iovcnt == 0 || iov_addr == 0 || total_len == 0) return;
    if (iovcnt > 64) iovcnt = 64;
    struct iovec remote_iovs[64];
    struct iovec l_iov = { .iov_base = remote_iovs, .iov_len = iovcnt * sizeof(struct iovec) };
    struct iovec r_iov = { .iov_base = (void *)(uintptr_t)iov_addr, .iov_len = iovcnt * sizeof(struct iovec) };
    if (process_vm_readv(tid, &l_iov, 1, &r_iov, 1, 0) <= 0) return;

    size_t capped = total_len > 262144 ? 262144 : total_len;
    uint8_t *flat = (uint8_t *)malloc(capped);
    if (!flat) return;
    size_t copied = 0;
    for (size_t i = 0; i < iovcnt && copied < capped; i++) {
        size_t chunk = remote_iovs[i].iov_len;
        if (chunk == 0 || !remote_iovs[i].iov_base) continue;
        if (copied + chunk > capped) chunk = capped - copied;
        struct iovec dl = { .iov_base = flat + copied, .iov_len = chunk };
        struct iovec dr = { .iov_base = remote_iovs[i].iov_base, .iov_len = chunk };
        ssize_t got = process_vm_readv(tid, &dl, 1, &dr, 1, 0);
        if (got > 0) copied += (size_t)got;
    }
    if (copied > 0) {
        emit_llmt_frame(tid, fd, flat, copied, dir);
    }
    free(flat);
}

int main(int argc, char **argv) {
    if (argc < 2) return 1;
    int status = 0;
    pid_t root_pid = 0;
    if (argc >= 3 && strcmp(argv[1], "-p") == 0) {
        root_pid = (pid_t)atoi(argv[2]);
        if (root_pid <= 0) return 1;
        attached_root_pid = root_pid;
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = on_stop_signal;
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);

        unsigned long seize_opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                                   PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC;
        char task_dir[128];
        snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", root_pid);
        DIR *d = opendir(task_dir);
        int attached_any = 0;
        if (d) {
            struct dirent *de;
            while ((de = readdir(d)) != NULL) {
                pid_t tid = (pid_t)atoi(de->d_name);
                if (tid <= 0) continue;
                if (ptrace(PTRACE_SEIZE, tid, 0, (void *)seize_opts) == 0) {
                    get_tid_state(tid)->needs_capture = 1;
                    ptrace(PTRACE_INTERRUPT, tid, 0, 0);
                    attached_any++;
                }
            }
            closedir(d);
        }
        if (!attached_any) {
            if (ptrace(PTRACE_SEIZE, root_pid, 0, (void *)seize_opts) != 0) return 2;
            get_tid_state(root_pid)->needs_capture = 1;
            ptrace(PTRACE_INTERRUPT, root_pid, 0, 0);
        }
    } else {
        root_pid = fork();
        if (root_pid < 0) return 1;
        if (root_pid == 0) {
            if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == 0) {
                raise(SIGSTOP);
            }
            execvp(argv[1], &argv[1]);
            _exit(127);
        }

        if (waitpid(root_pid, &status, 0) < 0) return 1;
        if (WIFEXITED(status)) return WEXITSTATUS(status);
        if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        unsigned long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK |
                             PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL;
        ptrace(PTRACE_SETOPTIONS, root_pid, 0, (void *)opts);
        ptrace(PTRACE_SYSCALL, root_pid, 0, 0);
    }

    int root_exit_code = 0;
    while (!g_stop) {
        pid_t tid = waitpid(-1, &status, __WALL);
        if (tid < 0) {
            if (errno == EINTR) {
                if (g_stop) break;
                continue;
            }
            break;
        }
        if (WIFEXITED(status)) {
            if (tid == root_pid) root_exit_code = WEXITSTATUS(status);
            clear_tid_state(tid);
            continue;
        }
        if (WIFSIGNALED(status)) {
            if (tid == root_pid) root_exit_code = 128 + WTERMSIG(status);
            clear_tid_state(tid);
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        unsigned int event = (unsigned int)status >> 16;
        if (event != 0) {
            if (event == PTRACE_EVENT_EXEC) {
                tid_state_t *st = get_tid_state(tid);
                st->needs_capture = check_needs_capture(tid);
                st->active = 0;
            } else if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK || event == PTRACE_EVENT_CLONE) {
                unsigned long new_tid = 0;
                if (ptrace(PTRACE_GETEVENTMSG, tid, NULL, &new_tid) == 0 && new_tid > 0) {
                    tid_state_t *parent_st = get_tid_state(tid);
                    tid_state_t *child_st = get_tid_state((pid_t)new_tid);
                    child_st->needs_capture = parent_st->needs_capture;
                }
            }
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            tid_state_t *st = get_tid_state(tid);
            if (st->needs_capture < 0) {
                st->needs_capture = check_needs_capture(tid);
            }
            if (st->needs_capture == 1) {
                struct ptrace_syscall_info info;
                if (ptrace(PTRACE_GET_SYSCALL_INFO, tid, sizeof(info), &info) >= 0) {
                    if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                        st->nr = info.entry.nr;
                        st->arg0 = info.entry.args[0];
                        st->arg1 = info.entry.args[1];
                        st->arg2 = info.entry.args[2];
                        st->active = 1;
                        if (st->nr == SYS_close && st->arg0 > 2 && st->arg0 < MAX_TRACKED_FDS) {
                            fd_http_gen[st->arg0] = 0;
                        }
                    } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && st->active) {
                        st->active = 0;
                        int64_t rval = info.exit.rval;
                        if (!info.exit.is_error && rval > 0) {
                            int fd = (int)st->arg0;
                            switch (st->nr) {
                            case SYS_write:
                            case SYS_sendto:
                                read_and_emit_buf(tid, fd, st->arg1, (size_t)rval, 0);
                                break;
                            case SYS_read:
                            case SYS_recvfrom:
                                read_and_emit_buf(tid, fd, st->arg1, (size_t)rval, 1);
                                break;
                            case SYS_writev:
                                read_and_emit_iov(tid, fd, st->arg1, (size_t)st->arg2, (size_t)rval, 0);
                                break;
                            case SYS_readv:
                                read_and_emit_iov(tid, fd, st->arg1, (size_t)st->arg2, (size_t)rval, 1);
                                break;
                            }
                        }
                    }
                }
            }
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }

        // Group-stop or normal signal delivery
        if (sig == SIGSTOP && get_tid_state(tid)->needs_capture < 0) {
            get_tid_state(tid)->needs_capture = check_needs_capture(tid);
            ptrace(PTRACE_SYSCALL, tid, 0, 0);
            continue;
        }
        ptrace(PTRACE_SYSCALL, tid, 0, (void *)(uintptr_t)sig);
    }
    if (attached_root_pid > 0) {
        for (int i = 0; i < MAX_TRACKED_TIDS; i++) {
            pid_t t = tid_table[i].tid;
            if (t > 0) {
                ptrace(PTRACE_INTERRUPT, t, 0, 0);
                waitpid(t, &status, __WALL);
                ptrace(PTRACE_DETACH, t, 0, 0);
            }
        }
    }
    return root_exit_code;
}
