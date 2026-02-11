//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define MAX_CMD_LEN 128 // 增加长度以容纳完整命令

struct event_t {
    u32 pid;
    u32 uid;
    u64 ts;
    u8  cmd[MAX_CMD_LEN]; // 这里存储完整命令行或 comm
    u32 af;
    u32 proto;
    u16 port;
    u8 ip[16];
};

struct event_t *unused __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Socket 类型追踪 Map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, int);
} temp_socket_types SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, int);
} fd_socket_types SEC(".maps");

// --- 核心：获取 cmdline 的 helper 函数 ---
static __always_inline void get_cmdline(void *output_buf, size_t max_len) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();
    
    // 1. 尝试通过 task->mm->arg_start 获取完整命令行
    if (task && task->mm) {
        unsigned long arg_start = 0;
        unsigned long arg_end = 0;
        
        // 读取地址指针（CO-RE 会自动处理内核偏移）
        bpf_probe_read_kernel(&arg_start, sizeof(arg_start), &task->mm->arg_start);
        bpf_probe_read_kernel(&arg_end, sizeof(arg_end), &task->mm->arg_end);

        unsigned long len = arg_end - arg_start;
        
        if (len > max_len - 1) {
            len = max_len - 1;
        }

        // 尝试从用户空间读取参数列表
        if (len > 0 && arg_start != 0) {
             long ret = bpf_probe_read_user(output_buf, len, (void *)arg_start);
             if (ret == 0) {
                 // 读取成功，直接返回
                 // 注意：这里读取到的是 "curl\0google.com\0"，Go 端需要处理 \0
                 return; 
             }
        }
    }

    // 2. 回退机制：如果上述失败（如内核线程没有 mm），使用 comm
    // bpf_get_current_comm 获取的是截断的进程名 (如 "curl")
    bpf_get_current_comm(output_buf, 16); // comm 通常只有 16 字节
}

// 提交事件的 Helper
static __always_inline void submit_event(void *ctx, u32 pid, u32 af, u32 proto, u16 port, u8 *ip) {
    struct event_t *e;
    e = bpf_ringbuf_reserve(&events, sizeof(struct event_t), 0);
    if (!e) return;

    e->pid = pid;
    e->uid = bpf_get_current_uid_gid();
    e->ts = bpf_ktime_get_ns();
    e->af = af;
    e->proto = proto;
    e->port = port;
    
    // 获取命令 (优先完整 cmdline，失败降级为 comm)
    // 先清空内存，防止脏数据
    __builtin_memset(e->cmd, 0, MAX_CMD_LEN);
    get_cmdline(e->cmd, MAX_CMD_LEN);

    if (af == AF_INET) {
        __builtin_memcpy(e->ip, ip, 4);
    } else {
        __builtin_memcpy(e->ip, ip, 16);
    }

    bpf_ringbuf_submit(e, 0);
}

// --- 以下 Hook 逻辑保持不变 ---

SEC("tracepoint/syscalls/sys_enter_socket")
int trace_socket_entry(struct trace_event_raw_sys_enter *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int type = (int)ctx->args[1] & 0xf;
    bpf_map_update_elem(&temp_socket_types, &tid, &type, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_socket")
int trace_socket_exit(struct trace_event_raw_sys_exit *ctx) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    int *type_ptr = bpf_map_lookup_elem(&temp_socket_types, &tid);
    int fd = (int)ctx->ret;

    if (type_ptr && fd >= 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u64 key = (pid_tgid & 0xFFFFFFFF00000000) | (u32)fd;
        bpf_map_update_elem(&fd_socket_types, &key, type_ptr, BPF_ANY);
        bpf_map_delete_elem(&temp_socket_types, &tid);
    }
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[1];
    int fd = (int)ctx->args[0];
    u16 family = 0;
    u16 port = 0;
    u8 ip_buf[16] = {0};

    if (bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family) != 0) return 0;
    if (family != AF_INET && family != AF_INET6) return 0;

    if (family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) != 0) return 0;
        port = sin.sin_port;
        __builtin_memcpy(ip_buf, &sin.sin_addr.s_addr, 4);
    } else {
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) != 0) return 0;
        port = sin6.sin6_port;
        __builtin_memcpy(ip_buf, sin6.sin6_addr.in6_u.u6_addr8, 16);
    }

    u32 proto = 0;
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 key = (pid_tgid & 0xFFFFFFFF00000000) | (u32)fd;
    int *proto_ptr = bpf_map_lookup_elem(&fd_socket_types, &key);
    if (proto_ptr) proto = *proto_ptr;

    submit_event(ctx, pid_tgid >> 32, family, proto, port, ip_buf);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto(struct trace_event_raw_sys_enter *ctx) {
    struct sockaddr *uservaddr = (struct sockaddr *)ctx->args[4];
    if (!uservaddr) return 0;

    u16 family = 0;
    if (bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family) != 0) return 0;
    if (family != AF_INET && family != AF_INET6) return 0;

    u16 port = 0;
    u8 ip_buf[16] = {0};

    if (family == AF_INET) {
        struct sockaddr_in sin;
        if (bpf_probe_read_user(&sin, sizeof(sin), uservaddr) != 0) return 0;
        port = sin.sin_port;
        __builtin_memcpy(ip_buf, &sin.sin_addr.s_addr, 4);
    } else {
        struct sockaddr_in6 sin6;
        if (bpf_probe_read_user(&sin6, sizeof(sin6), uservaddr) != 0) return 0;
        port = sin6.sin6_port;
        __builtin_memcpy(ip_buf, sin6.sin6_addr.in6_u.u6_addr8, 16);
    }

    if (port == 13568) { 
        submit_event(ctx, bpf_get_current_pid_tgid() >> 32, family, SOCK_DGRAM, port, ip_buf);
    }
    return 0;
}
