/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _FILE_ACCESS_H_
#define _FILE_ACCESS_H_

// trace_fd_access assesses a file descriptor access
__attribute__((always_inline)) static int trace_fd_access(struct pt_regs *ctx, int fd1, int fd2)
{
    u32 pid = bpf_get_current_pid_tgid();

    // select binary context
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // select profile cookie
    u32 cookie = binary_ctx->session_cookie;
    struct session_context_t *session = bpf_map_lookup_elem(&session_context, &cookie);
    if (session == NULL) {
        return 0;
    }

    // select file descriptor
    struct illegal_fd_t selector = {};
    selector.binary_cookie = binary_ctx->binary_cookie;
    if (fd1 != 0) {
        selector.fd = fd1;
        u8 *action = bpf_map_lookup_elem(&illegal_fds, &selector);
        if (action != NULL) {
            return override_return(ctx, *action, session, CATEGORY_FIM);
        }
    }
    if (fd2 != 0) {
        selector.fd = fd2;
        u8 *action = bpf_map_lookup_elem(&illegal_fds, &selector);
        if (action != NULL) {
            return override_return(ctx, *action, session, CATEGORY_FIM);
        }
    }
    return 0;
}

// read

SEC("kprobe/__x64_sys_read")
int kprobe_read(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_readv")
int kprobe_readv(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_preadv")
int kprobe_preadv(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_preadv2")
int kprobe_preadv2(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_pread64")
int kprobe_pread64(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_readdir")
int kprobe_readdir(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_readahead")
int kprobe_readahead(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

// Write

SEC("kprobe/__x64_sys_write")
int kprobe_write(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_writev")
int kprobe_writev(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_pwritev")
int kprobe_pwritev(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_pwritev2")
int kprobe_pwritev2(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_pwrite64")
int kprobe_pwrite64(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

// mmap

SEC("kprobe/__x64_sys_mmap")
int kprobe_mmap(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM5(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_pipe")
int kprobe_pipe(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fds[2];
    bpf_probe_read(&fds, sizeof(fds), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fds[0], fds[1]);
}

SEC("kprobe/__x64_sys_dup")
int kprobe_dup(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_dup2")
int kprobe_dup2(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM2(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_dup3")
int kprobe_dup3(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM2(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_sendfile")
int kprobe_sendfile(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM2(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_sendfile64")
int kprobe_sendfile64(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM2(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_fcntl")
int kprobe_fcntl(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_flock")
int kprobe_flock(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_fsync")
int kprobe_fsync(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_fdatasync")
int kprobe_fdatasync(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_syncfs")
int kprobe_syncfs(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_sync_file_range")
int kprobe_sync_file_range(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_sync_fallocate")
int kprobe_fallocate(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

SEC("kprobe/__x64_sys_splice")
int kprobe_splice(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM3(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_tee")
int kprobe_tee(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd1;
    bpf_probe_read(&fd1, sizeof(fd1), &PT_REGS_PARM1(ctx));
    int fd2;
    bpf_probe_read(&fd2, sizeof(fd2), &PT_REGS_PARM2(ctx));
    return trace_fd_access(kprobe_ctx, fd1, fd2);
}

SEC("kprobe/__x64_sys_vmsplice")
int kprobe_vmsplice(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int fd;
    bpf_probe_read(&fd, sizeof(fd), &PT_REGS_PARM1(ctx));
    return trace_fd_access(kprobe_ctx, fd, 0);
}

#endif
