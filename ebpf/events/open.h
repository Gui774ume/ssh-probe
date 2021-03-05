/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _OPEN_H_
#define _OPEN_H_

#define IS_ILLEGAL_OPEN 1

struct open_context_t {
    u64 inode;
    int flags;
    u8 action;
};

struct bpf_map_def SEC("maps/open_context") open_context = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(u64),
    .value_size = sizeof(struct open_context_t),
    .max_entries = 15000,
};

// trace_open_ret assesses an open return call
__attribute__((always_inline)) static int trace_open(struct pt_regs *ctx, int flags)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // get session context
    struct session_context_t *session = get_session(pid);
    if (session == NULL) {
        return 0;
    }

    // cache open flag
    struct open_context_t open_ctx = {};
    open_ctx.flags = flags;
    open_ctx.action = ACTION_ALLOW;
    bpf_map_update_elem(&open_context, &pid_tgid, &open_ctx, BPF_ANY);
    return 0;
}

SEC("kprobe/__x64_sys_open")
int kprobe_open(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int flags;
    bpf_probe_read(&flags, sizeof(flags), &PT_REGS_PARM2(ctx));
    return trace_open(kprobe_ctx, flags);
}

SEC("kprobe/__x64_sys_openat")
int kprobe_openat(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int flags;
    bpf_probe_read(&flags, sizeof(flags), &PT_REGS_PARM3(ctx));
    return trace_open(kprobe_ctx, flags);
}


struct illegal_fd_t {
    u32 fd;
    u32 binary_cookie;
};

struct bpf_map_def SEC("maps/illegal_fds") illegal_fds = {
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(struct illegal_fd_t),
    .value_size = sizeof(u8),
    .max_entries = 15000,
};

// get_inode_ino returns the inode number of an inode structure
__attribute__((always_inline)) unsigned long get_inode_ino(struct inode *inode)
{
    unsigned long ino;
    bpf_probe_read(&ino, sizeof(inode), &inode->i_ino);
    return ino;
}

// get_dentry_ino returns the inode number of the inode of the provided dentry
__attribute__((always_inline)) unsigned long get_dentry_ino(struct dentry *dentry)
{
    struct inode *d_inode;
    bpf_probe_read(&d_inode, sizeof(d_inode), &dentry->d_inode);
    return get_inode_ino(d_inode);
}

// get_path_ino returns the inode number of the inode of the dentry of the provided path
__attribute__((always_inline)) unsigned long  __attribute__((always_inline)) get_path_ino(struct path *path) {
    struct dentry *dentry;
    bpf_probe_read(&dentry, sizeof(dentry), &path->dentry);

    if (dentry) {
        return get_dentry_ino(dentry);
    }
    return 0;
}

struct inode_selector_t {
    u64 inode;
    u32 profile_cookie;
    u8 access_right;
};

struct bpf_map_def SEC("maps/inodes") inodes = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct inode_selector_t),
    .value_size = sizeof(u8),
    .max_entries = 150000,
};

SEC("kprobe/vfs_open")
int kprobe_vfs_open(struct pt_regs *ctx) {
    struct path *path = (struct path *)PT_REGS_PARM1(ctx);
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // select open context
    struct open_context_t *open_ctx = bpf_map_lookup_elem(&open_context, &pid_tgid);
    if (open_ctx == NULL) {
        // this call to vfs_open did not come from an open syscall, ignore
        return 0;
    }

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

    // check if the inode is in the list of watched files
    struct inode_selector_t selector = {};
    selector.inode = get_path_ino(path);
    selector.profile_cookie = session->profile_cookie;
    open_ctx->inode = selector.inode;

    if ((open_ctx->flags & 1)) {
        selector.access_right = WRITE_ACCESS;
    } else {
        selector.access_right = READ_ACCESS;
    }

    u8 *action = bpf_map_lookup_elem(&inodes, &selector);
    if (action == NULL) {
        // allow by default
        open_ctx->action = ACTION_ALLOW;
    } else {
        open_ctx->action = *action;
    }

    return 0;
}

struct fim_notification_t {
    struct notification_t notification;
    u64 inode;
    int syscall;
};

// trace_open_ret assesses an open return call
__attribute__((always_inline)) static int trace_open_ret(struct pt_regs *ctx, int fd, int syscall)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

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
    u32 cached_profile_cookie = session->profile_cookie;

    // check if the file descriptor is illegal
    struct open_context_t *open_ctx = bpf_map_lookup_elem(&open_context, &pid_tgid);
    if (open_ctx == NULL) {
        // shouldn't happen, ignore
        return 0;
    }
    if (open_ctx->action != ACTION_ALLOW) {
        struct illegal_fd_t fd_selector = {};
        fd_selector.fd = fd;
        fd_selector.binary_cookie = binary_ctx->binary_cookie;
        u8 action = open_ctx->action;
        bpf_map_update_elem(&illegal_fds, &fd_selector, &action, BPF_ANY);

        int blocked = override_return(ctx, action, session, CATEGORY_FIM);
        if (blocked && action == ACTION_MFA) {
            action = ACTION_BLOCK;
        }
        if (should_notify(action)) {
            struct fim_notification_t notif = {};
            notif.notification.timestamp = bpf_ktime_get_ns();
            notif.notification.session_login_timestamp = session->login_timestamp;
            notif.notification.profile_cookie = cached_profile_cookie;
            notif.notification.session_cookie = binary_ctx->session_cookie;
            notif.notification.category = CATEGORY_FIM;
            notif.notification.action = action;
            notif.inode = open_ctx->inode;
            notif.syscall = syscall;
            fill_process_context(&notif.notification);

            u32 cpu = bpf_get_smp_processor_id();
            bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
        }
    }
    return 0;
}

SEC("kretprobe/__x64_sys_open")
int kretprobe_open(struct pt_regs *ctx) {
    int fd = (int) PT_REGS_RC(ctx);
    return trace_open_ret(ctx, fd, 2);
}

SEC("kretprobe/__x64_sys_openat")
int kretprobe_openat(struct pt_regs *ctx) {
    int fd = (int) PT_REGS_RC(ctx);
    return trace_open_ret(ctx, fd, 257);
}

#endif
