/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _EXECVE_H_
#define _EXECVE_H_

struct binary_path_key_t
{
    u32 profile_cookie;
    char path[PATH_MAX_LEN];
};

struct binary_path_action_t {
    u64 inode;
    u8 action;
};

struct bpf_map_def SEC("maps/allowed_binaries") allowed_binaries = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct binary_path_key_t),
    .value_size = sizeof(u8),
    .max_entries = 1500,
};

struct process_monitoring_notification_t {
    struct notification_t notification;
    struct binary_path_key_t key;
};

// trace_execve assesses an execve call
__attribute__((always_inline)) static int trace_execve(struct pt_regs *ctx, char *filename)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    // get binary context
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // generate new binary cookie
    binary_ctx->binary_cookie = bpf_get_prandom_u32();

    // select profile cookie
    u32 cookie = binary_ctx->session_cookie;
    struct session_context_t *session = bpf_map_lookup_elem(&session_context, &cookie);
    if (session == NULL) {
        return 0;
    }

    // select binary action
    struct process_monitoring_notification_t notif = {};
    notif.key.profile_cookie = session->profile_cookie;
    int real_len = bpf_probe_read_str(&notif.key.path, PATH_MAX_LEN, filename);
    u8 *action = bpf_map_lookup_elem(&allowed_binaries, &notif.key);
    int blocked;
    u32 sent_action;
    if (action == NULL) {
        sent_action = session->unknown_binary_default;
        blocked = override_return(ctx, session->unknown_binary_default, session, CATEGORY_PROCESS_MONITORING);
    } else {
        sent_action = *action;
        blocked = override_return(ctx, sent_action, session, CATEGORY_PROCESS_MONITORING);
    }
    if (blocked && sent_action == ACTION_MFA) {
        sent_action = ACTION_BLOCK;
    }
    if (should_notify(sent_action)) {
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = notif.key.profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_PROCESS_MONITORING;
        notif.notification.action = sent_action;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(struct notification_t) + sizeof(u32) + (real_len & PATH_MAX_LEN));
    }
    return 0;
}

SEC("kprobe/__x64_sys_execve")
int kprobe_execve(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM1(ctx));
    return trace_execve(kprobe_ctx, filename);
}

SEC("kprobe/__x64_sys_execveat")
int kprobe_execveat(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(ctx));
    return trace_execve(kprobe_ctx, filename);
}

#endif
