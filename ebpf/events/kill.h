/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _KILL_H_
#define _KILL_H_

// trace_kill assesses a kill call
__attribute__((always_inline)) static int trace_kill(struct pt_regs *ctx, int sig, int syscall) {
    u32 pid = bpf_get_current_pid_tgid();

    // Only stop SIGKILL, SIGALRM, SIGTERM or SIGSTOP
    if (sig != 9 && sig != 14 && sig != 15 && sig != 19) {
        return 0;
    }

    // get binary context
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

    int blocked = override_return(ctx, session->kill, session, CATEGORY_KILL);
    u32 action = session->kill;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_KILL;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SEC("kprobe/__x64_sys_kill")
int kprobe_kill(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int sig;
    bpf_probe_read(&sig, sizeof(sig), &PT_REGS_PARM2(ctx));
    return trace_kill(kprobe_ctx, sig, 62);
}

SEC("kprobe/__x64_sys_tkill")
int kprobe_tkill(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int sig;
    bpf_probe_read(&sig, sizeof(sig), &PT_REGS_PARM2(ctx));
    return trace_kill(kprobe_ctx, sig, 200);
}

SEC("kprobe/__x64_sys_tgkill")
int kprobe_tgkill(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int sig;
    bpf_probe_read(&sig, sizeof(sig), &PT_REGS_PARM2(ctx));
    return trace_kill(kprobe_ctx, sig, 234);
}

#endif
