/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PROCESS_LEVEL_PROTECTIONS_H_
#define _PROCESS_LEVEL_PROTECTIONS_H_

// trace_process_level_protections assesses a process level protection call
__attribute__((always_inline)) static int trace_process_level_protections(struct pt_regs *ctx, int syscall) {
    u32 pid = bpf_get_current_pid_tgid();

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

    int blocked = override_return(ctx, session->process_level_protections, session, CATEGORY_PROCESS_LEVEL_PROTECTIONS);
    u32 action = session->process_level_protections;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_PROCESS_LEVEL_PROTECTIONS;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SYSCALL(ptrace, trace_process_level_protections, 101)
SYSCALL(memfd_create, trace_process_level_protections, 319)
SYSCALL(kcmp, trace_process_level_protections, 312)
SYSCALL(process_vm_readv, trace_process_level_protections, 310)
SYSCALL(process_vm_writev, trace_process_level_protections, 311)
SYSCALL(userfaultfd, trace_process_level_protections, 323)
SYSCALL(modify_ldt, trace_process_level_protections, 154)

#endif
