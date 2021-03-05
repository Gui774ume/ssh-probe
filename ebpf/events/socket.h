/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UN_SOCKET_H_
#define _UN_SOCKET_H_

// trace_socket assesses a socket creation call
__attribute__((always_inline)) static int trace_socket(struct pt_regs *ctx, int syscall) {
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

    int blocked = override_return(ctx, session->socket_creation, session, CATEGORY_SOCKET_CREATION);
    u32 action = session->socket_creation;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_SOCKET_CREATION;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SYSCALL(socket, trace_socket, 41)
SYSCALL(socketpair, trace_socket, 53)
SYSCALL(socketcall, trace_socket, 400)

#endif
