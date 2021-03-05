/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _UNLINK_AND_MOVE_H_
#define _UNLINK_AND_MOVE_H_

// trace_deletions_and_moves assesses an unlink or rename call
__attribute__((always_inline)) static int trace_deletions_and_moves(struct pt_regs *ctx, int syscall) {
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

    int blocked = override_return(ctx, session->deletions_and_moves, session, CATEGORY_DELETIONS_AND_MOVES);
    u32 action = session->deletions_and_moves;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_DELETIONS_AND_MOVES;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SYSCALL(unlink, trace_deletions_and_moves, 87)
SYSCALL(unlinkat, trace_deletions_and_moves, 263)
SYSCALL(rmdir, trace_deletions_and_moves, 84)
SYSCALL(rename, trace_deletions_and_moves, 82)
SYSCALL(renameat, trace_deletions_and_moves, 264)
SYSCALL(renameat2, trace_deletions_and_moves, 316)
SYSCALL(truncate, trace_deletions_and_moves, 76)
SYSCALL(ftruncate, trace_deletions_and_moves, 77)

#endif
