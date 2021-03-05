/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _ACTION_H_
#define _ACTION_H_

struct kill_request_t {
    u64 timestamp;
    u64 session_login_timestamp;
    u32 profile_cookie;
    u32 session_init_pid;
    u32 session_cookie;
    u32 padding;
};

// kill_requests is the perf ring buffer used to send kill requests to user space
struct bpf_map_def SEC("maps/kill_requests") kill_requests = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct notification_t {
    u64 timestamp;
    u64 session_login_timestamp;
    u32 profile_cookie;
    u32 session_cookie;
    u32 category;
    u32 action;
    u32 pid;
    u32 tid;
    char comm[TASK_COMM_LEN];
};

struct syscall_notification_t {
    struct notification_t notification;
    int syscall;
};

// notification is the perf ring buffer used to send notifications (other than kill requests) to user space
struct bpf_map_def SEC("maps/notifications") notifications = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

struct mfa_selector_t {
    u32 profile_cookie;
    u32 session_cookie;
    u8 scope;
};

// mfa_tokens contains the mfa tokens and expiration dates of admin operations that require mfa
struct bpf_map_def SEC("maps/mfa_tokens") mfa_tokens = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct mfa_selector_t),
    .value_size = sizeof(u64),
    .max_entries = 5000,
};

// load_unknown_user_default returns the default action for unknown users
__attribute__((always_inline)) static u8 load_unknown_user_default() {
    u64 unknown_user_default = 0;
    LOAD_CONSTANT("unknown_user_default", unknown_user_default);
    return (u8) unknown_user_default;
}

// load_notification_level returns the notification level
__attribute__((always_inline)) static u8 load_notification_level() {
    u64 notification_level = 0;
    LOAD_CONSTANT("notification_level", notification_level);
    return (u8) notification_level;
}

// should_notify returns 1 if a notification should be sent, based on the current notification level parameter
__attribute__((always_inline)) static int should_notify(u8 action) {
    u64 notification_level = load_notification_level();
    return (notification_level <= action);
}

// fill_process_context fills the provided notification with the process context available from eBPF
__attribute__((always_inline)) static u64 fill_process_context(struct notification_t *notif)
{
    // Comm
    bpf_get_current_comm(&notif->comm, sizeof(notif->comm));

    // Pid & Tid
    u64 id = bpf_get_current_pid_tgid();
    notif->pid = id >> 32;
    notif->tid = id;
    return id;
}

// override_return overrides the return value of a syscall based on the provided action. Returns 1 if the action was blocked
__attribute__((always_inline)) static int override_return(struct pt_regs *ctx, u8 action, struct session_context_t *session, u8 scope)
{
    switch (action) {
        case 0:
        {
            break;
        }
        case 1:
        {
            // override return
            bpf_override_return(ctx, OVERRIDE_RETURN_VALUE);
            break;
        }
        case 2:
        {
            struct mfa_selector_t selector = {};
            selector.profile_cookie = session->profile_cookie;
            selector.session_cookie = session->session_cookie;
            selector.scope = scope;
            u64 *expires_at = bpf_map_lookup_elem(&mfa_tokens, &selector);
            if (expires_at != NULL) {
                u64 now = bpf_ktime_get_ns();
                if (now <= *expires_at) {
                    break;
                }
            }
            // override return
            bpf_override_return(ctx, OVERRIDE_RETURN_VALUE);
            return 1;
        }
        case 3:
        {
            // override return
            bpf_override_return(ctx, OVERRIDE_RETURN_VALUE);

            // send kill order
            struct kill_request_t kr = {};
            kr.timestamp = bpf_ktime_get_ns();
            kr.session_login_timestamp = session->login_timestamp;
            kr.profile_cookie = session->profile_cookie;
            kr.session_cookie = session->session_cookie;
            kr.session_init_pid = session->init_pid;

            // dissociate session from profile token
            session->profile_cookie = UNKNOWN_USER_NAME;

            u32 cpu = bpf_get_smp_processor_id();
            bpf_perf_event_output(ctx, &kill_requests, cpu, &kr, sizeof(kr));
            return 1;
        }
    }
    return 0;
}

#endif
