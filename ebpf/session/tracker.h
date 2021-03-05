/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TRACKER_H_
#define _TRACKER_H_

struct bpf_map_def SEC("maps/user_profile_cookie") user_profile_cookie = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = USERNAME_MAX_LENGTH,
    .value_size = sizeof(u32),
    .max_entries = 5000,
};

struct bpf_map_def SEC("maps/session_context") session_context = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct session_context_t),
    .max_entries = 5000,
};

struct binary_context_t {
    u32 session_cookie;
    u32 binary_cookie;
};

struct bpf_map_def SEC("maps/pid_binary_context") pid_binary_context = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct binary_context_t),
    .max_entries = 32000,
};

// get_session returns the session in which the provided pid lives
__attribute__((always_inline)) static struct session_context_t *get_session(u32 pid)
{
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
    return session;
}

struct action_key {
    u32 profile_cookie;
    u32 category;
};

struct bpf_map_def SEC("maps/actions") actions = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct action_key),
    .value_size = sizeof(u8),
    .max_entries = 5000,
};

// fill_session_context fills the provided section context with its actions
__attribute__((always_inline)) static void fill_session_context(struct session_context_t *session)
{
    u8 *action;
    struct action_key key = {};
    key.profile_cookie = session->profile_cookie;
    u8 default_action = load_unknown_user_default();

    // unknown binary
    key.category = CATEGORY_UNKNOWN_BINARY;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->unknown_binary_default = default_action;
    } else {
        session->unknown_binary_default = *action;
    }

    // socket creation
    key.category = CATEGORY_SOCKET_CREATION;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->socket_creation = default_action;
    } else {
        session->socket_creation = *action;
    }

    // kill
    key.category = CATEGORY_KILL;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->kill = default_action;
    } else {
        session->kill = *action;
    }

    // privilege_elevation
    key.category = CATEGORY_PRIVILEGE_ELEVATION;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->privilege_elevation = default_action;
    } else {
        session->privilege_elevation = *action;
    }

    // deletions_and_moves
    key.category = CATEGORY_DELETIONS_AND_MOVES;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->deletions_and_moves = default_action;
    } else {
        session->deletions_and_moves = *action;
    }

    // os level protections
    key.category = CATEGORY_OS_LEVEL_PROTECTIONS;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->os_level_protections = default_action;
    } else {
        session->os_level_protections = *action;
    }

    // process level protections
    key.category = CATEGORY_PROCESS_LEVEL_PROTECTIONS;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->process_level_protections = default_action;
    } else {
        session->process_level_protections = *action;
    }

    // process level protections
    key.category = CATEGORY_PERFORMANCE_MONITORING;
    action = bpf_map_lookup_elem(&actions, &key);
    if (action == NULL) {
        session->performance_monitoring = default_action;
    } else {
        session->performance_monitoring = *action;
    }
}

/*
 * uprobe_setlogin is used to track new logins in the ssh daemon
 */
SEC("uprobe/setlogin")
int uprobe_setlogin(struct pt_regs *ctx)
{
    char *username = (void *)PT_REGS_PARM1(ctx);
    struct session_context_t session = {};
    char login[USERNAME_MAX_LENGTH] = {};

    // Select the profile cookie of the provided username
    bpf_probe_read_str(&login, USERNAME_MAX_LENGTH, username);
    u32 *profile_cookie = bpf_map_lookup_elem(&user_profile_cookie, login);
    if (profile_cookie == NULL) {
        session.profile_cookie = UNKNOWN_USER_NAME;
    } else {
        session.profile_cookie = *profile_cookie;
    }

    // Generate a random session cookie for this new ssh session
    u32 session_cookie = bpf_get_prandom_u32();
    session.login_timestamp = bpf_ktime_get_ns();
    u32 pid = bpf_get_current_pid_tgid();
    session.init_pid = pid;
    session.session_cookie = session_cookie;
    fill_session_context(&session);

    // Update the session cookie <-> session context mapping
    bpf_map_update_elem(&session_context, &session_cookie, &session, BPF_ANY);

    // Update the pid <-> session mapping
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        struct binary_context_t new_binary_ctx = {};
        new_binary_ctx.session_cookie = session_cookie;
        bpf_map_update_elem(&pid_binary_context, &pid, &new_binary_ctx, BPF_ANY);
    } else {
        binary_ctx->session_cookie = session_cookie;
    }
    return 0;
};

#endif
