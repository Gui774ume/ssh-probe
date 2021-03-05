/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PROCESS_LINEAGE_H_
#define _PROCESS_LINEAGE_H_

struct sched_process_fork_args
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;

    char parent_comm[16];
    pid_t parent_pid;
    char child_comm[16];
    pid_t child_pid;
};

/*
 * tracepoint__sched__sched_process_fork is used to track child processes and inherit session cookies
 */
SEC("tracepoint/sched/sched_process_fork")
int tracepoint__sched__sched_process_fork(struct sched_process_fork_args *ctx)
{
    u32 pid = bpf_get_current_pid_tgid();

    // get binary context
    struct binary_context_t *parent_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (parent_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // inherit session cookie
    u32 child_pid = (u32) ctx->child_pid;
    struct binary_context_t child_ctx = {};
    child_ctx.session_cookie = parent_ctx->session_cookie;
    child_ctx.binary_cookie = parent_ctx->binary_cookie;
    bpf_map_update_elem(&pid_binary_context, &child_pid, &child_ctx, BPF_ANY);
    return 0;
}

#endif
