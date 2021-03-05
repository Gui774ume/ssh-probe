/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _PRIVILEGE_ELEVATION_H_
#define _PRIVILEGE_ELEVATION_H_

// trace_privilege_elevation assesses a privilege elevation call
__attribute__((always_inline)) static int trace_privilege_elevation(struct pt_regs *ctx, int syscall) {
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

    int blocked = override_return(ctx, session->privilege_elevation, session, CATEGORY_PRIVILEGE_ELEVATION);
    u32 action = session->privilege_elevation;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_PRIVILEGE_ELEVATION;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SEC("kprobe/__x64_sys_setuid")
int kprobe_setuid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int id;
    bpf_probe_read(&id, sizeof(id), &PT_REGS_PARM1(ctx));
    if (id == 0) {
        return trace_privilege_elevation(kprobe_ctx, 105);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setgid")
int kprobe_setgid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int id;
    bpf_probe_read(&id, sizeof(id), &PT_REGS_PARM1(ctx));
    if (id == 0) {
        return trace_privilege_elevation(kprobe_ctx, 106);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setfsuid")
int kprobe_setfsuid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int id;
    bpf_probe_read(&id, sizeof(id), &PT_REGS_PARM1(ctx));
    if (id == 0) {
        return trace_privilege_elevation(kprobe_ctx, 122);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setfsgid")
int kprobe_setfsgid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int id;
    bpf_probe_read(&id, sizeof(id), &PT_REGS_PARM1(ctx));
    if (id == 0) {
        return trace_privilege_elevation(kprobe_ctx, 123);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setreuid")
int kprobe_setreuid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int rid;
    bpf_probe_read(&rid, sizeof(rid), &PT_REGS_PARM1(ctx));
    int eid;
    bpf_probe_read(&eid, sizeof(eid), &PT_REGS_PARM2(ctx));
    if (rid == 0 || eid == 0) {
        return trace_privilege_elevation(kprobe_ctx, 113);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setregid")
int kprobe_setregid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int rid;
    bpf_probe_read(&rid, sizeof(rid), &PT_REGS_PARM1(ctx));
    int eid;
    bpf_probe_read(&eid, sizeof(eid), &PT_REGS_PARM2(ctx));
    if (rid == 0 || eid == 0) {
        return trace_privilege_elevation(kprobe_ctx, 114);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setresgid")
int kprobe_setresgid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int rgid;
    bpf_probe_read(&rgid, sizeof(rgid), &PT_REGS_PARM1(ctx));
    int egid;
    bpf_probe_read(&egid, sizeof(egid), &PT_REGS_PARM2(ctx));
    int sgid;
    bpf_probe_read(&sgid, sizeof(sgid), &PT_REGS_PARM2(ctx));
    if (rgid == 0 || egid == 0 || sgid == 0) {
        return trace_privilege_elevation(kprobe_ctx, 119);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setresuid")
int kprobe_setresuid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int ruid;
    bpf_probe_read(&ruid, sizeof(ruid), &PT_REGS_PARM1(ctx));
    int euid;
    bpf_probe_read(&euid, sizeof(euid), &PT_REGS_PARM2(ctx));
    int suid;
    bpf_probe_read(&suid, sizeof(suid), &PT_REGS_PARM2(ctx));
    if (ruid == 0 || euid == 0 || suid == 0) {
        return trace_privilege_elevation(kprobe_ctx, 117);
    }
    return 0;
}

SEC("kprobe/__x64_sys_setpgid")
int kprobe_setpgid(struct pt_regs *kprobe_ctx) {
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    int pid;
    bpf_probe_read(&pid, sizeof(pid), &PT_REGS_PARM1(ctx));
    int pgid;
    bpf_probe_read(&pgid, sizeof(pgid), &PT_REGS_PARM2(ctx));
    if (pid == 0 || pgid == 0) {
        return trace_privilege_elevation(kprobe_ctx, 109);
    }
    return 0;
}

SYSCALL(setns, trace_privilege_elevation, 308)
SYSCALL(setsid, trace_privilege_elevation, 112)
SYSCALL(capset, trace_privilege_elevation, 126)
SYSCALL(personality, trace_privilege_elevation, 135)
SYSCALL(setpriority, trace_privilege_elevation, 141)
SYSCALL(sched_setparam, trace_privilege_elevation, 142)
SYSCALL(sched_setscheduler, trace_privilege_elevation, 144)
SYSCALL(sched_setaffinity, trace_privilege_elevation, 203)
SYSCALL(set_tid_address, trace_privilege_elevation, 218)
SYSCALL(set_thread_area, trace_privilege_elevation, 205)
SYSCALL(ioprio_set, trace_privilege_elevation, 251)
SYSCALL(acct, trace_privilege_elevation, 163)
SYSCALL(quotactl, trace_privilege_elevation, 179)

#endif
