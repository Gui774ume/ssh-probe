/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _OS_LEVEL_PROTECTIONS_H_
#define _OS_LEVEL_PROTECTIONS_H_

// trace_os_level_protections assesses an OS level protection call
__attribute__((always_inline)) static int trace_os_level_protections(struct pt_regs *ctx, int syscall) {
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

    int blocked = override_return(ctx, session->os_level_protections, session, CATEGORY_OS_LEVEL_PROTECTIONS);
    u32 action = session->os_level_protections;
    if (blocked && action == ACTION_MFA) {
        action = ACTION_BLOCK;
    }
    if (should_notify(action)) {
        struct syscall_notification_t notif = {};
        notif.notification.timestamp = bpf_ktime_get_ns();
        notif.notification.session_login_timestamp = session->login_timestamp;
        notif.notification.profile_cookie = cached_profile_cookie;
        notif.notification.session_cookie = binary_ctx->session_cookie;
        notif.notification.category = CATEGORY_OS_LEVEL_PROTECTIONS;
        notif.notification.action = action;
        notif.syscall = syscall;
        fill_process_context(&notif.notification);

        u32 cpu = bpf_get_smp_processor_id();
        bpf_perf_event_output(ctx, &notifications, cpu, &notif, sizeof(notif));
    }
    return 0;
}

SYSCALL(create_module, trace_os_level_protections, 174)
SYSCALL(delete_module, trace_os_level_protections, 176)
SYSCALL(query_module, trace_os_level_protections, 178)
SYSCALL(init_module, trace_os_level_protections, 175)
SYSCALL(finit_module, trace_os_level_protections, 313)
SYSCALL(reboot, trace_os_level_protections, 169)
SYSCALL(settimeofday, trace_os_level_protections, 164)
SYSCALL(clock_settime, trace_os_level_protections, 227)
SYSCALL(clock_adjtime, trace_os_level_protections, 305)
SYSCALL(stime, trace_os_level_protections, 160)
SYSCALL(setrlimit, trace_os_level_protections, 160)
SYSCALL(sysinfo, trace_os_level_protections, 99)
SYSCALL(syslog, trace_os_level_protections, 103)
SYSCALL(getrusage, trace_os_level_protections, 98)
SYSCALL(add_key, trace_os_level_protections, 248)
SYSCALL(keyctl, trace_os_level_protections, 250)
SYSCALL(request_key, trace_os_level_protections, 249)
SYSCALL(unshare, trace_os_level_protections, 272)
SYSCALL(get_kernel_syms, trace_os_level_protections, 177)
SYSCALL(get_mempolicy, trace_os_level_protections, 239)
SYSCALL(set_mempolicy, trace_os_level_protections, 238)
SYSCALL(mbind, trace_os_level_protections, 237)
SYSCALL(move_pages, trace_os_level_protections, 279)
SYSCALL(migrate_pages, trace_os_level_protections, 256)
SYSCALL(kexec_load, trace_os_level_protections, 246)
SYSCALL(kexec_file_load, trace_os_level_protections, 320)
SYSCALL(lookup_dcookie, trace_os_level_protections, 212)
SYSCALL(mount, trace_os_level_protections, 165)
SYSCALL(umount, trace_os_level_protections, 166)
SYSCALL(umount2, trace_os_level_protections, 166)
SYSCALL(name_to_handle_at, trace_os_level_protections, 303)
SYSCALL(open_by_handle_at, trace_os_level_protections, 304)
SYSCALL(nfsservctl, trace_os_level_protections, 180)
SYSCALL(pivot_root, trace_os_level_protections, 155)
SYSCALL(swapon, trace_os_level_protections, 167)
SYSCALL(swapoff, trace_os_level_protections, 168)
SYSCALL(sysfs, trace_os_level_protections, 139)
SYSCALL(_sysctl, trace_os_level_protections, 156)
SYSCALL(uselib, trace_os_level_protections, 134)
SYSCALL(ustat, trace_os_level_protections, 136)
SYSCALL(chroot, trace_os_level_protections, 161)
SYSCALL(sethostname, trace_os_level_protections, 170)
SYSCALL(setdomainname, trace_os_level_protections, 171)
SYSCALL(iopl, trace_os_level_protections, 172)
SYSCALL(ioperm, trace_os_level_protections, 173)

#endif
