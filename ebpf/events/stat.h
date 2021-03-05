/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _STAT_H_
#define _STAT_H_

#define OTP_REQUEST_SIZE 75

struct otp_request_t {
    u64 timestamp;
    u64 session_login_timestamp;
    u32 profile_cookie;
    u32 session_init_pid;
    u32 request_pid;
    u32 session_cookie;
    char otp[OTP_REQUEST_SIZE];
};

// otp_requests is the perf ring buffer used to send OTP requests to user space
struct bpf_map_def SEC("maps/otp_requests") otp_requests = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 0,
    .pinning = PIN_NONE,
    .namespace = "",
};

/*
 * kprobe_stat is used to track ssh-probe-auth instance for OTP verification
 */
SEC("kprobe/__x64_sys_newfstatat")
int kprobe_stat(struct pt_regs *kprobe_ctx)
{
    // retrieve stat filename
    struct pt_regs *ctx = (struct pt_regs *) PT_REGS_PARM1(kprobe_ctx);
    char *filename;
    bpf_probe_read(&filename, sizeof(filename), &PT_REGS_PARM2(ctx));

    u32 pid = bpf_get_current_pid_tgid();

    // get session cookie
    struct binary_context_t *binary_ctx = bpf_map_lookup_elem(&pid_binary_context, &pid);
    if (binary_ctx == NULL) {
        // the process is not part of an ssh session, ignore
        return 0;
    }

    // select session context
    u32 cookie = binary_ctx->session_cookie;
    struct session_context_t *session = bpf_map_lookup_elem(&session_context, &cookie);
    if (session == NULL) {
        return 0;
    }

    // create OTP request
    struct otp_request_t request = {};
    bpf_probe_read_str(&request.otp, OTP_REQUEST_SIZE, filename);
    if (request.otp[0] != 'o' || request.otp[1] != 't' || request.otp[2] != 'p' || request.otp[3] != ':' || request.otp[4] != '/' || request.otp[5] != '/') {
        // this is not an OTP request, ignore
        return 0;
    }
    // send OTP request to the backend
    request.timestamp = bpf_ktime_get_ns();
    request.session_login_timestamp = session->login_timestamp;
    request.profile_cookie = session->profile_cookie;
    request.session_init_pid = session->init_pid;
    request.request_pid = pid;
    request.session_cookie = binary_ctx->session_cookie;

    u32 cpu = bpf_get_smp_processor_id();
    bpf_perf_event_output(kprobe_ctx, &otp_requests, cpu, &request, sizeof(request));

    // notify ssh-probe-auth that ssh-probe received the OTP request
    return override_return(kprobe_ctx, ACTION_BLOCK, session, 0);
}

#endif
