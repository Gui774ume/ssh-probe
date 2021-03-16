/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#pragma clang diagnostic ignored "-Warray-bounds"
#pragma clang diagnostic ignored "-Wunused-label"
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Wframe-address"
#include <linux/kconfig.h>
#include <linux/version.h>

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 */
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif
/* Before bpf_helpers.h is included, uapi bpf.h has been
 * included, which references linux/types.h. This may bring
 * in asm_volatile_goto definition if permitted based on
 * compiler setup and kernel configs.
 *
 * clang does not support "asm volatile goto" yet.
 * So redefine asm_volatile_goto to some invalid asm code.
 * If asm_volatile_goto is actually used by the bpf program,
 * a compilation error will appear.
 */
#ifdef asm_volatile_goto
#undef asm_volatile_goto
#endif
#define asm_volatile_goto(x...) asm volatile("invalid use of asm_volatile_goto")

#include <linux/ptrace.h>
#include <linux/tty.h>
#include <linux/dcache.h>
#include <linux/path.h>
#pragma clang diagnostic pop

// Custom eBPF helpers
#include "bpf/bpf.h"
#include "bpf/bpf_map.h"
#include "bpf/bpf_helpers.h"

#include "session/session.h"

// utils
#include "utils/tail_call.h"
#include "utils/const.h"
#include "utils/action.h"
//#include "utils/process.h"

// Session tracking probes
#include "session/tracker.h"
#include "session/process_lineage.h"

// Events
#include "events/execve.h"
#include "events/unlink_and_move.h"
#include "events/stat.h"
#include "events/socket.h"
#include "events/privilege_elevation.h"
#include "events/process_level_protections.h"
#include "events/kill.h"
#include "events/os_level_protections.h"
#include "events/open.h"
#include "events/file_access.h"
#include "events/performance_monitoring.h"

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 0xFFFFFFFE;
