/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _CONST_H_
#define _CONST_H_

// PATH_MAX_LEN is limited to 255 as we won't really need more. The theoretical limit of the kernel is 4096 but
// as we control which path is supposed to be provided, we don't need to go as far as 4096. The paths provided
// for the allowed processes feature are also automatically added to the list of watched files. Any attempt to modify
// them will be stopped.
#define PATH_MAX_LEN 255

// USERNAME_MAX_LENGTH is the maximum length of a user name.
#define USERNAME_MAX_LENGTH 32

// UNKNOWN_USER_NAME When a user is unknown, its profile cookie will have the following value.
#define UNKNOWN_USER_NAME 42

// Actions define how a return value should be overridden
#define ACTION_ALLOW 0
#define ACTION_BLOCK 1
#define ACTION_MFA   2
#define ACTION_KILL  3

// OVERRIDE_RETURN_VALUE is the return value used to override the answer of the kernel. 13 = EACCESS = Permission denied
#define OVERRIDE_RETURN_VALUE -13

// Category identification keys are used to identify the right action in the actions map
#define CATEGORY_FIM                       1
#define CATEGORY_PROCESS_MONITORING        2
#define CATEGORY_UNKNOWN_BINARY            3
#define CATEGORY_SOCKET_CREATION           4
#define CATEGORY_DELETIONS_AND_MOVES       5
#define CATEGORY_PRIVILEGE_ELEVATION       6
#define CATEGORY_OS_LEVEL_PROTECTIONS      7
#define CATEGORY_PROCESS_LEVEL_PROTECTIONS 8
#define CATEGORY_PERFORMANCE_MONITORING    9
#define CATEGORY_KILL                      10
#define CATEGORY_GLOBAL                    11
#define CATEGORY_FAILED_MFA                12
#define CATEGORY_UNKNOWN_FILE              13

// *_ACCESS flags are used to define open access rights
#define READ_ACCESS 1
#define WRITE_ACCESS 2
#define ANY_ACCESS 3

// Notification levels
#define NOTIFY_ALLOW 1
#define NOTIFY_BLOCK 2
#define NOTIFY_MFA 3
#define NOTIFY_KILL 4

// LOAD_CONSTANT is a macro used to prepare constant edition at runtime
#define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))

// Macros used to list syscall hook points

#include "../bpf/bpf_helpers.h"

#define SYSCALL_PREFIX "__x64_sys_"
#define SYSCALL(syscall, func, id) SEC("kprobe/" SYSCALL_PREFIX #syscall) int kprobe__sys_##syscall(struct pt_regs *ctx) { return func(ctx, id); }
#define SYSCALL_RET(syscall, func, id) SEC("kretprobe/" SYSCALL_PREFIX #syscall) int kretprobe__sys_##syscall(struct pt_regs *ctx) { return func(ctx, id); }

#endif
