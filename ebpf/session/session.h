/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _SESSION_H_
#define _SESSION_H_

struct session_context_t
{
    u64 login_timestamp;
    u32 profile_cookie;
    u32 session_cookie;
    u32 init_pid;

    u8 unknown_binary_default;
    u8 deletions_and_moves;
    u8 socket_creation;
    u8 privilege_elevation;
    u8 os_level_protections;
    u8 process_level_protections;
    u8 performance_monitoring;
    u8 kill;
    u8 unknown_file_default;
};

#endif
