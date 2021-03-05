/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2020
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#ifndef _TAIL_CALL_H_
#define _TAIL_CALL_H_

#define PROCESS_MONITORING_TAILCALL 1

struct bpf_map_def SEC("maps/prog_array") prog_array = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = 4,
    .value_size = 4,
    .max_entries = 3,
};

#endif
