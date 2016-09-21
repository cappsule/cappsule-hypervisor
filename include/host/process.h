/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef HOST_PROCESS_H
#define HOST_PROCESS_H

#include <linux/types.h>

#include "common/error.h"

struct task_struct;

err_t create_process_bitmap(struct task_struct *capsule_task);
void free_process_bitmap(void);
int keep_userland_process(struct task_struct *task);

#endif /* _HOST_PROCESS_H */
