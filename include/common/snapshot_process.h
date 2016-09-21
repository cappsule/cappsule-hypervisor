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

#ifndef COMMON_SNAPSHOT_PROCESS_H
#define COMMON_SNAPSHOT_PROCESS_H

#include "cuapi/common/process.h"

struct task_struct;

/* informations related to the processes during snapshot */
struct snapshot_process {
	struct task_struct *capsule_task;
	struct allowed_pids allowed_pids;
	pid_t max_pid;
	void *pid_bitmap;
};

#endif /* COMMON_SNAPSHOT_PROCESS_H */
