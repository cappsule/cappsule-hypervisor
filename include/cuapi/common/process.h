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

#ifndef CUAPI_COMMON_PROCESS_H
#define CUAPI_COMMON_PROCESS_H

#include <linux/types.h>

enum pid_index {
	PID_INDEX_FS = 0,
	PID_INDEX_GUI,
	PID_INDEX_NET,
	PID_INDEX_XORG,
	PID_INDEX_MAX,
};

struct allowed_pids {
	pid_t pids[PID_INDEX_MAX];
};

#endif /* CUAPI_COMMON_PROCESS_H */
