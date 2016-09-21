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

#ifndef COMMON_SHARED_MEM_H
#define COMMON_SHARED_MEM_H

#include <asm/termios.h>

#include "common/exec_policy.h"
#include "common/snapshot_process.h"
#include "cuapi/common/uuid.h"


struct shared_mem {
	unsigned long blocked_intr_bitmap[256 / BITS_PER_LONG];
	struct winsize tty_size;

	/* The following variables are set by host during capsule
	 * initialization, but host never relies on them. It doesn't matter if
	 * guest modifies them. Ideally, these variables should be mapped in a
	 * read-only page. */

	/* These informations are specific to each capsule. */
	unsigned int capsule_id;
	struct uuid policy_uuid;
	bool no_gui;

	/* These informations are common to each capsule. */
	__u8 xchan_first_vector;
	struct snapshot_process process;
	struct exec_policies *exec_policies;
};

#endif /* COMMON_SHARED_MEM_H */
