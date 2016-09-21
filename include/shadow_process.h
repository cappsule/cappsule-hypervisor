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

#ifndef _SHADOW_PROCESS_H
#define _SHADOW_PROCESS_H

#include <linux/kref.h>
#include <linux/slab.h>
#include <linux/interrupt.h>

#include "common/log.h"
#include "cuapi/common/kill.h"
#include "common/memory.h"

struct daemon;

struct shadow_process {
	bool woken_up;
	unsigned int capsule_id;
	struct task_struct *task;
	atomic_t timer_set;
	struct tasklet_struct tasklet;
	struct kref refcount;
	int capsule_killed;
	kill_t kill_reason;

	struct daemon *daemon;
};

static inline void free_shadowp(struct kref *kref)
{
	struct shadow_process *shadowp;
	unsigned int id;

	shadowp = container_of(kref, struct shadow_process, refcount);
	id = shadowp->capsule_id;
	poison(shadowp, 0x81, sizeof(*shadowp));
	kfree(shadowp);

	cpsl_dbg(id, "shadowp freed");
}

int shadow_process(void *arg);

#endif /* _SHADOW_PROCESS_H */
