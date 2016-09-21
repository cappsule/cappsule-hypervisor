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

#include <linux/sched.h>

#include "shadow_process.h"
#include "common/vmcall.h"
#include "host/capsule.h"
#include "trusted/time.h"


/* A timer expired and capsule isn't running (trusted guest was interrupted).
 * Add pending interrupt to capsule and wake it up. */
enum hrtimer_restart trusted_clock_event_function(struct capsule *capsule)
{
	ktime_t interval;

	/* if shadow process hasn't scheduled yet, restart timer */
	if (current == capsule->shadowp->task) {
		interval = ns_to_ktime(100000);
		hrtimer_forward_now(&capsule->clock_timer, interval);
		return HRTIMER_RESTART;
	}

	cpu_vmcs_vmcall_ret(VMCALL_ADD_PENDING_TIMER_INTR, capsule->id);

	atomic_set(&capsule->shadowp->timer_set, 0);
	tasklet_schedule(&capsule->shadowp->tasklet);

	return HRTIMER_NORESTART;
}

void tasklet_wake_up_shadowp(unsigned long arg)
{
	struct shadow_process *shadowp;

	shadowp = (struct shadow_process *)arg;
	wake_up_process(shadowp->task);
}
