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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/hrtimer.h>
#include <asm/vmx.h>

#include "shadow_process.h"
#include "common/time.h"
#include "host/capsule.h"
#include "host/interrupt.h"
#include "host/time.h"

#define TSC_DIVISOR	32


enum hrtimer_restart capsule_clock_event_function(struct capsule *capsule)
{
	struct capsule *running_capsule;

	running_capsule = current_capsule(capsule->vcpu);

	atomic_set(&capsule->shadowp->timer_set, 0);

	if (capsule->id == running_capsule->id) {
		/* Nothing to do: a LOCAL_TIMER_VECTOR interrupt was received
		 * and the external interrupt VM-exit is ongoing.
		 * This function is called by the interrupt handler, and the
		 * interrupt is gone to be injected into guest.  */
	} else {
		/* The current guest is not the capsule which received the clock
		 * event. */
		add_pending_intr(capsule, LOCAL_TIMER_VECTOR, 0);
		tasklet_schedule(&capsule->shadowp->tasklet);
	}

	return HRTIMER_NORESTART;
}

static void set_timer(struct vcpu *vcpu, __u64 nsec)
{
	struct capsule *capsule;
	ktime_t expires, now, t;

	now = ktime_get_real();
	expires = ktime_add_ns(now, nsec);
	if (ktime_compare(expires, now) <= 0)
		return;

	/* don't cancel current timer if it is scheduled before the new one */
	capsule = current_capsule(vcpu);
	if (atomic_read(&capsule->shadowp->timer_set)) {
		t = hrtimer_get_remaining(&capsule->clock_timer);
		t = ktime_add(now, t);
		if (ktime_compare(expires, t) >= 0)
			return;
	} else {
		atomic_set(&capsule->shadowp->timer_set, 1);
	}

	hrtimer_start(&capsule->clock_timer, expires, HRTIMER_MODE_ABS);
}

void vmcall_set_timer(struct vcpu *vcpu, __u64 nsec)
{
	set_timer(vcpu, nsec);
}

void capsule_tsc_deadline(struct vcpu *vcpu, __u64 value)
{
	unsigned long cycles;
	__u64 tsc, nsec;

	rdtscll(tsc);
	if (tsc >= value)
		return;

	cycles = (value - tsc) / TSC_DIVISOR;
	nsec = cycles * (1000000 / cpu_khz);

	set_timer(vcpu, nsec);
}

void init_clock_timer(struct capsule *capsule)
{
	hrtimer_init(&capsule->clock_timer, CLOCK_REALTIME, HRTIMER_MODE_ABS);
	capsule->clock_timer.function = clock_event_function;
}
