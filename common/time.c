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

#include <linux/kernel.h>

#include "common/log.h"
#include "common/time.h"
#include "host/capsule.h"
#include "host/time.h"
#include "host/vcpu.h"
#include "trusted/time.h"


/* Can be called both in VMX root mode and VMX non root-mode.
 *
 * The idea of switching capsule->clock_timer.function at each capsule /
 * trusted guest transition is appealing, but it's broken. Let A and B be 2
 * capsules pinned to CPU 1, A is not running and B is running. We would have
 * the following timer functions:
 *  - A->clock_timer.function = trusted_clock_event_function;
 *  - B->clock_timer.function = capsule_clock_event_function;
 *
 * If B->clock_timer expires, an external interrupt triggers a VM-exit and the
 * hypervisor calls the IRQ handler of LOCAL_TIMER_INTERRUPT.
 * capsule_clock_event_function is called. If A->clock_timer has also expired,
 * trusted_clock_event_function is also called which is wrong. */
enum hrtimer_restart clock_event_function(struct hrtimer *timer)
{
	enum hrtimer_restart ret;
	struct capsule *capsule;
	unsigned int cpu;

	capsule = container_of(timer, struct capsule, clock_timer);

	/* interrupt is received on the same CPU that set the clock timer */
	cpu = smp_processor_id();
	if (cpu != capsule->vcpu->cpu) {
		hv_dbg("%s: BUG", __func__);
		return HRTIMER_NORESTART;
	}

	/* If CPU is in VMX root mode, this is straightforward. Otherwise, this
	 * function is called in IRQ context, in trusted guest. The capsule
	 * isn't running. */

	if (capsule->vcpu->guest == GUEST_CAPSULE) {
		/* VMX root mode */
		ret = capsule_clock_event_function(capsule);
	} else {
		/* VMX non-root mode */
		ret = trusted_clock_event_function(capsule);
	}

	return ret;
}
