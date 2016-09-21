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
#include <linux/kthread.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/vmx.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "shadow_process.h"
#include "common/vmcall.h"
#include "trusted/channel.h"
#include "trusted/xchan.h"


static int should_exit(struct shadow_process *shadowp)
{
	if (shadowp->capsule_killed) {
		cpsl_info(shadowp->capsule_id, "shadow process: exit forced");
		return 1;
	}

	/* SIGKILL and SIGTERM may be sent from userland */
	if (signal_pending(current)) {
		cpsl_info(shadowp->capsule_id, "shadow process: got SIGKILL");
		cpu_vmcs_vmcall(VMCALL_FATAL_SIGNAL, shadowp->capsule_id);
		return 1;
	}

	if (kthread_should_stop()) {
		cpsl_info(shadowp->capsule_id, "shadow process: should stop");
		cpu_vmcs_vmcall(VMCALL_FATAL_SIGNAL, shadowp->capsule_id);
		return 1;
	}

	return 0;
}

/* executed in guest (trusted context) */
int shadow_process(void *arg)
{
	struct shadow_process *shadowp;
	unsigned int id;
	int ret;

	shadowp = (struct shadow_process *)arg;
	shadowp->woken_up = true;
	id = shadowp->capsule_id;

	/* If capsule was killed, loop will break directly. If a fatal signal is
	 * pending, capsule will be killed via a VMCALL in while loop. */

	/* shadow process is bound to capsule CPU, thus vmcall is executed on
	 * expected CPU */
	cpu_vmcs_vmcall(VMCALL_LAUNCH_CAPSULE, id);

	/* allow kernel thread to receive these signals */
	allow_signal(SIGKILL);
	allow_signal(SIGTERM);

	while (1) {
		if (should_exit(shadowp))
			break;

		cpu_vmcs_vmcall(VMCALL_RESUME_EXECUTION, id);

		if (should_exit(shadowp))
			break;

		if (atomic_read(&shadowp->timer_set)) {
			/* A timer is set, switch shadow process state from
			 * TASK_RUNNING to TASK_INTERRUPTIBLE, and wait for
			 * timer to expire. */
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		} else {
			/* capsule reached its quantum, allow other processes in
			 * trusted guest to execute */
			schedule();
		}
	}

	ret = channel_capsule_exited(shadowp->daemon, id, shadowp->kill_reason);
	if (ret != 0)
		cpsl_err(id, "failed to notify daemon of capsule exit");

	/* shadow process mustn't use daemon anymore */
	shadowp->daemon = NULL;

	if (id != shadowp->capsule_id) {
		cpsl_dbg(id, "registers where not correctly restored (%d)!",
			 shadowp->capsule_id);
		return 0;
	}

	xchan_put_pages_by_id(id);

	tasklet_kill(&shadowp->tasklet);

	kref_put(&shadowp->refcount, free_shadowp);

	return 0;
}
