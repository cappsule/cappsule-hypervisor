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
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/vmx.h>
#include <linux/delay.h>

#include "common/vmcall.h"
#include "guest/init.h"
#include "guest/kernel_sched_sched.h"
#include "guest/shared_mem.h"
#include "guest/symbols.h"

static int forbidden_process(struct task_struct *p)
{
	if (p->pid >= shared_mem->process.max_pid)
		return 0;

	if (!test_bit(p->pid, shared_mem->process.pid_bitmap))
		return 0;

	return 1;
}

/* called from guest when __schedule() returns.
 * don't let thread continue its execution if not expected */
int guest_schedule_end(void)
{
	int allowed_to_run, ret;
	struct cfs_rq *cfs_rq;
	unsigned long flags;
	struct rq *rq;

	allowed_to_run = !forbidden_process(current);
	//printk(KERN_ERR "%s: %5d %s (%d)\n", __func__, current->pid,
	//       current->comm, allowed_to_run);

	if (allowed_to_run) {
		ret = 0;
	} else {
		/* Setting task state to TASK_UNINTERRUPTIBLE doesn't always
		 * prevent process to run again. On the contrary, removing
		 * process from runqueue is effective. */
		local_irq_save(flags);

		/* rq = task_rq(current); is not an option because runqueues
		 * aren't exported */
		cfs_rq = current->se.cfs_rq;
		rq = cfs_rq->rq;

		_deactivate_task(rq, current, 0);
		local_irq_restore(flags);

		/* __schedule() will be called again */
		ret = -1;
	}

	return ret;
}

/* A process may fork during snapshot (ie: parent is in fork syscall and child
 * isn't created yet), and its child is not present in pid_bitmap.
 *
 * A newly forked process directly context switches into ret_from_fork, which
 * calls schedule_tail(). Hook schedule_tail() and forbid process to run if not
 * allowed to. ret_from_fork isn't hooked directly to allow schedule_tail() to
 * executes. */
void guest_schedule_tail_end(void)
{
	//printk(KERN_ERR "%s: %s %d\n", __func__, current->comm, current->pid);

	/* Force child to schedule(). If child isn't allowed to run, it will be
	 * removed from runqueue thanks to guest_schedule_end(). */
	if (forbidden_process(current))
		schedule();
}

void guest_do_exit(int exit_code)
{
	printk(KERN_ERR "do_exit(%d) (%s)\n", exit_code, current->comm);

	if (current == shared_mem->process.capsule_task)
		cpu_vmcs_vmcall(VMCALL_EXIT, 0);
}
