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
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/vmx.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include "host/process.h"
#include "host/snapshot.h"
#include "host/symbols.h"


static const char *kthreads_comm[] = {
	"kdevtmpfs",
	"kthreadd",
	"watchdog",
	"rcu_sched",
	"ksoftirqd",
	"migration",		/* stop_cpus(), called by jump labels */
	"rcuob",
	"rcuos",
	"rcu_bh",
	"rcu_sched",
	NULL
};


static int keep_kthread(struct task_struct *task)
{
	const char **comm;
	char *p;

	for (comm = kthreads_comm; *comm != NULL; comm++) {
		p = strchr(task->comm, '/');
		if (p == NULL) {
			if (strcmp(*comm, task->comm) == 0)
				return 1;
		} else {
			if (strncmp(*comm, task->comm, p - task->comm) == 0)
				return 1;
		}
	}

	return 0;
}

static int keep_worker(struct task_struct *task)
{
	/* Allow every kworker to be scheduled in the capsule, because kworker's
	 * functions are filtered. It's not generic, and requires a whitelist of
	 * workqueue functions allowed to be executed. */
	return 1;

	/* A better solution requires kworkers to be frozen
	 * (freeze_workqueues_begin + freeze_workqueues_busy) before snapshot,
	 * and restarted during capsule's init (thaw_workqueues). Each workqueue
	 * can be filtered before being restarted. Nevertheless it doesn't work
	 * because some workqueues are not freezable
	 * (!(wq->flags & WQ_FREEZABLE)).  */
}

int keep_userland_process(struct task_struct *task)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(snapshot.process.allowed_pids.pids); i++) {
		if (snapshot.process.allowed_pids.pids[i] == task->pid)
			return 1;
	}

	return 0;
}

/* When snapshot is created, a bitmap is initialized with:
 *  - 0: process is allowed to run (fsclient, X, etc.),
 *  - 1: process is not allowed to run.
 *
 * During execution, capsules check this bitmap to know if a process is allowed
 * to run. It's not necessary to update bitmap when a process is created or
 * exits. Only processes allowed to run can call exit(), and a new process
 * already have its bit set to 0 (because its pid is necessarily different than
 * pid of an uninterruptible process). */
err_t create_process_bitmap(struct task_struct *task)
{
	struct task_struct *g, *p;
	size_t bitmap_size;
	void *pid_bitmap;
	pid_t max_pid;

	/* tasklist_lock should be held to iterate through each thread, but
	 * it's not the case (because tasklist_lock is not exported). This
	 * shouldn't be an issue because only one CPU is online during snapshot
	 * and we're in VMX-root mode (thus IRQs are disabled). */

	max_pid = 0;
	do_each_thread(g, p) {
		if (p->pid > max_pid)
			max_pid = p->pid;
	} while_each_thread(g, p);

	max_pid++;
	bitmap_size = max_pid / BITS_PER_BYTE;
	if (max_pid % BITS_PER_BYTE != 0)
		bitmap_size++;

	pid_bitmap = kzalloc(bitmap_size, GFP_ATOMIC);
	if (pid_bitmap == NULL)
		return ERROR_SNAP_PID_BITMAP_ALLOC_FAILED;

	do_each_thread(g, p) {
		/* Allow capsule_task->parent (fake /sbin/init of virtexec) and
		 * capsule_task (its child) to run. If /sbin/init can't run,
		 * exited children stay in zombie state in capsule.
		 *
		 * XXX: /sbin/init is not chrooted. It doesn't seem to be
		 * problematic because no files are open. */
		if (p == task || p == task->parent) {
			//hv_dbg("%s: %d %s", __func__, p->pid, p->comm);
			continue;
		}

		/* is_idle_task(p) */
		if (p->pid == 0) {
			continue;
		} else if (p->flags & PF_WQ_WORKER) {
			if (keep_worker(p))
				continue;
		} else if (p->flags & PF_KTHREAD) {
			if (keep_kthread(p))
				continue;
		} else if (keep_userland_process(p)) {
			continue;
		}

		set_bit(p->pid, pid_bitmap);
	} while_each_thread(g, p);

	snapshot.process.max_pid = max_pid;
	snapshot.process.pid_bitmap = pid_bitmap;
	snapshot.process.capsule_task = task;

	return SUCCESS;
}

void free_process_bitmap(void)
{
	kfree(snapshot.process.pid_bitmap);
	snapshot.process.pid_bitmap = NULL;
}
