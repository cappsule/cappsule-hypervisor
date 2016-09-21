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

#include <linux/kthread.h>
#include <linux/slab.h>

#include "common/error.h"
#include "shadow_process.h"
#include "common/params.h"
#include "common/vmcall.h"
#include "host/snapshot.h"
#include "trusted/channel.h"
#include "trusted/xchan.h"


err_t channel_create_capsule(void __user *u_params,
			     struct capsule_params *params,
			     unsigned int *result_capsule_id)
{
	struct xchan_memory *xchan_memory;
	struct shadow_process *shadowp;
	struct task_struct *kthread;
	unsigned int id, random_cpu;
	void *info_pages;
	size_t size;
	err_t err;

	info_pages = NULL;
	shadowp = NULL;
	xchan_memory = NULL;

	if (!snapshot_done) {
		err = ERROR_CREATION_NO_SNAPSHOT;
		goto error;
	}

	size = snapshot.params_npages * PAGE_SIZE;
	info_pages = kmalloc(size, GFP_KERNEL);
	shadowp = kzalloc(sizeof(*shadowp), GFP_KERNEL);

	if (info_pages == NULL || shadowp == NULL) {
		err = ERROR_CREATION_ALLOC_FAILED;
		goto error;
	}

	if (copy_from_user(info_pages, u_params, size) != 0) {
		err = ERROR_CREATION_INVALID_USER_PAGES;
		goto error;
	}

	xchan_memory = xchan_alloc_pages();
	if (xchan_memory == NULL) {
		err = ERROR_CREATION_XCHAN_ALLOC_FAILED;
		goto error;
	}

	params->info_pages = info_pages;
	params->xchan_pages = xchan_get_memory_pages(xchan_memory);

	/* create a kernel thread without starting it */
	kthread = kthread_create(&shadow_process, (void *)shadowp, "capsule");
	if (kthread == NULL) {
		err = ERROR_CREATION_KTHREAD_FAILED;
		goto error;
	}

	/* Bind shadow process to a random CPU. Use kthread_bind because
	 * kthread_create_on_cpu isn't exported. */
	random_cpu = smp_processor_id();
	kthread_bind(kthread, random_cpu);

	/* create capsule structure and initialize shadowp */
	shadowp->task = kthread;
	err = cpu_vmcs_vmcall3_ret(VMCALL_CREATE_CAPSULE,
				  (long)params, (long)shadowp);
	if (err != SUCCESS) {
		/* kthread will exit without calling shadow_process */
		kthread_stop(kthread);
		goto error;
	}

	id = shadowp->capsule_id;
	*result_capsule_id = id;

	/* once capsule id is known, kthread's name and xchan memory id can be
	 * set */
	snprintf(kthread->comm, sizeof(kthread->comm), "capsule-%u", id);
	xchan_set_memory_id(xchan_memory, id);

	/* start shadow process */
	if (wake_up_process(kthread) != 1)
		tg_err("BUG: failed to wake shadow process (capsule: %d)", id);

	return SUCCESS;

error:
	kfree(shadowp);
	kfree(info_pages);
	kfree(params);
	if (xchan_memory != NULL)
		xchan_put_pages(xchan_memory);
	return err;
}
