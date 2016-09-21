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
#include <linux/mutex.h>

#include "common/locks.h"
#include "common/symbols.h"
#include "common/vmcall.h"
#include "guest/shared_mem.h"
#include "trusted/channel.h"
#include "cuapi/error.h"
#include "cuapi/common/vmcall.h"

/* Put these functions in a special section, to prevent hypervisor from erasing
 * them. */
#define ATTR_SECTION	__attribute__((section(".keep.common")))


/* Ensure that some locks aren't held by the kernel before snapshot, because
 * they might never be released if processes holding them aren't allowed to run
 * in the guest.
 *
 * Locks held by the hypervisor in this function must be released both by the
 * guest and the hypervisor with release_locks_after_snapshot(). */
static void take_locks_before_snapshot(void)
{
	/* If module_mutex is held during snapshot, there's no garantee that the
	 * process holding the lock will be allowed to run and release it. If
	 * module_mutex is held, capsules can't load module, list modules,
	 * etc. */
	mutex_lock(&module_mutex);

	/* If uevent_sock_mutex is held, mfn_register() gets stuck in guest
	 * because kobject_get_path() relies on it. */
	mutex_lock(_uevent_sock_mutex);
}

/**
 * Call VMCALL_SNAPSHOT to create snapshot.
 *
 * This function is special: the code executed after the vmcall might either be
 * in trusted guest or in a capsule. If vmcall's return value is negative, it
 * tells that the code is executed in a capsule.
 */
static ATTR_SECTION unsigned long channel_snapshot(unsigned long arg)
{
	struct cappsule_ioc_snapshot __user *u_snapshot;
	unsigned int capsule_id;
	struct cappsule_ioc_snapshot s;
	unsigned long errno;
	err_t err;

	u_snapshot = (struct cappsule_ioc_snapshot __user *)arg;
	if (copy_from_user(&s, u_snapshot, sizeof(s)) != 0)
		return -EFAULT;

	take_locks_before_snapshot();

	err = cpu_vmcs_vmcall3_ret(VMCALL_SNAPSHOT, (unsigned long)s.params,
				   s.params_size);

	if ((int)err < 0) {
		/* guest_init() has already been executed */
		capsule_id = guest_get_capsule_id();
		put_user(capsule_id, &u_snapshot->result_capsule_id);
		errno = 1;
	} else {
		release_locks_after_snapshot();
		if (err == 0) {
			errno = 0;
		} else {
			/* The cast of (unsigned long)err is required, otherwise
			 *  -err is a 32bit integer. */
			errno = -(CAPPSULE_ERRNO_BASE + (unsigned long)err);
		}
	}

	return errno;
}

long ATTR_SECTION common_channel_ioctl(struct file *file, unsigned int cmd,
				       unsigned long arg)
{

	if (cmd == CAPPSULE_IOC_SNAPSHOT)
		return channel_snapshot(arg);

	return trusted_channel_ioctl(file, cmd, arg);
}
