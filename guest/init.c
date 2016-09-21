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
#include <linux/cryptohash.h>
#include <linux/random.h>

#include "common/locks.h"
#include "cuapi/common/process.h"
#include "guest/console.h"
#include "guest/init.h"
#include "guest/mfn.h"
#include "guest/process.h"
#include "guest/shared_mem.h"
#include "guest/symbols.h"
#include "guest/timers.h"
#include "guest/xchan.h"

MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);

#define NET_SECRET_SIZE	(MD5_MESSAGE_BYTES / 4)


static void disable_pid(enum pid_index pid_index)
{
	pid_t pid;

	pid = shared_mem->process.allowed_pids.pids[pid_index];
	if (pid != -1)
		set_bit(pid, shared_mem->process.pid_bitmap);
}

/* called from guest (encapsulated): in fact, it's its first instructions.
 *
 * starts running with irq disabled. */
void guest_init(void)
{
	guest_fix_timekeeping();
	setup_timers();

	/* Reinitialize net_secret. Differents capsule will not have identical,
	 * source port, tcp seq numbers, etc. */
	get_random_bytes(_net_secret, NET_SECRET_SIZE);

	init_apic();

	setup_shared_mem();

	/* don't allow guiclient to run if --no-gui is passed to virtexec */
	if (shared_mem->no_gui)
		disable_pid(PID_INDEX_GUI);

	local_irq_enable();

	release_locks_after_snapshot();

	guest_mfn_init();

	guest_xchan_init(shared_mem->xchan_first_vector);

	guest_tty_init();

	/* return to fake_return_stub which returns to saved rip */
	//printk(KERN_ERR "return from %s\n", __func__);
}

EXPORT_SYMBOL(guest_init);

static int __init cappsule_guest_init(void)
{
	err_t error;

	error = resolve_symbols(guest_symbols);
	if (error != SUCCESS) {
		/* errno is set to the value returned by the init function */
		return -(CAPPSULE_ERRNO_BASE + error);
	}

	error = resolve_per_cpu_symbols(guest_per_cpu_symbols);
	if (error != SUCCESS)
		return -(CAPPSULE_ERRNO_BASE + error);

	return 0;
}

static void __exit cappsule_guest_exit(void)
{

}

module_init(cappsule_guest_init);
module_exit(cappsule_guest_exit);
