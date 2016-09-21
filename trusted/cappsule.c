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

#include "common/bluepill.h"
#include "common/log.h"
#include "common/error.h"
#include "host/interrupt.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/vmm.h"
#include "trusted/channel.h"
#include "trusted/fingerprint.h"
#include "trusted/mfn.h"
#include "trusted/vmm.h"
#include "trusted/xchan.h"

MODULE_LICENSE("GPL");
MODULE_VERSION(VERSION);


static int __init cappsule_init(void)
{
	err_t error;

	error = log_init();
	if (error != SUCCESS)
		goto out;

	error = resolve_symbols(symbols);
	if (error != SUCCESS)
		goto symbols_error;

	error = resolve_per_cpu_symbols(per_cpu_symbols);
	if (error != SUCCESS)
		goto symbols_error;

	error = check_breakpoints();
	if (error != SUCCESS)
		goto symbols_error;

	error = channel_init();
	if (error != SUCCESS)
		goto symbols_error;

	error = host_mfn_init();
	if (error != SUCCESS)
		goto host_mfn_error;

	error = trusted_xchan_init();
	if (error != SUCCESS)
		goto trusted_xchan_error;

	resolve_interrupt_handlers();

	error = shrink_memory();
	if (error != SUCCESS)
		goto shrink_memory_error;

	error = init_vmm();
	if (error != SUCCESS)
		goto shrink_memory_error;

	error = bluepill();
	if (error != SUCCESS)
		goto bluepill_error;

	snapshot_done = 0;

	return SUCCESS;

bluepill_error:
	free_vmm();
shrink_memory_error:
	trusted_xchan_exit();
trusted_xchan_error:
	host_mfn_exit();
host_mfn_error:
	channel_exit();
symbols_error:
	log_exit();
out:
	/* errno is set to the value returned by the init function */
	return -(CAPPSULE_ERRNO_BASE + error);
}

static void __exit cappsule_exit(void)
{
	/* don't allow creation of new capsules */
	atomic_set(&vmm.module_being_removed, 1);

	kill_all_capsules();

	stop_vmm();
	free_vmm();

	delete_snapshot();
	trusted_xchan_exit();
	host_mfn_exit();
	channel_exit();
	log_exit();
}

module_init(cappsule_init);
module_exit(cappsule_exit);
