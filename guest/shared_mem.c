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

#include "common/vmcall.h"
#include "guest/init.h"
#include "guest/shared_mem.h"

struct shared_mem *shared_mem;


unsigned int guest_get_capsule_id(void)
{
	return shared_mem->capsule_id;
}

/* never used by cappsule.ko, but required */
EXPORT_SYMBOL(guest_get_capsule_id);

void setup_shared_mem(void)
{
	unsigned long gpa, page;

	page = __get_free_page(GFP_ATOMIC);
	if (page == 0)
		guest_error("allocation failed");

	/* force host to allocate pages */
	trigger_ept_violation(page);

	gpa = __pa(page);
	cpu_vmcs_vmcall(VMCALL_SHARE_MEM, gpa);

	shared_mem = (struct shared_mem *)page;
}

/* This function is required by cappsule-guest.ko, even if it's never
 * called. */
long trusted_channel_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	return -1;
}
