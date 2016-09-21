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

#ifndef _DEVICES_GUEST_INIT_H
#define _DEVICES_GUEST_INIT_H

#include "common/vmcall.h"

#define guest_error(fmt, ...)	do {			\
	printk(KERN_ERR fmt "\n", ##__VA_ARGS__);	\
	cpu_vmcs_vmcall(VMCALL_CAPSULE_ERROR, 0);	\
	} while (0)

void guest_init(void);

#endif /* _DEVICES_GUEST_INIT_H */
