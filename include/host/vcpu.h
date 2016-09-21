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

#ifndef HOST_VCPU_H
#define HOST_VCPU_H

#include "context.h"


enum guest_type {
	GUEST_TRUSTED,
	GUEST_CAPSULE,
};

struct vcpu {
	unsigned int cpu;
	bool bluepilled;
	bool stop_vmx;			/* vmm is stopping, stop vmx */
	struct regs regs;
	struct context trusted_ctx;
	enum guest_type guest;
	struct capsule *capsule;	/* NULL if guest is not a capsule */

	void *vmxon;
	void *vmm_stack;
	unsigned long guard_page;
	struct vmcs_region *vmcs_trusted;
	struct vmcs_template *trusted_template;
};

#endif /* HOST_VCPU_H */
