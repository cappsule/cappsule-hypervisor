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

#ifndef HOST_VMM_H
#define HOST_VMM_H

#include "cuapi/common/stats.h"

#define VMM_STATS	get_vmm_stats()

struct vmm {
	struct vcpu *vcpus;
	unsigned int max_cpus;

	/* first vector that guest can used for xchan interrupt */
	unsigned int xchan_first_vector;

	atomic_t pending_vmx_stop;

	atomic_t module_being_removed;

	int vpid_support;

	/* XXX: don't hardcode CPU limit. It should be dynamically allocated
	 * like vcpus. */
	struct vmm_stats stats[64];
};

extern struct vmm vmm;

static __always_inline struct vmm_stats *get_vmm_stats(void)
{
	unsigned int cpu;

	cpu = smp_processor_id();
	if (cpu >= ARRAY_SIZE(vmm.stats)) {
		printk(KERN_ERR "hardcoded CPU limit reached while getting VMM stats\n");
		cpu = 0;
	}

	return &vmm.stats[cpu];
}

void cpu_disable_vmx(void *arg);

#endif /* HOST_VMM_H */
