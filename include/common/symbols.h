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

#ifndef COMMON_SYMBOLS_H
#define COMMON_SYMBOLS_H

#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/irq.h>

#include "common/error.h"
#include "common/log.h"

#define SYMBOL(name)		{ #name, (unsigned long *)&_##name }
#define PER_CPU_SYMBOL(name)	{ #name, (unsigned long *)_##name }

/* this symbol is resolved by hypervisor and guest */
extern struct mutex *_uevent_sock_mutex;

struct symbol {
	char *name;
	unsigned long *addr;
};

struct per_cpu_symbol {
	char *name;
	unsigned long *addr; /* [NR_CPUS] */
};

static inline err_t resolve_symbols(struct symbol *symbols)
{
	char *name;
	int i;

	for (i = 0; symbols[i].name != NULL; i++) {
		name = symbols[i].name;
		*symbols[i].addr = (unsigned long)kallsyms_lookup_name(name);
		if (*symbols[i].addr == 0) {
			printk(KERN_ERR "can't resolve %s\n", name);
			return ERROR_SYMBOL_RESOLUTION;
		}
	}

	return SUCCESS;
}

static inline err_t resolve_per_cpu_symbols(struct per_cpu_symbol *per_cpu_symbols)
{
	unsigned long addr, *offsets;
	int cpu, i;

	/* don't overflow frame size, use kmalloc() */
	offsets = kmalloc_array(NR_CPUS, sizeof(unsigned long), GFP_KERNEL);
	if (offsets == NULL)
		return -1;

	for_each_possible_cpu(cpu)
		offsets[cpu] = __per_cpu_offset[cpu];

	for (i = 0; per_cpu_symbols[i].name != NULL; i++) {
		addr = kallsyms_lookup_name(per_cpu_symbols[i].name);
		if (addr == 0) {
			printk(KERN_ERR "can't resolve %s",
			       per_cpu_symbols[i].name);
			kfree(offsets);
			return ERROR_SYMBOL_RESOLUTION;
		}

		for_each_possible_cpu(cpu)
			per_cpu_symbols[i].addr[cpu] = offsets[cpu] + addr;
	}

	kfree(offsets);

	return SUCCESS;
}

#endif /* COMMON_SYMBOLS_H */
