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
#include <linux/version.h>
#include <linux/slab.h>

#include "common/log.h"
#include "common/error.h"
#include "host/symbols.h"

struct mm_struct *_init_mm;
struct list_head *_nosave_regions;
struct mutex *_uevent_sock_mutex;
int (*_is_vmalloc_or_module_addr)(const void *addr);
struct pglist_data *(*_first_online_pgdat)(void);
struct zone *(*_next_zone)(struct zone *zone);
int (*_pfn_is_nosave)(unsigned long);
unsigned long (*_shrink_all_memory)(unsigned long nr_pages);
void (*_native_safe_halt)(void);
void (*_vt_console_print)(void);
int (*_walk_page_range)(unsigned long addr, unsigned long end,
			struct mm_walk *walk);
void (*_schedule_tail)(struct task_struct *prev);
int (*_sys_execve)(const char *filename, const char * const*__argv,
		   const char * const*__envp);
void (*_process_one_work)(struct worker *worker, struct work_struct *work);

struct symbol symbols[] = {
	SYMBOL(init_mm),
	SYMBOL(nosave_regions),
	SYMBOL(uevent_sock_mutex),
	SYMBOL(is_vmalloc_or_module_addr),
	SYMBOL(first_online_pgdat),
	SYMBOL(next_zone),
	SYMBOL(pfn_is_nosave),
	SYMBOL(shrink_all_memory),
	SYMBOL(native_safe_halt),
	SYMBOL(vt_console_print),
	SYMBOL(walk_page_range),
	SYMBOL(schedule_tail),
	SYMBOL(sys_execve),
	SYMBOL(process_one_work),
	{ NULL, NULL }
};

struct per_cpu_symbol per_cpu_symbols[] = {
	{ NULL, NULL }
};
