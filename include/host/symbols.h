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

#ifndef HOST_SYMBOLS_H
#define HOST_SYMBOLS_H

#include "common/symbols.h"

struct mm_struct;
struct irq_chip;
struct mm_walk;
struct worker;

extern struct mm_struct *_init_mm;
extern struct list_head *_nosave_regions;
extern int (*_is_vmalloc_or_module_addr)(const void *addr);
extern struct pglist_data *(*_first_online_pgdat)(void);
extern struct zone *(*_next_zone)(struct zone *zone);
extern int (*_pfn_is_nosave)(unsigned long);
extern unsigned long (*_shrink_all_memory)(unsigned long nr_pages);
extern void (*_native_safe_halt)(void);
extern void (*_vt_console_print)(void);
extern int (*_walk_page_range)(unsigned long addr, unsigned long end,
			       struct mm_walk *walk);
extern void (*_schedule_tail)(struct task_struct *prev);
extern int (*_sys_execve)(const char *filename, const char * const*__argv,
			  const char * const*__envp);
extern void (*_process_one_work)(struct worker *worker, struct work_struct *work);


extern struct symbol symbols[];
extern struct per_cpu_symbol per_cpu_symbols[];

#endif /* HOST_SYMBOLS_H */
