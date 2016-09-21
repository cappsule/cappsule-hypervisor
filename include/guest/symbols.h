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

#ifndef GUEST_SYMBOLS_H
#define GUEST_SYMBOLS_H

#include "common/symbols.h"

struct rq;

extern u32 *_net_secret;

extern void (*_deactivate_task)(struct rq *rq, struct task_struct *p,
				int flags);
extern void (*_irq_set_chip_and_handler_name)(unsigned int, struct irq_chip *,
					irq_flow_handler_t, const char *);
extern void (*___schedule)(void);
extern struct tick_device *(*_tick_get_device)(int cpu);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
/* commit: b337a9380f7effd60d082569dd7e0b97a7549730
 * timer: Allocate per-cpu tvec_base's statically */
extern struct tvec_base *_tvec_bases[NR_CPUS];
#else
extern struct tvec_base **_tvec_bases[NR_CPUS];
#endif

extern struct symbol guest_symbols[];
extern struct per_cpu_symbol guest_per_cpu_symbols[];

#endif /* GUEST_SYMBOLS_H */
