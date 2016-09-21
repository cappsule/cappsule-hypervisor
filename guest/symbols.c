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

#include "guest/symbols.h"


u32 *_net_secret;
struct mutex *_uevent_sock_mutex;

void (*_irq_set_chip_and_handler_name)(unsigned int, struct irq_chip *,
				irq_flow_handler_t, const char *);
void (*_deactivate_task)(struct rq *rq, struct task_struct *p, int flags);
void (*___schedule)(void);
struct tick_device *(*_tick_get_device)(int cpu);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
struct tvec_base *_tvec_bases[NR_CPUS];
#else
struct tvec_base **_tvec_bases[NR_CPUS];
#endif

struct symbol guest_symbols[] = {
	SYMBOL(deactivate_task),
	SYMBOL(irq_set_chip_and_handler_name),
	SYMBOL(net_secret),
	SYMBOL(__schedule),
	SYMBOL(tick_get_device),
	SYMBOL(uevent_sock_mutex),
	{ NULL, NULL }
};

struct per_cpu_symbol guest_per_cpu_symbols[] = {
	PER_CPU_SYMBOL(tvec_bases),
	{ NULL, NULL }
};

EXPORT_SYMBOL(___schedule);

extern void guest_do_exit_stub(void);
EXPORT_SYMBOL(guest_do_exit_stub);

extern void guest_schedule_end_stub(void);
EXPORT_SYMBOL(guest_schedule_end_stub);

extern void guest_schedule_tail_end_stub(void);
EXPORT_SYMBOL(guest_schedule_tail_end_stub);

extern void guest_prepare_binprm_stub(void);
EXPORT_SYMBOL(guest_prepare_binprm_stub);

extern void fake_return_stub(void);
EXPORT_SYMBOL(fake_return_stub);

extern void process_one_work_stub(void);
EXPORT_SYMBOL(process_one_work_stub);
