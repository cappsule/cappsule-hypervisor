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

#ifndef CUAPI_COMMON_STATS_H
#define CUAPI_COMMON_STATS_H

#include "cuapi/common/vmcall.h"

struct event_counter {
	__u64 count;
	struct timespec elapsed_time;
};

#define NR_VM_EXIT_REASONS 64

/*
 * Structure storing capsule statistics.
 */
struct capsule_stats {
	/* Counters for VM-exits. */
	struct event_counter vm_exits[NR_VM_EXIT_REASONS];

	/* Counters for VM-calls. */
	struct event_counter vm_calls[NR_CAPSULE_VM_CALLS];

	/* Number of injected timer interrupts. */
	__u64 nr_local_timer_intr;

	/* Number of injected xchan interrupts. */
	__u64 nr_xchan_intr;

	/* Number of context switches. */
	__u64 nr_switches;

	/* Time spent in capsule mode. */
	struct timespec total_elapsed_time;
};

struct vmm_stats {
	struct event_counter vm_exits[NR_VM_EXIT_REASONS];
	struct event_counter xchan_guest_notif;
};

struct cappsule_ioc_stats {
	unsigned int capsule_id;
	struct capsule_stats stats;
};

struct cappsule_ioc_vmm_stats {
	unsigned int cpu;
	struct vmm_stats stats;
};

#endif
