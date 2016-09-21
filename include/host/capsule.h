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

#ifndef HOST_CAPSULE_H
#define HOST_CAPSULE_H

#include <linux/kref.h>
#include <linux/hrtimer.h>

#include "common/error.h"
#include "cuapi/common/kill.h"
#include "cuapi/common/stats.h"
#include "host/context.h"
#include "host/vcpu.h"
#include "host/xchan.h"


#ifndef RELEASE
# define ASSERT(x)	BUG_ON(!(x))
#else
# define ASSERT(x)	do { } while (0)
#endif

#define CPSL_ARGV_SETUP		0x001	/* set as soon as argv[] and envp[] are maped */
#define CPSL_EXITED		0x002	/* capsule has been killed, but isn't decapsulated yet */

/* It's sufficient to define 2 unique VPIDs: one for trusted guest (EPT not in
 * use) and another one for capsules (EPT in use):
 *
 *   If EPT is not in use, the logical processor associates all mappings it
 *   creates with the current VPID, and it will use such mappings to translate
 *   linear addresses. For that reason, a VMM should not use the same VPID for
 *   different non-EPT guests that use different page tables.
 *
 *   If EPT is in use, the logical processor associates all mappings it creates
 *   with the value of bits 51:12 of current EPTP. If a VMM uses different EPTP
 *   values for different guests, it may use the same VPID for those guests.
 *   Doing so cannot result in one guest using translations that pertain to the
 *   other. */
#define TRUSTED_GUEST_VPID	1
#define CAPSULE_VPID		2

/* struct guest_mem fits in one page */
#define CAPSULE_MEM_NPAGES	((PAGE_SIZE - sizeof(void *) - sizeof(unsigned int)) / sizeof(struct page *))

struct guest_mem {
	struct guest_mem *next;	/* next list element */
	unsigned int n;		/* number of entries in pages */
	struct page *pages[CAPSULE_MEM_NPAGES];
};

struct guest_memory {
	unsigned int npages;

	/* guest pages are stored in a linked list */
	struct guest_mem *first;
	struct guest_mem *curr;
};

struct pending_interrupt {
	/* Bitmap of enum interrupt_bit, small enough to be stored in a long.
	 * Functions manipulating this bitmap don't require the atomic
	 * guarantees because they're always called on capsule' cpu. */
	unsigned long bitmap;
};

union ept_pgd;
struct shadow_process;
struct capsule_params;

struct capsule {
	struct vcpu *vcpu;
	struct vmcs_region *vmcs;
	struct list_head list;
	unsigned int id;
	int flags;
	struct kref refcount;

	union ept_pgd *ept_pgd;
	unsigned long fault_address;	/* used to check if there's a loop in */
	unsigned int nfault;		/* EPT violations */

	struct capsule_params *params;

	ktime_t last_schedule;

	struct context ctx;
	int fpu_used;
	struct shadow_process *shadowp;

	/* maximum number of pages that can be allocated */
	unsigned long memory_max_npages;

	/* - page tables and copies of host kernel memory,
	 * - memory allocated in the capsule. */
	struct guest_memory pt_mem;
	struct guest_memory alloc_mem;

	struct pending_interrupt intr;
	struct shared_mem *shared_mem;
	struct hrtimer clock_timer;

	struct xchan xchan;

	/* Statistics. */
	struct capsule_stats stats;
};

static inline struct capsule *current_capsule(struct vcpu *vcpu)
{
	ASSERT(vcpu->guest == GUEST_CAPSULE);
	ASSERT(vcpu->capsule != NULL);
	return vcpu->capsule;
}

static inline int intr_pending(struct capsule *capsule)
{
	return capsule->intr.bitmap & (-1L);
}

void kill(struct vcpu *vcpu, kill_t reason);
void kill_s(struct capsule *capsule, kill_t reason);
err_t create_capsule(struct vcpu *vcpu, struct capsule_params *params,
		     struct shadow_process *shadowp);

struct capsule *get_capsule_from_id(unsigned int id);
struct capsule *capsule_from_id(unsigned int id);
void put_capsule(struct capsule *capsule);
int get_capsule_ids(unsigned int *ids, size_t size);

struct task_struct *get_shadow_process_task(unsigned int capsule_id);
struct task_struct *get_first_shadow_process_task(bool *woken_up);

void launch_capsule(struct vcpu *vcpu, struct capsule *capsule);

#endif /* HOST_CAPSULE_H */
