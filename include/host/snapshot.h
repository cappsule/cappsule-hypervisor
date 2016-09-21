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

#ifndef HOST_SNAPSHOT_H
#define HOST_SNAPSHOT_H

#include <asm/page.h>

#include "common/error.h"
#include "common/snapshot_process.h"
#include "host/context.h"
#include "host/segment.h"


#define MAX_PARAMS_NPAGES	5

struct page_prot {
	unsigned char prot;
};

struct snapshot {
	unsigned long cr3;
	unsigned long rip;
	unsigned long rflags;
	struct context ctx;
	struct vmcs_segment segs[NSEGREG];

	int npages;
	unsigned long *orig_pfn;
	unsigned long *copy_pfn;
	pte_t *pte;

	unsigned long params_gpa[MAX_PARAMS_NPAGES];
	unsigned long params_uaddr;
	unsigned int params_npages;

	struct snapshot_process process;
};

extern struct snapshot snapshot;
extern int snapshot_done;

struct vcpu;

void delete_snapshot(void);
pte_t snapshot_gpa_to_hva(unsigned long gpa);
err_t shrink_memory(void);
err_t do_snapshot(struct vcpu *vcpu, unsigned long params_uaddr,
		  unsigned int params_size);

#endif /* HOST_SNAPSHOT_H */
