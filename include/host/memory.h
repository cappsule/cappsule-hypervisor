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

#ifndef HOST_MEMORY_H
#define HOST_MEMORY_H

#include <asm/pgtable_types.h>

enum guest_mem_type {
	MEM_EPT,	/* page allocated by host for EPT */
	MEM_GUEST,	/* page for guest memory */
};

struct capsule;
struct winsize;
struct vcpu;

#define PTE_IGNORED_SHIFT	52
#define PTE_IS_INVALID(pte)	(pte_val(pte) == -1)
#define INVALID_PTE		__pte(-1)

/* Bits 62:52 are ignored. Use them to store page table level */
static inline enum pg_level get_pte_level(pte_t pte)
{
	return (pte.pte >> PTE_IGNORED_SHIFT) & 0x7ff;
}

static inline int set_pte_level(pte_t *pte, enum pg_level level)
{
	if (get_pte_level(*pte) != 0)
		return -1;

	pte->pte |= ((unsigned long)level << PTE_IGNORED_SHIFT);
	return 0;
}

pte_t get_host_pte(unsigned long pfn, enum pg_level *level);
void free_capsule_mem(struct capsule *capsule);
void dump_guest_calltrace(struct vcpu *vcpu);
struct guest_mem *alloc_guest_mem(void);
void free_guest_mem(struct guest_mem *mem);
void track_alloc(struct capsule *capsule, struct page *page,
		enum guest_mem_type type);
void alloc_guest_page(struct capsule *capsule, unsigned long gpa);

void map_argv_envp(struct capsule *capsule);
void map_exec_policies(struct capsule *capsule);

void share_device_mem(struct capsule *capsule, unsigned long gpa);
int resize_capsule_console(struct capsule *capsule,
			   struct winsize *console_size);

#endif /* HOST_MEMORY_H */
