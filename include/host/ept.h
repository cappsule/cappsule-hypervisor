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

#ifndef _EPT_H
#define _EPT_H 1

#include <asm/pgtable.h>

#define EPT_PROT_READ	(1 << 0)
#define EPT_PROT_WRITE	(1 << 1)
#define EPT_PROT_EXEC	(1 << 2)
#define EPT_PROT_RW	(EPT_PROT_READ | EPT_PROT_WRITE)
#define EPT_PROT_RX	(EPT_PROT_READ | EPT_PROT_EXEC)
#define EPT_PROT_RWX	(EPT_PROT_READ | EPT_PROT_WRITE | EPT_PROT_EXEC)


/* PGD (PML4E)
 *
 * (N–1):12  Physical address of 4-KByte aligned EPT page-directory-pointer
 *           table referenced by this entry
 *
 * Since no processors supporting the Intel 64 architecture support more than
 * 48 physical-address bits, the size of field "addr" is 36 bits. Ditto for
 * other structures. */
struct ept_pgd_bits {
	unsigned read		:1;
	unsigned write		:1;
	unsigned exec		:1;
	unsigned reserved1	:5;
	unsigned accessed	:1;
	unsigned ignored1	:3;
	unsigned long addr	:36;
	unsigned reserved2	:4;
	unsigned ignored2	:12;
} __attribute__((packed));

union ept_pgd {
	struct ept_pgd_bits bits;
	__u64 value;
};

/* PUD (PDPTE) */
struct ept_pud_bits {
	unsigned read		:1;
	unsigned write		:1;
	unsigned exec		:1;
	unsigned reserved1	:5;
	unsigned accessed	:1;
	unsigned ignored1	:3;
	unsigned long addr	:36;
	unsigned reserved2	:4;
	unsigned ignored2	:12;
} __attribute__((packed));

union ept_pud {
	struct ept_pud_bits bits;
	__u64 value;
};

/* PMD (PDE) */
struct ept_pmd_bits {
	unsigned read		:1;
	unsigned write		:1;
	unsigned exec		:1;
	unsigned reserved1	:4;
	unsigned zero		:1;
	unsigned accessed	:1;
	unsigned ignored1	:3;
	unsigned long addr	:36;
	unsigned reserved2	:4;
	unsigned ignored2	:12;
} __attribute__((packed));

union ept_pmd {
	struct ept_pmd_bits bits;
	__u64 value;
};

/* PTE */
struct ept_pte_bits {
	unsigned read		:1;
	unsigned write		:1;
	unsigned exec		:1;
	unsigned mem_type	:3;
	unsigned ignore_pat	:1;
	unsigned ignored1	:1;
	unsigned accessed	:1;
	unsigned dirty		:1;
	unsigned ignored2	:2;
	unsigned long addr	:36;
	unsigned reserved1	:4;
	unsigned ignored3	:11;
	unsigned suppress_ve	:1;
} __attribute__((packed));

union ept_pte {
	struct ept_pte_bits bits;
	__u64 value;
};

/* bits 47:39 */
#define ept_pgd_index(x)	((x >> 39) & 0x1ff)

/* bits 38:30 */
#define ept_pud_index(x)	((x >> 30) & 0x1ff)

/* bits 29:21 */
#define ept_pmd_index(x)	((x >> 21) & 0x1ff)

/* bits 20:12 */
#define ept_pte_index(x)	((x >> 12) & 0x1ff)

static inline int ept_pgd_present(union ept_pgd *pgd)
{
	return (pgd->value & 3) != 0;
}

static inline int ept_pud_present(union ept_pud *pud)
{
	return (pud->value & 3) != 0;
}

static inline int ept_pmd_present(union ept_pmd *pmd)
{
	return (pmd->value & 3) != 0;
}

static inline int ept_pte_present(union ept_pte *pte)
{
	return (pte->value & 3) != 0;
}

static inline unsigned long get_pte_prot(pte_t hpa)
{
	unsigned long prot;
	int force_exec = 1;

	prot = 0;

	if (pte_write(hpa))
		prot |= EPT_PROT_RW;

	/* XXX: always force EPT execute access to 1. */
	if (pte_exec(hpa) || force_exec)
		prot |= EPT_PROT_RX;

	return prot;
}

struct vmcall_gpa_hva_convert;
struct capsule;
struct vcpu;

void exit_ept_violation(struct vcpu *vcpu);
void exit_ept_misconfig(struct vcpu *vcpu);
void *gpa_to_hva(struct capsule *capsule, unsigned long gpa, unsigned long *prot);
int install_ept_translation(struct capsule *capsule, unsigned long gpa,
			unsigned long hpa, unsigned long prot);
void remove_ept_translation(struct capsule *capsule, unsigned long gpa);
unsigned long vmcall_gpa_to_hva(struct vmcall_gpa_hva_convert *convert);

#endif /* _EPT_H */
