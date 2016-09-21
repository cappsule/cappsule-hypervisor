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

#ifndef _COMMON_MEMORY_H
#define _COMMON_MEMORY_H

#include <asm/pgtable.h>


static inline void poison(void *addr, int c, size_t size)
{
	if (addr != NULL)
		memset(addr, c, size);
}

/**
 * Get PFN of user virtual address.
 * This function is declared in a header file because it's used by guest and
 * host.
 *
 * @return zero on error, -1 otherwise
 */
static inline unsigned long uaddr_pfn(unsigned long cr3, unsigned long uaddr)
{
	unsigned long pfn;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	pgd = (pgd_t *)__va(cr3 & PHYSICAL_PAGE_MASK) + pgd_index(uaddr);
	if (pgd_none(*pgd))
		return 0;

	pud = pud_offset(pgd, uaddr);
	if (pud_none(*pud))
		return 0;

	if (pud_large(*pud)) {
		pte = (pte_t *)pud;
		if (!pte_present(*pte))
			return 0;

		pfn = pte_pfn(*pte) + ((uaddr & ~PUD_MASK) >> PAGE_SHIFT);
		return pfn;
	}

	pmd = pmd_offset(pud, uaddr);
	if (pmd_none(*pmd))
		return 0;

	if (pmd_large(*pmd)) {
		pte = (pte_t *)pmd;
		if (!pte_present(*pte))
			return 0;

		pfn = pte_pfn(*pte) + ((uaddr & ~PMD_MASK) >> PAGE_SHIFT);
		return pfn;
	}

	pte = pte_offset_kernel(pmd, uaddr);

	if (pte_present(*pte))
		return pte_pfn(*pte);

	return 0;
}


#endif /* _COMMON_MEMORY_H */
