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

#ifndef COMMON_CR4_H
#define COMMON_CR4_H

#include <linux/version.h>
#include <asm/tlbflush.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
/* Set in this cpu's CR4. */
static inline void cr4_set_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = read_cr4();
	if ((cr4 | mask) != cr4) {
		cr4 |= mask;
		write_cr4(cr4);
	}
}

/* Clear in this cpu's CR4. */
static inline void cr4_clear_bits(unsigned long mask)
{
	unsigned long cr4;

	cr4 = read_cr4();
	if ((cr4 & ~mask) != cr4) {
		cr4 &= ~mask;
		write_cr4(cr4);
	}
}
#endif

#endif /* COMMON_CR4_H */
