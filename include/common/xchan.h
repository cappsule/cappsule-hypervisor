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

#ifndef COMMON_XCHAN_H
#define COMMON_XCHAN_H

#include <asm/irq_vectors.h>
#include <linux/kref.h>

#include "cuapi/common/xchan.h"

#ifndef IRQ0_VECTOR
#  define IRQ0_VECTOR	((FIRST_EXTERNAL_VECTOR + 16) & ~15)
#  define IRQ15_VECTOR	(IRQ0_VECTOR + 15)
#endif

struct xchan_pending_intr {
	unsigned int capsule_id;
	__u8 vector;
	int error;
};

static inline unsigned int xchan_vector_to_irq(unsigned int vector)
{
	return (vector - IRQ0_VECTOR) & 0xff;
}

void cpu_xchan_notify_guest(void *arg);

#endif /* COMMON_XCHAN_H */
