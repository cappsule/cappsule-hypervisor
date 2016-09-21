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

#ifndef _GUEST_SHARED_MEM_H
#define _GUEST_SHARED_MEM_H

#include "common/shared_mem.h"

extern struct shared_mem *shared_mem;

static inline void guest_get_self_policy_uuid(struct uuid *uuid)
{
	*uuid = shared_mem->policy_uuid;
}

/* Host may try to access to guest memory (eg: during installation of xchan
 * pages), but EPT translation may not have been installed yet, because pages
 * have been allocated in guest, but not read nor written.
 *
 * Force EPT violation with read access just after allocation. */
static inline void trigger_ept_violation(unsigned long page)
{
	volatile unsigned char c;
	unsigned char *addr;

	addr = (char *)page;
	c = addr[0];
}

unsigned int guest_get_capsule_id(void);
void setup_shared_mem(void);

#endif /* _GUEST_SHARED_MEM_H */
