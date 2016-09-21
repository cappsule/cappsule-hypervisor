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

#ifndef COMMON_MFN_H
#define COMMON_MFN_H

struct vmcall_gpa_hva_convert {
	unsigned int capsule_id;
	uid_t xorg_uid;
	unsigned int num_mfn;
	unsigned long *gpa;	/* gpa array is given by trusted guest */
	unsigned long *res_hva;	/* hva array is filled by host */
};

#endif /* COMMON_MFN_H */
