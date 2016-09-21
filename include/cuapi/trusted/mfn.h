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

#ifndef CUAPI_HOST_MFN_H
#define CUAPI_HOST_MFN_H

struct host_mfn {
	unsigned int capsule_id;
#ifdef __KERNEL__
	unsigned long __user *user_pfntable;
#else
	unsigned long *pfntable;
#endif /* __KERNEL__ */
	unsigned long num_mfn;
};

#endif /* CUAPI_HOST_MFN_H */
