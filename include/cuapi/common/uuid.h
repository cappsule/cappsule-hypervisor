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

#ifndef CUAPI_UUID_H
#define CUAPI_UUID_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#endif

struct uuid {
	uint32_t timelow;
	uint16_t timemid;
	uint16_t version_timehigh;
	uint8_t  variant_clockseqhigh;
	uint8_t  clockseqlow;
	uint8_t  node[6];
};

#endif /* CUAPI_UUID_H */
