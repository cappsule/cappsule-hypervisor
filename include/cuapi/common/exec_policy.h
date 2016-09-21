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

#ifndef CUAPI_EXEC_POLICY_H
#define CUAPI_EXEC_POLICY_H

#include "cuapi/common/uuid.h"

struct exec_policy {
	struct uuid uuid;
	unsigned int n;		/* number of paths */
	unsigned char data[];	/* unsigned int offsets[n];
				 * char paths[][n]; */
};

struct exec_policies {
	unsigned int n;		/* number of policies */
	unsigned int size;	/* size of policies (in bytes), page size aligned */
	unsigned char data[];	/* unsigned int offsets[n];
				 * struct exec_policy policies[n]; */
};

#endif /* CUAPI_EXEC_POLICY_H */
