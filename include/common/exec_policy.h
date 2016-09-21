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

#ifndef EXEC_POLICY_H
#define EXEC_POLICY_H

#include "cuapi/common/exec_policy.h"

void free_exec_policies(struct exec_policies *policies);
struct exec_policies *copy_exec_policies(char __user *buf, size_t size);
struct exec_policies *get_exec_policies(void);
void set_exec_policies(struct exec_policies *p);

#endif /* EXEC_POLICY_H */
