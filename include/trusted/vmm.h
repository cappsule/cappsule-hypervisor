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

#ifndef TRUSTED_VMM_H
#define TRUSTED_VMM_H

#include "common/error.h"

struct vcpu;

err_t cpu_enable_vmx(struct vcpu *vcpu);
void kill_all_capsules(void);
err_t init_vmm(void);
void free_vmm(void);
void stop_vmm(void);

#endif /* TRUSTED_VMM_H */
