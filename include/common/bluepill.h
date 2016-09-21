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

#ifndef BLUEPILL_H
#define BLUEPILL_H

#include "common/error.h"

struct vcpu;

void cpu_stop_vmm(void *arg);
void cpu_exit_bluepill(struct vcpu *vcpu);
err_t bluepill(void);

static void inline cpu_trigger_vm_exit(void *arg)
{
	cpuid_eax(0);
}

#endif /* BLUEPILL_H */
