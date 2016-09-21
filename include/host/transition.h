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

#ifndef _HOST_TRANSITION_H
#define _HOST_TRANSITION_H 1

struct capsule;
struct vcpu;

void force_shadow_process_fpu_usage(void);
void switch_to_trusted(struct vcpu *vcpu);
void switch_to_capsule(struct vcpu *vcpu, struct capsule *capsule);
err_t load_trusted_vmcs(struct vcpu *vcpu);
err_t load_capsule_vmcs(struct vcpu *vcpu, struct capsule *capsule);

#endif /* _HOST_TRANSITION_H */
