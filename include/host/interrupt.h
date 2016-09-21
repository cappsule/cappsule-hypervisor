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

#ifndef HOST_INTERRUPT_H
#define HOST_INTERRUPT_H

struct capsule;
struct vcpu;

void add_pending_intr(struct capsule *capsule, __u8 vector, int running);
void vmcall_add_pending_timer_intr(unsigned int id);
int vmcall_add_pending_xchan_intr(unsigned int id, __u8 vector);
void exit_pending_intr(struct vcpu *vcpu);
void exit_external_intr(struct vcpu *vcpu);
void exit_exception_or_nmi(struct vcpu *vcpu, unsigned long exit_qualification);
void resolve_interrupt_handlers(void);
void inject_gp_exception(int error_code);
void inject_ud_exception(void);
int host_add_pending_xchan_intr(struct vcpu *vcpu, unsigned int id, __u8 vector);

#endif /* HOST_INTERRUPT_H */
