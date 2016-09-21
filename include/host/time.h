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

#ifndef HOST_TIME_H
#define HOST_TIME_H

struct vcpu;

void init_clock_timer(struct capsule *capsule);
void vmcall_set_timer(struct vcpu *vcpu, __u64 nsec);
void capsule_tsc_deadline(struct vcpu *vcpu, __u64 value);
enum hrtimer_restart capsule_clock_event_function(struct capsule *capsule);

#endif /* HOST_TIME_H */
