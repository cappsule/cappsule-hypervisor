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

#ifndef HOST_XCHAN_H
#define HOST_XCHAN_H

#include "common/xchan.h"

struct xchan {
	struct eventfd_ctx *events[XCHAN_TYPE_MAX];
};

struct vcpu;

int xchan_set_event(unsigned int id, unsigned long arg1, struct eventfd_ctx *event);
int xchan_notify_trusted(struct vcpu *vcpu, unsigned long arg0);
void xchan_map_guest_page(struct vcpu *vcpu, unsigned long gpa, unsigned int n);
void xchan_guest_closed(struct vcpu *vcpu, unsigned long arg0);

#endif /* HOST_XCHAN_H */
