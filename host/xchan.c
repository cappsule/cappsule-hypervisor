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

#include <linux/eventfd.h>
#include <linux/kref.h>
#include <linux/sched.h>
#include <linux/miscdevice.h>
#include <linux/eventfd.h>
#include <linux/export.h>
#include <linux/if_tun.h>
#include <asm/uaccess.h>
#include <linux/ioctl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <net/sock.h>

#include "common/log.h"
#include "common/memory.h"
#include "common/params.h"
#include "common/xchan.h"
#include "host/capsule.h"
#include "host/ept.h"
#include "host/interrupt.h"
#include "host/vmm.h"
#include "host/vmx.h"
#include "host/xchan.h"


int xchan_notify_trusted(struct vcpu *vcpu, unsigned long arg0)
{
	enum xchan_type xchan_type;
	struct eventfd_ctx *event;
	struct capsule *capsule;

	xchan_type = arg0;
	if (xchan_type < 0 || xchan_type >= XCHAN_TYPE_MAX)
		return -EINVAL;

	capsule = current_capsule(vcpu);

	/* XXX: needs lock? */
	event = capsule->xchan.events[xchan_type];

	/* event is NULL if device in trusted guest doesn't have its xchan
	 * yet */
	if (event == NULL) {
		hv_dbg("%s: event is NULL (%d)", __func__, xchan_type);
		return -EINVAL;
	}

	eventfd_signal(event, 1);

	return 0;
}

int xchan_set_event(unsigned int id, unsigned long arg1, struct eventfd_ctx *event)
{
	enum xchan_type xchan_type;
	struct capsule *capsule;
	int ret;

	xchan_type = arg1;
	if (xchan_type < 0 || xchan_type >= XCHAN_TYPE_MAX)
		return -EINVAL;

	capsule = get_capsule_from_id(id);
	if (capsule == NULL) {
		hv_info("xchan failed to set event (invalid id %d)", id);
		return -EINVAL;
	}

	if (capsule->xchan.events[xchan_type] == NULL) {
		capsule->xchan.events[xchan_type] = event;
		ret = capsule->vcpu->cpu;
	} else {
		hv_info("xchan failed to set event (already set, id: %d)", id);
		ret = -EINVAL;
	}

	put_capsule(capsule);

	return ret;
}

void xchan_map_guest_page(struct vcpu *vcpu, unsigned long gpa, unsigned int n)
{
	struct capsule *capsule;
	unsigned long hpa;
	int err;

	capsule = current_capsule(vcpu);
	if (n >= XCHAN_NPAGES_TOTAL)
		kill_s(capsule, KILL_XCHAN_MAP_INVALID_INDEX);

	remove_ept_translation(capsule, gpa);

	hpa = __pa(capsule->params->xchan_pages + n * PAGE_SIZE);
	err = install_ept_translation(capsule, gpa, hpa, EPT_PROT_RW);
	if (err != 0)
		kill_s(capsule, KILL_XCHAN_MAP_PAGES);

	/* XXX: INVEPT_SINGLE_CONTEXT doesn't work */
	invept(INVEPT_ALL_CONTEXT, 0);
}

void xchan_guest_closed(struct vcpu *vcpu, unsigned long arg0)
{
	struct capsule *capsule;
	kill_t reason;

	capsule = current_capsule(vcpu);

	switch (arg0) {
	case XCHAN_NET:		reason = KILL_XCHAN_CLOSED_NET; break;
	case XCHAN_GUI:		reason = KILL_XCHAN_CLOSED_GUI; break;
	case XCHAN_FS:		reason = KILL_XCHAN_CLOSED_FS; break;
	case XCHAN_CONSOLE:	reason = KILL_XCHAN_CLOSED_CONSOLE; break;
	default:		reason = KILL_XCHAN_CLOSED_INVALID; break;
	}

	kill_s(capsule, reason);
}
