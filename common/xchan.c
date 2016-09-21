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

#include <linux/percpu.h>

#include "common/vmcall.h"
#include "common/xchan.h"
#include "host/interrupt.h"
#include "host/vcpu.h"
#include "host/vmm.h"


/* Can be called both in VMX root mode and VMX non root-mode.
 *
 * Wake up shadow process if capsule isn't running, otherwise inject pending
 * interrupt. */
void cpu_xchan_notify_guest(void *arg)
{
	struct xchan_pending_intr *intr;
	unsigned long reason;
	unsigned int cpu, id;
	struct vcpu *vcpu;
	__u8 vector;
	int ret;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];

	intr = (struct xchan_pending_intr *)arg;
	id = intr->capsule_id;
	vector = intr->vector;

	if (vcpu->guest == GUEST_CAPSULE) {
		/* VMX root mode */
		ret = host_add_pending_xchan_intr(vcpu, id, vector);
	} else {
		/* VMX non-root mode */
		reason = VMCALL_ADD_PENDING_XCHAN_INTR;
		ret = cpu_vmcs_vmcall3_ret(reason, id, vector);
	}

	intr->error = ret;
}
