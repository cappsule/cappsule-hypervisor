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

#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/traps.h>
#include <asm/vmx.h>

#include "host/capsule.h"
#include "host/transition.h"
#include "host/vmx.h"


void shadow_process_fpu_used(void);

/* force capsule to #NM on FPU usage */
static void trap_on_fpu_usage(struct capsule *capsule)
{
	unsigned long read_shadow;
	int host_owned;
	__u64 tmpl;
	__u32 tmp;

	capsule->fpu_used = 0;

	/* any modification of CR0.TS causes a VM-exit */
	tmpl = cpu_vmcs_readl(CR0_GUEST_HOST_MASK);
	host_owned = tmpl & X86_CR0_TS;
	if (!host_owned) {
		tmpl |= X86_CR0_TS;
		cpu_vmcs_writel(CR0_GUEST_HOST_MASK, tmpl);
	}

	/* any #NM causes a VM-exit */
	tmp = cpu_vmcs_read32(EXCEPTION_BITMAP);
	tmp |= (1 << X86_TRAP_NM);
	cpu_vmcs_write32(EXCEPTION_BITMAP, tmp);

	/* if CR0 guest host mask wasn't in use, set CR0 read shadow to the
	 * guest value */
	tmpl = cpu_vmcs_readl(GUEST_CR0);
	if (!host_owned) {
		read_shadow = cpu_vmcs_readl(CR0_READ_SHADOW);
		if ((read_shadow & X86_CR0_TS) != (tmpl & X86_CR0_TS)) {
			if (read_shadow & X86_CR0_TS)
				read_shadow &= ~X86_CR0_TS;
			else
				read_shadow |= X86_CR0_TS;
			cpu_vmcs_writel(CR0_READ_SHADOW, read_shadow);
		}
	}

	/* set guest CR0.TS (guest reads value from read shadow) to force #NM */
	if (!(tmpl & X86_CR0_TS)) {
		tmpl |= X86_CR0_TS;
		cpu_vmcs_writel(GUEST_CR0, tmpl);
	}
}

/* switch from trusted guest to capsule, not from capsule to capsule */
err_t load_capsule_vmcs(struct vcpu *vcpu, struct capsule *capsule)
{
	__u32 tmp;

	//tg_dbg("%s (cpu=%d)", __func__, smp_processor_id());

	ASSERT(vcpu == capsule->vcpu);

	if (cpu_vmcs_load(capsule->vmcs) != 0)
		return ERROR_LOAD_CAPSULE_VMCS;

	/* if pending interrupts, enable interrupt-window exiting */
	tmp = cpu_vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);
	if (intr_pending(capsule))
		tmp |= CPU_BASED_VIRTUAL_INTR_PENDING;
	else
		tmp &= ~CPU_BASED_VIRTUAL_INTR_PENDING;
	cpu_vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, tmp);

	trap_on_fpu_usage(capsule);

	vcpu->guest = GUEST_CAPSULE;
	vcpu->capsule = capsule;

	return SUCCESS;
}

err_t load_trusted_vmcs(struct vcpu *vcpu)
{
	//cpsl_dbg(vcpu->capsule->id, "%s (cpu=%d)",
	//	 __func__, smp_processor_id());

	ASSERT(vcpu->cpu == smp_processor_id());

	if (cpu_vmcs_load(vcpu->vmcs_trusted) != 0)
		return ERROR_LOAD_TRUSTED_VMCS;

	vcpu->guest = GUEST_TRUSTED;
	vcpu->capsule = NULL;

	return SUCCESS;
}

/* called from host */
void switch_to_capsule(struct vcpu *vcpu, struct capsule *capsule)
{
	struct regs regs;

	if (capsule->flags & CPSL_EXITED) {
		/* The capsule has already exited (but decapsulate has not been
		 * called). It should not try to schedule to capsule. */
		tg_info("%s: capsule has exited", __func__);
		return;
	}

	capsule->stats.nr_switches++;
	capsule->last_schedule = ktime_get();

	save_context(&vcpu->trusted_ctx, &vcpu->regs);
	restore_context(&capsule->ctx, &regs);

	if (load_capsule_vmcs(vcpu, capsule) != SUCCESS)
		kill_s(capsule, KILL_SWITCH_VM_TO_CAPSULE);

	cpu_vmx_resume(&regs);
}

/* Force shadow process to execute a FPU instruction. Since a capsule is
 * assigned to a shadow process:
 *  - we assume that the shadow process doesn't use FPU registers,
 *  - trusted guest kernel will save capsule FPU registers if shadow process is
 *    forced to execute one FPU instruction (fnop).
 *
 * Current vmcs must be the one from trusted guest */
void force_shadow_process_fpu_usage(void)
{
	unsigned long rsp;

	/* fake call to shadow_process_fpu_used (writes to trusted guest
	 * memory) */
	rsp = cpu_vmcs_readl(GUEST_RSP);
	rsp -= sizeof(unsigned long);
	*(unsigned long *)rsp = cpu_vmcs_readl(GUEST_RIP);
	cpu_vmcs_writel(GUEST_RSP, rsp);
	cpu_vmcs_writel(GUEST_RIP, (long)&shadow_process_fpu_used);
}

/* called from host */
void switch_to_trusted(struct vcpu *vcpu)
{
	struct capsule *capsule;
	struct task_struct *tsk;
	struct regs regs;
	ktime_t now;

	capsule = current_capsule(vcpu);
	tsk = get_current();

	now = ktime_get();
	timespec_add_ns(&capsule->stats.total_elapsed_time,
			ktime_to_ns(ktime_sub(now, capsule->last_schedule)));

	save_context(&capsule->ctx, &vcpu->regs);
	restore_context(&vcpu->trusted_ctx, &regs);

	if (load_trusted_vmcs(vcpu) != SUCCESS)
		panic("failed to load trusted vmcs");

	if (capsule->fpu_used) {
		force_shadow_process_fpu_usage();
		capsule->fpu_used = 0;
	}

	cpu_vmx_resume(&regs);
}
