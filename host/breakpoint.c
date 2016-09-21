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
#include <linux/binfmts.h>
#include <asm/vmx.h>

#include "common/log.h"
#include "host/breakpoint.h"
#include "host/symbols.h"
#include "host/vcpu.h"
#include "host/vmx.h"

#define CALL_SIZE	5

extern void guest_schedule_end_stub(void);
extern void guest_schedule_tail_end_stub(void);
extern void guest_do_exit_stub(void);
extern void guest_prepare_binprm_stub(void);
extern void process_one_work_stub(void);

struct breakpoint bp_do_exit,
	bp_schedule_end,
	bp_schedule_tail_end,
	bp_prepare_binprm,
	bp_vt_console_print,
	bp_process_one_work;


/* Breakpoint in encapsulated guest.
 *
 * Return 0 if INT3 trap must be delivered, otherwise, return 1 and emulate
 * hooked instruction. */
int handle_int3_hook(struct vcpu *vcpu)
{
	unsigned long rip;

	rip = cpu_vmcs_readl(GUEST_RIP);

	if (rip == bp_do_exit.addr) {
		/* guest_do_exit_stub() uses rax to return in do_exit() */
		vcpu->regs.rax = rip + CALL_SIZE;

		/* redirect execution to guest_do_exit_stub */
		cpu_vmcs_writel(GUEST_RIP, (unsigned long)guest_do_exit_stub);
		return 1;
	}

	else if (rip == bp_prepare_binprm.addr) {
		/* guest_prepare_binprm_stub() uses rax to return to
		 * prepare_binprm() */
		vcpu->regs.rax = rip + CALL_SIZE;

		/* redirect execution to guest_prepare_binprm_stub */
		cpu_vmcs_writel(GUEST_RIP, (unsigned long)guest_prepare_binprm_stub);
		return 1;
	}

	else if (rip == bp_schedule_end.addr) {
		/* redirect execution to guest_schedule_end_stub */
		cpu_vmcs_writel(GUEST_RIP, (unsigned long)guest_schedule_end_stub);
		return 1;
	}

	else if (rip == bp_schedule_tail_end.addr) {
		/* redirect execution to guest_schedule_tail_end_stub */
		cpu_vmcs_writel(GUEST_RIP, (unsigned long)guest_schedule_tail_end_stub);
		return 1;
	}

	else if (rip == bp_vt_console_print.addr) {
		cappsule_dmesg(vcpu->capsule, vcpu->regs.rsi, vcpu->regs.rdx);

		cpu_vmcs_writel(GUEST_RIP, rip + CALL_SIZE);
		return 1;
	}

	else if (rip == bp_process_one_work.addr) {
		vcpu->regs.rax = rip + CALL_SIZE;
		cpu_vmcs_writel(GUEST_RIP, (unsigned long)process_one_work_stub);
		return 1;
	}

	else {
		return 0;
	}
}
