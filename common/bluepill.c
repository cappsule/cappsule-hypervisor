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

#include <linux/cpu.h>

#include <asm/virtext.h>

#include "common/bluepill.h"
#include "common/cr4.h"
#include "common/error.h"
#include "common/log.h"
#include "common/vmcall.h"
#include "host/capsule.h"
#include "host/segment.h"
#include "host/transition.h"
#include "host/vcpu.h"
#include "host/vmcs.h"
#include "host/vmm.h"
#include "host/vmx.h"
#include "trusted/vmm.h"


/* can run in VMX root and non-root mode */
void cpu_stop_vmm(void *arg)
{
	struct vcpu *vcpu;
	unsigned int cpu;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];

	if (vcpu->bluepilled) {
		atomic_inc(&vmm.pending_vmx_stop);
		/* CPU will exit VMX on next vm-exit */
		vcpu->stop_vmx = true;
	}
}

/* This function begins its execution in VMX non-root mode, and if VMLAUNCH
 * succeeeds, returns in VMX root mode. */
static err_t cpu_vmx_fork(struct vcpu *vcpu)
{
	unsigned long guest_rflags, guest_rip, guest_rsp, host_rsp;
	__u32 vm_instr_error;
	__u8 error, cf, zf;
	err_t err;

	guest_rip = (unsigned long)&&guest_start;
	host_rsp = (unsigned long)vcpu->vmm_stack + PAGE_SIZE - 0x10;
	asm volatile ("mov %%rsp, %0" : "=m"(guest_rsp));

	/* Ensure CPU state isn't modified between VMCS initialization and
	 * vmlaunch. No need to call local_irq_restore() if vmlaunch succeeds,
	 * because guest_rflags is saved before interrupts disabling. */
	local_irq_save(guest_rflags);

	err = init_trusted_vmcs(vcpu->vmcs_trusted,
			  vcpu->trusted_template,
			  host_rsp,
			  vcpu->trusted_ctx.autoload_msr,
			  guest_rip,
			  guest_rsp,
			  guest_rflags);
	if (err != SUCCESS)
		return err;

	err = load_trusted_vmcs(vcpu);
	if (err != SUCCESS)
		return err;

	asm volatile (
		 ASM_VMX_VMLAUNCH "\n"
		 "setna %0\n"
		 "setb	%1\n"
		 "sete	%2\n"
		 : "=q"(error), "=qm"(cf), "=qm"(zf) :: "cc"
		 );

	if (error) {
		local_irq_restore(guest_rflags);
		vm_instr_error = cpu_vmcs_read32(VM_INSTRUCTION_ERROR);
		hv_err("vmlaunch failed (error: %d cf=%d zf=%d)",
		       vm_instr_error, cf, zf);
		return ERROR_VMLAUNCH_FAILED;
	} else {
guest_start:
		vcpu->bluepilled = true;
		return SUCCESS;
	}
}

void cpu_disable_vmx(void *arg)
{
	if (cpu_vmx_enabled()) {
		hv_dbg("%s: cpu %d", __func__, smp_processor_id());

		/* prevents potentially undesired retention of information
		 * cached from EPT paging structures and paging structures
		 * between separate uses of VMX operation. */
		invept(INVEPT_ALL_CONTEXT, 0);
		invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);

		cpu_vmxoff();

		cr4_clear_bits(X86_CR4_VMXE);
	}
}

static void cpu_bluepill(void *arg)
{
	struct vcpu *vcpu;
	unsigned int cpu;
	err_t *error;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];
	error = arg;

	hv_dbg("%s: cpu %d", __func__, cpu);

	*error = cpu_enable_vmx(vcpu);
	if (*error != SUCCESS)
		return;

	*error = cpu_vmx_fork(vcpu);
	if (*error != SUCCESS) {
		cpu_disable_vmx(NULL);
		return;
	}
}

/* called in VMX mode and returns in VMX non-root mode */
void cpu_exit_bluepill(struct vcpu *vcpu)
{
	unsigned long fs_base, gs_base, rip, rsp, cr0, cr3, cr4, rflags;
	unsigned short ds, es, fs, gs, selector[NSEGREG];
	enum segment_reg r;

	rsp = cpu_vmcs_readl(GUEST_RSP);
	rip = cpu_vmcs_readl(GUEST_RIP);
	cr0 = cpu_vmcs_readl(GUEST_CR0);
	cr3 = cpu_vmcs_readl(GUEST_CR3);
	cr4 = cpu_vmcs_readl(GUEST_CR4);
	rflags = cpu_vmcs_readl(GUEST_RFLAGS);

	fs_base = cpu_vmcs_read64(GUEST_FS_BASE);
	gs_base = cpu_vmcs_read64(GUEST_GS_BASE);

	for (r = ES; r < NSEGREG; r++) {
		selector[r] = cpu_vmcs_read16(GUEST_ES_SELECTOR + r * 2);
	}

	savesegment(fs, fs);
	savesegment(gs, gs);
	savesegment(ds, ds);
	savesegment(es, es);

	cpu_disable_vmx(NULL);
	vcpu->bluepilled = false;

	/* notify vmm that VMX is disabled on this CPU */
	atomic_dec(&vmm.pending_vmx_stop);
	vcpu->stop_vmx = false;

	write_cr0(cr0);
	write_cr3(cr3);

	/* Trusted guest doesn't rely on MSR_FS_BASE and MSR_GS_BASE MSRs. VMCS
	 * fields (GUEST_FS_BASE and GUEST_GS_BASE) reflect these values. */
	wrmsrl(MSR_FS_BASE, fs_base);
	wrmsrl(MSR_GS_BASE, gs_base);

	if (fs != selector[FS]) {
		hv_warn("fs selector: 0x%hx 0x%hx", fs, selector[FS]);
		loadsegment(fs, selector[FS]);
	}

	if (gs != selector[GS]) {
		hv_warn("gs selector: 0x%hx 0x%hx", gs, selector[GS]);
		loadsegment(gs, selector[GS]);
	}

	if (es != selector[ES]) {
		hv_warn("es selector: 0x%hx 0x%hx", es, selector[ES]);
		loadsegment(es, selector[ES]);
	}

	if (ds != selector[DS]) {
		hv_warn("ds selector: 0x%hx 0x%hx", ds, selector[DS]);
		loadsegment(ds, selector[DS]);
	}

	/* TR and LDTR segment selectors don't seem to be modified after their
	 * initialization, no need to restore it. */

	/* no need to restore MSR since host MSR are identical to MSR of trusted
	 * guest */

	/* iret isn't necessary, but useful since it restores cs, ss, rsp and
	 * rflags */
	asm volatile (
		/* prepare iret stack */
		"pushq	%1\n"
		"pushq	%2\n"
		"pushq	%3\n"
		"pushq	%4\n"
		"pushq	%5\n"
		/* restore every general purpose register */
		"mov %c[rax](%%rcx), %%rax\n"
		"mov %c[r15](%%rcx), %%r15\n"
		"mov %c[r14](%%rcx), %%r14\n"
		"mov %c[r13](%%rcx), %%r13\n"
		"mov %c[r12](%%rcx), %%r12\n"
		"mov %c[rbp](%%rcx), %%rbp\n"
		"mov %c[rbx](%%rcx), %%rbx\n"
		"mov %c[r11](%%rcx), %%r11\n"
		"mov %c[r10](%%rcx), %%r10\n"
		"mov %c[r9](%%rcx),  %%r9\n"
		"mov %c[r8](%%rcx),  %%r8\n"
		"mov %c[rdx](%%rcx), %%rdx\n"
		"mov %c[rsi](%%rcx), %%rsi\n"
		"mov %c[rdi](%%rcx), %%rdi\n"
		"mov %c[rcx](%%rcx), %%rcx\n"
		/* return after instruction responsible of vm-exit */
		"iretq\n"
		: :
		  "c"(vcpu),	/* assign vpcu to rcx */
		  "r"(selector[SS]),
		  "r"(rsp),
		  "r"(rflags),
		  "r"(selector[CS]),
		  "r"(rip),
		  [rax]"i"(offsetof(struct vcpu, regs.rax)),
		  [rcx]"i"(offsetof(struct vcpu, regs.rcx)),
		  [rdx]"i"(offsetof(struct vcpu, regs.rdx)),
		  [rbx]"i"(offsetof(struct vcpu, regs.rbx)),
		  [rbp]"i"(offsetof(struct vcpu, regs.rbp)),
		  [rsi]"i"(offsetof(struct vcpu, regs.rsi)),
		  [rdi]"i"(offsetof(struct vcpu, regs.rdi)),
		  [r8]"i"(offsetof(struct vcpu, regs.r8)),
		  [r9]"i"(offsetof(struct vcpu, regs.r9)),
		  [r10]"i"(offsetof(struct vcpu, regs.r10)),
		  [r11]"i"(offsetof(struct vcpu, regs.r11)),
		  [r12]"i"(offsetof(struct vcpu, regs.r12)),
		  [r13]"i"(offsetof(struct vcpu, regs.r13)),
		  [r14]"i"(offsetof(struct vcpu, regs.r14)),
		  [r15]"i"(offsetof(struct vcpu, regs.r15))
		: "cc", "memory");
}

static int cappsule_cpu_callback(struct notifier_block *nfb,
				 unsigned long action, void *hcpu)
{
	unsigned int cpu;
	err_t error;
	int ret;

	cpu = (unsigned long)hcpu;
	ASSERT(cpu < vmm.max_cpus);

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		ret = NOTIFY_OK;
		break;

	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		hv_dbg("%s: CPU_ONLINE %d", __func__, cpu);
		get_online_cpus();

		if (!cpu_online(cpu)) {
			hv_err("%s: cpu %d offline", __func__, cpu);
			error = -EINVAL;
		} else {
			smp_call_function_single(cpu,
						 cpu_bluepill,
						 &error,
						 true);
		}

		put_online_cpus();
		/* error is lost */
		ret = error ? NOTIFY_BAD : NOTIFY_OK;
		break;

	case CPU_DYING:
	case CPU_DYING_FROZEN:
		/* CPU not running any task, not handling interrupts, soon dead.
		 * Called on the dying cpu, interrupts are already disabled.
		 * Must not sleep, must not fail. */
		/* XXX: what if capsules are running on dying cpu? */
		hv_dbg("%s: CPU_DYING %d", __func__, cpu);

		atomic_set(&vmm.pending_vmx_stop, 0);
		smp_call_function_single(cpu, cpu_stop_vmm, NULL, true);

		while (atomic_read(&vmm.pending_vmx_stop) > 0) {
			smp_call_function_single(cpu,
						 cpu_trigger_vm_exit,
						 NULL,
						 true);
		}
		ret = NOTIFY_OK;
		break;

	default:
		ret = NOTIFY_OK;
		break;
	}

	return ret;
}

struct notifier_block cappsule_cpu_notifier =
{
	.notifier_call = cappsule_cpu_callback,
};

err_t bluepill(void)
{
	unsigned int cpu;
	err_t error;

	//cpu_notifier_register_begin();
	get_online_cpus();

	for_each_online_cpu(cpu) {
		smp_call_function_single(cpu, cpu_bluepill, &error, true);
		if (error != SUCCESS)
			break;
	}

	if (error == SUCCESS) {
		register_cpu_notifier(&cappsule_cpu_notifier);
	} else {
		for_each_online_cpu(cpu) {
			smp_call_function_single(cpu,
						 cpu_stop_vmm,
						 NULL,
						 true);
		}
	}

	put_online_cpus();
	//cpu_notifier_register_done();

	return error;
}
