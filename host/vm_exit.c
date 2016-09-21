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
#include <asm/vmx.h>
#include <asm/perf_event.h>
#include <asm/tlbflush.h>

#include "common/bluepill.h"
#include "common/log.h"
#include "common/vmcall.h"
#include "host/capsule.h"
#include "host/breakpoint.h"
#include "host/ept.h"
#include "host/interrupt.h"
#include "host/memory.h"
#include "host/snapshot.h"
#include "host/time.h"
#include "host/transition.h"
#include "host/vm_exit.h"
#include "host/vmm.h"
#include "host/vmx.h"
#include "host/xchan.h"

#define EXIT_REASON_GETSEC			11
#define EXIT_REASON_VM_ENTRY_FAILURE_MSR	34
#define EXIT_REASON_ACCESS_GDTR_IDTR		46
#define EXIT_REASON_ACCESS_LDTR_TR		47
#define EXIT_REASON_INVEPT			50
#define EXIT_REASON_INVVPID			53

struct qual_cr_access_bits {
	unsigned int cr			:4;
	unsigned int access_type	:2;
	unsigned int operand_type	:1;
	unsigned int reserved1		:1;
	unsigned int reg		:4;
	unsigned int reserved2		:4;
	unsigned int source_data	:16;
	unsigned int reserved3		:32;
} __attribute__((__packed__));

union qual_cr_access {
	struct qual_cr_access_bits bits;
	__u64 value;
};

struct qual_dr_access_bits {
	unsigned int dr			:3;
	unsigned int reserved1		:1;
	unsigned int direction		:1;
	unsigned int reserved2		:3;
	unsigned int reg		:4;
	unsigned int reserved3		:32;
	unsigned int reserved4		:20;
} __attribute__((__packed__));

union qual_dr_access {
	struct qual_dr_access_bits bits;
	__u64 value;
};

struct exit_qual_io_bits {
	unsigned int size		:3;
	unsigned int direction		:1;
	unsigned int string_instr	:1;
	unsigned int rep_prefixed	:1;
	unsigned int operand_enc	:1;
	unsigned int reserved1		:9;
	unsigned int port_number	:16;
	unsigned int reserved2		:32;
} __attribute__((__packed__));

union exit_qual_io {
	struct exit_qual_io_bits bits;
	__u64 value;
};

static void update_rip(void)
{
	unsigned long rip;
	__u32 len;

	rip = cpu_vmcs_readl(GUEST_RIP);
	len = cpu_vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	cpu_vmcs_writel(GUEST_RIP, rip + len);
}

/* set the TS bit of CR0 read shadow to the value expected by the capsule */
static void mov_to_cr0_capsule(struct vcpu *vcpu, unsigned long value)
{
	unsigned long mask, read_shadow;
	struct capsule *capsule;

	capsule = current_capsule(vcpu);
	mask = cpu_vmcs_readl(CR0_GUEST_HOST_MASK);
	read_shadow = cpu_vmcs_readl(CR0_READ_SHADOW);

	/* don't allow capsule to move an invalid value to CR0 */
	if ((value & mask & ~X86_CR0_TS) != (read_shadow & ~X86_CR0_TS))
		kill(vcpu, KILL_MOVE_TO_CR0);

	if (value & X86_CR0_TS)
		read_shadow |= X86_CR0_TS;
	else
		read_shadow &= ~X86_CR0_TS;
	cpu_vmcs_writel(CR0_READ_SHADOW, read_shadow);
}

static void exit_cr_clts_capsule(struct vcpu *vcpu)
{
	unsigned long mask, read_shadow;

	mask = cpu_vmcs_readl(CR0_GUEST_HOST_MASK);
	if (!(mask & X86_CR0_TS))
		kill(vcpu, KILL_CLTS);

	read_shadow = cpu_vmcs_readl(CR0_READ_SHADOW);
	read_shadow &= ~X86_CR0_TS;
	cpu_vmcs_writel(CR0_READ_SHADOW, read_shadow);
}

static void move_to_cr(struct vcpu *vcpu, union qual_cr_access cr_access)
{
	unsigned long value, *regs;
	struct capsule *capsule;
	unsigned short vpid;

	regs = (unsigned long *)&vcpu->regs;
	value = regs[cr_access.bits.reg];

	switch (cr_access.bits.cr) {
	case 0:
		if (vcpu->guest == GUEST_TRUSTED)
			tg_err("BUG: mov to CR0 (value: 0x%08lx)", value);
		else
			mov_to_cr0_capsule(vcpu, value);
		break;
	case 3:
		cpu_vmcs_writel(GUEST_CR3, value);

		if (vcpu->guest == GUEST_TRUSTED)
			vpid = TRUSTED_GUEST_VPID;
		else
			vpid = CAPSULE_VPID;
		invvpid(VMX_VPID_EXTENT_SINGLE_CONTEXT, vpid, 0);
		break;
	case 4:
		if (vcpu->guest == GUEST_CAPSULE) {
			capsule = current_capsule(vcpu);
			cpsl_info(capsule->id, "mov to CR4 (value: 0x%016lx)",
				  value);

			/* a write to CR4 triggers a VM-exit only if new value
			 * doesn't respect CR4 guest/host mask and CR4 read
			 * shadow */
			kill(vcpu, KILL_MOVE_TO_CR4);
		} else {
			/* this should never happen, otherwise invvpid must be
			 * called */
			tg_err("BUG: mov to CR4 (value: 0x%08lx)", value);
		}
		break;
	case 8:
		if (vcpu->guest == GUEST_TRUSTED)
			write_cr8(value);
		else
			kill(vcpu, KILL_MOVE_TO_CR8);
		break;
	default:
		if (vcpu->guest == GUEST_TRUSTED)
			tg_err("mov to CR%d", cr_access.bits.cr);
		else
			kill(vcpu, KILL_MOVE_TO_CRX);
		break;
	}
}

static void move_from_cr(struct vcpu *vcpu, union qual_cr_access cr_access)
{
	unsigned long value, *regs;

	switch (cr_access.bits.cr) {
	case 0:
		if (vcpu->guest == GUEST_CAPSULE)
			kill(vcpu, KILL_MOVE_FROM_CR0_BUG);
		else
			tg_err("BUG: VM-exit because of CR0 read");
		value = cpu_vmcs_readl(GUEST_CR0);
		break;

	case 3:
		value = cpu_vmcs_readl(GUEST_CR3);
		break;

	case 4:
		if (vcpu->guest == GUEST_CAPSULE)
			kill(vcpu, KILL_MOVE_FROM_CR4_BUG);
		else
			tg_err("BUG: VM-exit because of CR4 read");
		value = cpu_vmcs_readl(GUEST_CR4);
		break;

	case 8:
		if (vcpu->guest == GUEST_TRUSTED) {
			value = read_cr8();
		} else {
			kill(vcpu, KILL_MOVE_FROM_CR8);
			value = 0;
		}
		break;
	default:
		if (vcpu->guest == GUEST_TRUSTED) {
			tg_err("mov from CR%d", cr_access.bits.cr);
			return;
		} else {
			kill(vcpu, KILL_MOVE_FROM_CRX);
		}
		value = 0;
		break;
	}

	regs = (unsigned long *)&vcpu->regs;
	regs[cr_access.bits.reg] = value;
}

static void exit_cr_access(struct vcpu *vcpu, unsigned long qual)
{
	union qual_cr_access cr_access;
	unsigned long tmp;

	cr_access.value = qual;

	switch (cr_access.bits.access_type) {
	case 0:
		move_to_cr(vcpu, cr_access);
		break;
	case 1:
		move_from_cr(vcpu, cr_access);
		break;
	case 2:
		if (vcpu->guest == GUEST_TRUSTED) {
			tg_err("BUG: unexpected VM-exit because of CLTS");
			tmp = cpu_vmcs_readl(GUEST_CR0);
			tmp &= ~X86_CR0_TS;
			cpu_vmcs_writel(GUEST_CR0, tmp);
		} else {
			exit_cr_clts_capsule(vcpu);
		}
		break;
	case 3:
		/* TODO */
		if (vcpu->guest == GUEST_TRUSTED)
			tg_err("execution of LMSW");
		else
			kill(vcpu, KILL_LMSW_TODO);
		break;
	}
}

static int guest_cpl(void)
{
	return cpu_vmcs_read32(GUEST_CS_SELECTOR) & 3;
}

static void exit_dr_access(struct vcpu *vcpu, unsigned long qual)
{
	union qual_dr_access dr_access;
	unsigned long *regs;

	/* "MOV DR" [...] exits represent an exception to the principles
	 * identified in Section 25.1.1 in that they take priority over the
	 * following: general-protection exceptions based on privilege level;
	 * and invalid-opcode exceptions that occur because CR4.DE=1 and the
	 * instruction specified access to DR4 or DR5. */
	if (guest_cpl() != 0) {
		inject_gp_exception(0);
		return;
	}

	dr_access.value = qual;

	regs = (unsigned long *)&vcpu->regs;
	/*cpsl_dbg(vcpu->capsule->id, "%s DR%d (reg%d %016lx)",
		dr_access.bits.direction ? "read from" : "write to",
		dr_access.bits.dr,
		dr_access.bits.reg,
		regs[dr_access.bits.reg]);*/

	/* allow read from DR, always return 0 */
	if (dr_access.bits.direction == 1) {
		regs[dr_access.bits.reg] = 0;
	} else {
		/* ignore write to DR6 if value equals 0 (to allow gdb to work
		 * properly), and kill capsule otherwise */
		if (dr_access.bits.dr != 6 || regs[dr_access.bits.reg] != 0)
			kill(vcpu, KILL_WRITE_TO_DR);
	}

	update_rip();
}

static void exit_cpuid(struct vcpu *vcpu)
{
	unsigned int eax, ebx, ecx, edx;
	int info_and_features;

	eax = vcpu->regs.rax;
	ecx = vcpu->regs.rcx;
	info_and_features = (eax == 1);
	native_cpuid(&eax, &ebx, &ecx, &edx);

	/* don't let capsule think that cpu has vmx */
	if (info_and_features && vcpu->guest == GUEST_CAPSULE)
		ecx &= ~(1 << 5);

	vcpu->regs.rax = eax;
	vcpu->regs.rbx = ebx;
	vcpu->regs.rcx = ecx;
	vcpu->regs.rdx = edx;
}

static void exit_invlpg(struct vcpu *vcpu, unsigned long gva, int trusted)
{
	unsigned short vpid;

	/* if the memory address is in non-canonical form [...] INVLPG is the
	 * same as a NOP. */
	if ((((long)gva << 16) >> 16) != gva)
		return;

	vpid = trusted ? TRUSTED_GUEST_VPID : CAPSULE_VPID;
	invvpid(VMX_VPID_EXTENT_INDIVIDUAL_ADDR, vpid, gva);
}

static __u64 read_capsule_msr(struct vcpu *vcpu, __u32 msr)
{
	struct capsule *capsule;
	__u64 value;

	capsule = current_capsule(vcpu);
	switch (msr) {
	case MSR_KERNEL_GS_BASE:
		value = capsule->ctx.autoload_msr[0].value;
		break;
	default:
		value = 0;
		/* read from invalid autoload-MSR */
		kill(vcpu, KILL_AUTOLOAD_MSR_READ);
	}

	return value;
}

static void write_capsule_msr(struct vcpu *vcpu, __u32 msr, __u64 value)
{
	struct capsule *capsule;

	capsule = current_capsule(vcpu);
	switch (msr) {
	case MSR_KERNEL_GS_BASE:
		capsule->ctx.autoload_msr[0].value = value;
		break;
	default:
		/* write to invalid autoload-MSR */
		kill(vcpu, KILL_AUTOLOAD_MSR_WRITE);
	}
}

static void exit_msr_read(struct vcpu *vcpu)
{
	__u32 ecx = vcpu->regs.rcx;
	__u64 value;

	switch (ecx) {
	case MSR_FS_BASE:
		value = cpu_vmcs_read64(GUEST_FS_BASE);
		break;
	case MSR_GS_BASE:
		value = cpu_vmcs_read64(GUEST_GS_BASE);
		break;
	case MSR_IA32_SYSENTER_CS:
		value = cpu_vmcs_read32(GUEST_SYSENTER_CS);
		break;
	case MSR_KERNEL_GS_BASE:
		/* host shares its MSRs with trusted guest */
		if (vcpu->guest == GUEST_TRUSTED)
			rdmsrl(MSR_KERNEL_GS_BASE, value);
		else
			value = read_capsule_msr(vcpu, MSR_KERNEL_GS_BASE);
		break;
	case MSR_IA32_SYSENTER_ESP:
		value = cpu_vmcs_read64(GUEST_SYSENTER_ESP);
		break;
	case MSR_IA32_SYSENTER_EIP:
		value = cpu_vmcs_read64(GUEST_SYSENTER_EIP);
		break;
	case MSR_IA32_MCG_CAP:
	case MSR_IA32_MCG_STATUS:
	case MSR_IA32_TEMPERATURE_TARGET:
	case MSR_MTRRfix64K_00000:
	case MSR_MTRRfix16K_80000:
	case MSR_MTRRfix16K_A0000:
	case MSR_MTRRfix4K_C0000:
	case MSR_MTRRfix4K_C8000:
	case MSR_MTRRfix4K_D0000:
	case MSR_MTRRfix4K_D8000:
	case MSR_MTRRfix4K_E0000:
	case MSR_MTRRfix4K_E8000:
	case MSR_MTRRfix4K_F0000:
	case MSR_MTRRfix4K_F8000:
	case MSR_MTRRdefType:
	case MSR_IA32_PERF_CTL:
	case MSR_CORE_PERF_GLOBAL_STATUS:
		rdmsrl(ecx, value);
		break;
	default:
		if (vcpu->guest != GUEST_TRUSTED) {
			//struct capsule *capsule = current_capsule(vcpu);
			//cpsl_dbg(capsule->id, "rdmsr(0x%x) = 0x%016lx",
			//	 ecx, vcpu->regs.rax | (vcpu->regs.rdx << 32));
		}
		rdmsrl(ecx, value);
		break;
	}

	vcpu->regs.rax = value & 0xffffffff;
	vcpu->regs.rdx = value >> 32;
}

static void exit_msr_write_trusted(struct vcpu *vcpu, __u32 ecx, __u64 value)
{
	switch (ecx) {
	case MSR_FS_BASE:
		cpu_vmcs_write64(GUEST_FS_BASE, value);
		break;
	case MSR_GS_BASE:
		cpu_vmcs_write64(GUEST_GS_BASE, value);
		break;
	case MSR_IA32_SYSENTER_CS:
		cpu_vmcs_write32(GUEST_SYSENTER_CS, value);
		break;
	case MSR_IA32_SYSENTER_ESP:
		cpu_vmcs_write64(GUEST_SYSENTER_ESP, value);
		break;
	case MSR_IA32_SYSENTER_EIP:
		cpu_vmcs_write64(GUEST_SYSENTER_EIP, value);
		break;
	case MSR_IA32_PERF_CTL:
	case MSR_CORE_PERF_FIXED_CTR1:
	case MSR_CORE_PERF_GLOBAL_CTRL:
	case MSR_CORE_PERF_GLOBAL_OVF_CTRL:
	case MSR_IA32_TSC_DEADLINE:
		wrmsr(ecx, vcpu->regs.rax, vcpu->regs.rdx);
		break;
	default:
		//tg_dbg("wrmsr(0x%x, 0x%016llx)", ecx, value);
		wrmsr(ecx, vcpu->regs.rax, vcpu->regs.rdx);
		break;
	}
}

static void exit_msr_write_capsule(struct vcpu *vcpu, __u32 ecx, __u64 value)
{
	struct capsule *capsule;

	switch (ecx) {
	case MSR_FS_BASE:
		cpu_vmcs_write64(GUEST_FS_BASE, value);
		break;
	case MSR_GS_BASE:
		cpu_vmcs_write64(GUEST_GS_BASE, value);
		break;
	case MSR_KERNEL_GS_BASE:
		write_capsule_msr(vcpu, MSR_KERNEL_GS_BASE, value);
		break;

	/* there's no legit reason to modify these MSR which were initialized
	 * during boot */
	case MSR_IA32_SYSENTER_CS:
		kill(vcpu, KILL_MSR_WRITE_SYSENTER_CS);
		break;
	case MSR_IA32_SYSENTER_ESP:
		kill(vcpu, KILL_MSR_WRITE_SYSENTER_ESP);
		break;
	case MSR_IA32_SYSENTER_EIP:
		kill(vcpu, KILL_MSR_WRITE_SYSENTER_EIP);
		break;

	case MSR_IA32_TSC_DEADLINE:
		capsule_tsc_deadline(vcpu, value);
		break;

	/* IA32_X2APIC_EOI: x2APIC EOI Register (W/O) */
	case 0x80b:
		/* XXX - this MSR seems to be used by VMware 11, ignore it */
		break;

	case MSR_ARCH_PERFMON_EVENTSEL0:
	case MSR_CORE_PERF_GLOBAL_CTRL:
	default:
		capsule = current_capsule(vcpu);
		cpsl_info(capsule->id, "unknown msr 0x%08x", ecx);
		kill(vcpu, KILL_MSR_WRITE_UNKNOWN);
		break;
	}
}

static void exit_msr_write(struct vcpu *vcpu)
{
	__u64 value;
	__u32 ecx;

	value = (vcpu->regs.rax & 0xffffffff) | (vcpu->regs.rdx << 32);
	ecx = vcpu->regs.rcx;

	if (vcpu->guest == GUEST_TRUSTED)
		exit_msr_write_trusted(vcpu, ecx, value);
	else
		exit_msr_write_capsule(vcpu, ecx, value);
}

/* TODO: never called since SECONDARY_EXEC_DESC_TABLE_EXITING is disabled */
static void exit_exception_gdtr_idtr_access(struct vcpu *vcpu)
{
	__u32 instr_info;

	/* instruction identity: 0: SGDT, 1: SIDT, 2: LGDT, 3: LIDT */
	instr_info = cpu_vmcs_read32(VMX_INSTRUCTION_INFO);
	switch ((instr_info >> 28) & 3) {
	case 0:
	case 1:
		/* TODO: tedious, because it must write to guest memory */
		kill(vcpu, KILL_SGDT_SIDT);
		break;
	case 2:
	case 3:
		kill(vcpu, KILL_LGDT_LIDT);
		break;
	}
}

/* TODO: never called since SECONDARY_EXEC_DESC_TABLE_EXITING is disabled */
static void exit_exception_ldtr_tr_access(struct vcpu *vcpu)
{
	__u32 instr_info;

	/* instruction identity: 0: SLDT, 1: STR, 2: LLDT, 3: LTR */
	instr_info = cpu_vmcs_read32(VMX_INSTRUCTION_INFO);
	switch ((instr_info >> 28) & 3) {
	case 0:
		/* TODO: tedious, because it must write to guest memory */
		kill(vcpu, KILL_SLDT);
		break;
	case 1:
		kill(vcpu, KILL_STR);
		break;
	case 2:
		kill(vcpu, KILL_LLDT);
		break;
	case 3:
		kill(vcpu, KILL_LTR);
		break;
	}
}

static void exit_io_instruction(struct vcpu *vcpu, unsigned long qual)
{
	struct capsule *capsule;
	union exit_qual_io io;

	capsule = current_capsule(vcpu);
	io.value = qual;

	cpsl_info(capsule->id, "exit_io: %s %d (port=0x%x)",
		  io.bits.direction == 0 ? "OUT": "IN",
		  io.bits.size == 0 ? 1 : (io.bits.size == 1 ? 2 : 4),
		  io.bits.port_number);

	kill(vcpu, KILL_IO_INSTRUCTION);
}

static void exit_hlt(struct vcpu *vcpu)
{
	update_rip();
	switch_to_trusted(vcpu);
}

static void exit_monitor(void)
{
	update_rip();
}

static void exit_mwait(struct vcpu *vcpu)
{
	update_rip();
	switch_to_trusted(vcpu);
}

/* The preemption timer counted down to zero. */
static void exit_vmx_preemption_timer_expired(struct vcpu *vcpu)
{
	hv_dbg("exit_vmx_preemption_timer_expired");
}

static void exit_vmcall_trusted(struct vcpu *vcpu)
{
	unsigned long arg0, arg1, arg2;
	struct shadow_process *shadowp;
	struct capsule_params *params;
	enum vmcall_reason reason;
	struct task_struct *task;
	struct capsule *capsule;
	bool woken_up;

	reason = vcpu->regs.rdi;
	arg0 = vcpu->regs.rsi;

	switch (reason) {
	case VMCALL_STOP_VMM:
		cpu_exit_bluepill(vcpu);
		break;

	case VMCALL_SNAPSHOT:
		arg1 = vcpu->regs.rdx;
		vcpu->regs.rax = do_snapshot(vcpu, arg0, (int)arg1);
		break;

	case VMCALL_CREATE_CAPSULE:
		params = (struct capsule_params *)arg0;
		shadowp = (struct shadow_process *)vcpu->regs.rdx;
		vcpu->regs.rax = create_capsule(vcpu, params, shadowp);
		break;

	case VMCALL_LAUNCH_CAPSULE:
		capsule = capsule_from_id((int)arg0);
		if (capsule == NULL)
			break;
		launch_capsule(vcpu, capsule);
		break;

	case VMCALL_RESUME_EXECUTION:
		capsule = capsule_from_id((int)arg0);
		if (capsule == NULL)
			break;
		switch_to_capsule(vcpu, capsule);
		break;

	case VMCALL_FATAL_SIGNAL:
		capsule = capsule_from_id((int)arg0);
		if (capsule == NULL)
			break;
		kill_s(capsule, KILL_VMCALL_FATAL_SIGNAL);
		break;

	case VMCALL_XCHAN_SET_EVENT:
		arg1 = vcpu->regs.rdx;
		arg2 = vcpu->regs.rcx;
		vcpu->regs.rax = xchan_set_event((int)arg0, arg1, (void *)arg2);
		break;

	case VMCALL_ADD_PENDING_TIMER_INTR:
		vmcall_add_pending_timer_intr((int)arg0);
		break;

	case VMCALL_ADD_PENDING_XCHAN_INTR:
		arg1 = vcpu->regs.rdx;
		vcpu->regs.rax = vmcall_add_pending_xchan_intr((int)arg0, (__u8)arg1);
		break;

	case VMCALL_RESIZE_CONSOLE:
		capsule = capsule_from_id((int)arg0);
		if (capsule == NULL) {
			vcpu->regs.rax = -EINVAL;
			break;
		}
		arg1 = vcpu->regs.rdx;
		vcpu->regs.rax = resize_capsule_console(capsule, (struct winsize *)arg1);
		break;

	case VMCALL_GPA_TO_HVA:
		vcpu->regs.rax = vmcall_gpa_to_hva((void *)arg0);
		break;

	case VMCALL_GET_SHADOWP_TASK:
		task = get_shadow_process_task((unsigned int)arg0);
		vcpu->regs.rax = (unsigned long)task;
		break;

	case VMCALL_GET_FIRST_SHADOWP_TASK:
		task = get_first_shadow_process_task(&woken_up);
		vcpu->regs.rax = (unsigned long)task;
		*(bool *)arg0 = woken_up;
		break;

	case VMCALL_GET_CAPSULE_STATS:
		capsule = capsule_from_id((int)arg0);
		if (capsule == NULL) {
			vcpu->regs.rax = -EINVAL;
			break;
		}
		arg1 = vcpu->regs.rdx;
		memcpy((struct capsule_stats *)arg1, &capsule->stats,
		       sizeof(capsule->stats));
		vcpu->regs.rax = 0;
		break;

	case VMCALL_GET_CAPSULE_IDS:
		arg1 = vcpu->regs.rdx;
		vcpu->regs.rax = get_capsule_ids((unsigned int *)arg0, arg1);
		break;

	default:
		tg_err("%s(%d, %016lx)", __func__, reason, arg0);
		break;
	}
}

static void vmcall_gettimeofday(struct vcpu *vcpu)
{
	struct timeval tv;

	do_gettimeofday(&tv);
	vcpu->regs.rdx = tv.tv_sec;
	vcpu->regs.rcx = tv.tv_usec;
}

static void exit_vmcall_capsule(struct vcpu *vcpu)
{
	enum vmcall_reason reason;
	struct capsule *capsule;
	struct event_counter *event_ctr;
	struct timespec ts_start, ts_stop, ts_delta, *ts_elapsed;
	unsigned long arg0, arg1;

	getnstimeofday(&ts_start);

	capsule = current_capsule(vcpu);
	reason = vcpu->regs.rdi;
	arg0 = vcpu->regs.rsi;

	switch (reason) {
	case VMCALL_EXIT:
		//cpsl_dbg(capsule->id, "%s(exit)", __func__);
		kill(vcpu, KILL_VMCALL_EXIT);
		break;

	case VMCALL_FORBIDDEN_EXECVE:
		//cpsl_dbg(capsule->id, "%s(forbidden_execve)", __func__);
		kill(vcpu, KILL_FORBIDDEN_EXECVE);
		break;

	case VMCALL_SHARE_MEM:
		//cpsl_dbg(capsule->id, "%s(share_page, %016lx)", __func__, arg0);
		capsule = current_capsule(vcpu);
		share_device_mem(capsule, arg0);
		break;

	case VMCALL_GETTIMEOFDAY:
		//cpsl_dbg(capsule->id, "%s(gettimeofday)", __func__);
		vmcall_gettimeofday(vcpu);
		break;

	case VMCALL_SET_TIMER:
		//cpsl_dbg(capsule->id, "%s(set_timer)", __func__);
		vmcall_set_timer(vcpu, arg0);
		break;

	case VMCALL_XCHAN_NOTIFY_TRUSTED:
		//cpsl_dbg(capsule->id, "%s(xchan_notify_trusted)", __func__);
		vcpu->regs.rax = xchan_notify_trusted(vcpu, arg0);
		break;

	case VMCALL_XCHAN_MAP_GUEST_PAGE:
		//cpsl_dbg(capsule->id, "%s(xchan_map_guest_page)", __func__);
		arg1 = vcpu->regs.rdx;
		xchan_map_guest_page(vcpu, arg0, arg1);
		break;

	case VMCALL_XCHAN_CLOSED:
		//cpsl_dbg(capsule->id, "%s(xchan_closed)", __func__);
		xchan_guest_closed(vcpu, arg0);
		break;

	case VMCALL_CAPSULE_ERROR:
		//cpsl_dbg(capsule->id, "%s(capsule_error)", __func__);
		kill(vcpu, KILL_CAPSULE_ERROR);
		break;

	default:
		cpsl_info(capsule->id, "%s(%d, %016lx)",
			  __func__, reason, arg0);
		kill(vcpu, KILL_UNKNOWN_VMCALL);
	}

	getnstimeofday(&ts_stop);
	ts_delta = timespec_sub(ts_stop, ts_start);

	if (reason >= VMCALL_CAPSULE_START && reason < NR_VM_CALLS) {
		event_ctr = &capsule->stats.vm_calls[reason - VMCALL_CAPSULE_START];
		ts_elapsed = &event_ctr->elapsed_time;

		ts_elapsed->tv_sec += ts_delta.tv_sec;
		timespec_add_ns(ts_elapsed, ts_delta.tv_nsec);

		event_ctr->count++;
	}
}

static void exit_vmcall(struct vcpu *vcpu, int trusted)
{
	/* check that vmcall is not executed from userland */
	if (guest_cpl() != 0) {
		inject_ud_exception();
		return;
	}

	update_rip();

	if (trusted)
		exit_vmcall_trusted(vcpu);
	else
		exit_vmcall_capsule(vcpu);
}

static void vm_exit_trusted(struct vcpu *vcpu, __u32 reason, unsigned long qual)
{
	struct timespec ts_start, ts_stop, ts_delta, *ts_elapsed;

	getnstimeofday(&ts_start);

	switch (reason & 0xffff) {
	case EXIT_REASON_CR_ACCESS:
		exit_cr_access(vcpu, qual);
		update_rip();
		break;

	case EXIT_REASON_INVALID_STATE:
		panic("VM-entry failure due to invalid trusted state");
		break;

	case EXIT_REASON_MSR_READ:
		exit_msr_read(vcpu);
		update_rip();
		break;

	case EXIT_REASON_MSR_WRITE:
		exit_msr_write(vcpu);
		update_rip();
		break;

	case EXIT_REASON_EXCEPTION_NMI:
		exit_exception_or_nmi(vcpu, qual);
		break;

	case EXIT_REASON_TRIPLE_FAULT:
		panic("triple fault");
		break;

	case EXIT_REASON_VMCALL:
		exit_vmcall(vcpu, 1);
		break;

	/* following instructions cause VM Exits unconditionally */
	case EXIT_REASON_CPUID:
		exit_cpuid(vcpu);
		update_rip();
		break;

	case EXIT_REASON_INVLPG:
		exit_invlpg(vcpu, qual, 1);
		update_rip();
		break;

	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMOFF:
	case EXIT_REASON_VMON:
		inject_ud_exception();
		break;

	case EXIT_REASON_GETSEC:
	case EXIT_REASON_INVD:
	case EXIT_REASON_XSETBV:
		/* TODO */
		tg_err("unknown exit reason: %d", reason & 0xffff);
		update_rip();
		break;

	/* should not happen */
	default:
		tg_err("unknown exit reason: %d (cpu=%d)",
		       reason & 0xffff, smp_processor_id());
		update_rip();
		break;
	}

	getnstimeofday(&ts_stop);

	if (reason < NR_VM_EXIT_REASONS) {
		ts_delta = timespec_sub(ts_stop, ts_start);
		ts_elapsed = &VMM_STATS->vm_exits[reason].elapsed_time;
		ts_elapsed->tv_sec += ts_delta.tv_sec;
		timespec_add_ns(ts_elapsed, ts_delta.tv_nsec);
		VMM_STATS->vm_exits[reason].count++;
	}
}

static void vm_exit_capsule(struct vcpu *vcpu, __u32 reason, unsigned long qual)
{
	struct capsule *capsule;
	struct timespec ts_start, ts_stop, ts_delta, *ts_elapsed;

	capsule = current_capsule(vcpu);
	getnstimeofday(&ts_start);

	switch (reason & 0xffff) {
	case EXIT_REASON_CPUID:
		exit_cpuid(vcpu);
		update_rip();
		break;

	case EXIT_REASON_CR_ACCESS:
		exit_cr_access(vcpu, qual);
		update_rip();
		break;

	case EXIT_REASON_INVALID_STATE:
		kill(vcpu, KILL_VM_ENTRY_INVALID_STATE);
		break;

	case EXIT_REASON_MSR_READ:
		exit_msr_read(vcpu);
		update_rip();
		break;

	case EXIT_REASON_MSR_WRITE:
		exit_msr_write(vcpu);
		update_rip();
		break;

	case EXIT_REASON_EXCEPTION_NMI:
		exit_exception_or_nmi(vcpu, qual);
		break;

	case EXIT_REASON_EXTERNAL_INTERRUPT:
		exit_external_intr(vcpu);
		break;

	case EXIT_REASON_TRIPLE_FAULT:
		kill(vcpu, KILL_TRIPLE_FAULT);
		break;

	case EXIT_REASON_VMCALL:
		exit_vmcall(vcpu, 0);
		break;

	case EXIT_REASON_INVLPG:
		exit_invlpg(vcpu, qual, 0);
		update_rip();
		break;

	case EXIT_REASON_INVEPT:
	case EXIT_REASON_INVVPID:
	case EXIT_REASON_VMCLEAR:
	case EXIT_REASON_VMLAUNCH:
	case EXIT_REASON_VMPTRLD:
	case EXIT_REASON_VMPTRST:
	case EXIT_REASON_VMREAD:
	case EXIT_REASON_VMRESUME:
	case EXIT_REASON_VMWRITE:
	case EXIT_REASON_VMOFF:
	case EXIT_REASON_VMON:
		inject_ud_exception();
		break;

	case EXIT_REASON_ACCESS_GDTR_IDTR:
		exit_exception_gdtr_idtr_access(vcpu);
		update_rip();
		break;

	case EXIT_REASON_ACCESS_LDTR_TR:
		exit_exception_ldtr_tr_access(vcpu);
		update_rip();
		break;

	case EXIT_REASON_IO_INSTRUCTION:
		exit_io_instruction(vcpu, qual);
		update_rip();
		break;

	case EXIT_REASON_PREEMPTION_TIMER:
		exit_vmx_preemption_timer_expired(vcpu);
		break;

	case EXIT_REASON_PENDING_INTERRUPT:
		exit_pending_intr(vcpu);
		break;

	case EXIT_REASON_HLT:
		exit_hlt(vcpu);
		break;

	case EXIT_REASON_MONITOR_INSTRUCTION:
		exit_monitor();
		break;

	case EXIT_REASON_MWAIT_INSTRUCTION:
		exit_mwait(vcpu);
		break;

	case EXIT_REASON_EPT_VIOLATION:
		exit_ept_violation(vcpu);
		break;

	case EXIT_REASON_EPT_MISCONFIG:
		exit_ept_misconfig(vcpu);
		break;

	case EXIT_REASON_DR_ACCESS:
		exit_dr_access(vcpu, qual);
		break;

	/* Processing of an entry fails if an attempt to write bits 127:64 to
	 * the MSR indexed by bits 31:0 of the entry would cause a #GP exception
	 * if executed via WRMSR with CPL = 0.
	 *
	 * eg: wrmsrl(MSR_KERNEL_GS_BASE, 0xdeadbeef12345678), because value is
	 *     not canonical. (An attempt to write a non-canonical value (using
	 *     WRMSR) to the IA32_KernelGSBase MSR causes a #GP fault.) */
	case EXIT_REASON_VM_ENTRY_FAILURE_MSR:
		kill(vcpu, KILL_VM_ENTRY_FAILURE_MSR);
		break;

	default:
		cpsl_info(capsule->id, "unknown exit reason: %d",
			  reason & 0xffff);
		kill(vcpu, KILL_UNKNOWN_EXIT_REASON);
		break;
	}

	getnstimeofday(&ts_stop);
	ts_delta = timespec_sub(ts_stop, ts_start);

	if (reason < NR_VM_EXIT_REASONS) {
		ts_elapsed = &capsule->stats.vm_exits[reason].elapsed_time;

		ts_elapsed->tv_sec += ts_delta.tv_sec;
		timespec_add_ns(ts_elapsed, ts_delta.tv_nsec);

		capsule->stats.vm_exits[reason].count++;
	}
}

/* handle VM exits event */
void _vm_exit_handler(struct regs *regs)
{
	unsigned long qual;
	struct vcpu *vcpu;
	unsigned int cpu;
	__u32 reason;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];

	memcpy(&vcpu->regs, regs, sizeof(*regs));
	vcpu->regs.rsp = cpu_vmcs_readl(GUEST_RSP);

	reason = cpu_vmcs_read32(VM_EXIT_REASON);
	qual = cpu_vmcs_readl(EXIT_QUALIFICATION);

	if (vcpu->guest == GUEST_TRUSTED)
		vm_exit_trusted(vcpu, reason, qual);
	else
		vm_exit_capsule(vcpu, reason, qual);

	memcpy(regs, &vcpu->regs, sizeof(*regs));
	cpu_vmcs_writel(GUEST_RSP, vcpu->regs.rsp);

	if (native_save_fl() & X86_EFLAGS_IF) {
		hv_err("interrupts enabled in hypervisor (exit reason: %d)!",
			reason & 0xffff);
	}

	if (vcpu->stop_vmx) {
		/* stop_vmm() returns to GUEST_RIP */
		cpu_exit_bluepill(vcpu);
	}
}
