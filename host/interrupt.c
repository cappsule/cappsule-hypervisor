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

#include <asm/vmx.h>
#include <asm/perf_event.h>

#include "shadow_process.h"
#include "common/shared_mem.h"
#include "common/xchan.h"
#include "host/breakpoint.h"
#include "host/capsule.h"
#include "host/interrupt.h"
#include "host/memory.h"
#include "host/transition.h"
#include "host/traps.h"
#include "host/vmx.h"
#include "host/xchan.h"


/* borrowed value from RR_TIMESLICE: 100 msecs (x86 has a frequency of 1000HZ)
 * expressed in msecs */
#define CAPSULE_TIMESLICE	(100 * HZ / 1000)

struct intr_info_field_bits {
	unsigned int vector		:8;
	unsigned int interruption_type	:3;
	unsigned int error_code_valid	:1;
	unsigned int nmi_unblocking	:1;
	unsigned int reserved		:18;
	unsigned int valid		:1;
} __attribute__((__packed__));

union intr_info_field {
	struct intr_info_field_bits bits;
	__u32 value;
};

struct intr_info_field_inject_bits {
	unsigned int vector		:8;
	unsigned int interruption_type	:3;
	unsigned int deliver_error_code	:1;
	unsigned int reserved		:19;
	unsigned int valid		:1;
} __attribute__((__packed__));

union intr_info_field_inject {
	struct intr_info_field_inject_bits bits;
	__u32 value;
};

/* order is important because it determines which interrupt is injected first */
enum interrupt_bit {
	BIT_INTR_TIMER,
	BIT_INTR_XCHAN_FS,
	BIT_INTR_XCHAN_NET,
	BIT_INTR_XCHAN_CONSOLE,
	BIT_INTR_XCHAN_GUI,
	BIT_INTR_MAX
};

static unsigned long interrupt_handlers[NR_VECTORS];


static inline enum interrupt_bit interrupt_vector_to_bit(__u8 vector)
{
	enum interrupt_bit bit;

	if (vector == LOCAL_TIMER_VECTOR) {
		bit = BIT_INTR_TIMER;
	} else if (vector == vmm.xchan_first_vector + XCHAN_NET) {
		bit = BIT_INTR_XCHAN_NET;
	} else if (vector == vmm.xchan_first_vector + XCHAN_GUI) {
		bit = BIT_INTR_XCHAN_GUI;
	} else if (vector == vmm.xchan_first_vector + XCHAN_FS) {
		bit = BIT_INTR_XCHAN_FS;
	} else if (vector == vmm.xchan_first_vector + XCHAN_CONSOLE) {
		bit = BIT_INTR_XCHAN_CONSOLE;
	} else {
		printk(KERN_ERR "BUG: invalid intr vector %u\n", vector);
		bit = BIT_INTR_TIMER;
	}

	return bit;
}

static inline __u8 interrupt_bit_to_vector(enum interrupt_bit bit)
{
	__u8 vector;

	switch (bit) {
	case BIT_INTR_TIMER:
		vector = LOCAL_TIMER_VECTOR;
		break;
	case BIT_INTR_XCHAN_NET:
		vector = vmm.xchan_first_vector + XCHAN_NET;
		break;
	case BIT_INTR_XCHAN_GUI:
		vector = vmm.xchan_first_vector + XCHAN_GUI;
		break;
	case BIT_INTR_XCHAN_FS:
		vector = vmm.xchan_first_vector + XCHAN_FS;
		break;
	case BIT_INTR_XCHAN_CONSOLE:
		vector = vmm.xchan_first_vector + XCHAN_CONSOLE;
		break;
	default:
		printk(KERN_ERR "BUG: invalid bit intr %d\n", bit);
		vector = LOCAL_TIMER_VECTOR;
		break;
	}

	return vector;
}

/* schedule from capsule after CAPSULE_TIMESLICE milliseconds */
static void check_capsule_time_slice(struct capsule *capsule)
{
	ktime_t now;
	s64 diff;

	now = ktime_get();
	diff = ktime_to_ms(ktime_sub(now, capsule->last_schedule));

	if (diff > CAPSULE_TIMESLICE)
		switch_to_trusted(capsule->vcpu);
}

static void set_interrupt_window_exiting(int enable)
{
	__u32 tmp;

	tmp = cpu_vmcs_read32(CPU_BASED_VM_EXEC_CONTROL);

	if (enable)
		tmp |= CPU_BASED_VIRTUAL_INTR_PENDING;
	else
		tmp &= ~CPU_BASED_VIRTUAL_INTR_PENDING;

	cpu_vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, tmp);
}

/* capsule may not be running */
void add_pending_intr(struct capsule *capsule, __u8 vector, int running)
{
	enum interrupt_bit bit;

	bit = interrupt_vector_to_bit(vector);
	__set_bit(bit, &capsule->intr.bitmap);

	if (running)
		set_interrupt_window_exiting(1);
}

static void remove_pending_intr(struct capsule *capsule, __u8 vector)
{
	enum interrupt_bit bit;

	bit = interrupt_vector_to_bit(vector);
	__clear_bit(bit, &capsule->intr.bitmap);

	/* since it's always called with a capsule guest, it's safe to disable
	 * interrupt-window-exiting from here */
	if (!intr_pending(capsule))
		set_interrupt_window_exiting(0);
}

static int invalid_xchan(__u8 vector)
{
	return (vector < vmm.xchan_first_vector ||
		vector >= vmm.xchan_first_vector + XCHAN_TYPE_MAX);
}

/* inject external interrupt into vm */
static void inject_intr(struct capsule *capsule, __u8 vector)
{
	union intr_info_field_inject inject;

	if (vector != LOCAL_TIMER_VECTOR && invalid_xchan(vector)) {
		cpsl_dbg(capsule->id, "%s: invalid I/O vector (%d)",
			 __func__, vector);
		kill_s(capsule, KILL_XCHAN_VECTOR_BUG);
	}

	if (vector == LOCAL_TIMER_VECTOR)
		capsule->stats.nr_local_timer_intr++;
	else
		capsule->stats.nr_xchan_intr++;

	inject.bits.vector = vector;
	inject.bits.interruption_type = INTR_TYPE_EXT_INTR >> 8;
	inject.bits.deliver_error_code = 0;
	inject.bits.valid = 1;
	cpu_vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, inject.value);
}

/* check if I/O interrupt associated to vector is disabled */
static int is_io_intr_disabled(struct capsule *capsule, __u8 vector)
{
	struct shared_mem *mem;
	int irq;

	if (invalid_xchan(vector)) {
		cpsl_dbg(capsule->id, "BUG: invalid I/O vector (%d)", vector);
		kill_s(capsule, KILL_XCHAN_VECTOR_BUG);
	}

	irq = xchan_vector_to_irq(vector);
	mem = capsule->shared_mem;
	return (mem == NULL || test_bit(irq, mem->blocked_intr_bitmap));
}

static int interrupts_masked(struct capsule *capsule)
{
	__u32 intr_state;
	int blocking;

	if (!(cpu_vmcs_readl(GUEST_RFLAGS) & X86_EFLAGS_IF))
		return 1;

	intr_state = cpu_vmcs_readl(GUEST_INTERRUPTIBILITY_INFO);
	blocking = GUEST_INTR_STATE_STI | GUEST_INTR_STATE_MOV_SS;
	if (intr_state & blocking)
		return 1;

	return 0;
}

static int can_inject_intr(struct capsule *capsule)
{
	union intr_info_field_inject inject;

	/* check if an interrupt is already injected (the valid bit in the
	 * VM-Entry Interruption Information field is cleared on every VM
	 * exit) */
	inject.value = cpu_vmcs_read32(VM_ENTRY_INTR_INFO_FIELD);
	if (inject.bits.valid)
		return 0;

	/* From UTLK (chapter 4, IRQs and Interrupts):
	 * - When IF flag is clear, each maskable interrupt issued by the PIC is
	 *   temporarily ignored.
	 * - On the opposite, disabled interrupts are not lost: the PIC sends
	 *   them to the CPU as soon as they are reenabled again.
	 *
	 * Don't try to issue ignored interrupt (LOCAL_TIME_VECTOR), but store
	 * disabled interrupts (I/O from xchan). */
	if (interrupts_masked(capsule))
		return 0;

	return 1;
}

static int is_vector_disabled(struct capsule *capsule, __u8 vector)
{
	if (vector == LOCAL_TIMER_VECTOR)
		return 0;
	else
		return is_io_intr_disabled(capsule, vector);
}

static void inject_xchan_intr(struct capsule *capsule, __u8 vector)
{
	if (!can_inject_intr(capsule) || is_vector_disabled(capsule, vector)) {
		add_pending_intr(capsule, vector, 1);
	} else {
		inject_intr(capsule, vector);
		remove_pending_intr(capsule, vector);
	}
}

static void inject_timer_intr(struct capsule *capsule)
{
	if (!can_inject_intr(capsule)) {
		add_pending_intr(capsule, LOCAL_TIMER_VECTOR, 1);
	} else {
		inject_intr(capsule, LOCAL_TIMER_VECTOR);
		remove_pending_intr(capsule, LOCAL_TIMER_VECTOR);
	}
}

/* this function is executed on capsule's CPU, but capsule isn't running */
void vmcall_add_pending_timer_intr(unsigned int id)
{
	struct capsule *capsule;

	/* no reference to capsule is held */
	capsule = capsule_from_id(id);

	/* this should never happen: id is valid */
	if (capsule == NULL) {
		hv_dbg("%s: invalid capsule id: %d", __func__, id);
		return;
	}

	add_pending_intr(capsule, LOCAL_TIMER_VECTOR, 0);
}

/* A capsule is running. If it's the one that should receive the interrupt,
 * inject it. Otherwise, wake up corresponding shadow process. */
int host_add_pending_xchan_intr(struct vcpu *vcpu, unsigned int id, __u8 vector)
{
	struct capsule *capsule;

	capsule = get_capsule_from_id(id);
	if (capsule == NULL) {
		tg_dbg("%s: can't find capsule %d", __func__, id);
		return -EINVAL;
	}

	if (capsule == current_capsule(vcpu)) {
		inject_xchan_intr(capsule, vector);
	} else {
		add_pending_intr(capsule, vector, 0);
		tasklet_schedule(&capsule->shadowp->tasklet);
	}

	put_capsule(capsule);

	return 0;
}

/* Capsule isn't running, and a xchan interrupt must be delivered. Add pending
 * interrupt, and wake up shadow process if it wasn't already woken up. */
int vmcall_add_pending_xchan_intr(unsigned int id, __u8 vector)
{
	struct capsule *capsule;

	capsule = get_capsule_from_id(id);
	if (capsule == NULL) {
		tg_dbg("%s: can't find capsule %d", __func__, id);
		return -EINVAL;
	}

	add_pending_intr(capsule, vector, 0);
	tasklet_schedule(&capsule->shadowp->tasklet);

	put_capsule(capsule);

	return 0;
}

/*
 * Interrupt window. At the beginning of an instruction, RFLAGS.IF was 1; events
 * were not blocked by STI or by MOV SS; and the "interrupt-window exiting"
 * VM-execution control was 1.
 */
void exit_pending_intr(struct vcpu *vcpu)
{
	struct capsule *capsule;
	enum interrupt_bit bit;
	__u8 vector;

	capsule = current_capsule(vcpu);
	ASSERT(!interrupts_masked(capsule));
	if (!intr_pending(capsule)) {
		cpsl_dbg(capsule->id, "%s: 0 pending interrupt", __func__);
		set_interrupt_window_exiting(0);
		return;
	}

	if (!can_inject_intr(capsule))
		return;

	/* inject first pending interrupts which is not disabled */
	for (bit = 0; bit < BIT_INTR_MAX; bit++) {
		if (!test_bit(bit, &capsule->intr.bitmap))
			continue;

		vector = interrupt_bit_to_vector(bit);
		if (!is_vector_disabled(capsule, vector)) {
			inject_intr(capsule, vector);
			remove_pending_intr(capsule, vector);
			break;
		}
	}
}

/* External interrupt */
void exit_external_intr(struct vcpu *vcpu)
{
	unsigned long interrupt_handler;
	union intr_info_field info;
	struct capsule *capsule;

	capsule = current_capsule(vcpu);
	info.value = cpu_vmcs_read32(VM_EXIT_INTR_INFO);

	if (info.bits.interruption_type != INTR_TYPE_EXT_INTR >> 8) {
		cpsl_err(capsule->id, "BUG: unhandled external interrupt (%d, %d)",
			 info.bits.interruption_type,
			 info.bits.vector);
		return;
	}

	/* setup fake stack and call irq handler */
	interrupt_handler = interrupt_handlers[info.bits.vector];
	asm volatile (
		"push	%%rax\n"
		"mov	%%ss, %%rax\n"
		"push	%%rax\n"
		"lea	8(%%rsp), %%rax\n"
		"push	%%rax\n"
		"pushfq\n"
		"mov	%%cs, %%rax\n"
		"push	%%rax\n"
		"call	*%0\n"
		"pop	%%rax\n"
		: : "r"(interrupt_handler) : "rax"
		);

	/* LOCAL_TIMER_VECTOR is the only external interrupt from host injected
	 * into guest */
	if (info.bits.vector == LOCAL_TIMER_VECTOR)
		inject_timer_intr(capsule);

	check_capsule_time_slice(capsule);
}

static void inject_exception(unsigned int vector, unsigned int intr_type,
			int deliver_error_code)
{
	union intr_info_field_inject inject;

	inject.value = 0;
	inject.bits.valid = 1;
	inject.bits.vector = vector;
	inject.bits.interruption_type = intr_type;
	inject.bits.deliver_error_code = deliver_error_code;
	cpu_vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, inject.value);
}

void inject_gp_exception(int error_code)
{
	inject_exception(X86_TRAP_GP, INTR_TYPE_HARD_EXCEPTION >> 8, 1);
	cpu_vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, error_code);
}

void inject_ud_exception(void)
{
	inject_exception(X86_TRAP_UD, INTR_TYPE_HARD_EXCEPTION >> 8, 0);
}

static void hard_exception_df(struct vcpu *vcpu)
{
	dump_guest_calltrace(vcpu);
	kill(vcpu, KILL_DOUBLE_FAULT);
}

static void hard_exception_nm(struct vcpu *vcpu)
{
	unsigned long value, read_shadow;
	struct capsule *capsule;

	/* capsule is using FPU */
	capsule = current_capsule(vcpu);
	capsule->fpu_used = 1;

	/* don't trap on #NM until next schedule */
	value = cpu_vmcs_read32(EXCEPTION_BITMAP);
	value &= ~(1 << X86_TRAP_NM);
	cpu_vmcs_write32(EXCEPTION_BITMAP, value);

	/* allow capsule to modify CR0.TS freely */
	value = cpu_vmcs_readl(CR0_GUEST_HOST_MASK);
	value &= ~X86_CR0_TS;
	cpu_vmcs_writel(CR0_GUEST_HOST_MASK, value);

	/* restore real CR0.TS value, and inject #NM if guest CR0.TS is set */
	read_shadow = cpu_vmcs_readl(CR0_READ_SHADOW);
	if (!(read_shadow & X86_CR0_TS)) {
		value = cpu_vmcs_readl(GUEST_CR0);
		value &= ~X86_CR0_TS;
		cpu_vmcs_writel(GUEST_CR0, value);
	} else {
		/* CR0.TS is already set (otherwise there would be no #NM) */
		inject_exception(X86_TRAP_NM, INTR_TYPE_HARD_EXCEPTION >> 8, 0);
	}
}

static void hard_exception(struct vcpu *vcpu, unsigned int vector)
{
	/* #NM and #DF are the only hardware exception in capsule exception
	 * bitmap */
	ASSERT(vcpu->guest != GUEST_TRUSTED);

	switch (vector) {
	case X86_TRAP_DF:
		hard_exception_df(vcpu);
		break;
	case X86_TRAP_NM:
		hard_exception_nm(vcpu);
		break;
	default:
		kill(vcpu, KILL_HARD_EXCEPTION_BUG);
	}
}

static void soft_exception(struct vcpu *vcpu, unsigned int vector)
{
	unsigned int instr_len;

	/* #BP is the only software exception in exception bitmap */
	ASSERT(vector == X86_TRAP_BP);

	if (handle_int3_hook(vcpu))
		return;

	/* If the interruption type is software interrupt, software exception,
	 * or privileged software exception, the VM-entry instruction-length
	 * field is in the range 1-15. */
	instr_len = cpu_vmcs_read32(VM_EXIT_INSTRUCTION_LEN);
	cpu_vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, instr_len);

	/* Error codes are not pushed on the stack for exceptions that are
	 * generated externally (with the INTR or LINT[1:0] pins) or the INT n
	 * instruction, even if an error code is normally produced for those
	 * exceptions. */
	inject_exception(vector, INTR_TYPE_SOFT_EXCEPTION >> 8, 0);
}

/*
 * Exception or non-maskable interrupt (NMI). Either:
 * 1: Guest software caused an exception and the bit in the exception bitmap
 *    associated with exception's vector was 1.
 * 2: An NMI was delivered to the logical processor and the "NMI exiting"
 *    VM-execution control was 1. This case includes executions of BOUND that
 *    cause #BR, executions of INT3 (they cause #BP), executions of INTO that
 *    cause #OF, and executions of UD2 (they cause #UD).
 */
void exit_exception_or_nmi(struct vcpu *vcpu, unsigned long exit_qualification)
{
	union intr_info_field info;

	info.value = cpu_vmcs_read32(VM_EXIT_INTR_INFO);

	switch (info.bits.interruption_type) {
	case INTR_TYPE_HARD_EXCEPTION >> 8:
		hard_exception(vcpu, info.bits.vector);
		break;

	case INTR_TYPE_SOFT_EXCEPTION >> 8:
		soft_exception(vcpu, info.bits.vector);
		break;

	case INTR_TYPE_NMI_INTR >> 8:
	default:
		hv_err("%s: BUG: unhandled exception or nmi (%d, %d)",
		       __func__,
		       info.bits.interruption_type,
		       info.bits.vector);
		if (vcpu->guest == GUEST_CAPSULE)
			kill(vcpu, KILL_EXCEPTION_OR_NMI_BUG);
		break;
	}
}

void resolve_interrupt_handlers(void)
{
	struct desc_ptr idt;
	gate_desc *desc;
	int i;

	asm volatile ("sidt	%0\n" : "=m"(idt));

	desc = (gate_desc *)idt.address;
	for (i = 0; i < NR_VECTORS; i++)
		interrupt_handlers[i] = gate_offset(desc[i]);
}
