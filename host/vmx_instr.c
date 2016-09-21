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
#include <linux/mm.h>

#include "host/capsule.h"
#include "host/vmx.h"


noinline void cpu_vmxerror_error(void)
{
	__u32 vm_instr_error;
	vm_instr_error = cpu_vmcs_read32(VM_INSTRUCTION_ERROR);
	printk(KERN_ERR "[virt] vmresume error (err %d)\n", vm_instr_error);
	dump_stack();
}

noinline void cpu_vmwrite_error(unsigned long field, unsigned long value)
{
	printk(KERN_ERR "[virt] vmwrite error: reg %lx value %lx (err %d)\n",
		   field, value, cpu_vmcs_read32(VM_INSTRUCTION_ERROR));
	dump_stack();
}

/* all general purpose registers except RIP and RSP are invalid  */
noinline void cpu_vmresume_failed(void)
{
	struct capsule *capsule;
	__u32 vm_instr_error;
	struct vcpu *vcpu;
	unsigned int cpu;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];

	vm_instr_error = cpu_vmcs_read32(VM_INSTRUCTION_ERROR);

	if (vcpu->guest == GUEST_TRUSTED) {
		panic("vmresume failed (error: %d)", vm_instr_error);
	} else {
		capsule = current_capsule(vcpu);
		cpsl_err(capsule->id, "vmresume failed (error: %d)",
			 vm_instr_error);
		kill(vcpu, KILL_VMRESUME_FAILED);
	}
}
