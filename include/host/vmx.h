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

#ifndef HOST_VMX_H
#define HOST_VMX_H

#include "host/context.h"
#include "host/vmm.h"
#include "common/log.h"

#define MSR_IA32_VMX_BASIC		0x00000480
#define INVEPT_SINGLE_CONTEXT		1
#define INVEPT_ALL_CONTEXT		2

#define VMX_VPID_EXTENT_INDIVIDUAL_ADDR	0
#define VMX_VPID_EXTENT_RETAIN_GLOBALS	3

struct vmcs_region;

void cpu_vmxerror_error(void);
void cpu_vmwrite_error(unsigned long field, unsigned long value);
void cpu_vmresume_failed(void);


static __always_inline unsigned long cpu_vmcs_readl(unsigned long field)
{
	unsigned long value;

	asm volatile (
		ASM_VMX_VMREAD_RDX_RAX
		: "=a"(value) : "d"(field) : "cc"
	);

	return value;
}

static __always_inline __u16 cpu_vmcs_read16(unsigned long field)
{
	return cpu_vmcs_readl(field);
}

static __always_inline __u32 cpu_vmcs_read32(unsigned long field)
{
	return cpu_vmcs_readl(field);
}

static __always_inline __u64 cpu_vmcs_read64(unsigned long field)
{
	return cpu_vmcs_readl(field);
}

static __always_inline void cpu_vmcs_writel(unsigned long field,
					    unsigned long value)
{
	__u8 error;

	asm volatile (
		ASM_VMX_VMWRITE_RAX_RDX "; setna %0"
		: "=q"(error) : "a"(value), "d"(field) : "cc"
	);

	if (unlikely(error))
		cpu_vmwrite_error(field, value);
}

static __always_inline void cpu_vmcs_write16(unsigned long field, __u16 value)
{
	cpu_vmcs_writel(field, value);
}

static __always_inline void cpu_vmcs_write32(unsigned long field, __u32 value)
{
	cpu_vmcs_writel(field, value);
}

static __always_inline void cpu_vmcs_write64(unsigned long field, __u64 value)
{
	cpu_vmcs_writel(field, value);
}

static __always_inline int cpu_vmcs_load(struct vmcs_region *vmcs_region)
{
	__u64 phys_addr = __pa(vmcs_region);
	__u8 error;

	asm volatile (
		ASM_VMX_VMPTRLD_RAX "; setna %0"
		: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		: "cc", "memory"
	);

	if (error) {
		printk(KERN_ERR "[virt] vmptrld %p/%llx failed\n", vmcs_region,
			   phys_addr);
		return -1;
	}

	return 0;
}

static __always_inline int cpu_vmcs_clear(struct vmcs_region *vmcs_region)
{
	__u64 phys_addr = __pa(vmcs_region);
	__u8 error;

	asm volatile (
		ASM_VMX_VMCLEAR_RAX "; setna %0"
		: "=qm"(error) : "a"(&phys_addr), "m"(phys_addr)
		: "cc", "memory"
	);

	if (error) {
		printk(KERN_ERR "[virt] vmclear fail: %p/%llx\n", vmcs_region, phys_addr);
		return -1;
	}

	return 0;
}

static __always_inline void cpu_vmx_resume(struct regs *regs)
{
	__u8 error;

	asm volatile (
		"mov %1, %%rcx\n"
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
		ASM_VMX_VMRESUME "\n"
		"setna %0"
		: "=q"(error)
		: "c"(regs),
		  [rax]"i"(offsetof(struct regs, rax)),
		  [rcx]"i"(offsetof(struct regs, rcx)),
		  [rdx]"i"(offsetof(struct regs, rdx)),
		  [rbx]"i"(offsetof(struct regs, rbx)),
		  [rbp]"i"(offsetof(struct regs, rbp)),
		  [rsi]"i"(offsetof(struct regs, rsi)),
		  [rdi]"i"(offsetof(struct regs, rdi)),
		  [r8]"i"(offsetof(struct regs, r8)),
		  [r9]"i"(offsetof(struct regs, r9)),
		  [r10]"i"(offsetof(struct regs, r10)),
		  [r11]"i"(offsetof(struct regs, r11)),
		  [r12]"i"(offsetof(struct regs, r12)),
		  [r13]"i"(offsetof(struct regs, r13)),
		  [r14]"i"(offsetof(struct regs, r14)),
		  [r15]"i"(offsetof(struct regs, r15))
		: "cc", "memory"
	);

	/* never reached, except if vmresume failed */
	cpu_vmresume_failed();
}

static __always_inline int cpu_vmxon(void *vmxon_region)
{
	__u64 phys_addr = __pa(vmxon_region);
	int ret;

	asm volatile (
		ASM_VMX_VMXON_RAX "\n"
		"jc	1f\n"
		"xor	%%rax, %%rax\n"
		"jmp	2f\n"
		"1:\n"
		"xor	%%rax, %%rax\n"
		"dec	%%rax\n"
		"2:\n"
		: "=a"(ret) : "a"(&phys_addr), "m"(phys_addr)
		: "memory", "cc"
	);

	return ret;
}

static __always_inline void invept(int ext, __u64 eptp)
{
	__u8 error, vmfailvalid, vmfailinvalid;
	struct {
		__u64 eptp;
		__u64 zero;
	} operand = { eptp, 0 };

	asm volatile (
		ASM_VMX_INVEPT "\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid)
		: "a" (&operand), "c" (ext)
		: "cc", "memory"
	);

	if (error) {
		printk(KERN_ERR "invept %d failed (%d %d)\n", ext,
			vmfailinvalid, vmfailvalid);
	}
}

static inline void invvpid(int ext, u16 vpid, unsigned long gva)
{
	__u8 error, vmfailvalid, vmfailinvalid;
	struct {
		__u64 vpid :16;
		__u64 rsvd :48;
		__u64 gva;
	} operand;

	/* one can argue this check should be done by the caller, but it's
	 * easy to miss this check somewhere, and VPID is supported by every CPU
	 * nowadays. */
	if (!vmm.vpid_support)
		return;

	if (ext == VMX_VPID_EXTENT_INDIVIDUAL_ADDR) {
		/* even if caller is responsible of this, ensure that guest
		 * linear address is canonical */
		if ((((long)gva << 16) >> 16) != gva) {
			printk(KERN_ERR "BUG: invvpid: address is not canonical\n");
			return;
		}
	}

	operand.vpid = vpid;
	operand.rsvd = 0;
	operand.gva = gva;

	asm volatile (
		ASM_VMX_INVVPID "\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid)
		: "a"(&operand), "c"(ext)
		: "cc", "memory"
	);

	if (error) {
		printk(KERN_ERR "invvpid %d failed (%d %d)\n", ext,
			vmfailinvalid, vmfailvalid);
	}
}

#endif /* HOST_VMX_H */
