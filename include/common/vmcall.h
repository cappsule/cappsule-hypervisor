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

#ifndef VMCALL_H
#define VMCALL_H

#include "cuapi/common/vmcall.h"

static __always_inline void vmcall_error(unsigned long reason,
					__u8 invalid,
					__u8 valid)
{
	/* vmcall instruction is never called in VMX root operation. One can
	 * know which kind of guest failed thanks to the vmcall's reason.
	 * Unfortunately, tg_err() can't be used because it calls cpsl_log()
	 * which isn't available in cappsule-guest.ko. */
	printk(KERN_ERR "[cappsule] vmcall %ld failed (%d %d)", reason, invalid,
	      valid);
}

/* use gcc calling convention to pass parameters through vmcall:
 * reason: rdi, args: rsi, rdx, rcx, etc. */

static __always_inline void cpu_vmcs_vmcall(unsigned long reason,
					    unsigned long arg0)
{
	__u8 error, vmfailinvalid, vmfailvalid;

	asm volatile (
		/* clear ZF and CF, otherwise guest may think that vmcall
		 * failed. encapsulated process may trick this by setting rsp to
		 * zero, but what's the point? */
		"test	%%rsp, %%rsp\n"

		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid)
		: "D"(reason), "S"(arg0) : "cc", "memory"
	);

	if (error)
		vmcall_error(reason, vmfailinvalid, vmfailvalid);
}

/* vmcall returns an value into rax */
static __always_inline long cpu_vmcs_vmcall_ret(unsigned long reason,
						unsigned long arg0)
{
	__u8 error, vmfailinvalid, vmfailvalid;
	unsigned long ret;

	asm volatile (
		"test	%%rsp, %%rsp\n"

		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid),
		  "=a"(ret)
		: "D"(reason), "S"(arg0) : "cc", "memory"
	);

	if (error) {
		vmcall_error(reason, vmfailinvalid, vmfailvalid);
		ret = -1;
	}

	return ret;
}

static __always_inline void cpu_vmcs_vmcall3(unsigned long reason,
					     unsigned long arg0,
					     unsigned long arg1)
{
	__u8 error, vmfailinvalid, vmfailvalid;

	asm volatile (
		"test	%%rsp, %%rsp\n"

		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid)
		: "D"(reason), "S"(arg0), "d"(arg1) : "cc", "memory"
	);

	if (error)
		vmcall_error(reason, vmfailinvalid, vmfailvalid);
}


static __always_inline long cpu_vmcs_vmcall3_ret(unsigned long reason,
						 unsigned long arg0,
						 unsigned long arg1)
{
	__u8 error, vmfailinvalid, vmfailvalid;
	unsigned long ret;

	asm volatile (
		"test	%%rsp, %%rsp\n"

		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid),
		  "=a"(ret)
		: "D"(reason), "S"(arg0), "d"(arg1) : "cc", "memory"
	);

	if (error) {
		vmcall_error(reason, vmfailinvalid, vmfailvalid);
		ret = -1;
	}

	return ret;
}

static __always_inline long cpu_vmcs_vmcall4_ret(unsigned long reason,
						 unsigned long arg0,
						 unsigned long arg1,
						 unsigned long arg2)
{
	__u8 error, vmfailinvalid, vmfailvalid;
	unsigned long ret;

	asm volatile (
		"test	%%rsp, %%rsp\n"

		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid),
		  "=a"(ret)
		: "D"(reason), "S"(arg0), "d"(arg1), "c"(arg2) : "cc", "memory"
	);

	if (error) {
		vmcall_error(reason, vmfailinvalid, vmfailvalid);
		ret = -1;
	}

	return ret;
}


/* store result into res1 and res2 */
static __always_inline void cpu_vmcs_vmcall2(unsigned long reason,
					     unsigned long arg0,
					     unsigned long *res1,
					     unsigned long *res2)
{
	__u8 error, vmfailinvalid, vmfailvalid;
	unsigned long rdx, rcx;

	asm volatile (
		"test	%%rsp, %%rsp\n"

		/* vmcall2 is responsible of putting result into rdx and rcx */
		"vmcall\n"
		"setbe	%0\n"
		"setb	%1\n"
		"sete	%2\n"
		: "=qm"(error), "=qm"(vmfailinvalid), "=qm"(vmfailvalid),
		  "=d"(rdx), "=c"(rcx)
		: "D"(reason), "S"(arg0)
		: "cc", "memory"
	);

	if (error)
		vmcall_error(reason, vmfailinvalid, vmfailvalid);

	*res1 = rdx;
	*res2 = rcx;
}

#endif /* VMCALL_H */
