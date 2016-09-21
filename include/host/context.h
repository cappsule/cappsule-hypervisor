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

#ifndef HOST_CONTEXT_H
#define HOST_CONTEXT_H

#include <asm/vmx.h>


/* for the time being:
 * - MSR_KERNEL_GS_BASE */
#define AUTOLOAD_MSR_NUMBER	1

/* Register order must not be altered: move_from_cr(), move_to_cr(),
 * exit_dr_access() (and probably other functions) relies on it. */
struct regs {
	unsigned long rax;
	unsigned long rcx;
	unsigned long rdx;
	unsigned long rbx;
	unsigned long rsp;
	unsigned long rbp;
	unsigned long rsi;
	unsigned long rdi;
	unsigned long r8;
	unsigned long r9;
	unsigned long r10;
	unsigned long r11;
	unsigned long r12;
	unsigned long r13;
	unsigned long r14;
	unsigned long r15;
} __attribute__((__packed__));

/* MSR are handled by VMX: physical address of (struct vmx_msr_entry *) must be
 * specified. Even if they aren't saved and restored manually, it makes sense to
 * put this structure in context. */
struct context {
	struct regs regs;
	/* XXX: MSR-store and MSR-load addresses must be 16-byte aligned. It
	 * doesn't make sense to use  __attribute__ ((aligned (16))) because
	 * allocation alignment can't be predicted? */
	struct vmx_msr_entry autoload_msr[AUTOLOAD_MSR_NUMBER];
};

static inline void save_context(struct context *ctx, struct regs *regs)
{
	memcpy(&ctx->regs, regs, sizeof(*regs));
}

static inline void restore_context(struct context *ctx, struct regs *regs)
{
	memcpy(regs, &ctx->regs, sizeof(*regs));
}

static inline void init_autoload_msr(struct vmx_msr_entry *msr)
{
	int i;

	memset(msr, 0, sizeof(*msr) * AUTOLOAD_MSR_NUMBER);
	msr[0].index = MSR_KERNEL_GS_BASE;

	for (i = 0; i < AUTOLOAD_MSR_NUMBER; i++)
		rdmsrl(msr[i].index, msr[i].value);
}

#endif /* HOST_CONTEXT_H */
