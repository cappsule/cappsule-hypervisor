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

#include "common/symbols.h"
#include "common/log.h"
#include "guest/symbols.h"
#include "host/breakpoint.h"
#include "host/symbols.h"
#include "trusted/fingerprint.h"

/* nop [rax+0+rax], eax */
#define NOP1 "\x0f\x1f\x44\x00\x00"
/* nop */
#define NOP2 "\x66\x66\x66\x66\x90"


/* because of paravirt, gcc appends 5 bytes at the beginning of every function
 * (verified on Linux ubuntu 3.11.0-17-generic #31~precise1-Ubuntu SMP Tue Feb 4
 * 21:25:43 UTC 2014 x86_64 GNU/Linux). */
#define FINGERPRINT(name, start)					\
	do {								\
		p = (unsigned char *)start;				\
		if (memcmp(p, NOP1, sizeof(NOP1)-1) != 0 &&		\
		    memcmp(p, NOP2, sizeof(NOP2)-1) != 0) {		\
			hv_err("%p %016lx", p, *(unsigned long *)p);	\
			hv_err("fingerprint failed: %d", __LINE__);	\
			return ERROR_CHECK_BREAKPOINTS;			\
		}							\
		bp_##name.addr = (unsigned long)p;			\
	} while (0)

static bool is_pop_instruction(unsigned char *p, size_t size)
{
	bool ret = false;

	if (size == 1) {
		if (*p >= 0x58 && *p <= 0x5e)
			ret = true;
	} else if (size == 2) {
		if (*p == 0x41 && (*(p+1) >= 0x58 && *(p+1) <= 0x5f))
			ret = true;
	}

	return ret;
}

static unsigned long find_pop_ret(void *start)
{
	unsigned char *p;

	for (p = (unsigned char *)start; ; p++) {
		if (*p == (unsigned char)INSTR_RET) {
			/* pop instruction is one or two bytes long */
			if (is_pop_instruction(p-1, 1))
				return (unsigned long)p;
			if (is_pop_instruction(p-2, 2))
				return (unsigned long)p;
		}
	}

	return 0;
}

err_t check_breakpoints(void)
{
	unsigned char *p;

	FINGERPRINT(do_exit,          do_exit);
	FINGERPRINT(prepare_binprm,   prepare_binprm);
	FINGERPRINT(vt_console_print, _vt_console_print);
	FINGERPRINT(process_one_work, _process_one_work);

	/* It's tempting to put a breakpoint at the function entry and modify
	 * saved RIP in stack to call an additional function when it returns.
	 * Unfortunately, some processes may be in the middle of __schedule()
	 * during snapshot, and won't call the additional function when they
	 * return. */
	bp_schedule_end.addr = find_pop_ret(___schedule);
	bp_schedule_tail_end.addr = find_pop_ret(_schedule_tail);

	return SUCCESS;
}
