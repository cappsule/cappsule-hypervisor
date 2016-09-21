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

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#define INSTR_MOV_RBP_RSP	"\x48\x89\xe5"
#define INSTR_PUSH_RBP		"\x55"
#define INSTR_LEAVE		(unsigned char)'\xc9'
#define INSTR_RET		(unsigned char)'\xc3'
#define INSTR_INT3		(unsigned char)'\xcc'

struct breakpoint {
	unsigned long addr;
	unsigned char code;
};

extern struct breakpoint bp_do_exit,
	bp_schedule_end,
	bp_schedule_tail_end,
	bp_prepare_binprm,
	bp_vt_console_print,
	bp_process_one_work;

struct vcpu;

int handle_int3_hook(struct vcpu *vcpu);

void unset_breakpoints(void);
void set_breakpoints(void);

#endif /* BREAKPOINT_H */
