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

#ifndef CUAPI_KILL_H
#define CUAPI_KILL_H

typedef enum {
	KILL_VMCALL_EXIT = 0,		/* encaspulated process exited */
	KILL_VMCALL_FATAL_SIGNAL,	/* shadow process killed */

	/* VM-exits */
	KILL_MOVE_TO_CR0,
	KILL_MOVE_TO_CR4,
	KILL_MOVE_TO_CR8,
	KILL_MOVE_TO_CRX,

	KILL_CLTS,

	KILL_MOVE_FROM_CR0_BUG,
	KILL_MOVE_FROM_CR4_BUG,
	KILL_MOVE_FROM_CR8,
	KILL_MOVE_FROM_CRX,

	KILL_LMSW_TODO,

	KILL_WRITE_TO_DR,

	KILL_AUTOLOAD_MSR_READ,
	KILL_AUTOLOAD_MSR_WRITE,
	KILL_MSR_WRITE_SYSENTER_CS,
	KILL_MSR_WRITE_SYSENTER_ESP,
	KILL_MSR_WRITE_SYSENTER_EIP,
	KILL_MSR_WRITE_UNKNOWN,

	KILL_SGDT_SIDT,
	KILL_LGDT_LIDT,

	KILL_SLDT,
	KILL_STR,
	KILL_LLDT,
	KILL_LTR,

	KILL_IO_INSTRUCTION,

	KILL_FORBIDDEN_EXECVE,
	KILL_UNKNOWN_VMCALL,

	KILL_TRIPLE_FAULT,
	KILL_VM_ENTRY_INVALID_STATE,
	KILL_VM_ENTRY_FAILURE_MSR,
	KILL_UNKNOWN_EXIT_REASON,

	/* vmx instructions */
	KILL_VMLAUNCH_FAILED,
	KILL_VMRESUME_FAILED,
	KILL_SWITCH_VM_TO_CAPSULE,

	/* memory */
	KILL_TRACK_ALLOC_MEM_MAX,
	KILL_TRACK_ALLOC_FAILED,
	KILL_ALLOC_GUEST_PAGE,
	KILL_ALLOC_GUEST_PAGE_INSTALL_EPT,
	KILL_MAP_ARGV_ENVP_INSTALL_EPT,
	KILL_MAP_POLICIES_NOT_SET,
	KILL_MAP_POLICIES_INSTALL_EPT,

	/* devices host */
	KILL_SHARE_DEVICE_MEM_INVALID_GPA,
	KILL_SHARE_DEVICE_MEM_TOO_MUCH_CALL,

	/* interrupts */
	KILL_XCHAN_VECTOR_BUG,
	KILL_DOUBLE_FAULT,
	KILL_HARD_EXCEPTION_BUG,
	KILL_EXCEPTION_OR_NMI_BUG,

	/* ept */
	KILL_PUD_ALLOC_FAILED,
	KILL_PMD_ALLOC_FAILED,
	KILL_PTE_ALLOC_FAILED,

	KILL_REMOVE_GPA_BAD_PUD,
	KILL_REMOVE_GPA_HUGE_PUD,
	KILL_REMOVE_GPA_BAD_PMD,
	KILL_REMOVE_GPA_LARGE_PMD,
	KILL_REMOVE_GPA_BAD_PTE,

	KILL_DUP_PAGE_FAILED,
	KILL_SELF_MODIF_CODE_INSTALL_EPT,

	KILL_EPT_VIOLATION_LOOP,
	KILL_EPT_VIOLATION_INSTALL_EPT,
	KILL_EPT_MISCONFIGURATION,

	/* log */
	KILL_DMESG_INVALID_ADDR,

	/* xchan */
	KILL_XCHAN_MAP_INVALID_INDEX,
	KILL_XCHAN_MAP_PAGES,
	KILL_XCHAN_CLOSED_NET,
	KILL_XCHAN_CLOSED_GUI,
	KILL_XCHAN_CLOSED_FS,
	KILL_XCHAN_CLOSED_CONSOLE,
	KILL_XCHAN_CLOSED_INVALID,

	/* capsule error */
	KILL_CAPSULE_ERROR,

	MAX_KILL_REASON,
} kill_t;


#ifndef RELEASE

#define KILL_MSG_FMT	"%s"

extern const char *kill_messages[];

static inline const char *kill_msg(kill_t reason)
{
	unsigned int msg_index = reason;

	if (msg_index >= MAX_KILL_REASON)
		return "invalid kill reason";
	else
		return kill_messages[msg_index];
}

#else

#define KILL_MSG_FMT	"%d"

static inline int kill_msg(kill_t reason)
{
	return reason;
}

#endif /* RELEASE */

#endif /* CUAPI_KILL_H */
