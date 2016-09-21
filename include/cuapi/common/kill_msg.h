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

#ifndef CUAPI_KILL_MSG_H
#define CUAPI_KILL_MSG_H

#include "cuapi/common/kill.h"

#ifndef RELEASE

#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(condition)	((void)sizeof(char[1 - 2*!!(condition)]))
#endif

#define X(k, v)			[k] = v,

#define ENUM_MAP(X) 											\
	X(KILL_VMCALL_EXIT,			"encapsulated process exited")				\
	X(KILL_VMCALL_FATAL_SIGNAL,		"shadow process received fatal signal")			\
													\
	/* VM-exits */											\
	X(KILL_MOVE_TO_CR0,			"write invalid CR0 value")				\
	X(KILL_MOVE_TO_CR4,			"write invalid CR4 value")				\
	X(KILL_MOVE_TO_CR8,			"write to CR8")						\
	X(KILL_MOVE_TO_CRX,			"write to unknown control register (BUG)")		\
													\
	X(KILL_CLTS,				"execution of CLTS")					\
													\
	X(KILL_MOVE_FROM_CR0_BUG,		"CR0 read (BUG)")					\
	X(KILL_MOVE_FROM_CR4_BUG,		"CR4 read (BUG)")					\
	X(KILL_MOVE_FROM_CR8,			"CR8 read")						\
	X(KILL_MOVE_FROM_CRX,			"read unknown control register (BUG)")			\
													\
	X(KILL_LMSW_TODO,			"execution of LMSW (TODO)")				\
													\
	X(KILL_WRITE_TO_DR,			"write to debug register")				\
													\
	X(KILL_AUTOLOAD_MSR_READ,		"read from unknown autoload MSR (BUG)")			\
	X(KILL_AUTOLOAD_MSR_WRITE,		"write to unknown autoload MSR (BUG)")			\
	X(KILL_MSR_WRITE_SYSENTER_CS,		"write to SYSENTER_CS MSR")				\
	X(KILL_MSR_WRITE_SYSENTER_ESP,		"write to SYSENTER_ESP MSR")				\
	X(KILL_MSR_WRITE_SYSENTER_EIP,		"write to SYSENTER_EIP MSR")				\
	X(KILL_MSR_WRITE_UNKNOWN,		"write to unknown MSR")					\
													\
	X(KILL_SGDT_SIDT,			"execution of SGDT/SIDT")				\
	X(KILL_LGDT_LIDT,			"execution of LGDT/LIDT")				\
													\
	X(KILL_SLDT,				"execution of SLDT")					\
	X(KILL_STR,				"execution of STR")					\
	X(KILL_LLDT,				"execution of LLDT")					\
	X(KILL_LTR,				"execution of LTR")					\
													\
	X(KILL_IO_INSTRUCTION,			"execution of an I/O instruction")			\
													\
	X(KILL_FORBIDDEN_EXECVE,		"forbidden execve")					\
	X(KILL_UNKNOWN_VMCALL,			"unknown VMCALL")					\
													\
	X(KILL_TRIPLE_FAULT,			"triple fault")						\
	X(KILL_VM_ENTRY_INVALID_STATE,		"VM-entry invalid state")				\
	X(KILL_VM_ENTRY_FAILURE_MSR,		"VM-entry failure")					\
	X(KILL_UNKNOWN_EXIT_REASON,		"unknown exit reason (BUG)")				\
													\
	/* vmx instructions */										\
	X(KILL_VMLAUNCH_FAILED,			"VMLAUNCH failed")					\
	X(KILL_VMRESUME_FAILED,			"VMRESUME failed")					\
	X(KILL_SWITCH_VM_TO_CAPSULE,		"VMLOAD failed (BUG)")					\
													\
	/* memory */											\
	X(KILL_TRACK_ALLOC_MEM_MAX,		"capsule's memory limit reached")			\
	X(KILL_TRACK_ALLOC_FAILED,		"memory allocation failed (track alloc)")		\
	X(KILL_ALLOC_GUEST_PAGE,		"memory allocation failed (guest page)")		\
	X(KILL_ALLOC_GUEST_PAGE_INSTALL_EPT,	"install EPT translation failed (alloc guest page)")	\
	X(KILL_MAP_ARGV_ENVP_INSTALL_EPT,	"install EPT translation failed (map argv)")		\
	X(KILL_MAP_POLICIES_NOT_SET,		"exec policies not set (BUG)")				\
	X(KILL_MAP_POLICIES_INSTALL_EPT,	"install EPT translation failed (exec policies)")	\
													\
	/* devices host */										\
	X(KILL_SHARE_DEVICE_MEM_INVALID_GPA,	"invalid GPA for shared mem")				\
	X(KILL_SHARE_DEVICE_MEM_TOO_MUCH_CALL,	"too much SHARE_MEM VMCALLs")				\
													\
	/* interrupts */										\
	X(KILL_XCHAN_VECTOR_BUG,		"invalid I/O vector (BUG)")				\
	X(KILL_DOUBLE_FAULT,			"double fault")						\
	X(KILL_HARD_EXCEPTION_BUG,		"invalid hard exception (BUG)")				\
	X(KILL_EXCEPTION_OR_NMI_BUG,		"invalid exception or NMI (BUG)")			\
													\
	/* ept */											\
	X(KILL_PUD_ALLOC_FAILED,		"memory allocation failed (PUD)")			\
	X(KILL_PMD_ALLOC_FAILED,		"memory allocation failed (PMD)")			\
	X(KILL_PTE_ALLOC_FAILED,		"memory allocation failed (PTE)")			\
													\
	X(KILL_REMOVE_GPA_BAD_PUD,		"remove EPT translation failed (bad PUD)")		\
	X(KILL_REMOVE_GPA_HUGE_PUD,		"remove EPT translation failed (huge PUD)")		\
	X(KILL_REMOVE_GPA_BAD_PMD,		"remove EPT translation failed (bad PMD)")		\
	X(KILL_REMOVE_GPA_LARGE_PMD,		"remove EPT translation failed (large PMD)")		\
	X(KILL_REMOVE_GPA_BAD_PTE,		"remove EPT translation failed (bad PTE)")		\
													\
	X(KILL_DUP_PAGE_FAILED,			"memory allocation failed (dup page)")			\
	X(KILL_SELF_MODIF_CODE_INSTALL_EPT,	"install EPT translation failed (self-modifying code)")	\
													\
	X(KILL_EPT_VIOLATION_LOOP,		"loop in EPT violation (BUG)")				\
	X(KILL_EPT_VIOLATION_INSTALL_EPT,	"install EPT translation failed (EPT violation)")	\
	X(KILL_EPT_MISCONFIGURATION,		"EPT misconfiguration (BUG)")				\
													\
	/* log */											\
	X(KILL_DMESG_INVALID_ADDR,		"invalid address in dmesg")				\
													\
	/* xchan */											\
	X(KILL_XCHAN_MAP_INVALID_INDEX,		"xchan: invalid index")					\
	X(KILL_XCHAN_MAP_PAGES,			"xchan: can't map pages")				\
	X(KILL_XCHAN_CLOSED_NET,		"xchan: net closed")					\
	X(KILL_XCHAN_CLOSED_GUI,		"xchan: gui closed")					\
	X(KILL_XCHAN_CLOSED_FS,			"xchan: fs closed")					\
	X(KILL_XCHAN_CLOSED_CONSOLE,		"xchan: console closed")				\
	X(KILL_XCHAN_CLOSED_INVALID,		"xchan: invalid closed")				\
													\
	/* capsule error */										\
	X(KILL_CAPSULE_ERROR,			"capsule error")

const char *kill_messages[] = {
	ENUM_MAP(X)
};
#undef X

#define X(n, v)		+ 1
#define NB_MSG		(0 ENUM_MAP(X))

/* ensure at compile time that each kill_t has an index in kill_messages
 * array */
void check_array_size_at_compile_time(void)
{
	BUILD_BUG_ON(NB_MSG != MAX_KILL_REASON);
}

#endif /* RELEASE */

#endif /* CUAPI_KILL_MSG_H */
