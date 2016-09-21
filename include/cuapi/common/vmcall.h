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

#ifndef CUAPI_COMMON_VMCALL_H
#define CUAPI_COMMON_VMCALL_H

enum vmcall_reason {
	/* vmcalls for trusted guest */
	VMCALL_STOP_VMM = 0,
	VMCALL_SNAPSHOT,
	VMCALL_CREATE_CAPSULE,
	VMCALL_LAUNCH_CAPSULE,
	VMCALL_RESUME_EXECUTION,
	VMCALL_FATAL_SIGNAL,
	VMCALL_XCHAN_SET_EVENT,
	VMCALL_ADD_PENDING_TIMER_INTR,
	VMCALL_ADD_PENDING_XCHAN_INTR,
	VMCALL_GPA_TO_HVA,
	VMCALL_KILLALL,
	VMCALL_GET_SHADOWP_TASK,
	VMCALL_GET_FIRST_SHADOWP_TASK,
	VMCALL_GET_CAPSULE_STATS,
	VMCALL_GET_CAPSULE_IDS,
	VMCALL_RESIZE_CONSOLE,

	/* vmcalls for capsule */
	VMCALL_CAPSULE_START,
	VMCALL_EXIT = VMCALL_CAPSULE_START,
	VMCALL_FORBIDDEN_EXECVE,
	VMCALL_SHARE_MEM,
	VMCALL_GETTIMEOFDAY,
	VMCALL_SET_TIMER,
	VMCALL_XCHAN_NOTIFY_TRUSTED,
	VMCALL_XCHAN_MAP_GUEST_PAGE,
	VMCALL_XCHAN_CLOSED,
	VMCALL_CAPSULE_ERROR,

	/* number of VM calls, not a real call type */
	NR_VM_CALLS
};
#define NR_CAPSULE_VM_CALLS (NR_VM_CALLS - VMCALL_CAPSULE_START - 1)

#endif
