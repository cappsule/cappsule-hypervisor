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

#ifndef CUAPI_TRUSTED_CHANNEL_H
#define CUAPI_TRUSTED_CHANNEL_H

#include <stdbool.h>
#include <linux/types.h>
#include <linux/limits.h>

#ifdef __KERNEL__
#include <asm/termios.h>
#else
#include <sys/ioctl.h>
#endif

#include "cuapi/common/kill.h"
#include "cuapi/common/uuid.h"

/* Maximum number of capsules running simultaneously.*/
#define MAX_CAPSULE			32

#define CHANNEL_DEVICE_NAME		"cappsule"

#define CAPPSULE_IOC_MAGIC		'C'
#define CAPPSULE_IOC_SET_PIDS		_IOW(CAPPSULE_IOC_MAGIC,  0, struct allowed_pids)
#define CAPPSULE_IOC_SNAPSHOT		_IOW(CAPPSULE_IOC_MAGIC,  1, struct cappsule_ioc_snapshot *)
#define CAPPSULE_IOC_SET_EXEC_POLICIES	_IOW(CAPPSULE_IOC_MAGIC,  2, int)
#define CAPPSULE_IOC_CREATE_CAPSULE	_IOWR(CAPPSULE_IOC_MAGIC, 3, struct cappsule_ioc_create *)
#define CAPPSULE_IOC_KILL_CAPSULE	_IOWR(CAPPSULE_IOC_MAGIC, 4, unsigned int)
#define CAPPSULE_IOC_GET_CAPSULE_STATS	_IOWR(CAPPSULE_IOC_MAGIC, 5, struct cappsule_ioc_stats *)
#define CAPPSULE_IOC_GET_VMM_STATS	_IOWR(CAPPSULE_IOC_MAGIC, 6, struct capsule_ioc_vmm_stats *)
#define CAPPSULE_IOC_LIST_CAPSULES	_IOWR(CAPPSULE_IOC_MAGIC, 7, struct cappsule_ioc_list *)

struct cappsule_ioc_policies {
#ifdef __KERNEL__
	void __user *buf;
#else
	void *buf;
#endif
	size_t size;
};

struct cappsule_ioc_snapshot {
	void *params;
	unsigned int params_size;
	unsigned int result_capsule_id;	/* set by kernel of capsule */
};

struct cappsule_ioc_create {
	void *params;
	struct uuid policy_uuid;
	bool no_gui;
	struct winsize tty_size;
	unsigned int memory_limit;	/* in MB */
	uid_t uid;

	unsigned int result_capsule_id;	/* set by kernel */
};

struct cappsule_ioc_list {
	size_t nr_capsules;
	unsigned int capsule_ids[0];
};

struct capsule_event_kill {
	unsigned int capsule_id;
	kill_t reason;
};

#endif /* CUAPI_TRUSTED_CHANNEL_H */
