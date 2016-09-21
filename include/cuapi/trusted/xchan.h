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

#ifndef CUAPI_TRUSTED_XCHAN_H
#define CUAPI_TRUSTED_XCHAN_H

#include "cuapi/common/xchan.h"

#define TRUSTED_XCHAN_DEVICE_NAME		"cappsule-xchan"

#define CAPPSULE_IOC_XCHAN_MAGIC		'T'
#define CAPPSULE_IOC_XCHAN_INFOS		_IOW(CAPPSULE_IOC_XCHAN_MAGIC, 0, struct xchan_ioctl *)
#define CAPPSULE_IOC_XCHAN_NOTIFY		_IOW(CAPPSULE_IOC_XCHAN_MAGIC, 1, unsigned int)
#define CAPPSULE_IOC_XCHAN_CONSOLE_RESIZE	_IOW(CAPPSULE_IOC_XCHAN_MAGIC, 2, struct winsize *)

struct winsize;

struct xchan_ioctl {
	unsigned int capsule_id;
	enum xchan_type type;
	int eventfd;
};

#endif /* CUAPI_TRUSTED_XCHAN_H */
