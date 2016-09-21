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

#ifndef CUAPI_GUEST_XCHAN_H
#define CUAPI_GUEST_XCHAN_H

#include "cuapi/common/xchan.h"

#define GUEST_XCHAN_DEVICE_NAME	"xchan"

#define XCHAN_IOC_GUEST_MAGIC		'G'
#define XCHAN_IOC_GUEST_SET_INFOS	_IOW(XCHAN_IOC_GUEST_MAGIC, 0, int)
#define XCHAN_IOC_GUEST_NOTIFY		_IOW(XCHAN_IOC_GUEST_MAGIC, 1, struct xchan_guest_ioctl)

struct xchan_guest_ioctl {
	enum xchan_type type;
	int eventfd;
};

#endif /* CUAPI_GUEST_XCHAN_H */
