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

#ifndef COMMON_PARAMS_H
#define COMMON_PARAMS_H

#include <asm/termios.h>

#include "cuapi/common/uuid.h"

struct daemon;

struct capsule_params {
	struct uuid policy_uuid;
	bool no_gui;
	struct winsize tty_size;
	unsigned int memory_limit;
	void *info_pages;
	unsigned long xchan_pages;
	uid_t uid;

	/* only use by shadow process */
	struct daemon *daemon;
};

#endif /* COMMON_PARAMS_H */
