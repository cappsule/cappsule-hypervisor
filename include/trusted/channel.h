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

#ifndef TRUSTED_CHANNEL_H
#define TRUSTED_CHANNEL_H

#include "common/error.h"
#include "cuapi/common/kill.h"
#include "cuapi/common/uuid.h"
#include "cuapi/trusted/channel.h"

struct capsule_params;
struct daemon;

err_t channel_init(void);
void channel_exit(void);
int channel_capsule_exited(struct daemon *daemon, unsigned int capsule_id,
			   kill_t reason);
err_t channel_create_capsule(void __user *u_params,
			     struct capsule_params *params,
			     unsigned int *result_capsule_id);
long trusted_channel_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg);

#endif /* TRUSTED_CHANNEL_H */
