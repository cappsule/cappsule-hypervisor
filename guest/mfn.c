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

#include <linux/miscdevice.h>
#include <linux/ioctl.h>
#include <linux/mm.h>
#include <linux/fs.h>

#include "guest/init.h"
#include "guest/mfn.h"
#include "common/memory.h"


static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	unsigned long pfn, uaddr;
	long ret;

	/* /dev/mfn is owned by root and the permissions are 0600. Anyway, it
	 * doesn't hurt to check privileges. */
	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	if (_IOC_TYPE(cmd) != MFN_IOC_MAGIC)
		return -ENOTTY;

	switch (cmd) {
	case MFN_GET:
		uaddr = arg;
		pfn = uaddr_pfn(read_cr3(), uaddr);
		ret = (pfn != 0) ? (long)pfn : -EINVAL;
		break;

	default:
		ret = -EINVAL;
	}

	return ret;
}

static int close(struct inode *inode, struct file *file)
{
	return 0;
}

static const struct file_operations mfn_fops = {
	.owner          = THIS_MODULE,
	.release        = close,
	.unlocked_ioctl = ioctl,
	.llseek         = default_llseek,
};

static struct miscdevice mfn_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = GUEST_MFN_DEVICE_NAME,
	.fops  = &mfn_fops,
};

void guest_mfn_init(void)
{
	if (misc_register(&mfn_dev) != 0)
		guest_error("failed to register " GUEST_MFN_DEVICE_NAME " device");
}
