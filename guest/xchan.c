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
#include <linux/kthread.h>
#include <linux/eventfd.h>
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/mm.h>
#include <linux/fs.h>

#include "guest/console.h"
#include "guest/init.h"
#include "guest/shared_mem.h"
#include "guest/symbols.h"
#include "guest/xchan.h"
#include "common/vmcall.h"
#include "common/xchan.h"

struct tasklet_struct *xchan_console_notify;
static struct eventfd_ctx *events[XCHAN_TYPE_MAX];

struct guest_xchan {
	int initialized;
	enum xchan_type type;
	unsigned long *pages;
};

static irqreturn_t xchan_interrupt(int irq, void *arg)
{
	enum xchan_type type;
	irqreturn_t ret;

	type = (unsigned int)((unsigned long)arg);
	ret = IRQ_HANDLED;

	switch (type) {
	case XCHAN_CONSOLE:
		if (xchan_console_notify != NULL)
			tasklet_schedule(xchan_console_notify);
		break;
	case XCHAN_NET:
	case XCHAN_GUI:
	case XCHAN_FS:
		if (events[type] != NULL)
			eventfd_signal(events[type], 1);
		break;
	default:
		printk(KERN_ERR "BUG: invalid xchan interrupt (%d)\n", irq);
		ret = IRQ_NONE;
		break;
	}

	return ret;
}

static void disable_cpsl_irq(struct irq_data *data)
{
	set_bit(data->irq, shared_mem->blocked_intr_bitmap);
}

static void enable_cpsl_irq(struct irq_data *data)
{
	clear_bit(data->irq, shared_mem->blocked_intr_bitmap);
}

static void null_ack_apic_edge(struct irq_data *data)
{
}

static struct irq_chip cpsl_irq_controller = {
	.name         = "cpsl",
	.irq_mask     = disable_cpsl_irq,
	.irq_mask_ack = disable_cpsl_irq,
	.irq_unmask   = enable_cpsl_irq,

	.irq_ack      = null_ack_apic_edge,
};

/* An IRQ handler may already be installed, and it may not support line sharing.
 * Guest makes no use of original interrupts, which can be removed without
 * further checks. */
static void remove_irq_if_present(unsigned int irq)
{
	struct irq_desc *desc;
	unsigned long flags;

	desc = irq_to_desc(irq);
	if (desc != NULL) {
		raw_spin_lock_irqsave(&desc->lock, flags);
		desc->action = NULL;
		raw_spin_unlock_irqrestore(&desc->lock, flags);
	}
}

static void setup_xchan_interrupt(unsigned int irq, enum xchan_type type)
{
	unsigned long flags;
	void *arg;
	int err;

	/* irq_alloc_descs_from() can be called to return the first irq of
	 * XCHAN_TYPE_MAX consecutive irq. Nevertheless, it doesn't work because
	 * there may not be any interrupt vector corresponding to allocated IRQ.
	 *
	 * Current solution uses reserved IRQ already allocated, for which a
	 * vector is assigned: __this_cpu_read(vector_irq[vector]) != -1. */

	err = irq_alloc_desc_at(irq, 0);
	if (err < 0 && err != -EEXIST)
		guest_error("couldn't alloc irq");

	_irq_set_chip_and_handler_name(irq,
				       &cpsl_irq_controller,
				       handle_level_irq,
				       "cpsl xchan level");

	remove_irq_if_present(irq);

	/* install irq handler */
	flags = 0;
	arg = (void *)type;
	err = request_irq(irq, xchan_interrupt, flags, "cappsule xchan", arg);
	if (err)
		guest_error("request_irq failed (%d)", err);
}

static void setup_xchan_interrupts(__u8 xchan_first_vector)
{
	enum xchan_type type;
	unsigned int irq;

	for (type = 0; type < XCHAN_TYPE_MAX; type++) {
		irq = xchan_vector_to_irq(xchan_first_vector + type);
		setup_xchan_interrupt(irq, type);
	}
}

static int install_userland_mappings(unsigned int start,
				     unsigned int npages,
				     struct vm_area_struct *vma)
{
	unsigned long gpa, page, pfn, uaddr;
	int err, i;

	if (vma->vm_end - vma->vm_start != npages * PAGE_SIZE)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	uaddr = vma->vm_start;

	for (i = start; i < start + npages; i++) {
		page = __get_free_page(GFP_KERNEL);
		if (page == 0)
			return -ENOMEM;

		trigger_ept_violation(page);

		gpa = __pa(page);
		cpu_vmcs_vmcall3(VMCALL_XCHAN_MAP_GUEST_PAGE, gpa, i);

		pfn =  gpa >> PAGE_SHIFT;
		err = remap_pfn_range(vma, uaddr, pfn, PAGE_SIZE, vma->vm_page_prot);
		if (err)
			return err;

		uaddr += PAGE_SIZE;
	}

	return 0;
}

static int mmap(struct file *file, struct vm_area_struct *vma)
{
	struct guest_xchan *xchan;
	unsigned int npages;
	int start;

	xchan = (struct guest_xchan *)file->private_data;
	if (!xchan->initialized)
		return -EINVAL;

	npages = xchan_npages(xchan->type);
	start = xchan_start_page(xchan->type);
	if (npages == 0 || start == -1)
		return -EINVAL;

	return install_userland_mappings(start, npages, vma);
}

static int xchan_set_infos(struct guest_xchan *xchan, enum xchan_type type, int eventfd)
{
	struct eventfd_ctx *event;

	if (xchan->initialized)
		return -EPERM;

	if (type < 0 || type >= XCHAN_TYPE_MAX)
		return -EINVAL;

	if (events[type] != NULL)
		return -EINVAL;

	event = eventfd_ctx_fdget(eventfd);
	if (IS_ERR(event))
		return PTR_ERR(event);

	events[type] = event;

	xchan->type = type;
	xchan->initialized = 1;

	return 0;
}

static int xchan_notify_host(struct guest_xchan *xchan)
{
	if (!xchan->initialized)
		return -EPERM;

	return cpu_vmcs_vmcall_ret(VMCALL_XCHAN_NOTIFY_TRUSTED, xchan->type);
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct xchan_guest_ioctl infos;
	struct guest_xchan *xchan;
	const void __user *uarg;
	long ret;

	if (_IOC_TYPE(cmd) != XCHAN_IOC_GUEST_MAGIC)
		return -ENOTTY;

	xchan = (struct guest_xchan *)file->private_data;

	switch (cmd) {
	case XCHAN_IOC_GUEST_SET_INFOS:
		uarg = (const void __user *)arg;
		if (copy_from_user(&infos, uarg, sizeof(infos)) != 0)
			return -EFAULT;

		ret = xchan_set_infos(xchan, infos.type, infos.eventfd);
		break;

	case XCHAN_IOC_GUEST_NOTIFY:
		ret = xchan_notify_host(xchan);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int open(struct inode *inode, struct file *filp)
{
	struct guest_xchan *xchan;

	xchan = kzalloc(sizeof(*xchan), GFP_KERNEL);
	if (xchan == NULL)
		return -ENOMEM;

	xchan->initialized = 0;
	xchan->pages = NULL;
	filp->private_data = xchan;

	return 0;
}

static int close(struct inode *inode, struct file *file)
{
	struct guest_xchan *xchan;

	/* Once an xchan fd is opened it should never be closed (otherwise it
	 * means that fs/gui/net/console client exited). This vmcall kills the
	 * capsule. */
	xchan = (struct guest_xchan *)file->private_data;
	cpu_vmcs_vmcall(VMCALL_XCHAN_CLOSED, xchan->type);

	/* never reached */
	return 0;
}

static const struct file_operations xchan_fops = {
	.owner          = THIS_MODULE,
	.open		= open,
	.release        = close,
	.unlocked_ioctl = ioctl,
	.mmap           = mmap,
};

static struct miscdevice xchan_dev = {
	.minor = MISC_DYNAMIC_MINOR,
	.name  = GUEST_XCHAN_DEVICE_NAME,
	.fops  = &xchan_fops,
	.mode  = S_IRUGO | S_IWUGO,
};

void guest_xchan_init(__u8 xchan_first_vector)
{
	if (misc_register(&xchan_dev) != 0)
		guest_error("failed to register " GUEST_XCHAN_DEVICE_NAME " device");

	setup_xchan_interrupts(xchan_first_vector);

	xchan_console_notify = NULL;
	memset(events, 0, sizeof(*events));
}
