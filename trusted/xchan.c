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
#include <linux/eventfd.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/cacheflush.h>
#include <asm/irq.h>

#include "common/log.h"
#include "common/error.h"
#include "host/vmm.h"
#include "trusted/channel.h"
#include "trusted/xchan.h"
#include "common/memory.h"
#include "common/vmcall.h"
#include "common/xchan.h"

/* Allocation of the xchan pages of a capsule is initiated on capsule creation.
 * Pages can't be freed on capsule' exit because they still may be in use in
 * userland.
 *
 * A refcount is taken:
 *  - if allocation succed,
 *  - by userland processes of trusted guest when xchan pages are mmaped.
 *
 * Refcount is decremented during shadow process' exit, and each time a userland
 * process unmap the pages. */
struct xchan_memory {
	struct list_head list;
	unsigned long pages;
	unsigned int order;
	struct kref refcount;

	/* capsule_id is unset until capsule is created */
	unsigned int capsule_id;
};

/* file's private_data */
struct trusted_xchan {
	int initialized;
	enum xchan_type type;
	atomic_t pages_mmaped;
	unsigned int cpu;
	struct xchan_memory *memory;
};

/* list of struct xchan_memory, protected by a lock */
static DEFINE_RWLOCK(memories_lock);
static LIST_HEAD(memories);


/**
 * Once capsule is created, its capsule's id can be assigned to the memory
 * structure.
 */
void xchan_set_memory_id(struct xchan_memory *memory, unsigned int capsule_id)
{
	memory->capsule_id = capsule_id;
}

/**
 * Return allocated pages. It only exists to avoid the declaration of
 * xchan_memory structure outside of this file.
 */
unsigned long xchan_get_memory_pages(struct xchan_memory *memory)
{
	return memory->pages;
}

/**
 * Free pages and remove memory structure from the memories list.
 */
static void xchan_free_pages(struct kref *kref)
{
	struct xchan_memory *memory;

	memory = container_of(kref, struct xchan_memory, refcount);

	//tg_dbg("%s (0x%016lx, %d)", __func__, memory->pages, memory->order);

	if (set_memory_wb(memory->pages, 1 << memory->order) != 0)
		tg_err("failed to restore memory attribute");
	free_pages(memory->pages, memory->order);

	write_lock(&memories_lock);
	list_del(&memory->list);
	write_unlock(&memories_lock);

	memset(memory, 0, sizeof(*memory));
	kfree(memory);
}

/**
 * Free memory if its refcount reaches 0.
 */
int xchan_put_pages(struct xchan_memory *memory)
{
	kref_put(&memory->refcount, xchan_free_pages);
	return 0;
}

static struct xchan_memory *get_memory_from_id(unsigned int capsule_id)
{
	struct xchan_memory *memory, *res;

	res = NULL;
	read_lock(&memories_lock);
	list_for_each_entry(memory, &memories, list) {
		if (memory->capsule_id == capsule_id) {
			res = memory;
			break;
		}
	}
	read_unlock(&memories_lock);

	return res;
}

int xchan_put_pages_by_id(unsigned int id)
{
	struct xchan_memory *memory;

	memory = get_memory_from_id(id);
	if (memory == NULL)
		return -1;

	return xchan_put_pages(memory);
}

static unsigned long xchan_get_pages(struct trusted_xchan *xchan)
{
	struct xchan_memory *memory;

	memory = xchan->memory;
	kref_get(&memory->refcount);

	return memory->pages;
}

static int install_userland_mappings(unsigned long pfn,
				     unsigned int npages,
				     struct vm_area_struct *vma)
{
	unsigned long addr;
	size_t size;
	int err;

	if (vma->vm_end - vma->vm_start != npages * PAGE_SIZE)
		return -EINVAL;

	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	addr = vma->vm_start;
	size = npages * PAGE_SIZE;

	err = remap_pfn_range(vma, addr, pfn, size, vma->vm_page_prot);
	return err;
}

static int mmap(struct file *file, struct vm_area_struct *vma)
{
	struct trusted_xchan *xchan;
	unsigned long pfn, pages;
	unsigned int npages;
	int ret, start;

	xchan = (struct trusted_xchan *)file->private_data;
	if (!xchan->initialized)
		return -EINVAL;

	npages = xchan_npages(xchan->type);
	start = xchan_start_page(xchan->type);
	if (npages == 0 || start == -1) {
		tg_dbg("xchan: invalid type");
		return -EINVAL;
	}

	pages = xchan_get_pages(xchan);
	pfn = __pa(pages) >> PAGE_SHIFT;
	if (pfn == 0) {
		xchan_put_pages(xchan->memory);
		return -EINVAL;
	}

	ret = install_userland_mappings(pfn + start, npages, vma);
	if (ret != 0) {
		tg_dbg("xchan: failed to install userland mapping");
		xchan_put_pages(xchan->memory);
		return ret;
	}

	atomic_inc(&xchan->pages_mmaped);

	return 0;
}

/* set file private data (id, xchan type) and set capsule event */
static int xchan_set_infos(struct trusted_xchan *xchan,
			   struct xchan_ioctl *infos)
{
	struct xchan_memory *memory;
	struct eventfd_ctx *event;
	unsigned int id;
	int ret;

	if (xchan->initialized)
		return -EPERM;

	if (infos->type < 0 || infos->type >= XCHAN_TYPE_MAX) {
		tg_info("xchan: failed to set infos (invalid type)");
		return -EINVAL;
	}

	id = infos->capsule_id;
	memory = get_memory_from_id(id);
	if (memory == NULL) {
		tg_info("xchan: failed to set infos (invalid id %d)", id);
		return -EINVAL;
	}

	event = eventfd_ctx_fdget(infos->eventfd);
	if (IS_ERR(event)) {
		tg_info("xchan: failed to set infos (invalid eventfd %d)",
		       infos->eventfd);
		return PTR_ERR(event);
	}

	ret = cpu_vmcs_vmcall4_ret(VMCALL_XCHAN_SET_EVENT,
				   id,
				   infos->type,
				   (unsigned long)event);
	if (ret < 0) {
		tg_info("xchan: failed to set infos (vmcall failed, capsule %d)",
			id);
		eventfd_ctx_put(event);
		return -EINVAL;
	}

	xchan->type = infos->type;
	xchan->cpu = ret;
	xchan->memory = memory;

	mb();
	xchan->initialized = 1;

	return 0;
}

static int xchan_notify_guest(struct trusted_xchan *xchan)
{
	struct timespec ts_start, ts_stop, ts_delta, *ts_elapsed;
	struct xchan_pending_intr arg;
	enum xchan_type type;
	void (*f)(void *);

	if (!xchan->initialized)
		return -EPERM;

	type = xchan->type;
	if (type < 0 || type >= XCHAN_TYPE_MAX)
		return -EINVAL;

	arg.capsule_id = xchan->memory->capsule_id;
	arg.vector = vmm.xchan_first_vector + type;
	f = cpu_xchan_notify_guest;

	getnstimeofday(&ts_start);

	smp_call_function_single(xchan->cpu, f, &arg, true);

	getnstimeofday(&ts_stop);

	/* Current CPU may theorically change, but it's highly unlikely to
	 * happen. Even if it was the case, gathered statistics won't be
	 * attributed to the right CPU. Not a big deal. */
	ts_delta = timespec_sub(ts_stop, ts_start);
	ts_elapsed = &VMM_STATS->xchan_guest_notif.elapsed_time;
	ts_elapsed->tv_sec += ts_delta.tv_sec;
	timespec_add_ns(ts_elapsed, ts_delta.tv_nsec);
	VMM_STATS->xchan_guest_notif.count++;

	return arg.error;
}

static int xchan_console_resize(struct trusted_xchan *xchan, struct winsize tty_size)
{
	int ret;

	ret = cpu_vmcs_vmcall3_ret(VMCALL_RESIZE_CONSOLE,
				   xchan->memory->capsule_id,
				   (unsigned long)&tty_size);
	if (ret != 0)
		return ret;

	return xchan_notify_guest(xchan);
}

static long ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct trusted_xchan *xchan;
	struct winsize tty_size;
	struct xchan_ioctl infos;
	void __user *uarg;
	long ret;

	xchan = (struct trusted_xchan *)file->private_data;

	switch (cmd) {
	case CAPPSULE_IOC_XCHAN_INFOS:
		uarg = (void __user *)arg;
		if (copy_from_user(&infos, uarg, sizeof(infos)) != 0)
			return -EFAULT;

		ret = xchan_set_infos(xchan, &infos);
		break;

	case CAPPSULE_IOC_XCHAN_NOTIFY:
		ret = xchan_notify_guest(xchan);
		break;

	case CAPPSULE_IOC_XCHAN_CONSOLE_RESIZE:
		if (xchan->type != XCHAN_CONSOLE)
			return -ENOSYS;

		uarg = (void __user *)arg;
		if (copy_from_user(&tty_size, uarg, sizeof(tty_size)))
			return -EFAULT;

		ret = xchan_console_resize(xchan, tty_size);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int open(struct inode *inode, struct file *filp)
{
	struct trusted_xchan *xchan;

	if (!capable(CAP_SYS_RAWIO))
		return -EPERM;

	xchan = kmalloc(sizeof(*xchan), GFP_KERNEL);
	if (xchan == NULL)
		return -ENOMEM;

	xchan->initialized = 0;
	xchan->type = XCHAN_TYPE_MAX;
	xchan->cpu = -1;
	xchan->memory = NULL;
	atomic_set(&xchan->pages_mmaped, 0);
	filp->private_data = xchan;

	return 0;
}

static int close(struct inode *inode, struct file *file)
{
	struct trusted_xchan *xchan;

	xchan = (struct trusted_xchan *)file->private_data;
	if (atomic_read(&xchan->pages_mmaped) != 0)
		xchan_put_pages(xchan->memory);

	kfree(file->private_data);
	file->private_data = NULL;

	return 0;
}

static const struct file_operations xchan_fops = {
	.owner          = THIS_MODULE,
	.open           = open,
	.release        = close,
	.unlocked_ioctl = ioctl,
	.mmap           = mmap,
};

static struct miscdevice *xchan_dev;

err_t trusted_xchan_init(void)
{
	xchan_dev = kzalloc(sizeof(*xchan_dev), GFP_KERNEL);
	if (xchan_dev == NULL)
		return ERROR_ALLOC_FAILED;

	xchan_dev->minor = MISC_DYNAMIC_MINOR;
	xchan_dev->name = TRUSTED_XCHAN_DEVICE_NAME;
	xchan_dev->fops = &xchan_fops;

	if (misc_register(xchan_dev) != 0) {
		kfree(xchan_dev);
		return ERROR_XCHAN_DEVICE_REGISTRATION;
	}

	return SUCCESS;
}

void trusted_xchan_exit(void)
{
	misc_deregister(xchan_dev);
	kfree(xchan_dev);
}

struct xchan_memory *xchan_alloc_pages(void)
{
	struct xchan_memory *memory;
	unsigned long pages;
	unsigned int order;
	int err;

	memory = kmalloc(sizeof(*memory), GFP_KERNEL);
	if (memory == NULL) {
		err = -ENOMEM;
		goto kmalloc_failed;
	}

	order = get_order(XCHAN_NPAGES_TOTAL * PAGE_SIZE);
	pages = __get_free_pages(GFP_USER | __GFP_ZERO, order);
	if (pages == 0) {
		err = -ENOMEM;
		goto alloc_failed;
	}

	err = set_memory_uc(pages, 1 << order);
	if (err) {
		err = -EINVAL;
		goto set_memory_attr_failed;
	}

	memory->pages = pages;
	memory->order = order;
	memory->capsule_id = -1;
	kref_init(&memory->refcount);

	//tg_dbg("%s (0x%016lx, %d)", __func__, memory->pages, memory->order);

	write_lock(&memories_lock);
	list_add(&memory->list, &memories);
	write_unlock(&memories_lock);

	return memory;

set_memory_attr_failed:
	free_pages(pages, order);
alloc_failed:
	kfree(memory);
kmalloc_failed:
	return NULL;
}

err_t find_xchan_first_vector(void)
{
	unsigned int i, vector;
	int ok;

	/* On cpu 0, IRQ0_VECTOR..IRQ15_VECTOR are assigned to IRQ 0..15. Since
	 * vector_irq isn't exported, the mapping can't be verified.
	 * Nevertheless, APIC seems to reset vector[irq] to -1 when irq is
	 * assigned to another vector.
	 *
	 * This loop tries to find XCHAN_TYPE_MAX consecutive used vectors for
	 * guest xchan interrupts. */
	for (vector = IRQ0_VECTOR; vector <= IRQ15_VECTOR - XCHAN_TYPE_MAX; vector++) {
		ok = 1;
		for (i = 0; i < XCHAN_TYPE_MAX; i++) {
			if (!vector_used_by_percpu_irq(vector + i)) {
				ok = 0;
				break;
			}
		}
		if (ok) {
			vmm.xchan_first_vector = vector;
			return SUCCESS;
		}
	}

	return ERROR_XCHAN_INTR_VECTOR;
}
