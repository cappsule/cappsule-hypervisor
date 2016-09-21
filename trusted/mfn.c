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
#include <linux/sched.h>
#include <asm/uaccess.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>

#include "common/error.h"
#include "common/log.h"
#include "common/mfn.h"
#include "common/vmcall.h"
#include "trusted/mfn.h"

#define INVALID_CAPSULE_ID	(~0)


static int install_userland_mappings(unsigned int id,
				     unsigned long __user *user_pfntable,
				     unsigned long num_mfn,
				     struct vm_area_struct *vma)
{
	unsigned long addr, gpa, hva, pfn, ret;
	struct vmcall_gpa_hva_convert convert;
	unsigned long *pfntable, *hvatable;
	unsigned int i;
	size_t size;
	int err;

	if (vma->vm_flags & VM_WRITE)
		return -EINVAL;

	if (vma->vm_end - vma->vm_start != num_mfn * PAGE_SIZE) {
		cpsl_err(id, "%s: invalid size", __func__);
		return -EINVAL;
	}

	/* copy GPAs from userland */
	pfntable = kmalloc_array(num_mfn, sizeof(*pfntable), GFP_KERNEL);
	if (pfntable == NULL)
		return -ENOMEM;

	size = sizeof(*pfntable) * num_mfn;
	if (copy_from_user(pfntable, user_pfntable, size) != 0) {
		kfree(pfntable);
		return -EFAULT;
	}

	for (i = 0; i < num_mfn; i++) {
		gpa = pfntable[i] << PAGE_SHIFT;
		pfntable[i] = gpa;
	}

	/* allocate an array for HVAs */
	hvatable = kmalloc_array(num_mfn, sizeof(*hvatable), GFP_KERNEL);
	if (hvatable == NULL) {
		kfree(pfntable);
		return -ENOMEM;
	}

	/* get HVAs */
	convert.capsule_id = id;
	convert.xorg_uid = __kuid_val(current_uid());
	convert.num_mfn = num_mfn;
	convert.gpa = pfntable;
	convert.res_hva = hvatable;

	ret = cpu_vmcs_vmcall_ret(VMCALL_GPA_TO_HVA, (unsigned long)&convert);
	if (ret != 0) {
		kfree(pfntable);
		kfree(hvatable);
		return -EINVAL;
	}

	kfree(pfntable);

	/* no need to set vma->flags: remap_pfn_ranges() sets
	 * VM_IO | VM_PFNMAP | VM_DONTEXPAND | VM_DONTDUMP */
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	addr = vma->vm_start;
	err = 0;

	for (i = 0; i < num_mfn; i++) {
		hva = hvatable[i];
		if (hva == 0) {
			tg_err("%s: guest address unmapped", __func__);
			err = -ENOENT;
			break;
		}

		//cpsl_dbg(capsule->id, "%s: %lx %ld", __func__, addr, pfn);
		pfn = __pa(hva) >> PAGE_SHIFT;
		err = remap_pfn_range(vma, addr, pfn, PAGE_SIZE, vma->vm_page_prot);
		if (err) {
			cpsl_err(id, "%s: remap_pfn_range failed %lx %ld: %d",
				 __func__, addr, pfn, err);
			break;
		}

		addr += PAGE_SIZE;
	}

	/* XXX: remove mappings if error? */

	kfree(hvatable);

	return err;
}

static int mmap(struct file *file, struct vm_area_struct *vma)
{
	struct host_mfn *host_mfn;
	int ret;

	host_mfn = file->private_data;

	if (host_mfn->capsule_id == INVALID_CAPSULE_ID) {
		hv_err("%s: uninitialized capsule id", __func__);
		return -EINVAL;
	}

	ret = install_userland_mappings(host_mfn->capsule_id,
					host_mfn->user_pfntable,
					host_mfn->num_mfn,
					vma);

	return ret;
}

static ssize_t write(struct file *file, const char __user *in,
		size_t size, loff_t *off)
{
	struct host_mfn *host_mfn, tmp;

	if (size != sizeof(tmp))
		return -EINVAL;

	/* copy user data to a tmp structure to avoid incomplete copy */
	if (copy_from_user(&tmp, in, size) != 0)
		return -EFAULT;

	host_mfn = file->private_data;
	*host_mfn = tmp;

	return size;
}

static const char *xorg_exe[] = {
	"/usr/lib/xorg/Xorg",
	"/usr/bin/Xorg",
	NULL
};

/* Xorg is the only process allowed to access to this device. */
static bool is_program_allowed(void)
{
	struct task_struct *task;
	struct file *exe_file;
	struct mm_struct *mm;
	const char **p;
	char buf[128];
	char *path;

	task = get_current();
	mm = get_task_mm(task);
	if (mm == NULL)
		return false;

	exe_file = get_mm_exe_file(mm);
	mmput(mm);
	if (exe_file == NULL)
		return false;

	path = d_path(&exe_file->f_path, buf, sizeof(buf));
	fput(exe_file);

	if (IS_ERR(path))
		return false;

	for (p = xorg_exe; *p != NULL; p++) {
		if (strcmp(*p, path) == 0)
			return true;
	}

	return false;
}

static int open(struct inode *inode, struct file *filp)
{
	struct host_mfn *host_mfn;

	if (!is_program_allowed())
		return -EPERM;

	host_mfn = kzalloc(sizeof(*host_mfn), GFP_KERNEL);
	if (host_mfn == NULL)
		return -ENOMEM;

	host_mfn->capsule_id = INVALID_CAPSULE_ID;
	filp->private_data = host_mfn;

	return 0;
}

static int close(struct inode *inode, struct file *file)
{
	kfree(file->private_data);
	file->private_data = NULL;

	return 0;
}

static const struct file_operations mfn_fops = {
	.owner          = THIS_MODULE,
	.open           = open,
	.release        = close,
	.write          = write,
	.mmap           = mmap,
};

static struct miscdevice *mfn_dev;

err_t host_mfn_init(void)
{
	mfn_dev = kzalloc(sizeof(*mfn_dev), GFP_KERNEL);
	if (mfn_dev == NULL)
		return ERROR_ALLOC_FAILED;

	mfn_dev->minor = MISC_DYNAMIC_MINOR;
	mfn_dev->name = "capsule_mfn";
	mfn_dev->fops = &mfn_fops;
	mfn_dev->mode = S_IRUGO | S_IWUGO;

	if (misc_register(mfn_dev) != 0) {
		kfree(mfn_dev);
		return ERROR_XCHAN_DEVICE_REGISTRATION;
	}

	return SUCCESS;
}

void host_mfn_exit(void)
{
	misc_deregister(mfn_dev);
	kfree(mfn_dev);
}
