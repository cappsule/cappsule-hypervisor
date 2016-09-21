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
#include <linux/export.h>
#include <linux/if_tun.h>
#include <asm/uaccess.h>
#include <linux/ioctl.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <net/sock.h>

#include "common/channel.h"
#include "common/log.h"
#include "common/error.h"
#include "common/exec_policy.h"
#include "common/params.h"
#include "guest/shared_mem.h"
#include "common/vmcall.h"
#include "host/process.h"
#include "host/snapshot.h"
#include "host/vmm.h"
#include "trusted/channel.h"
#include "trusted/xchan.h"
#include "cuapi/common/stats.h"

struct daemon_capsule {
	struct list_head list;
	struct capsule_event_kill event;
};

struct daemon {
	/* protect the following lists */
	rwlock_t lock;
	struct list_head running_capsules;
	struct list_head exited_capsules;

	wait_queue_head_t exited_waitq;

	struct kref refcount;
};

static struct miscdevice *channel_dev;
static atomic_t daemon_count;


/* free daemon structure once the channel file descriptor is closed and every
 * shadow processes exits */
static void release_daemon(struct kref *kref)
{
	struct daemon_capsule *running, *exited, *tmp;
	struct daemon *daemon;

	daemon = container_of(kref, struct daemon, refcount);

	/* locking isn't needed because there's no more daemon consumer */

	list_for_each_entry_safe(running, tmp, &daemon->running_capsules, list) {
		kfree(running);
	}

	list_for_each_entry_safe(exited, tmp, &daemon->exited_capsules, list) {
		kfree(exited);
	}

	kfree(daemon);
}

/**
 * Add a capsule to the running list.
 */
static void add_running_capsule(struct daemon *daemon,
				struct daemon_capsule *running)
{
	write_lock(&daemon->lock);
	list_add(&running->list, &daemon->running_capsules);
	write_unlock(&daemon->lock);
}

/**
 * Switch a capsule from running list to the exited list. It wakes up process
 * blocked on poll and allow it to read exited capsules.
 *
 * It must be called by shadow process before exiting.
 */
int channel_capsule_exited(struct daemon *daemon, unsigned int capsule_id,
			   kill_t reason)
{
	struct daemon_capsule *c, *running, *exited;
	int ret;

	running = NULL;
	read_lock(&daemon->lock);
	list_for_each_entry(c, &daemon->running_capsules, list) {
		if (c->event.capsule_id == capsule_id) {
			running = c;
			break;
		}
	}
	read_unlock(&daemon->lock);

	if (running != NULL) {
		write_lock(&daemon->lock);

		/* remove from running list */
		list_del(&running->list);

		/* append to exited list */
		exited = running;
		exited->event.reason = reason;
		list_add(&exited->list, &daemon->exited_capsules);

		/* wake up poll */
		wake_up_interruptible(&daemon->exited_waitq);

		write_unlock(&daemon->lock);
		ret = 0;
	} else {
		ret = -1;
	}

	/* shadow process won't use daemon anymore */
	kref_put(&daemon->refcount, release_daemon);

	return ret;
}

/**
 * Wait until a capsule exits.
 */
static unsigned int poll(struct file *filp, poll_table *wait)
{
	struct daemon *daemon;
	unsigned int mask;

	daemon = filp->private_data;
	poll_wait(filp, &daemon->exited_waitq, wait);

	mask = 0;
	read_lock(&daemon->lock);
	if (!list_empty(&daemon->exited_capsules))
		mask = POLLIN | POLLRDNORM;
	read_unlock(&daemon->lock);

	return mask;
}

static struct daemon_capsule *get_first_exited_capsule(struct daemon *daemon)
{
	struct daemon_capsule *exited;

	write_lock(&daemon->lock);

	if (list_empty(&daemon->exited_capsules)) {
		exited = NULL;
	} else {
		exited = list_first_entry(&daemon->exited_capsules,
					  struct daemon_capsule,
					  list);
		list_del(&exited->list);
	}

	write_unlock(&daemon->lock);

	return exited;
}

/**
 * Return 0 if no capsule has exited.
 */
static ssize_t read(struct file *filp, char __user *buf, size_t count,
		    loff_t *pos)
{
	struct daemon_capsule *exited;
	struct daemon *daemon;
	ssize_t ret;

	if (count != sizeof(exited->event))
		return -EINVAL;

	daemon = filp->private_data;
	exited = get_first_exited_capsule(daemon);

	if (exited != NULL) {
		ret = copy_to_user(buf, &exited->event, sizeof(exited->event));
		kfree(exited);
		ret = (ret == 0) ? sizeof(exited->event) : -EFAULT;
	} else {
		ret = 0;
	}

	return ret;
}

static int channel_kill_capsule(unsigned int capsule_id)
{
	struct task_struct *task;
	unsigned long ret;

	ret = cpu_vmcs_vmcall_ret(VMCALL_GET_SHADOWP_TASK, capsule_id);
	task = (struct task_struct *)ret;
	if (task == NULL)
		return -ESRCH;

	kthread_stop(task);
	put_task_struct(task);

	return 0;
}

static int channel_get_capsule_stats(unsigned int capsule_id,
				     struct capsule_stats __user *ustats)
{
	struct capsule_stats *cap_stats;
	err_t err;

	cap_stats = kzalloc(sizeof(*cap_stats), GFP_KERNEL);
	if (!cap_stats)
		return -ENOMEM;

	err = cpu_vmcs_vmcall3_ret(VMCALL_GET_CAPSULE_STATS,
				   capsule_id, (unsigned long)cap_stats);
	if (err != SUCCESS) {
		kfree(cap_stats);
		return err;
	}

	if (copy_to_user(ustats, cap_stats, sizeof(*cap_stats))) {
		kfree(cap_stats);
		return -EFAULT;
	}

	kfree(cap_stats);
	return 0;
}

static int channel_get_capsule_ids(struct cappsule_ioc_list __user *u_list)
{
	size_t bufsize, user_count;
	size_t nr_capsules;
	unsigned int *ids;
	int res;

	if (get_user(user_count, &u_list->nr_capsules))
		return -EFAULT;

	bufsize = min(user_count, (size_t)MAX_CAPSULE) * sizeof(unsigned int);
	ids = kzalloc(bufsize, GFP_KERNEL);
	if (ids == NULL)
		return -ENOMEM;

	// Returns the number of ids.
	res = cpu_vmcs_vmcall3_ret(VMCALL_GET_CAPSULE_IDS,
				   (long)ids, bufsize);

	if (res < 0) {
		kfree(ids);
		return res;
	}

	// Returns list of capsule ids to userland.
	nr_capsules = res;
	if (copy_to_user(&u_list->capsule_ids, ids, nr_capsules * sizeof(unsigned int))) {
		kfree(ids);
		return -EFAULT;
	}
	kfree(ids);

	if (put_user(nr_capsules, &u_list->nr_capsules))
		return -EFAULT;

	return nr_capsules;
}

static int channel_get_vmm_stats(unsigned int cpu,
				 struct vmm_stats __user *ustats)
{
	struct vmm_stats *stats;
	int ret;

	/* XXX. This is racy: VMM statistics may changed while being copied to
	 * userland. The only solution seems to update and gather each CPU
	 * statistic in VMX-root mode from the right CPU; but it introduces a
	 * lot of overhead. */

	if (cpu >= ARRAY_SIZE(vmm.stats))
		return -EINVAL;

	stats = &vmm.stats[cpu];
	ret = copy_to_user(ustats, stats, sizeof(*stats));

	return ret;
}

/**
 * This function is meant to be called by common_channel_ioctl().
 */
long trusted_channel_ioctl(struct file *file, unsigned int cmd,
			   unsigned long arg)
{
	struct cappsule_ioc_vmm_stats __user *u_vmm_stats;
	struct exec_policies *old_policies, *policies;
	struct cappsule_ioc_create __user *u_create;
	struct cappsule_ioc_stats __user *u_stats;
	struct cappsule_ioc_list __user *u_list;
	struct daemon_capsule *running_capsule;
	struct cappsule_ioc_create create;
	struct cappsule_ioc_policies p;
	struct capsule_params *params;
	unsigned int capsule_id, cpu;
	struct allowed_pids pids;
	struct daemon *daemon;
	void __user *uarg;
	size_t size;
	err_t err;
	long ret;

	switch (cmd) {
	/* case CAPPSULE_IOC_SNAPSHOT is handled in common_channel_ioctl() */

	case CAPPSULE_IOC_SET_PIDS:
		uarg = (void __user *)arg;
		if (copy_from_user(&pids, uarg, sizeof(pids)) != 0)
			return -EFAULT;

		size = sizeof(snapshot.process.allowed_pids);
		memcpy(&snapshot.process.allowed_pids, &pids, size);

		ret = 0;
		break;

	case CAPPSULE_IOC_SET_EXEC_POLICIES:
		uarg = (void __user *)arg;
		if (copy_from_user(&p, uarg, sizeof(p)) != 0)
			return -EFAULT;

		policies = copy_exec_policies(p.buf, p.size);
		if (!IS_ERR(policies)) {
			old_policies = get_exec_policies();
			set_exec_policies(policies);

			/* free previous policies if any */
			if (old_policies != NULL)
				free_exec_policies(old_policies);

			ret = 0;
		} else {
			ret = PTR_ERR(policies);
		}
		break;

	case CAPPSULE_IOC_CREATE_CAPSULE:
		u_create = (struct cappsule_ioc_create __user *)arg;
		if (copy_from_user(&create, u_create, sizeof(create)) != 0)
			return -EFAULT;

		/* params is freed on capsule exit, or by
		 * channel_create_capsule() if the creation fails */
		params = kzalloc(sizeof(*params), GFP_KERNEL);
		if (params == NULL)
			return -ENOMEM;

		running_capsule = kmalloc(sizeof(*running_capsule), GFP_KERNEL);
		if (running_capsule == NULL) {
			kfree(params);
			return -ENOMEM;
		}

		daemon = file->private_data;

		params->policy_uuid = create.policy_uuid;
		params->no_gui = create.no_gui;
		params->tty_size = create.tty_size;
		params->memory_limit = create.memory_limit;
		params->info_pages = 0;
		params->xchan_pages = 0;
		params->uid = create.uid;
		params->daemon = daemon;

		kref_get(&daemon->refcount);

		err = channel_create_capsule(create.params, params, &capsule_id);
		ret = err ? -(CAPPSULE_ERRNO_BASE + (long)err) : 0;

		if (ret == 0) {
			if (put_user(capsule_id, &u_create->result_capsule_id) != 0)
				hv_dbg("failed to set capsule_id in userland infos");

			/* add capsule to the running list */
			running_capsule->event.capsule_id = capsule_id;
			running_capsule->event.reason = MAX_KILL_REASON;
			add_running_capsule(daemon, running_capsule);
		} else {
			kref_put(&daemon->refcount, release_daemon);
			kfree(running_capsule);
		}
		break;

	case CAPPSULE_IOC_KILL_CAPSULE:
		ret = channel_kill_capsule((unsigned int)arg);
		break;

	case CAPPSULE_IOC_GET_CAPSULE_STATS:
		u_stats = (struct cappsule_ioc_stats __user *)arg;
		if (get_user(capsule_id, &u_stats->capsule_id))
			return -EFAULT;

		ret = channel_get_capsule_stats(capsule_id, &u_stats->stats);
		break;

	case CAPPSULE_IOC_LIST_CAPSULES:
		u_list = (struct cappsule_ioc_list *)arg;
		ret = channel_get_capsule_ids(u_list);
		break;

	case CAPPSULE_IOC_GET_VMM_STATS:
		u_vmm_stats = (struct cappsule_ioc_vmm_stats __user *)arg;
		if (get_user(cpu, &u_vmm_stats->cpu))
			return -EFAULT;

		ret = channel_get_vmm_stats(cpu, &u_vmm_stats->stats);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int open(struct inode *inode, struct file *file)
{
	struct daemon *daemon;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	daemon = kmalloc(sizeof(*daemon), GFP_KERNEL);
	if (daemon == NULL)
		return -ENOMEM;

	/* no more than one daemon process is allowed to communicate with
	 * hypervisor through the channel file descriptor */
	if (atomic_cmpxchg(&daemon_count, 0, 1) != 0) {
		kfree(daemon);
		return -EEXIST;
	}

	daemon->lock = __RW_LOCK_UNLOCKED(daemon->lock);
	INIT_LIST_HEAD(&daemon->running_capsules);
	INIT_LIST_HEAD(&daemon->exited_capsules);
	init_waitqueue_head(&daemon->exited_waitq);
	kref_init(&daemon->refcount);

	file->private_data = daemon;

	return 0;
}

static int close(struct inode *inode, struct file *file)
{
	struct daemon *daemon = file->private_data;

	kref_put(&daemon->refcount, release_daemon);
	atomic_set(&daemon_count, 0);

	return 0;
}

static const struct file_operations channel_fops = {
	.owner          = THIS_MODULE,
	.read           = read,
	.poll           = poll,
	.unlocked_ioctl = common_channel_ioctl,
	.open           = open,
	.release        = close,
};

err_t channel_init(void)
{
	channel_dev = kzalloc(sizeof(*channel_dev), GFP_KERNEL);
	if (channel_dev == NULL)
		return ERROR_ALLOC_FAILED;

	channel_dev->minor = MISC_DYNAMIC_MINOR;
	channel_dev->name = CHANNEL_DEVICE_NAME;
	channel_dev->fops = &channel_fops,

	set_exec_policies(NULL);
	atomic_set(&daemon_count, 0);

	if (misc_register(channel_dev) != 0) {
		kfree(channel_dev);
		return ERROR_XCHAN_DEVICE_REGISTRATION;
	}

	return SUCCESS;
}

void channel_exit(void)
{
	struct exec_policies *exec_policies;

	misc_deregister(channel_dev);

	kfree(channel_dev);
	channel_dev = NULL;

	exec_policies = get_exec_policies();
	if (exec_policies != NULL)
		free_exec_policies(exec_policies);
}
