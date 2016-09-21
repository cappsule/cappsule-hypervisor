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

#include <linux/kernel.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/gfp.h>
#include <linux/fs.h>
#include <linux/poll.h>
#include <linux/sched.h>

#include "common/log.h"
#include "host/capsule.h"
#include "host/ept.h"
#include "common/error.h"

#define MAX_ENTRIES	64
#define DMESG_PREFIX	"[cpsl] "
#define DMESG_SIZE	1024

static struct cpslog {
	atomic_t nconsumer;
	spinlock_t prod_lock;
	spinlock_t cons_lock;
	unsigned int tail;
	unsigned int head;
	size_t size;
	wait_queue_head_t waitq;
	struct log_entry entries[MAX_ENTRIES];
} *cpslog;

static inline int same_page(unsigned long p, unsigned long q)
{
	return ((p & PAGE_MASK) == (q & PAGE_MASK));
}

/* beware, addr and count come directly from capsule */
void cappsule_dmesg(struct capsule *capsule, unsigned long addr, size_t count)
{
	unsigned long gpa;
	size_t offset;
	void *hva;
	char *buf;

	offset = addr & (PAGE_SIZE-1);
	if (!same_page(addr, addr + count))
		count = PAGE_SIZE - offset;

	if (count > LOG_LINE_MAX)
		count = LOG_LINE_MAX;

	gpa = __pa(addr & PAGE_MASK);
	hva = gpa_to_hva(capsule, gpa, NULL);
	if (hva == NULL)
		kill_s(capsule, KILL_DMESG_INVALID_ADDR);

	buf = kmalloc(count + 1, GFP_ATOMIC);
	if (buf == NULL) {
		printk(KERN_ERR "%s: kmalloc failed\n", __func__);
		return;
	}

	memcpy(buf, hva + offset, count);
	buf[count] = '\x00';
	cpsl_dmesg(capsule->id, "%s", buf);

	kfree(buf);
}

/* amount of space left */
static size_t cpslog_space(unsigned int head, unsigned int tail, size_t size)
{
	if (head == tail)
		return size - 1;
	else if (head > tail)
		return size - 1 - (head - tail);
	else
		return tail - head - 1;
}

/* amount of entries filled */
static size_t cpslog_count(unsigned int head, unsigned int tail, size_t size)
{
	if (head >= tail)
		return head - tail;
	else
		return size - tail + head;
}

static unsigned int cpslog_poll(struct file *file, poll_table *wait)
{
	unsigned int count, head, tail;

	poll_wait(file, &cpslog->waitq, wait);

	spin_lock(&cpslog->cons_lock);
	head = cpslog->head;
	tail = ACCESS_ONCE(cpslog->tail);
	count = cpslog_count(head, tail, cpslog->size);
	spin_unlock(&cpslog->cons_lock);

	return (count > 0) ? POLLIN : 0;
}

/* copy an entry to userland
 * algorithm from Documentation/circular_buffers.txt */
static ssize_t cpslog_read(struct file *file,
			   char __user *buf,
			   size_t count,
			   loff_t *pos)
{
	struct log_entry *entry;
	unsigned int head, tail;
	ssize_t ret, size;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (entry == NULL)
		return -EIO;

	spin_lock(&cpslog->cons_lock);

	head = ACCESS_ONCE(cpslog->head);
	tail = cpslog->tail;

	if (cpslog_count(head, tail, cpslog->size) >= 1) {
		smp_read_barrier_depends();

		size = sizeof(entry->header);
		size += cpslog->entries[tail].header.size;

		/* don't copy entry directly to userland since copy_to_user can
		 * sleep and cons_lock is held */
		memcpy(entry, &cpslog->entries[tail], size);

		smp_mb();

		cpslog->tail = (tail + 1) & (cpslog->size - 1);
	} else {
		size = 0;
	}

	spin_unlock(&cpslog->cons_lock);

	if (size > 0) {
		if (count < size)
			size = count;
		if (copy_to_user(buf, entry, size) != 0)
			ret = -EFAULT;
		else
			ret = size;
	} else {
		ret = -EAGAIN;
	}

	kfree(entry);

	return ret;
}

static void fill_entry(struct log_entry *entry,
		       enum CPSL_LOG_FACILIY facility,
		       enum CPSL_LOG_LEVEL level,
		       unsigned int id,
		       const char *fmt,
		       va_list args)
{
	size_t len;

	len = vscnprintf(entry->buffer, sizeof(entry->buffer)-1, fmt, args);
	entry->buffer[len] = '\x00';
	entry->header.timestamp = local_clock();
	entry->header.size = len + 1;
	entry->header.id = id;
	entry->header.facility = facility;
	entry->header.level = level;

	if (level == CPSL_WARN || level == CPSL_WARN)
		printk(KERN_ERR "%s\n", entry->buffer);
}

static void log_to_dmesg(enum CPSL_LOG_FACILIY facility,
			 enum CPSL_LOG_LEVEL level,
			 unsigned int id,
			 const char *fmt,
			 va_list args)
{
	char *buf, *p;
	int ret;

	buf = kmalloc(DMESG_SIZE, GFP_ATOMIC);
	if (buf == NULL) {
		printk(KERN_ERR "%s\n", fmt);
		return;
	}

	strcpy(buf, DMESG_PREFIX);
	p = buf + sizeof(DMESG_PREFIX)-1;

	switch (facility) {
	case LOG_HV:
		strcpy(p, "hv: ");
		p += 4;
		break;
	case LOG_CPSL:
		p += sprintf(p, "capsule %d: ", id);
		break;
	case LOG_TG:
		strcat(p, "tg: ");
		p += 4;
		break;
	}

	ret = vscnprintf(p, DMESG_SIZE - (p - buf) - 1, fmt, args);
	p[ret] = '\x00';

	/* remove trailing line returns from capsule dmesg entry */
	if (level == CPSL_DMESG) {
		while (ret > 0 && buf[ret-1] == '\n')
			ret--;
	}

	printk(KERN_ERR "%s\n", buf);

	kfree(buf);
}

/* insert a new log entry */
void cpsl_log(enum CPSL_LOG_FACILIY facility,
	      enum CPSL_LOG_LEVEL level,
	      unsigned int id,
	      const char *fmt,
	      ...)
{
	struct log_entry *entry;
	unsigned int head, tail;
	va_list args;
	int inserted;

	if (atomic_read(&cpslog->nconsumer) == 0)
		goto fallback;

	spin_lock(&cpslog->prod_lock);

	head = cpslog->head;
	tail = ACCESS_ONCE(cpslog->tail);

	if (cpslog_space(head, tail, cpslog->size) >= 1) {
		va_start(args, fmt);
		entry = &cpslog->entries[head];
		fill_entry(entry, facility, level, id, fmt, args);
		va_end(args);

		smp_wmb();

		cpslog->head = (head + 1) & (cpslog->size - 1);
		inserted = 1;
	} else {
		inserted = 0;
	}

	spin_unlock(&cpslog->prod_lock);

	if (inserted) {
		wake_up(&cpslog->waitq);
		return;
	}

fallback:
	/* log entry to dmesg if there is no consumer or no entry available */
	va_start(args, fmt);
	log_to_dmesg(facility, level, id, fmt, args);
	va_end(args);
}

static int cpslog_open(struct inode *inode, struct file *file)
{
	int n;

	n = atomic_inc_return(&cpslog->nconsumer);
	if (n > 1) {
		atomic_dec(&cpslog->nconsumer);
		return -ENFILE;
	}

	return 0;
}

static int cpslog_close(struct inode *inode, struct file *file)
{
	atomic_dec(&cpslog->nconsumer);

	return 0;
}

static const struct file_operations log_fops = {
	.owner          = THIS_MODULE,
	.open           = cpslog_open,
	.poll           = cpslog_poll,
	.read           = cpslog_read,
	.release        = cpslog_close,
	.llseek         = default_llseek,
};

static struct miscdevice *log_dev;

err_t log_init(void)
{
	cpslog = kzalloc(sizeof(*cpslog), GFP_KERNEL);
	if (cpslog == NULL)
		return ERROR_ALLOC_FAILED;

	log_dev = kzalloc(sizeof(*log_dev), GFP_KERNEL);
	if (log_dev == NULL) {
		kfree(cpslog);
		return ERROR_ALLOC_FAILED;
	}

	log_dev->minor = MISC_DYNAMIC_MINOR;
	log_dev->name = LOG_DEVICE;
	log_dev->fops = &log_fops,

	atomic_set(&cpslog->nconsumer, 0);
	spin_lock_init(&cpslog->prod_lock);
	spin_lock_init(&cpslog->cons_lock);
	cpslog->head = 0;
	cpslog->tail = 0;
	cpslog->size = MAX_ENTRIES;
	init_waitqueue_head(&cpslog->waitq);

	if (misc_register(log_dev) != 0) {
		kfree(cpslog);
		kfree(log_dev);
		return ERROR_LOG_DEVICE_REGISTRATION;
	}

	return SUCCESS;
}

void log_exit(void)
{
	/* TODO: dump entries which aren't consumed yet */
	misc_deregister(log_dev);
	kfree(log_dev);
	kfree(cpslog);
}
