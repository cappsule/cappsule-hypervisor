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

#include <linux/workqueue.h>
#include <linux/kallsyms.h>
#include <linux/backing-dev.h>
#include <linux/device.h>

struct worker;


static void dummy(struct work_struct *work)
{
}

static const char *workqueues_name[] = {
	"flush_to_ldisc",	/* tty */
	"vmstat_update",	/* update of /proc/vmstat */
	/* bdi_writeback_workfn is specially handled */
	NULL
};

static int keep_bdi_writeback(struct work_struct *work)
{
	struct backing_dev_info *bdi;
	struct bdi_writeback *wb;

	wb = container_of(to_delayed_work(work), struct bdi_writeback, dwork);
	bdi = wb->bdi;

	/* Pages from block devices may still be cached. Only allow fuse
	 * devices. */
	if (strcmp(bdi->name, "fuse") == 0)
		return 1;

	return 0;
}

static int keep_workqueue(const char *func_name, struct work_struct *work)
{
	const char **name;

	for (name = workqueues_name; *name != NULL; name++) {
		if (strcmp(*name, func_name) == 0)
			return 1;
	}

	if (strcmp(func_name, "bdi_writeback_workfn") == 0)
		return keep_bdi_writeback(work);

	return 0;
}

void filter_workqueue(struct worker *worker, struct work_struct *work)
{
	char name[512], *p;

	sprint_symbol(name, (long unsigned int)work->func);
	p = strchr(name, '+');
	if (p != NULL)
		*p = '\x00';

	/* replace work function if the original isn't allowed to run */
	if (work->func != dummy && !keep_workqueue(name, work))
		work->func = dummy;
}
