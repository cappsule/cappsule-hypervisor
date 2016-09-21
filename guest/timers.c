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

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/hrtimer.h>
#include <linux/kallsyms.h>
#include <linux/tick.h>
#include <asm/vmx.h>

#include "guest/init.h"
#include "guest/timers.h"
#include "guest/symbols.h"
#include "common/vmcall.h"

/* c1797baf6880174f899ce3960d0598f5bbeeb7ff
 * tick: Move core only declarations and functions to core */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
enum tick_device_mode {
	TICKDEV_MODE_PERIODIC,
	TICKDEV_MODE_ONESHOT,
};

struct tick_device {
	struct clock_event_device *evtdev;
	enum tick_device_mode mode;
};
#endif

#define TVN_BITS (CONFIG_BASE_SMALL ? 4 : 6)
#define TVR_BITS (CONFIG_BASE_SMALL ? 6 : 8)
#define TVN_SIZE (1 << TVN_BITS)
#define TVR_SIZE (1 << TVR_BITS)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
/* commit: 1dabbcec2c0a36fe43509d06499b9e512e70a028
 * timer: Use hlist for the timer wheel hash buckets */
#define LIST_TYPE		struct hlist_head
#define LIST_FOR_EACH_ENTRY	hlist_for_each_entry
#else
#define LIST_TYPE		struct list_head
#define LIST_FOR_EACH_ENTRY	list_for_each_entry
#endif

struct tvec {
	LIST_TYPE vec[TVN_SIZE];
};

struct tvec_root {
	LIST_TYPE vec[TVR_SIZE];
};

struct tvec_base {
	spinlock_t lock;
	struct timer_list *running_timer;
	unsigned long timer_jiffies;
	unsigned long next_timer;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,5,0)
	/* commit: 99d5f3aac674fe081ffddd2dbb8946ccbc14c410
	 * timers: Add accounting of non deferrable timers */
	unsigned long active_timers;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,5)
	/* commit: fff421580f512fc044cc7421fdff31a7a6997350
	 * timers: Track total number of timers in list */
	unsigned long all_timers;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,3)
	/* commit: d6f93829811a3e74f58e3c3823d507411eed651a
	 * timer: Store cpu-number in struct tvec_base */
	int cpu;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
	/* commit: bc7a34b8b9ebfb0f4b8a35a72a0b134fd6c5ef50
	 * timer: Reduce timer migration overhead if disabled */
	bool migration_enabled;
	/* commit: 683be13a284720205228e29207ef11a1c3c322b9
	 * timer: Minimize nohz off overhead */
	bool nohz_active;
#endif
	struct tvec_root tv1;
	struct tvec tv2;
	struct tvec tv3;
	struct tvec tv4;
	struct tvec tv5;
} ____cacheline_aligned;


static const char *timer_name[] = {
	"delayed_work_timer_fn+0x0",
	"commit_timeout+0x0",
	"wakeup_timer_fn+0x0",
	"idle_worker_timeout+0x0",
	"process_timeout+0x0",
	"mce_start_timer+0x0",
	NULL,
};

static void do_nothing(unsigned long data)
{
}

static int allowed_timer(char *name)
{
	const char **p;

	for (p = timer_name; *p != NULL; p++)
		if (strcmp(*p, name) == 0)
			return 1;

	return 0;
}

static void filter_timer_list(LIST_TYPE *head)
{
	struct timer_list *timer;
	char name[512], *p;
	int allowed;

	LIST_FOR_EACH_ENTRY(timer, head, entry) {
		sprint_symbol(name, (unsigned long)timer->function);
		if ((p = strchr(name, '/')) != NULL)
			*p = '\x00';

		allowed = allowed_timer(name);
		//printk(KERN_ERR "%s timer %s"
		//       allowed ? "keeping " : "removing", name);

		/* timer could be deleted, but it's difficult because
		 * detach_expired_timer() isn't exported */
		if (!allowed)
			timer->function = do_nothing;
	}
}

/* XXX: temporary solution. May need some cleanup. How does /proc/timer_list
 * works?
 *
 * Required, otherwise hardware timers (network card for example) may expire */
void setup_timers(void)
{
	struct tvec_base *base;
	int i;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,0,0)
	base = _tvec_bases[smp_processor_id()];
#else
	base = *_tvec_bases[smp_processor_id()];
#endif

	for (i = 0; i < TVR_SIZE; i++)
		filter_timer_list(base->tv1.vec + i);

	for (i = 0; i < TVN_SIZE; i++) {
		filter_timer_list(base->tv2.vec + i);
		filter_timer_list(base->tv3.vec + i);
		filter_timer_list(base->tv4.vec + i);
		filter_timer_list(base->tv5.vec + i);
	}
}

/* called from guest
 *
 * Guest time is already accurate, but if timekeeping.cycle_last is not up to
 * date, timespec_add_ns() takes a hundred of seconds (!) to return (because of
 * a 64 bits overflow). */
void guest_fix_timekeeping(void)
{
	struct timespec ts;
	struct timeval tv;
	int ret;

	tv.tv_sec = 0;
	tv.tv_usec = 0;
	cpu_vmcs_vmcall2(VMCALL_GETTIMEOFDAY, 0, &tv.tv_sec, &tv.tv_usec);

	/* do_gettimeofday sets a struct timeval but do_settimeofday expects a
	 * struct timespec */
	ts.tv_sec = tv.tv_sec;
	ts.tv_nsec = tv.tv_usec * NSEC_PER_USEC;

	/* XXX: oops_in_progress is set to 1 to avoid annoying warning (because
	 * IRQs are enabled). Callstack:
	 *
	 *   do_settimeofday
	 *     clock_was_set
	 *       on_each_cpu
	 *         smp_call_function
	 *           smp_call_function_many
	 *
	 *   WARN_ON_ONCE(cpu_online(this_cpu) && irqs_disabled()
	 *      && !oops_in_progress && !early_boot_irqs_disabled); */
	oops_in_progress = 1;
	ret = do_settimeofday(&ts);
	oops_in_progress = 0;

	if (ret != 0)
		guest_error("settimeofday failed");
}

static u32 null_apic_read(u32 reg)
{
	return 0;
}

static void null_apic_write(u32 reg, u32 v)
{
}

static int handle_lapic_next_event(unsigned long delta,
				   struct clock_event_device *evt)
{
	__u64 nsec;

	nsec = (delta << evt->shift) / evt->mult;
	cpu_vmcs_vmcall(VMCALL_SET_TIMER, nsec);

	return 0;
}

void init_apic(void)
{
	struct clock_event_device *levt;
	struct tick_device *dev;

	dev = _tick_get_device(smp_processor_id());
	levt = dev->evtdev;

	levt->set_next_event = handle_lapic_next_event;
	/* XXX: .broadcast? */

	apic->read = null_apic_read;
	apic->write = null_apic_write;
}
