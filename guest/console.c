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
#include <linux/uaccess.h>
#include <linux/ioctl.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/tty_flip.h>

#include "common/vmcall.h"
#include "common/xchan.h"
#include "guest/console.h"
#include "guest/init.h"
#include "guest/shared_mem.h"

extern struct tasklet_struct *xchan_console_notify;

struct ring {
	spinlock_t lock;
	size_t size;
	unsigned char *data;
	atomic_t *notified;
	size_t *start;
	size_t *end;
};

struct cappsule_guest_console {
	/* TTY port associated with this console. */
	struct tty_port tty_port;
	spinlock_t lock;

	/* xchan rings */
	bool activated;
	struct ring ring_r;
	struct ring ring_w;

	/* interrupt handling */
	struct tasklet_struct notify;
};

#define RING_WRITE_HELPER(ring, buf, end, n, size, ret) do {	\
	if (n > size)						\
		n = size;					\
	memcpy(ring->data + end, buf, n);			\
	end = (end + n) % ring->size;				\
	ret += n;						\
} while (0)

#define RING_READ_HELPER(ring, buf, start, n, size, ret) do {	\
	if (n > size)						\
		n = size;					\
	memcpy(buf, ring->data + start, n);			\
	start = (start + n) % ring->size;			\
	ret += n;						\
} while (0)

// XXX: Race condition possible when reading start and end.
static size_t ring_used_space(struct ring *ring)
{
	size_t start, end;

	start = *ring->start;
	end = *ring->end;

	BUG_ON(start > ring->size || end > ring->size);

	if (start <= end)
		return end - start;
	else
		return end + (ring->size - start);
}

static size_t ring_free_space(struct ring *ring)
{
	return ring->size - ring_used_space(ring) - 1;
}

static ssize_t ring_read_unlocked(struct ring *ring, void *buf, size_t size)
{
	size_t end, n, ret, start;

	start = *ring->start;
	end = *ring->end;

	if (start >= ring->size || end >= ring->size)
		return -EINVAL;

	/* ensure ring isn't empty */
	if (start == end) {
		atomic_set(ring->notified, 0);
		return 0;
	}

	ret = 0;
	if (end < start) {
		n = ring->size - start;
		RING_READ_HELPER(ring, buf, start, n, size, ret);
		buf = (unsigned char __user *)buf + n;
		size -= n;
	}

	n = end - start;
	RING_READ_HELPER(ring, buf, start, n, size, ret);

	if (start == end)
		atomic_set(ring->notified, 0);

	*ring->start = start;

	return ret;
}

static ssize_t ring_write_unlocked(struct ring *ring,
				   const void *buf, size_t size)
{
	size_t end, n, ret, start;
	bool full;

	start = *ring->start;
	end = *ring->end;

	if (start >= ring->size || end >= ring->size)
		return -EINVAL;

	ret = 0;
	full = false;
	if (start <= end) {
		if (start > 0) {
			n = ring->size - end;
		} else {
			/* ensure ring isn't full */
			if (end == ring->size - 1)
				return 0;

			/* let one slot empty to indicate that ring will be
			 * full */
			n = ring->size - end - 1;
			full = true;
		}

		RING_WRITE_HELPER(ring, buf, end, n, size, ret);
		buf = (unsigned char __user *)buf + n;
		size -= n;
	}

	/* ensure ring isn't full */
	if (!full && start - end > 1) {
		n = start - end - 1;
		RING_WRITE_HELPER(ring, buf, end, n, size, ret);
	}

	*ring->end = end;

	return ret;
}

static ssize_t ring_write(struct ring *ring, const void *buf, size_t size)
{
	ssize_t ret;

	spin_lock(&ring->lock);
	ret = ring_write_unlocked(ring, buf, size);
	spin_unlock(&ring->lock);

	return ret;
}

static void ring_init(struct ring *ring, unsigned char *p, size_t size)
{
	size_t used;

	memset(ring, 0, sizeof(*ring));

	used = sizeof(*ring->notified) +
	       sizeof(*ring->start) +
	       sizeof(*ring->end);

	ring->size = size - used;

	/* don't memset p to 0 here: if trusted guest already write something to
	 * the ring buffer, capsule would overwrite it */

	/* shared memory: [ buf... ][ start ][ end ] */
	ring->data = p;
	ring->notified = (atomic_t *)(ring->data + ring->size);
	ring->start = (size_t *)((unsigned char *)ring->notified + sizeof(*ring->notified));
	ring->end = (size_t *)((unsigned char *)ring->start + sizeof(*ring->start));
}

#define NR_CAPPSULE_TTYS 1
static struct cappsule_guest_console guest_consoles[NR_CAPPSULE_TTYS];

static void xchan_console_set_handler(struct cappsule_guest_console *console,
				      void (*notify_routine)(unsigned long))
{
	tasklet_init(&console->notify, notify_routine, (unsigned long)console);
	xchan_console_notify = &console->notify;
}

static int xchan_console_rings_init(struct cappsule_guest_console *guest_console)
{
	unsigned long gpa, pages, start;
	unsigned int npages, order;
	unsigned char *p;
	size_t size;
	int i;

	npages = xchan_npages(XCHAN_CONSOLE);
	start = xchan_start_page(XCHAN_CONSOLE);

	order = order_base_2(npages);
	pages = __get_free_pages(GFP_KERNEL, order);
	if (pages == 0) {
		guest_error("not enough memory for console rings");
		return -ENOMEM;
	}

	p = (unsigned char *)pages;
	gpa = __pa(pages);
	for (i = start; i < start + npages; i++) {
		trigger_ept_violation((unsigned long)p);
		cpu_vmcs_vmcall3(VMCALL_XCHAN_MAP_GUEST_PAGE, gpa, i);
		p += PAGE_SIZE;
		gpa += PAGE_SIZE;
	}

	p = (unsigned char *)pages;
	size = npages * PAGE_SIZE / 2;
	ring_init(&guest_console->ring_w, p, size);
	p += size;
	ring_init(&guest_console->ring_r, p, size);

	return 0;
}

/*
 * Returns the available write space for the tty.
 */
static int guest_tty_write_room(struct tty_struct *tty)
{
	struct cappsule_guest_console *guest_console = tty->driver_data;

	return ring_free_space(&guest_console->ring_w);
}

/*
 * Returns the available read space for the tty.
 */
static int guest_tty_chars_in_buffer(struct tty_struct *tty)
{
	struct cappsule_guest_console *guest_console = tty->driver_data;

	return ring_used_space(&guest_console->ring_r);
}

static int guest_tty_open(struct tty_struct *tty, struct file *f)
{
	struct cappsule_guest_console *guest_console;
	guest_console = &guest_consoles[tty->index];

	if (tty_do_resize(tty, &shared_mem->tty_size))
		printk(KERN_WARNING "failed to set tty size\n");

	return tty_port_open(&guest_console->tty_port, tty, f);
}

static void guest_tty_close(struct tty_struct *tty, struct file *f)
{
	struct cappsule_guest_console *guest_console = tty->driver_data;

	return tty_port_close(&guest_console->tty_port, tty, f);
}

static int guest_tty_write(struct tty_struct *tty,
			   const unsigned char *buf, int count)
{
	struct cappsule_guest_console *guest_console = tty->driver_data;
	ssize_t ret;
	int err;

	ret = ring_write(&guest_console->ring_w, buf, count);

	if (guest_tty_write_room(tty) == 0)
		atomic_set(guest_console->ring_w.notified, 0);

	if (ret > 0) {
		err = cpu_vmcs_vmcall_ret(VMCALL_XCHAN_NOTIFY_TRUSTED,
					  XCHAN_CONSOLE);
		if (err != 0) {
			printk(KERN_ERR "%s: vmcall failed\n", __func__);
			ret = -EINVAL;
		}
	}

	return ret;
}

static int guest_tty_put_char(struct tty_struct *tty, unsigned char ch)
{
	return guest_tty_write(tty, &ch, sizeof(ch));
}

/*
 * Wake up TTY waiters if writing data becomes available.
 */
static void guest_tty_try_wakeup(struct tty_port *port)
{
	struct tty_struct *tty;
	size_t write_room;

	tty = tty_port_tty_get(port);
	write_room = guest_tty_write_room(tty);

	if (write_room > 0 && waitqueue_active(&tty->write_wait))
		tty_wakeup(tty);

	tty_kref_put(tty);
}

/*
 * Called when new incoming data becomes available.
 * Cannot sleep.
 */
static void guest_tty_notify(unsigned long arg)
{
	struct cappsule_guest_console *guest_console;
	struct tty_port *port;
	size_t bytes_avail;
	unsigned char *data;
	struct winsize current_size, actual_size;

	guest_console = (struct cappsule_guest_console *)arg;
	port = &guest_console->tty_port;

	/* Wake up the TTY if it has become writable. */
	guest_tty_try_wakeup(port);

	actual_size = shared_mem->tty_size;
	current_size = port->tty->winsize;

	/* Update the tty size if it has changed. */
	if (actual_size.ws_row != current_size.ws_row ||
	    actual_size.ws_col != current_size.ws_col) {
		if (!tty_do_resize(port->tty, &actual_size))
			printk(KERN_WARNING "cannot update tty size\n");
	}

	bytes_avail = ring_used_space(&guest_console->ring_r);
	if (bytes_avail == 0)
		return;

	bytes_avail = tty_prepare_flip_string(port, &data, bytes_avail);
	if (bytes_avail == 0)
		return;

	/* No need to lock the ring, we are alone here, and we cannot sleep. */
	ring_read_unlocked(&guest_console->ring_r, data, bytes_avail);

	tty_flip_buffer_push(port);
}

static int guest_tty_port_activate(struct tty_port *port,
				   struct tty_struct *tty)
{
	struct cappsule_guest_console *guest_console;
	int ret;

	guest_console = container_of(port,
				     struct cappsule_guest_console, tty_port);

	/* Maps the console memory rings on activation. */
	spin_lock(&guest_console->lock);
	if (!guest_console->activated) {
		ret = xchan_console_rings_init(guest_console);
		if (ret != 0)
			return ret;

		xchan_console_set_handler(guest_console, guest_tty_notify);
		guest_console->activated = true;
	}
	spin_unlock(&guest_console->lock);

	tty->driver_data = guest_console;

	return 0;
}

static void guest_tty_port_shutdown(struct tty_port *port)
{
	/* XXX: xchan rings remaining mapped ? */
	/* XXX: interrupt handler still in place */
}

static const struct tty_operations guest_tty_ops = {
	.open = guest_tty_open,
	.close = guest_tty_close,
	.write = guest_tty_write,
	.put_char = guest_tty_put_char,
	.write_room = guest_tty_write_room,
	.chars_in_buffer = guest_tty_chars_in_buffer,
};

static const struct tty_port_operations guest_tty_port_ops = {
	.activate = guest_tty_port_activate,
	.shutdown = guest_tty_port_shutdown,
};

void guest_tty_init(void)
{
	struct tty_driver *guest_tty_driver;
	struct device *dev;
	unsigned int i;
	struct cappsule_guest_console *guest_console;

	guest_tty_driver = tty_alloc_driver(NR_CAPPSULE_TTYS,
					    TTY_DRIVER_RESET_TERMIOS |
					    TTY_DRIVER_REAL_RAW |
					    TTY_DRIVER_DYNAMIC_DEV);

	if (guest_tty_driver == NULL)
		guest_error("cannot allocate tty driver");

	guest_tty_driver->driver_name = "cappsule_tty_driver";
	guest_tty_driver->name = GUEST_CONSOLE_DEVICE_BASENAME;
	guest_tty_driver->major = 0;
	guest_tty_driver->minor_start = 0;
	guest_tty_driver->type = TTY_DRIVER_TYPE_SERIAL;
	guest_tty_driver->subtype = SERIAL_TYPE_NORMAL;
	guest_tty_driver->init_termios = tty_std_termios;
	guest_tty_driver->init_termios.c_iflag = ICRNL | IUTF8;
	guest_tty_driver->init_termios.c_oflag = ONLCR | OPOST;
	guest_tty_driver->init_termios.c_cflag = B1152000 | CS8 | CREAD;
	guest_tty_driver->init_termios.c_lflag = ISIG | ICANON | IEXTEN |
						 ECHO | ECHOE | ECHOK |
						 ECHOCTL | ECHOKE;

	tty_set_operations(guest_tty_driver, &guest_tty_ops);

	if (tty_register_driver(guest_tty_driver))
		guest_error("could not register tty driver");

	for (i = 0; i < NR_CAPPSULE_TTYS; i++) {
		guest_console = &guest_consoles[i];

		tty_port_init(&guest_console->tty_port);
		guest_console->tty_port.ops = &guest_tty_port_ops;

		dev = tty_port_register_device(&guest_console->tty_port,
					       guest_tty_driver, i, NULL);
		if (IS_ERR(dev))
			guest_error("could not register tty port device");
	}
}
