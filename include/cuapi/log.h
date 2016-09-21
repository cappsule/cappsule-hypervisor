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

#ifndef CUAPI_LOG_H
#define CUAPI_LOG_H

#define LOG_DEVICE	"cappsule-log"
#define LOG_LINE_MAX	1024

enum CPSL_LOG_FACILIY {
	LOG_HV,		/* message about hypervisor */
	LOG_CPSL,	/* message about cappsule */
	LOG_TG,		/* message about trusted guest */
};

enum CPSL_LOG_LEVEL {
	CPSL_ERR,
	CPSL_WARN,
	CPSL_INFO,
	CPSL_DEBUG,
	CPSL_DMESG,	/* printk from capsule */
};

struct log_header {
	unsigned long timestamp;
	unsigned short size;
	unsigned short id;
	unsigned char level;
	unsigned char facility;
} __attribute__((packed));

struct log_entry {
	struct log_header header;
	char buffer[LOG_LINE_MAX];
};

#endif /* CUAPI_LOG_H */
