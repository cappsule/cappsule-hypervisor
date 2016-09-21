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

#ifndef COMMON_LOG_H
#define COMMON_LOG_H

#include "cuapi/log.h"
#include "common/error.h"

struct capsule;
void cappsule_dmesg(struct capsule *capsule, unsigned long addr, size_t count);
err_t log_init(void);
void log_exit(void);
void cpsl_log(enum CPSL_LOG_FACILIY facility,
	      enum CPSL_LOG_LEVEL level,
	      unsigned int id,
	      const char *fmt,
	      ...);

#if 1
#ifndef RELEASE
#define cpsl_log_(facility, level, id, fmt, ...)			\
	cpsl_log(facility, level, id, fmt, ##__VA_ARGS__)
#else
#define cpsl_log_(facility, level, id, fmt, ...) do {			\
	if (level != CPSL_DEBUG)					\
		cpsl_log(facility, level, id, fmt, ##__VA_ARGS__);	\
	} while (0)
#endif
#else
#define cpsl_log_(facility, level, id, fmt, ...)	printk(KERN_ERR fmt "\n", ##__VA_ARGS__)
#endif

#define hv_err(fmt, ...)	cpsl_log_(LOG_HV, CPSL_ERR, 0, fmt, ##__VA_ARGS__)
#define hv_warn(fmt, ...)	cpsl_log_(LOG_HV, CPSL_WARN, 0, fmt, ##__VA_ARGS__)
#define hv_info(fmt, ...)	cpsl_log_(LOG_HV, CPSL_INFO, 0, fmt, ##__VA_ARGS__)
#define hv_dbg(fmt, ...)	cpsl_log_(LOG_HV, CPSL_DEBUG, 0, fmt, ##__VA_ARGS__)

#define tg_err(fmt, ...)	cpsl_log_(LOG_TG, CPSL_ERR, 0, fmt, ##__VA_ARGS__)
#define tg_warn(fmt, ...)	cpsl_log_(LOG_TG, CPSL_WARN, 0, fmt, ##__VA_ARGS__)
#define tg_info(fmt, ...)	cpsl_log_(LOG_TG, CPSL_INFO, 0, fmt, ##__VA_ARGS__)
#define tg_dbg(fmt, ...)	cpsl_log_(LOG_TG, CPSL_DEBUG, 0, fmt, ##__VA_ARGS__)

#define cpsl_err(id, fmt, ...)		cpsl_log_(LOG_CPSL, CPSL_ERR, id, fmt, ##__VA_ARGS__)
#define cpsl_warn(id, fmt, ...)		cpsl_log_(LOG_CPSL, CPSL_WARN, id, fmt, ##__VA_ARGS__)
#define cpsl_info(id, fmt, ...)		cpsl_log_(LOG_CPSL, CPSL_INFO, id, fmt, ##__VA_ARGS__)
#define cpsl_dbg(id, fmt, ...)		cpsl_log_(LOG_CPSL, CPSL_DEBUG, id, fmt, ##__VA_ARGS__)
#define cpsl_dmesg(id, fmt, ...)	cpsl_log_(LOG_CPSL, CPSL_DMESG, id, fmt, ##__VA_ARGS__)

#endif /* COMMON_LOG_H */
