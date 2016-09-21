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

#ifndef CUAPI_COMMON_XCHAN_H
#define CUAPI_COMMON_XCHAN_H

enum xchan_type {
	XCHAN_NET = 0,
	XCHAN_GUI,
	XCHAN_FS,
	XCHAN_CONSOLE,
	XCHAN_TYPE_MAX
};

#define XCHAN_NPAGES_NET	(64 * 2)
#define XCHAN_NPAGES_GUI	(8 * 2)
#define XCHAN_NPAGES_FS		(33 * 2)
#define XCHAN_NPAGES_CONSOLE	(8 * 2)

#define XCHAN_NPAGES_TOTAL	(	\
	XCHAN_NPAGES_NET +		\
	XCHAN_NPAGES_GUI +		\
	XCHAN_NPAGES_FS +		\
	XCHAN_NPAGES_CONSOLE		\
	)

static inline unsigned int xchan_npages(enum xchan_type type)
{
	unsigned int npages;

	switch (type) {
	case XCHAN_CONSOLE:	npages = XCHAN_NPAGES_CONSOLE; break;
	case XCHAN_FS:		npages = XCHAN_NPAGES_FS; break;
	case XCHAN_GUI:		npages = XCHAN_NPAGES_GUI; break;
	case XCHAN_NET:		npages = XCHAN_NPAGES_NET; break;
	default:		npages = 0; break;
	}

	return npages;
}

static inline int xchan_start_page(enum xchan_type type)
{
	unsigned int start;

	start = -1;

	/* note there's no break (instead for default) */
	switch (type) {
	case XCHAN_NET: 	start += XCHAN_NPAGES_GUI;
	case XCHAN_GUI:		start += XCHAN_NPAGES_FS;
	case XCHAN_FS:		start += XCHAN_NPAGES_CONSOLE;
	case XCHAN_CONSOLE:	start += 1;
	default:		break;
	}

	return start;
}

#endif /* CUAPI_COMMON_XCHAN_H */
