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

#ifndef _HOST_SEGMENT_H
#define _HOST_SEGMENT_H 1

enum segment_reg {
	ES,
	CS,
	SS,
	DS,
	FS,
	GS,
	LDTR,
	TR,
	NSEGREG,
};

struct segment_access_rights {
	union {
		struct {
			unsigned type:4;
			unsigned s:1;
			unsigned dpl:2;
			unsigned present:1;
			unsigned reserved1:4;
			unsigned avl:1;
			unsigned l:1;
			unsigned db:1;
			unsigned g:1;
			unsigned unusable:1;
			unsigned reserved2:15;
		};
		__u32 access;
	};
};

struct segment_selector {
	__u32 limit;
	__u64 base;
};

struct vmcs_segment {
	__u16 selector;
	__u32 limit;
	__u32 ar_bytes;
	__u64 base;
};

/* ugly gcc extension. */
#define SEGMENT_NAME(r) ({			\
	char *p;				\
	switch (r) {				\
	case ES: p = "ES"; break;		\
	case CS: p = "CS"; break;		\
	case SS: p = "SS"; break;		\
	case DS: p = "DS"; break;		\
	case FS: p = "FS"; break;		\
	case GS: p = "GS"; break;		\
	case LDTR: p = "LDTR"; break;		\
	case TR: p = "TR"; break;		\
	default: p = "??"; break;		\
	}					\
	p;					\
})

#endif /* _HOST_SEGMENT_H */
