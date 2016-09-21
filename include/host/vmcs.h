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

#ifndef _HOST_VMCS_H
#define _HOST_VMCS_H 1

struct ia32_vmx_basic_msr_bits {
	__u32 revid;
	unsigned region_size     :12;
	unsigned RegionClear     :1;
	unsigned Reserved1       :3;
	unsigned phy_addr_width  :1;
	unsigned DualMon         :1;
	unsigned mem_type        :4;
	unsigned VmExitReport    :1;
	unsigned Reserved2       :9;
} __attribute__((__packed__));

union ia32_vmx_basic_msr {
	struct ia32_vmx_basic_msr_bits bits;
	__u64 value;
};

struct vmcs_region;

void init_vmcs_capsule_template(void);
struct vmcs_template *alloc_vmcs_template(void);
struct vmcs_region *alloc_vmcs(gfp_t flags);
err_t init_trusted_vmcs(struct vmcs_region *vmcs,
			struct vmcs_template *tmpl,
			unsigned long host_rsp,
			struct vmx_msr_entry *autoload_msr,
			unsigned long guest_rip,
			unsigned long guest_rsp,
			unsigned long guest_rflags);
err_t create_capsule_vmcs(struct vmcs_region **vmcs,
			  struct vmcs_template *tmpl,
			  unsigned long eptp,
			  unsigned long guest_msr);
int init_vmcs_bitmaps(void);
void free_vmcs_bitmaps(void);

#endif /* _HOST_VMCS_H */
