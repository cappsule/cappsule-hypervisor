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

#include <asm/vmx.h>
#include <asm/traps.h>
#include <asm/desc.h>
#include <linux/gfp.h>
#include <linux/slab.h>

#include "common/log.h"
#include "guest/init.h"
#include "host/capsule.h"
#include "host/segment.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/vm_exit.h"
#include "host/vmcs.h"
#include "host/vmx.h"

//#define DUMP_CONTROLS
//#define DUMP_VMCS

#define PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER	0x00000040
#define CPU_BASED_MONITOR_TRAP_FLAG		0x08000000
#define SECONDARY_EXEC_DESC_TABLE_EXITING	0x00000004
#define SECONDARY_EXEC_RDRAND_EXITING		0x00000800
#define SECONDARY_EXEC_ENABLE_VM_FUNCTIONS	0x00002000
#define SECONDARY_EXEC_EPT_VIOLATION_VE		0x00040000

struct vmcs_guest_template {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;

	unsigned long dr7;

	unsigned long rsp;
	unsigned long rip;
	unsigned long rflags;

	struct vmcs_segment seg[NSEGREG];

	__u32 gdtr_limit;
	unsigned long gdtr_base;
	__u32 idtr_limit;
	unsigned long idtr_base;

	__u64 ia32_debugctl;
	__u32 sysenter_cs;
	unsigned long sysenter_esp;
	unsigned long sysenter_eip;

	__u32 activity_state;
	__u32 interruptibility_info;
	__u32 pending_dbg_exceptions;
	__u64 vmcs_link_pointer;
};

struct vmcs_host_template {
	unsigned long cr0;
	unsigned long cr3;
	unsigned long cr4;

	unsigned long rsp;
	unsigned long rip;

	__u16 es_selector;
	__u16 cs_selector;
	__u16 ss_selector;
	__u16 ds_selector;
	__u16 fs_selector;
	__u16 gs_selector;
	__u16 tr_selector;

	unsigned long fs_base;
	unsigned long gs_base;
	unsigned long tr_base;
	unsigned long gdtr_base;
	unsigned long idtr_base;

	__u32 ia32_sysenter_cs;
	unsigned long ia32_sysenter_esp;
	unsigned long ia32_sysenter_eip;
};

struct vmcs_template {
	__u32 revid;

	struct vmcs_guest_template guest;
	struct vmcs_host_template host;

	__u32 pin_based_vm_exec_control;
	__u32 cpu_based_vm_exec_control;
	__u32 secondary_vm_exec_control;

	__u32 exception_bitmap;
	__u64 io_bitmap_a;
	__u64 io_bitmap_b;

	__u64 tsc_offset;

	unsigned long cr0_guest_host_mask;
	unsigned long cr0_read_shadow;

	unsigned long cr4_guest_host_mask;
	unsigned long cr4_read_shadow;

	__u32 cr3_target_count;
	unsigned long cr3_target_value0;
	unsigned long cr3_target_value1;
	unsigned long cr3_target_value2;
	unsigned long cr3_target_value3;

	__u64 virtual_apic_page_addr;

	__u64 msr_bitmap;

	__u16 virtual_processor_id;

	__u32 tpr_threshold;

	__u32 vm_exit_controls;
	__u32 vm_exit_msr_store_count;
	__u32 vm_exit_msr_load_count;
	__u64 vm_exit_msr_load_addr;

	__u32 vm_entry_controls;
	__u32 vm_entry_msr_load_count;
	__u32 vm_entry_intr_info_field;
	__u32 vm_entry_exception_error_code;
	__u32 vm_entry_instruction_len;
};

struct vmcs_region {
	__u32 revid;
	__u32 vmx_abort;
	__u8 data[0];
} __attribute__((__packed__));

static struct vmcs_template capsule_template;
static void *io_bitmap_a_region, *io_bitmap_b_region, *msr_bitmap_region;
static int msr_bitmap_capability;


#ifdef DUMP_CONTROLS
static void dump_secondary_exec_control(__u32 tmp)
{
	hv_dbg("secondary-vm-exec-control: 0x%08x", tmp);
	if (tmp & SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES)
		hv_dbg("       Virtualize APIC accesses");
	if (tmp & SECONDARY_EXEC_ENABLE_EPT)
		hv_dbg("       Enable EPT");
	if (tmp & SECONDARY_EXEC_DESC_TABLE_EXITING)
		hv_dbg("       Descriptor-table exiting");
	if (tmp & SECONDARY_EXEC_RDTSCP)
		hv_dbg("       Enable RDTSCP");
	if (tmp & SECONDARY_EXEC_VIRTUALIZE_X2APIC_MODE)
		hv_dbg("       Virtualize x2APIC mode");
	if (tmp & SECONDARY_EXEC_ENABLE_VPID)
		hv_dbg("       Enable VPID");
	if (tmp & SECONDARY_EXEC_WBINVD_EXITING)
		hv_dbg("       WBINVD exiting");
	if (tmp & SECONDARY_EXEC_UNRESTRICTED_GUEST)
		hv_dbg("       Unrestricted guest");
	if (tmp & SECONDARY_EXEC_APIC_REGISTER_VIRT)
		hv_dbg("       APIC-register virtualization");
	if (tmp & SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY)
		hv_dbg("       Virtual-interrupt delivery");
	if (tmp & SECONDARY_EXEC_PAUSE_LOOP_EXITING)
		hv_dbg("       PAUSE-loop exiting");
	if (tmp & SECONDARY_EXEC_RDRAND_EXITING)
		hv_dbg("       RDRAND exiting");
	if (tmp & SECONDARY_EXEC_ENABLE_INVPCID)
		hv_dbg("       INVPCID");
	if (tmp & SECONDARY_EXEC_ENABLE_VM_FUNCTIONS)
		hv_dbg("       Enable VM functions");
	if (tmp & SECONDARY_EXEC_SHADOW_VMCS)
		hv_dbg("       VMCS shadowing");
	if (tmp & SECONDARY_EXEC_EPT_VIOLATION_VE)
		hv_dbg("       EPT-violation #VE");
}
static void dump_cpu_exec_control(__u32 tmp)
{
	hv_dbg("cpu-base-vm-exec-control: 0x%08x", tmp);
	if (tmp & CPU_BASED_VIRTUAL_INTR_PENDING)
		hv_dbg("       Interrupt-window exiting");
	if (tmp & CPU_BASED_USE_TSC_OFFSETING)
		hv_dbg("       Use TSC offsetting");
	if (tmp & CPU_BASED_HLT_EXITING)
		hv_dbg("       HLT exiting");
	if (tmp & CPU_BASED_INVLPG_EXITING)
		hv_dbg("       INVLPG exiting");
	if (tmp & CPU_BASED_MWAIT_EXITING)
		hv_dbg("       MWAIT exiting");
	if (tmp & CPU_BASED_RDPMC_EXITING)
		hv_dbg("       RDPMC exiting");
	if (tmp & CPU_BASED_RDTSC_EXITING)
		hv_dbg("       RDTSC exiting");
	if (tmp & CPU_BASED_CR3_LOAD_EXITING)
		hv_dbg("       CR3-load exiting");
	if (tmp & CPU_BASED_CR3_STORE_EXITING)
		hv_dbg("       CR3-store exiting");
	if (tmp & CPU_BASED_CR8_LOAD_EXITING)
		hv_dbg("       CR8-load exiting");
	if (tmp & CPU_BASED_CR8_STORE_EXITING)
		hv_dbg("       CR8-store exiting");
	if (tmp & CPU_BASED_TPR_SHADOW)
		hv_dbg("       Use TPR shadow");
	if (tmp & CPU_BASED_VIRTUAL_NMI_PENDING)
		hv_dbg("       NMI-window exiting");
	if (tmp & CPU_BASED_MOV_DR_EXITING)
		hv_dbg("       MOV-DR exiting");
	if (tmp & CPU_BASED_UNCOND_IO_EXITING)
		hv_dbg("       Unconditional I/O exiting");
	if (tmp & CPU_BASED_USE_IO_BITMAPS)
		hv_dbg("       Use I/O bitmaps");
	if (tmp & CPU_BASED_MONITOR_TRAP_FLAG)
		hv_dbg("       Monitor trap flag");
	if (tmp & CPU_BASED_USE_MSR_BITMAPS)
		hv_dbg("       Use MSR bitmaps");
	if (tmp & CPU_BASED_MONITOR_EXITING)
		hv_dbg("       MONITOR exiting");
	if (tmp & CPU_BASED_PAUSE_EXITING)
		hv_dbg("       PAUSE exiting");
	if (tmp & CPU_BASED_ACTIVATE_SECONDARY_CONTROLS)
		hv_dbg("       Activate secondary controls");
}

static void dump_pin_exec_control(__u32 tmp)
{
	hv_dbg("pin-based-vm-exec-control: 0x%08x", tmp);
	if (tmp & PIN_BASED_EXT_INTR_MASK)
		hv_dbg("       External-interrupt exiting");
	if (tmp & PIN_BASED_NMI_EXITING)
		hv_dbg("       NMI exiting");
	if (tmp & PIN_BASED_VIRTUAL_NMIS)
		hv_dbg("       Virtual NMIs");
	if (tmp & PIN_BASED_ACTIVATE_VMX_PREEMPTION_TIMER)
		hv_dbg("       Activate VMX-preemption timer");
	if (tmp & 0x00000080)
		hv_dbg("       Process posted interrupts");
}

static void dump_exit_controls(__u32 tmp)
{
	hv_dbg("vm-exit-controls: 0x%08x", tmp);
	if (tmp & VM_EXIT_SAVE_DEBUG_CONTROLS)
		hv_dbg("       Save debug controls");
	if (tmp & VM_EXIT_HOST_ADDR_SPACE_SIZE)
		hv_dbg("       Host address-space size");
	if (tmp & VM_EXIT_LOAD_IA32_PERF_GLOBAL_CTRL)
		hv_dbg("       Load IA32_PERF_GLOBAL_CTRL");
	if (tmp & VM_EXIT_ACK_INTR_ON_EXIT)
		hv_dbg("       Acknowledge interrupt on exit");
	if (tmp & VM_EXIT_SAVE_IA32_PAT)
		hv_dbg("       Save IA32_PAT");
	if (tmp & VM_EXIT_LOAD_IA32_PAT)
		hv_dbg("       Load IA32_PAT");
	if (tmp & VM_EXIT_SAVE_IA32_EFER)
		hv_dbg("       Save IA32_EFER");
	if (tmp & VM_EXIT_LOAD_IA32_EFER)
		hv_dbg("       Load IA32_EFER");
	if (tmp & VM_EXIT_SAVE_VMX_PREEMPTION_TIMER)
		hv_dbg("       Save VMX-preemption timer value");
}

static void dump_entry_controls(__u32 tmp)
{
	hv_dbg("vm-entry-controls: 0x%08x", tmp);
	if (tmp & VM_ENTRY_LOAD_DEBUG_CONTROLS)
		hv_dbg("       Load debug controls");
	if (tmp & VM_ENTRY_IA32E_MODE)
		hv_dbg("       IA-32e mode guest");
	if (tmp & VM_ENTRY_SMM)
		hv_dbg("       Entry to SMM");
	if (tmp & VM_ENTRY_DEACT_DUAL_MONITOR)
		hv_dbg("       Deactivate dual-monitor treatment");
	if (tmp & VM_ENTRY_LOAD_IA32_PERF_GLOBAL_CTRL)
		hv_dbg("       Load IA32_PERF_GLOBAL_CTRL");
	if (tmp & VM_ENTRY_LOAD_IA32_PAT)
		hv_dbg("       Load IA32_PAT");
	if (tmp & VM_ENTRY_LOAD_IA32_EFER)
		hv_dbg("       Load IA32_EFER");
}
#endif /* DUMP_CONTROLS */

#ifdef DUMP_VMCS
static void dump_vmcs(struct vmcs_template *tmpl)
{
	struct vmcs_segment *seg;
	enum segment_reg r;

	/* guest state */
	hv_dbg("GUEST_CR0 %016lx", tmpl->guest.cr0);
	hv_dbg("GUEST_CR3 %016lx", tmpl->guest.cr3);
	hv_dbg("GUEST_CR4 %016lx", tmpl->guest.cr4);

	hv_dbg("GUEST_DR7 %016lx", tmpl->guest.dr7);

	hv_dbg("GUEST_RSP %016lx", tmpl->guest.rsp);
	hv_dbg("GUEST_RIP %016lx", tmpl->guest.rip);
	hv_dbg("GUEST_RFLAGS %016lx", tmpl->guest.rflags);

	for (r = ES; r < NSEGREG; r++) {
		seg = &tmpl->guest.seg[r];
		hv_dbg("GUEST_ES_SELECTOR %d: 0x%02x", r, seg->selector);
		hv_dbg("GUEST_ES_LIMIT + %d: 0x%08x", r, seg->limit);
		hv_dbg("GUEST_ES_AR_BYTES + %d: 0x%08x", r, seg->ar_bytes);
		hv_dbg("GUEST_ES_BASE + %d: 0x%016llx", r, seg->base);
	}

	hv_dbg("GUEST_GDTR_LIMIT: 0x%08x", tmpl->guest.gdtr_limit);
	hv_dbg("GUEST_GDTR_BASE %016lx", tmpl->guest.gdtr_base);

	hv_dbg("GUEST_IDTR_LIMIT: 0x%08x", tmpl->guest.idtr_limit);
	hv_dbg("GUEST_IDTR_BASE %016lx", tmpl->guest.idtr_base);

	hv_dbg("GUEST_IA32_DEBUGCTL: %016llx", tmpl->guest.ia32_debugctl);
	hv_dbg("GUEST_SYSENTER_CS: 0x%08x", tmpl->guest.sysenter_cs);
	hv_dbg("GUEST_SYSENTER_ESP: %016lx", tmpl->guest.sysenter_esp);
	hv_dbg("GUEST_SYSENTER_EIP: %016lx", tmpl->guest.sysenter_eip);

	hv_dbg("GUEST_ACTIVITY_STATE: 0x%08x", tmpl->guest.activity_state);
	hv_dbg("GUEST_INTERRUPTIBILITY_INFO: 0x%08x", tmpl->guest.interruptibility_info);
	hv_dbg("GUEST_PENDING_DBG_EXCEPTIONS: 0x%08x", tmpl->guest.pending_dbg_exceptions);
	hv_dbg("VMCS_LINK_POINTER: %016llx", tmpl->guest.vmcs_link_pointer);

	/* host state */
	hv_dbg("HOST_CR0 %016lx", tmpl->host.cr0);
	hv_dbg("HOST_CR3 %016lx", tmpl->host.cr3);
	hv_dbg("HOST_CR4 %016lx", tmpl->host.cr4);

	hv_dbg("HOST_RSP %016lx", tmpl->host.rsp);
	hv_dbg("HOST_RIP %016lx", tmpl->host.rip);

	hv_dbg("HOST_ES_SELECTOR: 0x%02x", tmpl->host.es_selector);
	hv_dbg("HOST_CS_SELECTOR: 0x%02x", tmpl->host.cs_selector);
	hv_dbg("HOST_SS_SELECTOR: 0x%02x", tmpl->host.ss_selector);
	hv_dbg("HOST_DS_SELECTOR: 0x%02x", tmpl->host.ds_selector);
	hv_dbg("HOST_FS_SELECTOR: 0x%02x", tmpl->host.fs_selector);
	hv_dbg("HOST_GS_SELECTOR: 0x%02x", tmpl->host.gs_selector);
	hv_dbg("HOST_TR_SELECTOR: 0x%02x", tmpl->host.tr_selector);

	hv_dbg("HOST_FS_BASE %016lx", tmpl->host.fs_base);
	hv_dbg("HOST_GS_BASE %016lx", tmpl->host.gs_base);
	hv_dbg("HOST_TR_BASE %016lx", tmpl->host.tr_base);
	hv_dbg("HOST_GDTR_BASE %016lx", tmpl->host.gdtr_base);
	hv_dbg("HOST_IDTR_BASE %016lx", tmpl->host.idtr_base);

	hv_dbg("HOST_IA32_SYSENTER_CS: 0x%08x", tmpl->host.ia32_sysenter_cs);
	hv_dbg("HOST_IA32_SYSENTER_ESP: %016lx", tmpl->host.ia32_sysenter_esp);
	hv_dbg("HOST_IA32_SYSENTER_EIP: %016lx", tmpl->host.ia32_sysenter_eip);

	/* exec control */
	hv_dbg("PIN_BASED_VM_EXEC_CONTROL: 0x%08x", tmpl->pin_based_vm_exec_control);
	hv_dbg("CPU_BASED_VM_EXEC_CONTROL: 0x%08x", tmpl->cpu_based_vm_exec_control);
	hv_dbg("SECONDARY_VM_EXEC_CONTROL: 0x%08x", tmpl->secondary_vm_exec_control);

	hv_dbg("EXCEPTION_BITMAP: 0x%08x", tmpl->exception_bitmap);
	hv_dbg("IO_BITMAP_A: %016llx", tmpl->io_bitmap_a);
	hv_dbg("IO_BITMAP_B: %016llx", tmpl->io_bitmap_b);

	hv_dbg("TSC_OFFSET: %016llx", tmpl->tsc_offset);

	hv_dbg("CR0_GUEST_HOST_MASK %016lx", tmpl->cr0_guest_host_mask);
	hv_dbg("CR0_READ_SHADOW %016lx", tmpl->cr0_read_shadow);

	hv_dbg("CR4_GUEST_HOST_MASK %016lx", tmpl->cr4_guest_host_mask);
	hv_dbg("CR4_READ_SHADOW %016lx", tmpl->cr4_read_shadow);

	hv_dbg("CR3_TARGET_COUNT: 0x%08x", tmpl->cr3_target_count);
	hv_dbg("CR3_TARGET_VALUE0 %016lx", tmpl->cr3_target_value0);
	hv_dbg("CR3_TARGET_VALUE1 %016lx", tmpl->cr3_target_value1);
	hv_dbg("CR3_TARGET_VALUE2 %016lx", tmpl->cr3_target_value2);
	hv_dbg("CR3_TARGET_VALUE3 %016lx", tmpl->cr3_target_value3);

	hv_dbg("VIRTUAL_APIC_PAGE_ADDR %016llx", tmpl->virtual_apic_page_addr);

	hv_dbg("MSR_BITMAP %016llx", tmpl->msr_bitmap);

	if (vmm.vpid_support)
		hv_dbg("VIRTUAL_PROCESSOR_ID %d", tmpl->virtual_processor_id);

	hv_dbg("TPR_THRESHOLD: 0x%08x", tmpl->tpr_threshold);

	/* exit control */
	hv_dbg("VM_EXIT_CONTROLS: 0x%08x", tmpl->vm_exit_controls);

	hv_dbg("VM_EXIT_MSR_STORE_COUNT: 0x%08x", tmpl->vm_exit_msr_store_count);
	hv_dbg("VM_EXIT_MSR_LOAD_COUNT: 0x%08x", tmpl->vm_exit_msr_load_count);
	hv_dbg("VM_EXIT_MSR_LOAD_ADDR %016llx", tmpl->vm_exit_msr_load_addr);

	/* entry control */
	hv_dbg("VM_ENTRY_CONTROLS: 0x%08x", tmpl->vm_entry_controls);

	hv_dbg("VM_ENTRY_MSR_LOAD_COUNT: 0x%08x", tmpl->vm_entry_msr_load_count);
	hv_dbg("VM_ENTRY_INTR_INFO_FIELD: 0x%08x", tmpl->vm_entry_intr_info_field);
	hv_dbg("VM_ENTRY_EXCEPTION_ERROR_CODE: 0x%08x", tmpl->vm_entry_exception_error_code);
	hv_dbg("VM_ENTRY_INSTRUCTION_LEN: 0x%08x", tmpl->vm_entry_instruction_len);
}
#endif /* DUMP_VMCS */

static void apply_vmcs_template(struct vmcs_template *tmpl)
{
	struct vmcs_segment *seg;
	enum segment_reg r;

#ifdef DUMP_VMCS
	dump_vmcs(tmpl);
#endif

	/* guest state */
	cpu_vmcs_writel(GUEST_CR0, tmpl->guest.cr0);
	cpu_vmcs_writel(GUEST_CR3, tmpl->guest.cr3);
	cpu_vmcs_writel(GUEST_CR4, tmpl->guest.cr4);

	cpu_vmcs_writel(GUEST_DR7, tmpl->guest.dr7);

	cpu_vmcs_writel(GUEST_RSP, tmpl->guest.rsp);
	cpu_vmcs_writel(GUEST_RIP, tmpl->guest.rip);
	cpu_vmcs_writel(GUEST_RFLAGS, tmpl->guest.rflags);

	for (r = ES; r < NSEGREG; r++) {
		seg = &tmpl->guest.seg[r];
		cpu_vmcs_write16(GUEST_ES_SELECTOR + r * 2, seg->selector);
		cpu_vmcs_write32(GUEST_ES_LIMIT + r * 2, seg->limit);
		cpu_vmcs_write32(GUEST_ES_AR_BYTES + r * 2, seg->ar_bytes);
		cpu_vmcs_write64(GUEST_ES_BASE + r * 2, seg->base);
	}

	cpu_vmcs_write32(GUEST_GDTR_LIMIT, tmpl->guest.gdtr_limit);
	cpu_vmcs_writel(GUEST_GDTR_BASE, tmpl->guest.gdtr_base);

	cpu_vmcs_write32(GUEST_IDTR_LIMIT, tmpl->guest.idtr_limit);
	cpu_vmcs_writel(GUEST_IDTR_BASE, tmpl->guest.idtr_base);

	cpu_vmcs_write64(GUEST_IA32_DEBUGCTL, tmpl->guest.ia32_debugctl);
	cpu_vmcs_write32(GUEST_SYSENTER_CS, tmpl->guest.sysenter_cs);
	cpu_vmcs_writel(GUEST_SYSENTER_ESP, tmpl->guest.sysenter_esp);
	cpu_vmcs_writel(GUEST_SYSENTER_EIP, tmpl->guest.sysenter_eip);

	cpu_vmcs_write32(GUEST_ACTIVITY_STATE, tmpl->guest.activity_state);
	cpu_vmcs_write32(GUEST_INTERRUPTIBILITY_INFO, tmpl->guest.interruptibility_info);
	cpu_vmcs_write32(GUEST_PENDING_DBG_EXCEPTIONS, tmpl->guest.pending_dbg_exceptions);
	cpu_vmcs_write64(VMCS_LINK_POINTER, tmpl->guest.vmcs_link_pointer);

	/* host state */
	cpu_vmcs_writel(HOST_CR0, tmpl->host.cr0);
	cpu_vmcs_writel(HOST_CR3, tmpl->host.cr3);
	cpu_vmcs_writel(HOST_CR4, tmpl->host.cr4);

	cpu_vmcs_writel(HOST_RSP, tmpl->host.rsp);
	cpu_vmcs_writel(HOST_RIP, tmpl->host.rip);

	cpu_vmcs_write16(HOST_ES_SELECTOR, tmpl->host.es_selector);
	cpu_vmcs_write16(HOST_CS_SELECTOR, tmpl->host.cs_selector);
	cpu_vmcs_write16(HOST_SS_SELECTOR, tmpl->host.ss_selector);
	cpu_vmcs_write16(HOST_DS_SELECTOR, tmpl->host.ds_selector);
	cpu_vmcs_write16(HOST_FS_SELECTOR, tmpl->host.fs_selector);
	cpu_vmcs_write16(HOST_GS_SELECTOR, tmpl->host.gs_selector);
	cpu_vmcs_write16(HOST_TR_SELECTOR, tmpl->host.tr_selector);

	cpu_vmcs_writel(HOST_FS_BASE, tmpl->host.fs_base);
	cpu_vmcs_writel(HOST_GS_BASE, tmpl->host.gs_base);
	cpu_vmcs_writel(HOST_TR_BASE, tmpl->host.tr_base);
	cpu_vmcs_writel(HOST_GDTR_BASE, tmpl->host.gdtr_base);
	cpu_vmcs_writel(HOST_IDTR_BASE, tmpl->host.idtr_base);

	cpu_vmcs_write32(HOST_IA32_SYSENTER_CS, tmpl->host.ia32_sysenter_cs);
	cpu_vmcs_writel(HOST_IA32_SYSENTER_ESP, tmpl->host.ia32_sysenter_esp);
	cpu_vmcs_writel(HOST_IA32_SYSENTER_EIP, tmpl->host.ia32_sysenter_eip);

	/* exec control */
	cpu_vmcs_write32(PIN_BASED_VM_EXEC_CONTROL, tmpl->pin_based_vm_exec_control);
	cpu_vmcs_write32(CPU_BASED_VM_EXEC_CONTROL, tmpl->cpu_based_vm_exec_control);
	cpu_vmcs_write32(SECONDARY_VM_EXEC_CONTROL, tmpl->secondary_vm_exec_control);

	cpu_vmcs_write32(EXCEPTION_BITMAP, tmpl->exception_bitmap);
	cpu_vmcs_write64(IO_BITMAP_A, tmpl->io_bitmap_a);
	cpu_vmcs_write64(IO_BITMAP_B, tmpl->io_bitmap_b);

	cpu_vmcs_write64(TSC_OFFSET, tmpl->tsc_offset);

	cpu_vmcs_writel(CR0_GUEST_HOST_MASK, tmpl->cr0_guest_host_mask);
	cpu_vmcs_writel(CR0_READ_SHADOW, tmpl->cr0_read_shadow);

	cpu_vmcs_writel(CR4_GUEST_HOST_MASK, tmpl->cr4_guest_host_mask);
	cpu_vmcs_writel(CR4_READ_SHADOW, tmpl->cr4_read_shadow);

	cpu_vmcs_write32(CR3_TARGET_COUNT, tmpl->cr3_target_count);
	cpu_vmcs_writel(CR3_TARGET_VALUE0, tmpl->cr3_target_value0);
	cpu_vmcs_writel(CR3_TARGET_VALUE1, tmpl->cr3_target_value1);
	cpu_vmcs_writel(CR3_TARGET_VALUE2, tmpl->cr3_target_value2);
	cpu_vmcs_writel(CR3_TARGET_VALUE3, tmpl->cr3_target_value3);

	cpu_vmcs_write64(VIRTUAL_APIC_PAGE_ADDR, tmpl->virtual_apic_page_addr);

	cpu_vmcs_write64(MSR_BITMAP, tmpl->msr_bitmap);

	/* The virtual-processor identifier (VPID) [...] exists only on
	 * processors that support the 1-setting of the "enable VPID"
	 * VM-execution control */
	if (vmm.vpid_support)
		cpu_vmcs_write16(VIRTUAL_PROCESSOR_ID, tmpl->virtual_processor_id);

	cpu_vmcs_write32(TPR_THRESHOLD, tmpl->tpr_threshold);

	/* exit control */
	cpu_vmcs_write32(VM_EXIT_CONTROLS, tmpl->vm_exit_controls);

	cpu_vmcs_write32(VM_EXIT_MSR_STORE_COUNT, tmpl->vm_exit_msr_store_count);
	cpu_vmcs_write32(VM_EXIT_MSR_LOAD_COUNT, tmpl->vm_exit_msr_load_count);
	cpu_vmcs_write64(VM_EXIT_MSR_LOAD_ADDR, tmpl->vm_exit_msr_load_addr);

	/* entry control */
	cpu_vmcs_write32(VM_ENTRY_CONTROLS, tmpl->vm_entry_controls);

	cpu_vmcs_write32(VM_ENTRY_MSR_LOAD_COUNT, tmpl->vm_entry_msr_load_count);
	cpu_vmcs_write32(VM_ENTRY_INTR_INFO_FIELD, tmpl->vm_entry_intr_info_field);
	cpu_vmcs_write32(VM_ENTRY_EXCEPTION_ERROR_CODE, tmpl->vm_entry_exception_error_code);
	cpu_vmcs_write32(VM_ENTRY_INSTRUCTION_LEN, tmpl->vm_entry_instruction_len);
}

static struct desc_struct *init_segment_selector(struct segment_selector *segsel,
						 unsigned short selector,
						 unsigned long gdt_base)
{
	struct desc_struct *desc;

	desc = (struct desc_struct *)(gdt_base + (selector & ~0x7));
	//hv_dbg("       desc %d = %016lx", selector, *(unsigned long *)desc);

	segsel->base = desc->base0 | desc->base1 << 16 | desc->base2 << 24;
	segsel->limit = desc->limit0 | desc->limit << 16;

	/* this is a TSS or callgate etc, save the base high part */
	if (desc->s == 0) {
		__u64 tmp;
		tmp = (*(__u64 *)((__u8 *)desc + 8));
		segsel->base = (segsel->base & 0xffffffff) | (tmp << 32);
	}

	/* 4096-bit granularity is enabled for this segment, scale the limit */
	if (desc->g)
		segsel->limit = (segsel->limit << 12) + 0xfff;

	return desc;
}

static void VmxFillGuestSelectorData(struct vmcs_template *tmpl,
				     unsigned long gdt_base,
				     enum segment_reg segreg,
				     unsigned short selector)
{
	struct segment_access_rights ar;
	struct segment_selector segsel;
	struct desc_struct *desc;
	struct vmcs_segment *seg;

	memset(&ar, 0, sizeof(ar));
	desc = init_segment_selector(&segsel, selector, gdt_base);

	ar.type     = desc->type;
	ar.s        = desc->s;
	ar.dpl      = desc->dpl;
	ar.present  = desc->p;
	ar.avl      = desc->avl;
	ar.l        = desc->l;
	ar.db       = desc->d;
	ar.g        = desc->g;
	ar.unusable = (selector == 0);

	seg = &tmpl->guest.seg[segreg];
	seg->selector = selector;
	seg->limit = segsel.limit;
	seg->ar_bytes = ar.access;

	switch (segreg) {
	case FS:
		rdmsrl(MSR_FS_BASE, seg->base);
		break;
	case GS:
		rdmsrl(MSR_GS_BASE, seg->base);
		break;
	case TR:
	case LDTR:
	/* In 64-bit mode [...] the processor treats the segment base of CS, DS,
	 * ES, SS as zero.
	 * Anyway...*/
	case ES:
	case CS:
	case SS:
	case DS:
	default:
		seg->base = segsel.base;
		break;
	}
}

static void setup_tmpl_guest_state(struct vmcs_template *tmpl,
				   unsigned long guest_rip,
				   unsigned long guest_rsp,
				   unsigned long guest_rflags)
{
	unsigned int ds, cs, es, ss, fs, gs;
	struct desc_ptr idt, gdt;
	unsigned long ldtr, tr;

	/* control registers CR0, CR3, CR4 */
	tmpl->guest.cr0 = read_cr0();
	tmpl->guest.cr3 = read_cr3();
	tmpl->guest.cr4 = native_read_cr4();

	/* debug register: DR7 */
	tmpl->guest.dr7 = native_get_debugreg(7);

	/* RSP, RIP, RFLAGS */
	tmpl->guest.rsp = guest_rsp;
	tmpl->guest.rip = guest_rip;
	tmpl->guest.rflags = guest_rflags;

	/* CS, SS, DS, ES, FS, GS, LDTR, TR */
	savesegment(cs, cs);
	savesegment(ss, ss);
	savesegment(ds, ds);
	savesegment(es, es);
	savesegment(fs, fs);
	savesegment(gs, gs);
	store_ldt(ldtr);
	store_tr(tr);

	native_store_gdt(&gdt);
	VmxFillGuestSelectorData(tmpl, gdt.address, CS, cs);
	VmxFillGuestSelectorData(tmpl, gdt.address, SS, ss);
	VmxFillGuestSelectorData(tmpl, gdt.address, DS, ds);
	VmxFillGuestSelectorData(tmpl, gdt.address, ES, es);
	VmxFillGuestSelectorData(tmpl, gdt.address, FS, fs);
	VmxFillGuestSelectorData(tmpl, gdt.address, GS, gs);
	VmxFillGuestSelectorData(tmpl, gdt.address, LDTR, ldtr);
	VmxFillGuestSelectorData(tmpl, gdt.address, TR, tr);

	/* GDTR, IDTR */
	tmpl->guest.gdtr_limit = gdt.size;
	tmpl->guest.gdtr_base = gdt.address;
	//hv_dbg("       gdt.limit = %08x", gdt.size);
	//hv_dbg("       gdt.base  = %016lx", gdt.address);

	store_idt(&idt);
	tmpl->guest.idtr_limit = idt.size;
	tmpl->guest.idtr_base = idt.address;
	//hv_dbg("       idt.limit = %08x", idt.size);
	//hv_dbg("       idt.base  = %016lx", idt.address);

	/* MSR
	 * TODO: the following registers are optional and may not always be set:
	 *  - IA32_PERF_GLOBAL_CTRL
	 *  - IA32_PAT
	 *  - IA32_EFER */
	rdmsrl(MSR_IA32_DEBUGCTLMSR, tmpl->guest.ia32_debugctl);
	rdmsrl(MSR_IA32_SYSENTER_CS, tmpl->guest.sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, tmpl->guest.sysenter_esp);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl->guest.sysenter_eip);
	//rdmsrl(MSR_CORE_PERF_GLOBAL_CTRL, tmpl->guest.ia32_perf_global_ctrl);
	//rdmsrl(MSR_IA32_CR_PAT, tmpl->guest.ia32_pat);
	//rdmsrl(MSR_EFER, tmpl->guest.ia32_efer);

	/* SMBASE */
	/* XXX: not defined in vmx.h */

	/* Guest Non-Register State */
	tmpl->guest.activity_state = GUEST_ACTIVITY_ACTIVE;
	tmpl->guest.interruptibility_info = 0;
	tmpl->guest.pending_dbg_exceptions = 0;
	tmpl->guest.vmcs_link_pointer = 0xffffffffffffffffL;
}

static void set_fixed_bits(int name,
			   unsigned long *value,
			   unsigned long fixed0,
			   unsigned long fixed1)
{
	unsigned long tmp, fix;

	tmp = (fixed0 & fixed1);
	if ((tmp & *value) != tmp) {
		fix = (tmp & *value) ^ tmp;
		hv_warn("fixing invalid host CR%d: set bits 0x%08lx",
			name, fix);
		*value |= fix;
	}

	tmp = ((~fixed0) & (~fixed1));
	if ((tmp & ~(*value)) != tmp) {
		fix = (tmp & ~(*value)) ^ tmp;
		hv_warn("fixing invalid host CR%d: unset bits 0x%08lx",
			name, fix);
		*value &= ~fix;
	}
}

static void check_segment_selector(enum segment_reg segreg,
				   unsigned short selector)
{
	/* The selector fields for CS and TR cannot be 0000H. */
	if ((segreg == CS || segreg == TR) && selector == 0) {
		hv_err("error: invalid segment register selector %s (0)",
		       SEGMENT_NAME(segreg));
	}

	/* In the selector field for each of CS, SS, DS, ES, FS, GS and TR, the
	 * RPL (bits 1:0) and the TI flag (bit 2) must be 0. */
	if (((selector & 3) != 0) || ((selector & 4) != 0)) {
		hv_err("error: invalid segment register selector %s: 0x%x",
		       SEGMENT_NAME(segreg), selector);
	}
}

static void setup_tmpl_host_state(struct vmcs_template *tmpl,
				  unsigned long host_rsp,
				  unsigned long host_cr3)
{
	unsigned long cr0_fixed0, cr0_fixed1, cr4_fixed0, cr4_fixed1;
	struct segment_selector segsel;
	struct desc_ptr gdt, idt;

	/* control registers CR0, CR3, CR4 */
	tmpl->host.cr0 = read_cr0();
	tmpl->host.cr3 = host_cr3;
	tmpl->host.cr4 = native_read_cr4();
	//hv_dbg("        CR0 = %016lx", read_cr0());
	//hv_dbg("        CR3 = %016lx", read_cr3());
	//hv_dbg("        CR4 = %016lx", read_cr4());
	//hv_dbg("        EFER = %016llx", native_read_msr(MSR_EFER));
	//hv_dbg("        CR0_FIXED0 = %016llx", native_read_msr(MSR_IA32_VMX_CR0_FIXED0));
	//hv_dbg("        CR0_FIXED1 = %016llx", native_read_msr(MSR_IA32_VMX_CR0_FIXED1));
	//hv_dbg("        CR4_FIXED0 = %016llx", native_read_msr(MSR_IA32_VMX_CR4_FIXED0));
	//hv_dbg("        CR4_FIXED1 = %016llx", native_read_msr(MSR_IA32_VMX_CR4_FIXED1));

	rdmsrl(MSR_IA32_VMX_CR0_FIXED0, cr0_fixed0);
	rdmsrl(MSR_IA32_VMX_CR0_FIXED1, cr0_fixed1);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED0, cr4_fixed0);
	rdmsrl(MSR_IA32_VMX_CR4_FIXED1, cr4_fixed1);

	set_fixed_bits(0, &tmpl->host.cr0, cr0_fixed0, cr0_fixed1);
	set_fixed_bits(4, &tmpl->host.cr4, cr4_fixed0, cr4_fixed1);

	/* RSP, RIP */
	tmpl->host.rsp = host_rsp;
	tmpl->host.rip = (unsigned long)vm_exit_handler;

	/* CS, SS, DS, ES, FS, GS, TR: selectors.
	 * Even if FS segment register is not used by kernel, vmlaunch fails if
	 * the selector field isn't 0. */
	savesegment(cs, tmpl->host.cs_selector);
	savesegment(ss, tmpl->host.ss_selector);
	savesegment(ds, tmpl->host.ds_selector);
	savesegment(es, tmpl->host.es_selector);
	savesegment(gs, tmpl->host.gs_selector);
	tmpl->host.fs_selector = 0;
	store_tr(tmpl->host.tr_selector);

	check_segment_selector(CS, tmpl->host.cs_selector);
	check_segment_selector(SS, tmpl->host.ss_selector);
	check_segment_selector(DS, tmpl->host.ds_selector);
	check_segment_selector(ES, tmpl->host.es_selector);
	check_segment_selector(FS, tmpl->host.fs_selector);
	check_segment_selector(GS, tmpl->host.gs_selector);
	check_segment_selector(TR, tmpl->host.tr_selector);

	/* FS, GS, TR, GDTR, IDTR: base */
	native_store_gdt(&gdt);
	store_idt(&idt);
	init_segment_selector(&segsel, tmpl->host.tr_selector, gdt.address);
	rdmsrl(MSR_FS_BASE, tmpl->host.fs_base);
	rdmsrl(MSR_GS_BASE, tmpl->host.gs_base);
	tmpl->host.tr_base = segsel.base;
	tmpl->host.gdtr_base = gdt.address;
	tmpl->host.idtr_base = idt.address;
	//hv_dbg("       HOST_TR_BASE = %016llx", segsel.base);

	/* MSR */
	rdmsrl(MSR_IA32_SYSENTER_CS, tmpl->host.ia32_sysenter_cs);
	rdmsrl(MSR_IA32_SYSENTER_ESP, tmpl->host.ia32_sysenter_esp);
	rdmsrl(MSR_IA32_SYSENTER_EIP, tmpl->host.ia32_sysenter_eip);

	/* SMBASE */
	/* XXX: not defined in vmx.h */
}

/* XXX: sandbox escape if ioports change
 * CPU_BASED_UNCOND_IO_EXITING should be use once capsule will not rely on
 * serial port anymore to export syslog. */
static void init_io_bitmaps(void)
{
	int i;

	memset(io_bitmap_a_region, 0xffffffff, PAGE_SIZE);
	memset(io_bitmap_b_region, 0xffffffff, PAGE_SIZE);

	/* $ grep serial /proc/ioports
	 *   02f8-02ff : serial
	 *   03f8-03ff : serial
	 * XXX: may not be identical across different VM */
	for (i = 0; i < 8; i++) {
		clear_bit(0x2f8 + i, io_bitmap_a_region);
		clear_bit(0x3f8 + i, io_bitmap_a_region);
	}
}

/* This bitmap is both used by capsule and trusted guest. Access to any MSR
 * causes a VM-exit (except MSR_KERNEL_GS_BASE which is automatically
 * loaded/stored on VM-exit/VM-entry). */
static void init_msr_bitmap(void)
{
	void *bitmap;

	memset(msr_bitmap_region, 0xffffffff, PAGE_SIZE);

	/* read bitmap for low MSRs */
	bitmap = msr_bitmap_region;

	/* read bitmap for high MSRs */
	bitmap = (unsigned char *)bitmap + 1024;
	clear_bit(MSR_KERNEL_GS_BASE & 0x1fff, bitmap);

	/* write bitmap for low MSRs */
	bitmap = (unsigned char *)bitmap + 1024;

	/* write bitmap for high MSRs */
	bitmap = (unsigned char *)bitmap + 1024;
	clear_bit(MSR_KERNEL_GS_BASE & 0x1fff, bitmap);
}

static __u32 mandatory_ctrl(unsigned int msr, __u32 tmp)
{
	unsigned long n;

	rdmsrl(msr, n);
	tmp |= (n & 0xffffffff);
	tmp &= (n >> 32);

	return tmp;
}

static void setup_tmpl_exec_control(struct vmcs_template *tmpl, int trusted)
{
	__u32 tmp;

	/* Pin */
	tmp = 0;
	if (!trusted)
		tmp |= PIN_BASED_EXT_INTR_MASK;

	tmp = mandatory_ctrl(MSR_IA32_VMX_PINBASED_CTLS, tmp);
	tmpl->pin_based_vm_exec_control = tmp;

#ifdef DUMP_CONTROLS
	dump_pin_exec_control(tmp);
#endif

	/* Primary Processor */
	tmp  = CPU_BASED_CR8_LOAD_EXITING;
	tmp |= CPU_BASED_CR8_STORE_EXITING;
	if (msr_bitmap_capability)
		tmp |= CPU_BASED_USE_MSR_BITMAPS;

	if (!trusted) {
		tmp |= CPU_BASED_HLT_EXITING;
		tmp |= CPU_BASED_MWAIT_EXITING;
		tmp |= CPU_BASED_MOV_DR_EXITING;
		tmp |= CPU_BASED_USE_IO_BITMAPS;
		tmp |= CPU_BASED_MONITOR_EXITING;
		tmp |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	}

	if (vmm.vpid_support)
		tmp |= CPU_BASED_INVLPG_EXITING;

	tmp = mandatory_ctrl(MSR_IA32_VMX_PROCBASED_CTLS, tmp);
	tmpl->cpu_based_vm_exec_control = tmp;

#ifdef DUMP_CONTROLS
	dump_cpu_exec_control(tmp);
#endif

	/* Secondary Processor */
	tmp = 0;

	/* enable VPID only if not supported */
	if (vmm.vpid_support)
		tmp |= SECONDARY_EXEC_ENABLE_VPID;

	if (!trusted) {
		/* TODO: disabled at the moment, because some legit programs
		 *       (eg: Firefox) make use of LDT. It could be interesting
		 *       to exit on these instructionsin order to block
		 *       potential kernel exploits (eg: IDT access.) */
		/* exit on LGDT, LIDT, LLDT, LTR, SGDT, SIDT, SLDT, and STR */
		//tmp |= SECONDARY_EXEC_DESC_TABLE_EXITING;
		tmp |= SECONDARY_EXEC_ENABLE_EPT;
	}

	/* SECONDARY_EXEC_ENABLE_INVPCID is not set: Linux doesn't use invpcid
	 * instruction. In consequence, execution of INVPCID causes an #UD. */

	tmp = mandatory_ctrl(MSR_IA32_VMX_PROCBASED_CTLS2, tmp);
	tmpl->secondary_vm_exec_control = tmp;

#ifdef DUMP_CONTROLS
	dump_secondary_exec_control(tmp);
#endif

	/* Exception Bitmap: exit on int3 and double fault in guest */
	tmpl->exception_bitmap = 0;
	if (!trusted) {
		tmpl->exception_bitmap |= (1 << X86_TRAP_BP);
		tmpl->exception_bitmap |= (1 << X86_TRAP_DF);
	}

	init_io_bitmaps();
	tmpl->io_bitmap_a = __pa(io_bitmap_a_region);
	tmpl->io_bitmap_b = __pa(io_bitmap_b_region);

	tmpl->tsc_offset = 0;

	/* force ProtectionEnabled and PaGing in guest */
	tmpl->cr0_guest_host_mask = X86_CR0_PE | X86_CR0_PG;
	tmpl->cr0_read_shadow = X86_CR0_PE | X86_CR0_PG;

	/* force VMX to be disabled in guest */
	tmpl->cr4_guest_host_mask = 0;
	if (!trusted)
		tmpl->cr4_guest_host_mask |= X86_CR4_VMXE;
	tmpl->cr4_read_shadow = 0;

	tmpl->cr3_target_count = 0;
	tmpl->cr3_target_value0 = 0;
	tmpl->cr3_target_value1 = 0;
	tmpl->cr3_target_value2 = 0;
	tmpl->cr3_target_value3 = 0;

	tmpl->virtual_apic_page_addr = 0xffffffffffffffffUL;

	if (msr_bitmap_capability)
		tmpl->msr_bitmap = __pa(msr_bitmap_region);
	else
		tmpl->msr_bitmap = 0xffffffffffffffffUL;

	tmpl->tpr_threshold = 0;

	tmpl->virtual_processor_id = trusted ? TRUSTED_GUEST_VPID : CAPSULE_VPID;
}

static void setup_tmpl_exit_control(struct vmcs_template *tmpl,
				    int trusted,
				    unsigned long host_msr)
{
	__u32 tmp;

	tmp = VM_EXIT_HOST_ADDR_SPACE_SIZE;
	if (!trusted)
		tmp |= VM_EXIT_ACK_INTR_ON_EXIT;

	tmp = mandatory_ctrl(MSR_IA32_VMX_EXIT_CTLS, tmp);
	tmpl->vm_exit_controls = tmp;

#ifdef DUMP_CONTROLS
	dump_exit_controls(tmp);
#endif

	/* VM_EXIT_MSR_STORE_ADDR is directly written to vmcs by
	 * init_trusted_vmcs/capsule_vmcs_from_template */
	tmpl->vm_exit_msr_store_count = AUTOLOAD_MSR_NUMBER;

	/* host_msr equals __pa(vcpu->trusted_ctx.autoload_msr) (for both
	 * trusted guest and capsule): it makes use of trusted guest MSR */
	tmpl->vm_exit_msr_load_count = AUTOLOAD_MSR_NUMBER;
	tmpl->vm_exit_msr_load_addr = host_msr;
}

static void setup_tmpl_entry_control(struct vmcs_template *tmpl)
{
	__u32 tmp;

	tmp = mandatory_ctrl(MSR_IA32_VMX_ENTRY_CTLS, VM_ENTRY_IA32E_MODE);
	tmpl->vm_entry_controls = tmp;

#ifdef DUMP_CONTROLS
	dump_entry_controls(tmp);
#endif

	/* VM_ENTRY_MSR_LOAD_ADDR is directly written to vmcs by
	 * create_trusted/capsule_vmcs_from_template */
	tmpl->vm_entry_msr_load_count = AUTOLOAD_MSR_NUMBER;

	tmpl->vm_entry_intr_info_field = 0;
	tmpl->vm_entry_exception_error_code = 0;
	tmpl->vm_entry_instruction_len = 0;
}

struct vmcs_template *alloc_vmcs_template(void)
{
	struct vmcs_template *tmpl;

	tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);

	return tmpl;
}

void init_vmcs_capsule_template(void)
{
	unsigned long guest_rflags, guest_rip, guest_rsp;
	struct vmcs_template *tmpl;

	guest_rsp = snapshot.ctx.regs.rsp;
	guest_rip = (unsigned long)guest_init;
	/* start capsule with irq disabled */
	guest_rflags = snapshot.rflags & ~X86_EFLAGS_IF;

	tmpl = &capsule_template;
	setup_tmpl_guest_state(tmpl, guest_rip, guest_rsp, guest_rflags);
	setup_tmpl_exec_control(tmpl, 0);
	setup_tmpl_exit_control(tmpl, 0, 0);
	setup_tmpl_entry_control(tmpl);

	capsule_template.guest.cr3 = snapshot.cr3;
	memcpy(&capsule_template.guest.seg, &snapshot.segs,
		sizeof(snapshot.segs));
}

struct vmcs_region *alloc_vmcs(gfp_t flags)
{
	struct vmcs_region *vmcs;

	vmcs = (struct vmcs_region *)get_zeroed_page(flags);
	if (vmcs == NULL)
		return NULL;

	return vmcs;
}

static err_t load_vmcs(struct vmcs_region *vmcs, bool trusted)
{
	union ia32_vmx_basic_msr vmx_basic_msr;
	int error;

	rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic_msr.value);

	memset(vmcs, 0, PAGE_SIZE);
	vmcs->revid = vmx_basic_msr.bits.revid;

	error = cpu_vmcs_clear(vmcs);
	if (error != 0) {
		if (trusted)
			return ERROR_CLEAR_TRUSTED_VMCS;
		else
			return ERROR_CLEAR_CAPSULE_VMCS;
	}

	error = cpu_vmcs_load(vmcs);
	if (error != 0) {
		if (trusted)
			return ERROR_LOAD_TRUSTED_VMCS;
		else
			return ERROR_LOAD_CAPSULE_VMCS;
	}

	return SUCCESS;
}

err_t init_trusted_vmcs(struct vmcs_region *vmcs,
			struct vmcs_template *tmpl,
			unsigned long host_rsp,
			struct vmx_msr_entry *autoload_msr,
			unsigned long guest_rip,
			unsigned long guest_rsp,
			unsigned long guest_rflags)
{
	unsigned long host_cr3;
	unsigned long host_msr;
	err_t err;

	err = load_vmcs(vmcs, true);
	if (err != SUCCESS)
		return err;

	/* fill trusted template
	 * TODO: cleanup. Trusted template is partially used: only host-state
	 * fields and some control fields are needed later. */
	host_cr3 = __pa(_init_mm->pgd);
	host_msr = __pa(autoload_msr);

	memset(tmpl, 0, sizeof(*tmpl));
	setup_tmpl_host_state(tmpl, host_rsp, host_cr3);
	setup_tmpl_guest_state(tmpl, guest_rip, guest_rsp, guest_rflags);
	setup_tmpl_exec_control(tmpl, 1);
	setup_tmpl_exit_control(tmpl, 1, host_msr);
	setup_tmpl_entry_control(tmpl);

	apply_vmcs_template(tmpl);

	/* host shares its MSR with trusted guest, thus guest_msr == host_msr */
	init_autoload_msr(autoload_msr);
	cpu_vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, host_msr);
	cpu_vmcs_write64(VM_EXIT_MSR_STORE_ADDR, host_msr);

	return SUCCESS;
}

err_t create_capsule_vmcs(struct vmcs_region **vmcs_result,
			  struct vmcs_template *tmpl,
			  unsigned long eptp,
			  unsigned long guest_msr)
{
	struct vmcs_region *vmcs;
	struct vmcs_template t;
	err_t err;

	*vmcs_result = NULL;

	/* GFP_ATOMIC because called from hypervisor */
	vmcs = alloc_vmcs(GFP_ATOMIC);
	if (vmcs == NULL)
		return ERROR_CREATION_ALLOC_FAILED;

	err = load_vmcs(vmcs, false);
	if (err != 0) {
		free_page((unsigned long)vmcs);
		return err;
	}

	/* initialize template with capsule template */
	memcpy(&t, &capsule_template, sizeof(capsule_template));

	/* copy host state and some control fields from trusted template */
	memcpy(&t.host, &tmpl->host, sizeof(tmpl->host));
	t.vm_exit_msr_load_addr = tmpl->vm_exit_msr_load_addr;

	apply_vmcs_template(&t);

	/* these values are different for each capsule, and thus can't be
	 * inherited from template */
	cpu_vmcs_write64(EPT_POINTER, eptp);
	cpu_vmcs_write64(VM_ENTRY_MSR_LOAD_ADDR, guest_msr);
	cpu_vmcs_write64(VM_EXIT_MSR_STORE_ADDR, guest_msr);

	*vmcs_result = vmcs;

	return SUCCESS;
}

static int xalloc_page(void **x)
{
	unsigned long p;

	p = get_zeroed_page(GFP_KERNEL);
	*x = (void *)p;
	if (p == 0)
		return -ENOMEM;

	return 0;
}

int init_vmcs_bitmaps(void)
{
	__u64 msr;
	int err;

	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS, msr);
	if (msr & ((__u64)CPU_BASED_USE_MSR_BITMAPS << 32))
		msr_bitmap_capability = 1;
	else
		msr_bitmap_capability = 0;

	err  = xalloc_page(&io_bitmap_a_region);
	err |= xalloc_page(&io_bitmap_b_region);
	err |= xalloc_page(&msr_bitmap_region);
	if (err != 0) {
		hv_err("get_zeroed_page() failed");
		return err;
	}

	init_msr_bitmap();

	return 0;
}

void free_vmcs_bitmaps(void)
{
	free_page((unsigned long)io_bitmap_a_region);
	free_page((unsigned long)io_bitmap_b_region);
	free_page((unsigned long)msr_bitmap_region);

	io_bitmap_a_region = NULL;
	io_bitmap_b_region = NULL;
	msr_bitmap_region = NULL;
}
