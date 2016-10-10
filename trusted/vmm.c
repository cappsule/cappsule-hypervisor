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
#include <linux/kthread.h>
#include <linux/cpu.h>

#include <asm/virtext.h>

#include "common/bluepill.h"
#include "common/cr4.h"
#include "common/error.h"
#include "common/log.h"
#include "common/vmcall.h"
#include "host/capsule.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/vcpu.h"
#include "host/vmcs.h"
#include "host/vmm.h"
#include "host/vmx.h"
#include "trusted/vmm.h"
#include "trusted/xchan.h"


struct ia32_feature_control_msr {
	unsigned lock            :1;
	unsigned VmxonInSmx      :1;
	unsigned VmxonOutSmx     :1;
	unsigned Reserved2       :29;
	__u32 reserved3;
} __attribute__((__packed__));

struct vmm vmm;
extern struct notifier_block cappsule_cpu_notifier;


/* Return an error if page is not 4K. Since this function is usually called to
 * set a guard page as read-only, unexpected crash may happen otherwise. */
static int set_host_page_wrpot(unsigned long vaddr, int writeable)
{
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep, pte;

	pgd = pgd_offset(_init_mm, vaddr);
	if (pgd_none(*pgd))
		return -1;

	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud) || pud_large(*pud))
		return -1;

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd) || pmd_large(*pmd))
		return -1;

	ptep = pte_offset_kernel(pmd, vaddr);
	pte = *ptep;

	if (pte_none(pte) || !pfn_valid(pte_pfn(pte)))
		return -1;

	if (writeable)
		set_pte(ptep, pte_mkwrite(pte));
	else
		set_pte(ptep, pte_wrprotect(pte));

	__flush_tlb_one(vaddr);

	return 0;
}

/* Set host page read-only. Usually used to trigger a fault from hypervisor or
 * guest and easier debug if one tries to write to this page. */
static int set_host_page_ro(unsigned long addr)
{
	return set_host_page_wrpot(addr, 0);
}

static int set_host_page_rw(unsigned long addr)
{
	return set_host_page_wrpot(addr, 1);
}

/* Allocate 2 consecutive pages: guard page followed by vmm stack.
 *
 * Unnecessary complicated: the 2 pages must not be allocated as 2M or 1G page,
 * otherwise vmm stack will also be set as read-only. Since there is no way to
 * force __get_free_pages() to allocate 4K page, retry until expected result. */
static err_t alloc_guard_page(unsigned int order, unsigned long *result)
{
	unsigned long guard_page, *large_pages, *p;
	size_t size;
	err_t error;
	int n;

	large_pages = NULL;
	error = SUCCESS;
	n = 0;

	while (1) {
		guard_page = __get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
		if (guard_page == 0)
			break;

		if (set_host_page_ro(guard_page) == 0)
			break;

		size = sizeof(*large_pages) * (n + 1);
		p = krealloc(large_pages, size, GFP_KERNEL);
		if (p == NULL) {
			free_pages(guard_page, order);
			error = ERROR_ALLOC_GUARD_PAGE;
			break;
		}

		large_pages = p;
		large_pages[n++] = guard_page;

		//hv_dbg("failed to alloc guard page, retrying");
	}

	for (p = large_pages; n > 0; n--) {
		free_pages(*large_pages, order);
		large_pages++;
	}

	*result = guard_page;
	return error;
}

static err_t cpu_check_capability(void)
{
	struct ia32_feature_control_msr feature_control_msr;
	__u64 msr, capability_ept_vpid, controls2_msr;

	/* check for VMX in CPUID */
	if (!cpu_has_vmx())
		return ERROR_CPU_NO_VMX;

	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS, msr);
	if (!(msr & ((__u64)CPU_BASED_ACTIVATE_SECONDARY_CONTROLS << 32)))
		return ERROR_CPU_NO_SECONDARY_CONTROLS;

	/* check for EPT capability
	 * A.10 VPID AND EPT CAPABILITIES */
	rdmsrl(MSR_IA32_VMX_PROCBASED_CTLS2, controls2_msr);
	if (!((controls2_msr >> 32) & SECONDARY_EXEC_ENABLE_EPT))
		return ERROR_CPU_NO_EPT;

	rdmsrl(MSR_IA32_VMX_EPT_VPID_CAP, capability_ept_vpid);
	//hv_dbg("capabilities ept_vpid: %016llx", capability_ept_vpid);
	if (!(capability_ept_vpid & (1 << 14)))
		return ERROR_CPU_WB_MEMORY_TYPE;
	else if (!(capability_ept_vpid & (1 << 20)))
		return ERROR_CPU_NO_INVEPT;
	else if (!(capability_ept_vpid & (1 << 26)))
		return ERROR_CPU_INVEPT_TYPE;

	if (((controls2_msr >> 32) & SECONDARY_EXEC_ENABLE_VPID) &&
	    (capability_ept_vpid & 0xf0100000000UL) == 0xf0100000000UL)
		vmm.vpid_support = 1;
	else
		hv_info("invvpid is not supported");

	/* A.1 BASIC VMX INFORMATION *
	 * 23.7 ENABLING AND ENTERING VMX OPERATION */
	rdmsrl(MSR_IA32_FEATURE_CONTROL, *(__u64 *)&feature_control_msr);
	//hv_dbg("ftr_ctrl_msr = 0x%016llx", *(__u64 *)&feature_control_msr);
	if (!feature_control_msr.lock)
		return ERROR_CPU_VMX_DISABLED;

	return SUCCESS;
}

err_t cpu_enable_vmx(struct vcpu *vcpu)
{
	err_t error;

	error = cpu_check_capability();
	if (error != SUCCESS)
		return error;

	if (cpu_vmx_enabled())
		return ERROR_VMX_ALREADY_ENABLED;

	/* enable VMX in CR4 */
	cr4_set_bits(X86_CR4_VMXE);

	/* enable VMX operation for current processor with VMXON instruction */
	error = cpu_vmxon(vcpu->vmxon);
	if (error != SUCCESS) {
		cr4_clear_bits(X86_CR4_VMXE);
		return ERROR_VMXON_FAILED;
	}

	/* prevents potentially undesired retention of information cached from
	 * EPT paging structures and paging structures between separate uses of
	 * VMX operation. */
	invept(INVEPT_ALL_CONTEXT, 0);
	invvpid(VMX_VPID_EXTENT_ALL_CONTEXT, 0, 0);

	return SUCCESS;
}

static void free_vcpu(struct vcpu *vcpu)
{
	if (vcpu == NULL)
		return;

	if (vcpu->vmxon != NULL) {
		free_page((unsigned long)vcpu->vmxon);
		vcpu->vmxon = NULL;
	}

	if (vcpu->guard_page != 0) {
		/* Does the kernel reuse page without changing its permissions?
		 * Restore original permissions, just in case.
		 * Error code is not checked since set_host_page_rw()
		 * succeed. */
		set_host_page_rw(vcpu->guard_page);
		free_pages(vcpu->guard_page, 1);
		vcpu->guard_page = 0;
	}

	if (vcpu->vmcs_trusted != NULL) {
		free_page((unsigned long)vcpu->vmcs_trusted);
		vcpu->vmcs_trusted = NULL;
	}

	if (vcpu->trusted_template != NULL) {
		kfree(vcpu->trusted_template);
		vcpu->trusted_template = NULL;
	}
}

void kill_all_capsules(void)
{
	struct task_struct *task;
	unsigned long ret;
	bool woken_up;

	while (1) {
		ret = cpu_vmcs_vmcall_ret(VMCALL_GET_FIRST_SHADOWP_TASK,
					  (unsigned long)&woken_up);

		task = (struct task_struct *)ret;
		if (task == NULL)
			break;

		/* There seems to be a bug in the Linux kernel. Even if
		 * wake_up_process() is successfully called by
		 * channel_create_capsule(), kthread_stop() may not allow
		 * threadfn to be called and return -EINTR. In that case,
		 * shadow_process() is never called and the capsule isn't
		 * removed from the list, leading this function to an infinite
		 * loop.
		 *
		 * If shadow_process wasn't called, let it some time to be
		 * woken up before retrying. */
		if (!woken_up) {
			tg_warn("shadow_process wasn't woken up, retrying...");
			put_task_struct(task);
			schedule();
			continue;
		}

		/* kill capsule and wait for its exit */
		if (kthread_stop(task) != 0) {
			tg_err("BUG: failed to stop shadow process kthread");

			/* this is the only way not to stay in an infinite
			 * loop */
			tg_err("A crash may happen if other capsules are alive.");
			put_task_struct(task);
			break;
		}

		put_task_struct(task);
	}
}

void stop_vmm(void)
{
	unsigned int cpu;

	hv_info("%s", __func__);

	//cpu_notifier_register_begin();
	get_online_cpus();

	/* disable VMX on this CPU directly, because this CPU is in VMX non-root
	 * mode */
	cpu = get_cpu();
	cpu_vmcs_vmcall(VMCALL_STOP_VMM, 0);

	/* tell VMM on other CPUs to disable VMX */
	atomic_set(&vmm.pending_vmx_stop, 0);
	smp_call_function(cpu_stop_vmm, NULL, true);
	put_cpu();

	while (atomic_read(&vmm.pending_vmx_stop) > 0) {
		/* Wait until VMX is disabled on other CPUs. Far from ideal:
		 * since CPUs may be idle, force a vm-exit. */
		smp_call_function(cpu_trigger_vm_exit, NULL, true);
	}

	unregister_cpu_notifier(&cappsule_cpu_notifier);

	put_online_cpus();
	//cpu_notifier_register_done();
}

void free_vmm(void)
{
	int i;

	if (vmm.vcpus != NULL) {
		for (i = 0; i < vmm.max_cpus; i++) {
			free_vcpu(&vmm.vcpus[i]);
		}
		kfree(vmm.vcpus);
		vmm.vcpus = NULL;
	}

	free_vmcs_bitmaps();
}

static err_t init_vcpu(struct vcpu *vcpu,
		       unsigned int cpu,
		       union ia32_vmx_basic_msr msr)
{
	err_t error;

	vcpu->cpu = cpu;
	vcpu->bluepilled = false;
	vcpu->stop_vmx = false;
	vcpu->vmxon = NULL;
	vcpu->vmm_stack = NULL;
	vcpu->guard_page = 0;
	vcpu->vmcs_trusted = NULL;

	error = alloc_guard_page(1, &vcpu->guard_page);
	if (error != SUCCESS)
		return error;

	vcpu->vmm_stack = (void *)(vcpu->guard_page + PAGE_SIZE);
	//hv_dbg("vmm_stack: %p", vmm_stack);

	vcpu->vmxon = (void *)get_zeroed_page(GFP_KERNEL);
	if (vcpu->vmxon == NULL)
		return ERROR_ALLOC_FAILED;

	//hv_dbg("%s: vmcs of cpu #%d = %p", __func__, cpu, vcpu->vmcs_trusted);
	memcpy(vcpu->vmxon, &msr.bits.revid, sizeof(msr.bits.revid));

	vcpu->vmcs_trusted = alloc_vmcs(GFP_KERNEL);
	if (vcpu->vmcs_trusted == NULL)
		return ERROR_ALLOC_FAILED;

	vcpu->trusted_template = alloc_vmcs_template();
	if (vcpu->trusted_template == NULL)
		return ERROR_ALLOC_FAILED;

	return SUCCESS;
}

/* allocate vmm fields */
err_t init_vmm(void)
{
	union ia32_vmx_basic_msr vmx_basic_msr;
	err_t error;
	int i;

	memset(&vmm, 0, sizeof(vmm));

	error = find_xchan_first_vector();
	if (error != SUCCESS)
		goto out;

	atomic_set(&vmm.module_being_removed, 0);

	vmm.max_cpus = num_possible_cpus();
	vmm.vcpus = kzalloc(sizeof(*vmm.vcpus) * vmm.max_cpus, GFP_KERNEL);
	if (vmm.vcpus == NULL) {
		error = ERROR_ALLOC_FAILED;
		goto out;
	}

	/* XXX: can be different for each CPU */
	rdmsrl(MSR_IA32_VMX_BASIC, vmx_basic_msr.value);
	//hv_dbg("vmx_basic_msr = 0x%016llx", vmx_basic_msr.value);
	//hv_dbg("rev_id        = %d", vmx_basic_msr.bits.revid);
	//hv_dbg("region_size   = %d", vmx_basic_msr.bits.region_size);
	//hv_dbg("mem_type      = %d", vmx_basic_msr.bits.mem_type);

	error = init_vmcs_bitmaps();
	if (error)
		goto out;

	/* init every possible vcpu */
	for (i = 0; i < vmm.max_cpus; i++) {
		error = init_vcpu(&vmm.vcpus[i], i, vmx_basic_msr);
		if (error != SUCCESS)
			goto out;
	}

out:
	if (error != SUCCESS)
		free_vmm();

	return error;
}
