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
#include <linux/syscalls.h>
#include <asm/vmx.h>
#include <asm/perf_event.h>
#include <asm/syscalls.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>

#include "common/log.h"
#include "common/mfn.h"
#include "common/params.h"
#include "host/capsule.h"
#include "host/ept.h"
#include "host/memory.h"
#include "host/snapshot.h"
#include "host/vmx.h"

#define EPT_QUAL_DATA_READ	(1 << 0)
#define EPT_QUAL_DATA_WRITE	(1 << 1)
#define EPT_QUAL_DATA_EXEC	(1 << 2)
#define EPT_QUAL_BIT1		(1 << 3)
#define EPT_QUAL_BIT2		(1 << 4)
#define EPT_QUAL_BIT3		(1 << 5)
#define EPT_QUAL_GVA_VALID	(1 << 7)
#define EPT_QUAL_DIRTY		(1 << 8)


static union ept_pud *ept_pgd_addr(union ept_pgd *pgd)
{
	return (union ept_pud *)__va(pgd->bits.addr << PAGE_SHIFT);
}

static union ept_pmd *ept_pud_addr(union ept_pud *pud)
{
	return (union ept_pmd *)__va(pud->bits.addr << PAGE_SHIFT);
}

static union ept_pte *ept_pmd_addr(union ept_pmd *pmd)
{
	return (union ept_pte *)__va(pmd->bits.addr << PAGE_SHIFT);
}

/* pgd entry not present */
static void alloc_pud(struct capsule *capsule, union ept_pgd *pgd)
{
	union ept_pud *pud;

	pud = (union ept_pud *)get_zeroed_page(GFP_ATOMIC);
	if (pud == NULL)
		kill_s(capsule, KILL_PUD_ALLOC_FAILED);

	track_alloc(capsule, virt_to_page(pud), MEM_EPT);

	//cpsl_dbg(capsule->id, "[+] pud allocate (%016lx: %016lx)", (unsigned long)pud, __pa(pud));

	pgd->value = 0;
	pgd->bits.read = 1;
	pgd->bits.write = 1;
	pgd->bits.exec = 1;
	pgd->bits.addr = __pa(pud) >> PAGE_SHIFT;
}


/* pud entry not present */
static void alloc_pmd(struct capsule *capsule, union ept_pud *pud)
{
	union ept_pmd *pmd;

	pmd = (union ept_pmd *)get_zeroed_page(GFP_ATOMIC);
	if (pmd == NULL)
		kill_s(capsule, KILL_PMD_ALLOC_FAILED);

	track_alloc(capsule, virt_to_page(pmd), MEM_EPT);

	//cpsl_dbg(capsule->id, "[+] pmd allocate (%016lx: %016lx)", (unsigned long)pmd, __pa(pmd));

	pud->value = 0;
	pud->bits.read = 1;
	pud->bits.write = 1;
	pud->bits.exec = 1;
	pud->bits.addr = __pa(pmd) >> PAGE_SHIFT;
}

/* pmd entry not present */
static void alloc_pt(struct capsule *capsule, union ept_pmd *pmd)
{
	union ept_pte *pt;

	pt = (union ept_pte *)get_zeroed_page(GFP_ATOMIC);
	if (pt == NULL)
		kill_s(capsule, KILL_PTE_ALLOC_FAILED);

	track_alloc(capsule, virt_to_page(pt), MEM_EPT);

	//cpsl_dbg(capsule->id, "[+] pt allocate (%016lx: %016lx)", (unsigned long)pt, __pa(pt));

	pmd->value = 0;
	pmd->bits.read = 1;
	pmd->bits.write = 1;
	pmd->bits.exec = 1;
	pmd->bits.addr = __pa(pt) >> PAGE_SHIFT;
}

void remove_ept_translation(struct capsule *capsule, unsigned long gpa)
{
	union ept_pgd *pgde;
	union ept_pud *pude;
	union ept_pmd *pmde;
	union ept_pte *pte;

	/* Page Global Dir */
	pgde = capsule->ept_pgd + ept_pgd_index(gpa);
	if (!ept_pgd_present(pgde))
		kill_s(capsule, KILL_REMOVE_GPA_BAD_PUD);

	/* Page Upper Dir */
	pude = ept_pgd_addr(pgde) + ept_pud_index(gpa);
	if (!ept_pud_present(pude))
		kill_s(capsule, KILL_REMOVE_GPA_BAD_PUD);

	if (pude->value & (1 << 7))
		kill_s(capsule, KILL_REMOVE_GPA_HUGE_PUD);

	/* Page Middle Dir */
	pmde = ept_pud_addr(pude) + ept_pmd_index(gpa);
	if (!ept_pmd_present(pmde))
		kill_s(capsule, KILL_REMOVE_GPA_BAD_PMD);

	if (pmde->value & (1 << 7))
		kill_s(capsule, KILL_REMOVE_GPA_LARGE_PMD);

	/* Page Table */
	pte = ept_pmd_addr(pmde) + ept_pte_index(gpa);
	if (!ept_pte_present(pte))
		kill_s(capsule, KILL_REMOVE_GPA_BAD_PTE);

	pte->value = 0;
}

/* return 0 on success, -1 otherwise (page is already installed) */
int install_ept_translation(struct capsule *capsule, unsigned long gpa,
			unsigned long hpa, unsigned long prot)
{
	union ept_pgd *pgde;
	union ept_pud *pude;
	union ept_pmd *pmde;
	union ept_pte *pte;

	//cpsl_dbg(capsule->id, "> install_ept_translation %016lx %016lx", gpa, hpa);

	/* Page Global Dir */
	pgde = capsule->ept_pgd + ept_pgd_index(gpa);
	if (!ept_pgd_present(pgde))
		alloc_pud(capsule, pgde);

	/* Page Upper Dir */
	pude = ept_pgd_addr(pgde) + ept_pud_index(gpa);
	if (!ept_pud_present(pude))
		alloc_pmd(capsule, pude);

	/* Page Middle Dir */
	pmde = ept_pud_addr(pude) + ept_pmd_index(gpa);
	if (!ept_pmd_present(pmde))
		alloc_pt(capsule, pmde);

	/* Page Table */
	pte = ept_pmd_addr(pmde) + ept_pte_index(gpa);
	if (ept_pte_present(pte))
		return -1;

	pte->value = 0;
	pte->value |= prot & EPT_PROT_RWX;
	pte->bits.addr = hpa >> PAGE_SHIFT;
	pte->bits.mem_type = 6;

	return 0;
}

static unsigned long dup_page(struct capsule *capsule, unsigned long snap_pa)
{
	struct page *new_page;
	unsigned long hpa;
	void *from, *to;

	to = (void *)__get_free_page(GFP_ATOMIC | __GFP_ZERO);
	if (to == NULL)
		kill_s(capsule, KILL_DUP_PAGE_FAILED);

	new_page = virt_to_page(to);
	track_alloc(capsule, new_page, MEM_GUEST);

	from = __va(snap_pa);
	memcpy(to, from, PAGE_SIZE);

	hpa = __pa(to);
	return hpa;
}

static void handle_self_modifying_code(struct capsule *capsule,
				unsigned long gpa, unsigned long snap_pa,
				unsigned long prot)
{
	unsigned long hpa;

	cpsl_info(capsule->id, "self-modifying code (rip: %016lx)",
		  cpu_vmcs_readl(GUEST_RIP));

	remove_ept_translation(capsule, gpa);

	prot |= EPT_PROT_WRITE;
	hpa = dup_page(capsule, snap_pa);
	if (install_ept_translation(capsule, gpa, hpa, prot) != 0)
		kill_s(capsule, KILL_SELF_MODIF_CODE_INSTALL_EPT);
}

static void handle_ept_violation(struct vcpu *vcpu, unsigned long gpa,
				unsigned long gva, unsigned long qual)
{
	unsigned long hpa, prot, snap_pa;
	struct capsule *capsule;
	pte_t hpte;

	if (0) {
		char name[512], reason[16];
		sprint_symbol(name, cpu_vmcs_readl(GUEST_RIP));
		sprintf(reason, "%c%c%c %c%c%c %d %d",
			qual & 1 ? 'r' : '-',
			qual & 2 ? 'w' : '-',
			qual & 4 ? 'x' : '-',
			qual & 8 ? 'R' : '-',
			qual & 0x10 ? 'W' : '-',
			qual & 0x20 ? 'X' : '-',
			qual & (1 << 7) ? 1 : 0,
			qual & (1 << 8) ? 1 : 0);
		cpsl_dbg(capsule->id, "ept violation at %016lx / %016lx, (%s), %s",
			 gpa, gva, name, reason);
	}

	capsule = current_capsule(vcpu);

	/* It would be nice to call map_argv_envp() from create_capsule(),
	 * however capsule is still not running at this moment and
	 * kill_capsule() may be called. */
	if (!(capsule->flags & CPSL_ARGV_SETUP)) {
		map_argv_envp(capsule);
		map_exec_policies(capsule);
		capsule->flags |= CPSL_ARGV_SETUP;
		return;
	}

	if (capsule->fault_address != gpa) {
		capsule->fault_address = gpa;
		capsule->nfault = 0;
	} else {
		capsule->nfault++;
		if (capsule->nfault == 3) {
			cpsl_err(capsule->id, "address: %016lx (rip=%016lx)",
				 gpa, cpu_vmcs_readl(GUEST_RIP));
			dump_guest_calltrace(vcpu);
			kill_s(capsule, KILL_EPT_VIOLATION_LOOP);
		}
	}

	gpa &= PAGE_MASK;

	/* if gpa was allocated by guest, it would be in EPT
	 * no need to search anywhere else than in snapshot memory */
	hpte = snapshot_gpa_to_hva(gpa);
	if (pte_val(hpte) == 0) {
		alloc_guest_page(capsule, gpa);
		return;
	}

	snap_pa = pte_pfn(hpte) << PAGE_SHIFT;
	if (pte_write(hpte))
		hpa = dup_page(capsule, snap_pa);
	else
		hpa = snap_pa;

	prot = get_pte_prot(hpte);
	if (install_ept_translation(capsule, gpa, hpa, prot) != 0) {
		/* If these conditions are met:
		 *  - access causing the EPT violation was a data write;
		 *  - write bit of EPT paging structure entries used to
		 *    translate the guest-physical address of the access causing
		 *    the EPT violation is not set,
		 * then kernel is modifying its code at runtime (jump-labels for
		 * example.) */
		if (!(qual & EPT_QUAL_DATA_WRITE) || (qual & EPT_QUAL_BIT2) ||
			(prot & EPT_PROT_RW))
			handle_self_modifying_code(capsule, gpa, snap_pa, prot);
		else
			kill_s(capsule, KILL_EPT_VIOLATION_INSTALL_EPT);
	}

}

void exit_ept_violation(struct vcpu *vcpu)
{
	unsigned long exit_qualification;
	__u64 gva, gpa;

	exit_qualification = cpu_vmcs_readl(EXIT_QUALIFICATION);
	gva = cpu_vmcs_read64(GUEST_LINEAR_ADDRESS);
	gpa = cpu_vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	//cpsl_dbg(capsule->id, "exit_ept_violation %016llx %016llx %ld", gva,
	//	 gpa, exit_qualification);

	handle_ept_violation(vcpu, gpa, gva, exit_qualification);
}

void exit_ept_misconfig(struct vcpu *vcpu)
{
	struct capsule *capsule;
	union ept_pgd *pgde;
	union ept_pud *pude;
	union ept_pmd *pmde;
	union ept_pte *pte;
	__u64 gpa;

	capsule = current_capsule(vcpu);

	gpa = cpu_vmcs_read64(GUEST_PHYSICAL_ADDRESS);

	cpsl_err(capsule->id, "exit_ept_misconfig %016llx %p",
		 gpa, gpa_to_hva(capsule, gpa, NULL));

	pgde = capsule->ept_pgd + ept_pgd_index(gpa);
	/* no entry in EPT PGD? */
	if (!ept_pgd_present(pgde)) {
		cpsl_err(capsule->id, "no pgd");
		goto out;
	}

	/* Page Upper Dir */
	pude = ept_pgd_addr(pgde) + ept_pud_index(gpa);
	if (!ept_pud_present(pude)) {
		cpsl_err(capsule->id, "no pud");
		goto out;
	}

	if (pude->value & (1 << 7)) {
		cpsl_err(capsule->id, "huge pud");
		goto out;
	}

	/* Page Middle Dir */
	pmde = ept_pud_addr(pude) + ept_pmd_index(gpa);
	if (!ept_pmd_present(pmde)) {
		cpsl_err(capsule->id, "no pmd");
		goto out;
	}

	if (pmde->value & (1 << 7)) {
		cpsl_err(capsule->id, "large pmd");
		goto out;
	}

	/* Page Table */
	pte = ept_pmd_addr(pmde) + ept_pte_index(gpa);
	if (!ept_pte_present(pte)) {
		cpsl_err(capsule->id, "no pte");
		goto out;
	}

out:
	kill(vcpu, KILL_EPT_MISCONFIGURATION);
}

/* GPA -> HVA */
void *gpa_to_hva(struct capsule *capsule, unsigned long gpa, unsigned long *prot)
{
	union ept_pgd *pgde;
	union ept_pud *pude;
	union ept_pmd *pmde;
	union ept_pte *pte;
	unsigned long hpa;
	void *hva;

	//cpsl_dbg(capsule->id, "gpa -> hva: %016lx", gpa);

	/* Page Global Dir */
	pgde = capsule->ept_pgd + ept_pgd_index(gpa);
	/* no entry in EPT PGD? */
	if (!ept_pgd_present(pgde))
		return NULL;

	/* Page Upper Dir */
	pude = ept_pgd_addr(pgde) + ept_pud_index(gpa);
	if (!ept_pud_present(pude))
		return NULL;

	if (pude->value & (1 << 7)) {
		hv_err("BUG: huge pgd in gpa_to_hva");
		return NULL;
	}

	/* Page Middle Dir */
	pmde = ept_pud_addr(pude) + ept_pmd_index(gpa);
	if (!ept_pmd_present(pmde))
		return NULL;

	if (pmde->value & (1 << 7)) {
		hv_err("BUG: large pgd in gpa_to_hva");
		return NULL;
	}

	/* Page Table */
	pte = ept_pmd_addr(pmde) + ept_pte_index(gpa);
	if (!ept_pte_present(pte))
		return NULL;

	hpa = pte->bits.addr << PAGE_SHIFT;
	hva = __va(hpa);

	if (prot != NULL)
		*prot = pte->value & EPT_PROT_RWX;

	return hva;
}

/**
 * Convert a batch of GPAs to HVAs.
 *
 * @return 0 on success, -1 otherwised.
 */
unsigned long vmcall_gpa_to_hva(struct vmcall_gpa_hva_convert *convert)
{
	struct capsule *capsule;
	unsigned int i;
	uid_t xorg_uid;
	void *hva;

	capsule = get_capsule_from_id(convert->capsule_id);
	if (capsule == NULL) {
		tg_err("%s: can't find capsule %d", __func__,
		       convert->capsule_id);
		return -1;
	}

	/* Users able to ptrace the Xorg process can access to the memory of any
	 * capsule. Ensure that Xorg runs as root (this is the case in old
	 * distros) or runs with the same user than the capsule. */
	xorg_uid = convert->xorg_uid;
	if (xorg_uid != 0 && xorg_uid != capsule->params->uid) {
		tg_err("%s: user %d isn't allowed to access to capsule %d",
		       __func__, xorg_uid, convert->capsule_id);
		put_capsule(capsule);
		return -1;
	}

	for (i = 0; i < convert->num_mfn; i++) {
		hva = gpa_to_hva(capsule, convert->gpa[i], NULL);
		convert->res_hva[i] = (unsigned long)hva;
	}

	put_capsule(capsule);

	return 0;
}
