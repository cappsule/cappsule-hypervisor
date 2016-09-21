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
#include <linux/kallsyms.h>
#include <linux/syscalls.h>
#include <uapi/linux/uio.h>
#include <asm/vmx.h>
#include <asm/perf_event.h>
#include <asm/syscalls.h>
#include <asm/pgalloc.h>
#include <linux/hugetlb.h>
#include <linux/mm.h>

#include "common/log.h"
#include "common/exec_policy.h"
#include "common/memory.h"
#include "common/params.h"
#include "common/shared_mem.h"
#include "host/capsule.h"
#include "host/ept.h"
#include "host/memory.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/vmx.h"


pte_t get_host_pte(unsigned long pfn, enum pg_level *level)
{
	unsigned long vaddr;
	pgd_t *pgd;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	vaddr = (unsigned long)__va(pfn << PAGE_SHIFT);

	pgd = pgd_offset(_init_mm, vaddr);
	if (pgd_none(*pgd))
		return INVALID_PTE;

	pud = pud_offset(pgd, vaddr);
	if (pud_none(*pud))
		return INVALID_PTE;

	if (pud_large(*pud)) {
		*level = PG_LEVEL_1G;
		pte = (pte_t *)pud;
		goto out;
	}

	pmd = pmd_offset(pud, vaddr);
	if (pmd_none(*pmd))
		return INVALID_PTE;

	if (pmd_large(*pmd)) {
		*level = PG_LEVEL_2M;
		pte = (pte_t *)pmd;
		goto out;
	}

	pte = pte_offset_kernel(pmd, vaddr);
	if (pte_none(*pte) || !pfn_valid(pte_pfn(*pte)))
		return INVALID_PTE;

	*level = PG_LEVEL_4K;

out:
	return *pte;
}

static void free_capsule_mem_helper(struct guest_memory *memory)
{
	struct guest_mem *mem, *tmp;

	mem = memory->first;
	while (mem != NULL) {
		tmp = mem->next;
		free_guest_mem(mem);
		mem = tmp;
	}
}

/* called in vmx-root mode */
void free_capsule_mem(struct capsule *capsule)
{
	cpsl_info(capsule->id, "memory usage: ept: %ldM; alloc: %ldM",
		  capsule->pt_mem.npages * PAGE_SIZE / (1024 * 1024),
		  capsule->alloc_mem.npages * PAGE_SIZE / (1024 * 1024));

	free_capsule_mem_helper(&capsule->pt_mem);
	free_capsule_mem_helper(&capsule->alloc_mem);

	/* capsule->ept_pgd MUST be freed in vmx-root mode, otherwise some
	 * userland processes become very slow to respond. WTF. */
	poison(capsule->ept_pgd, 0x62, PAGE_SIZE);
	free_page((unsigned long)capsule->ept_pgd);
	capsule->ept_pgd = NULL;
}

struct guest_mem *alloc_guest_mem(void)
{
	struct guest_mem *mem;

	BUILD_BUG_ON(sizeof(struct guest_mem) != PAGE_SIZE);

	mem = (struct guest_mem *)__get_free_page(GFP_ATOMIC);
	if (mem == NULL)
		return NULL;

	mem->next = NULL;
	mem->n = 0;

	return mem;
}

void free_guest_mem(struct guest_mem *mem)
{
	unsigned long addr;
	struct page *page;
	int i;

	for (i = 0; i < mem->n; i++) {
		page = mem->pages[i];
		poison(page_address(page), 0x67, PAGE_SIZE);
		__free_page(page);
	}

	addr = (unsigned long)mem;
	poison(mem, 0x65, PAGE_SIZE);
	free_page(addr);
}

void track_alloc(struct capsule *capsule, struct page *page,
		 enum guest_mem_type type)
{
	struct guest_memory *memory = NULL;
	struct guest_mem *mem;

	switch (type) {
	case MEM_EPT:
		memory = &capsule->pt_mem;
		break;

	case MEM_GUEST:
		memory = &capsule->alloc_mem;
		break;
	}

	mem = memory->curr;

	/* allocate a new guest_mem structure if necessary */
	if (mem->n >= CAPSULE_MEM_NPAGES) {
		struct guest_mem *new;
		unsigned int npages;

		/* check if memory limit is reached */
		npages = capsule->pt_mem.npages + capsule->alloc_mem.npages;
		if (npages >= capsule->memory_max_npages) {
			poison(page_address(page), 0x67, PAGE_SIZE);
			__free_page(page);
			kill_s(capsule, KILL_TRACK_ALLOC_MEM_MAX);
		}

		new = alloc_guest_mem();
		if (new == NULL) {
			poison(page_address(page), 0x67, PAGE_SIZE);
			__free_page(page);
			kill_s(capsule, KILL_TRACK_ALLOC_FAILED);
		}

		new->next = NULL;
		new->n = 0;

		memory->curr = new;

		mem->next = new;
		mem = new;
	}

	mem->pages[mem->n++] = page;
	memory->npages++;
}

void dump_guest_calltrace(struct vcpu *vcpu)
{
	unsigned long addr, fs, gs, shadowgs, *rsp;
	unsigned short fsindex, gsindex;
	struct capsule *capsule;
	char name[512];
	int i, j;

	capsule = current_capsule(vcpu);
	addr = vcpu->regs.rsp;
	rsp = gpa_to_hva(capsule, __pa(addr), NULL);

	rdmsrl(MSR_KERNEL_GS_BASE, shadowgs);
	fs = cpu_vmcs_read64(GUEST_FS_BASE);
	gs = cpu_vmcs_read64(GUEST_GS_BASE);
	fsindex = cpu_vmcs_read16(GUEST_FS_SELECTOR);
	gsindex = cpu_vmcs_read16(GUEST_GS_SELECTOR);

	printk(KERN_ERR
		"RAX: 0x%016lx RBX: 0x%016lx RCX: 0x%016lx RDX: 0x%016lx RFLAGS: 0x%08lx\n"
		"RSI: 0x%016lx RDI: 0x%016lx RBP: 0x%016lx RSP: 0x%016lx RIP: 0x%016lx\n"
		"R8 : 0x%016lx R9 : 0x%016lx R10: 0x%016lx R11: 0x%016lx R12: 0x%016lx\n"
		"CR0: 0x%016lx CR2: 0x%016lx CR3: 0x%016lx CR4: 0x%016lx\n"
		"FS: %016lx(%04x) GS:%016lx(%04x) kGS: 0x%016lx\n",
		vcpu->regs.rax, vcpu->regs.rbx, vcpu->regs.rcx, vcpu->regs.rdx, cpu_vmcs_readl(GUEST_RFLAGS),
		vcpu->regs.rsi, vcpu->regs.rdi, vcpu->regs.rbp, vcpu->regs.rsp, cpu_vmcs_readl(GUEST_RIP),
		vcpu->regs.r8, vcpu->regs.r9, vcpu->regs.r10, vcpu->regs.r11, vcpu->regs.r12,
		cpu_vmcs_readl(GUEST_CR0), read_cr2(), cpu_vmcs_readl(GUEST_CR3), cpu_vmcs_readl(GUEST_CR4),
		fs, fsindex, gs, gsindex, shadowgs);

	printk(KERN_ERR "call stack:\n");
	if (rsp) {
		for (i = 0; i < 16; i += 4) {
			/* break if different page */
			if (((unsigned long)(rsp + i + 3) & PAGE_MASK) != ((unsigned long)rsp & PAGE_MASK))
				break;

			printk(KERN_ERR " %016lx %016lx %016lx %016lx\n",
				rsp[i], rsp[i+1], rsp[i+2], rsp[i+3]);
		}
	}

	printk(KERN_ERR "call trace (rip=%016lx):\n", cpu_vmcs_readl(GUEST_RIP));
	if (rsp) {
		for (i = 0, j = 0; i < 16 && j < 1024; j++) {
			/* break if different page */
			if (((unsigned long)(rsp + j) & PAGE_MASK) != ((unsigned long)rsp & PAGE_MASK))
				break;

			if (sprint_symbol(name, rsp[j]) == 0)
				continue;
			if (name[0] == '0' && name[1] == 'x')
				continue;
			printk(KERN_ERR ">> %s\n", name);
			i++;
		}
	}
}

void alloc_guest_page(struct capsule *capsule, unsigned long gpa)
{
	struct page *host_page;
	unsigned long hpa;

	host_page = alloc_pages(GFP_ATOMIC | __GFP_ZERO, 0);
	if (host_page == NULL)
		kill_s(capsule, KILL_ALLOC_GUEST_PAGE);

	track_alloc(capsule, host_page, MEM_GUEST);

	/* install GPA -> HPA translation */
	hpa = __pa(page_address(host_page));
	//cpsl_dbg(capsule->id, "alloc_guest_page %016lx - %016lx", gpa, hpa);
	if (install_ept_translation(capsule, gpa, hpa, EPT_PROT_RWX) != 0)
		kill_s(capsule, KILL_ALLOC_GUEST_PAGE_INSTALL_EPT);
}

/* argv and envp are on NPAGES_ARGV_ENVP consecutive pages (virtexec.c) */
void map_argv_envp(struct capsule *capsule)
{
	unsigned long gpa, hpa;
	unsigned char *p;
	int err, i;

	p = capsule->params->info_pages;

	for (i = 0; i < snapshot.params_npages; i++) {
		hpa = __pa(p + i * PAGE_SIZE);
		gpa = snapshot.params_gpa[i];
		err = install_ept_translation(capsule, gpa, hpa, EPT_PROT_RW);
		if (err != 0)
			kill_s(capsule, KILL_MAP_ARGV_ENVP_INSTALL_EPT);
	}
}

/* Map exec_policies pages read-only.
 *
 * Capsule is responsible of checking if a call to execve is allowed or not, and
 * thus needs to access to exec policies. */
void map_exec_policies(struct capsule *capsule)
{
	struct exec_policies *exec_policies;
	unsigned long kaddr, gpa, hpa;
	unsigned int npages;
	int err, i;

	exec_policies = get_exec_policies();
	if (exec_policies == NULL)
		kill_s(capsule, KILL_MAP_POLICIES_NOT_SET);

	npages = exec_policies->size / PAGE_SIZE;
	kaddr = (unsigned long)exec_policies;
	for (i = 0; i < npages; i++) {
		gpa = __pa(kaddr);
		hpa = __pa(kaddr);
		err = install_ept_translation(capsule, gpa, hpa, EPT_PROT_READ);
		if (err != 0)
			kill_s(capsule, KILL_MAP_POLICIES_INSTALL_EPT);
		kaddr += PAGE_SIZE;
	}
}

int resize_capsule_console(struct capsule *capsule,
			   struct winsize *console_size)
{
	if (capsule->shared_mem == NULL)
		return -1;

	capsule->shared_mem->tty_size = *console_size;
	return 0;
}

void share_device_mem(struct capsule *capsule, unsigned long gpa)
{
	//cpsl_dbg(capsule->id, "share_device_mem(%d, %016lx)",
	//	capsule->share_mem_vmcall, gpa);

	/* don't allow capsule to allocate shared memory twice */
	if (capsule->shared_mem != NULL)
		kill_s(capsule, KILL_SHARE_DEVICE_MEM_TOO_MUCH_CALL);

	/* blocked_inter is allocated by guest */
	capsule->shared_mem = gpa_to_hva(capsule, gpa, NULL);
	if (capsule->shared_mem == NULL)
		kill_s(capsule, KILL_SHARE_DEVICE_MEM_INVALID_GPA);

	capsule->shared_mem->tty_size = capsule->params->tty_size;
	memset(&capsule->shared_mem->blocked_intr_bitmap, 0,
	       sizeof(capsule->shared_mem->blocked_intr_bitmap));

	capsule->shared_mem->capsule_id = capsule->id;
	capsule->shared_mem->policy_uuid = capsule->params->policy_uuid;
	capsule->shared_mem->no_gui = capsule->params->no_gui;

	capsule->shared_mem->xchan_first_vector = vmm.xchan_first_vector;
	capsule->shared_mem->process = snapshot.process;
	capsule->shared_mem->exec_policies = get_exec_policies();
}
