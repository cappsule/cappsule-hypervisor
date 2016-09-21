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
#include <linux/slab.h>
#include <linux/mm.h>
#include <asm/page.h>
#include <asm/vmx.h>
#include <linux/skbuff.h>
#include <linux/sched.h>

#include "common/channel.h"
#include "common/log.h"
#include "common/error.h"
#include "common/memory.h"
#include "host/capsule.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/process.h"
#include "host/breakpoint.h"
#include "host/memory.h"
#include "host/vmcs.h"
#include "host/vmx.h"

#define BITMAP_END		(~0)
#define BITS_PER_BITMAP		(PAGE_SIZE * BITS_PER_BYTE)
#define COUNT_ERROR		(~0)
#define JMP_SIZE		5
#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)


struct snapshot_bitmap {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
	void *data;
};

struct bitmap_position {
	struct list_head *first_bitmap;
	struct snapshot_bitmap *bm;
	unsigned long offset;
};

struct erase_range {
	void *start;
	void *end;
};

struct snapshot snapshot;
int snapshot_done;

extern void fake_return_stub(void);
extern unsigned long __start_erase_text, __stop_erase_text;
extern unsigned long __start_keep_common, __stop_keep_common;


static void snapshot_fix_pfn(pte_t *pte, unsigned long pfn)
{
	pte->pte &= ~PTE_PFN_MASK;
	pte->pte |= (pfn << PAGE_SHIFT) & PTE_PFN_MASK;
}

/* TODO: improve search efficiency */
static unsigned long snapshot_find_pfn(unsigned long pfn)
{
	int i;

	for (i = 0; i < snapshot.npages; i++) {
		if (snapshot.orig_pfn[i] == pfn)
			return snapshot.copy_pfn[i];
	}

	return -1; /* TODO: -1 is signed */
}

pte_t snapshot_gpa_to_hva(unsigned long gpa)
{
	unsigned long pfn;
	int i;

	pfn = gpa >> PAGE_SHIFT;

	for (i = 0; i < snapshot.npages; i++) {
		if (snapshot.orig_pfn[i] == pfn)
			return snapshot.pte[i];
	}

	return __pte(0);
}

/* this function should not be called to check that a virtual address is mapped
 * in guest (because it doesn't use page tables), use translate_addr()
 * instead */
static struct page *snapshot_addr_to_page(unsigned long addr)
{
	struct page *page;
	unsigned long pfn;

	if (!_is_vmalloc_or_module_addr((void *)addr))
		pfn = virt_to_pfn(addr);
	else
		pfn = vmalloc_to_pfn((void *)addr);

	pfn = snapshot_find_pfn(pfn);
	if (pfn == -1)
		return NULL;

	page = pfn_to_page(pfn);
	return page;
}

/* return corresponding virtual address of addr in snapshot memory */
static unsigned long snapshot_addr(unsigned long addr)
{
	unsigned long snap_addr;
	struct page *page;

	page = snapshot_addr_to_page(addr);
	if (page == NULL)
		return 0;

	snap_addr = (unsigned long)page_address(page) + (addr & ~PAGE_MASK);
	return snap_addr;
}

static err_t modify_snapshot(void *dst, void *src, size_t len)
{
	unsigned long addr;

	addr = snapshot_addr((unsigned long)dst);
	if (addr == 0)
		return ERROR_SNAP_FIX_INVALID_ADDR;

	if (((addr + len) & PAGE_MASK) != (addr & PAGE_MASK))
		return ERROR_SNAP_FIX_MULTIPLE_PAGES;

	memcpy((void *)addr, src, len);

	return SUCCESS;
}

static int erase_memory(unsigned long addr, size_t size)
{
	unsigned long gpa, hpa;
	unsigned int offset;
	unsigned char *hva;
	pte_t hpte;
	size_t n;

	offset = addr & ~PAGE_MASK;

	while (size > 0) {
		if (_is_vmalloc_or_module_addr((void *)addr))
			gpa = vmalloc_to_pfn((void *)addr) << PAGE_SHIFT;
		else
			gpa = __pa(addr);

		hpte = snapshot_gpa_to_hva(gpa);
		if (pte_val(hpte) == 0)
			return -1;

		hpa = pte_pfn(hpte) << PAGE_SHIFT;
		hva = __va(hpa);

		if (offset == 0) {
			n = (size > PAGE_SIZE) ? PAGE_SIZE : size;
		} else {
			hva += offset;
			if (size > PAGE_SIZE - offset)
				n = PAGE_SIZE - offset;
			else
				n = size;
			offset = 0;
		}

		memset(hva, 0xca, n);
		size -= n;
		addr += n;
	}

	return 0;
}

/**
 * Capsules shouldn't be able to dump kernel memory to get the code of the
 * hypervisor. Fill module memory with garbage.
 *
 * Erase .text section of cappsule.ko memory in snapshot, while keeping
 * .keep.common section from common/channel.o.
 */
static err_t erase_module_memory(void)
{
	struct erase_range ranges[] = {
		{ &__start_erase_text, &__start_keep_common },
		{ &__stop_keep_common, &__stop_erase_text },
	};
	struct erase_range *range;
	unsigned long addr;
	unsigned int i;
	size_t size;

	for (i = 0; i < ARRAY_SIZE(ranges); i++) {
		range = &ranges[i];
		addr = (unsigned long)range->start;
		size = (size_t)(range->end - range->start);
		if (erase_memory(addr, size) != 0)
			return ERROR_SNAP_ERASE_MODULE_MEMORY;
	}

	return SUCCESS;
}

static err_t snapshot_push_on_stack(unsigned long *rsp, unsigned long value,
				    int *stack_shift)
{
	int error;

	*stack_shift += sizeof(unsigned long);
	*rsp -= sizeof(unsigned long);
	error = modify_snapshot((void *)*rsp, &value, sizeof(value));

	return error;
}

/* call guest_init() from guest
 * return -1 on error, stack shift otherwise */
static err_t fake_method_call(unsigned long rip, unsigned long rsp,
			      int *stack_shift)
{
	struct regs *regs;
	err_t err;

	/* push rip */
	err = snapshot_push_on_stack(&rsp, rip, stack_shift);
	if (err != SUCCESS)
		return err;

	/* save regs which are not preserved, which will be restored by
	 * fake_return_stub */
	regs = &snapshot.ctx.regs;
	if ((err = snapshot_push_on_stack(&rsp, regs->rdi, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->rsi, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->rdx, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->rax, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->r8,  stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->r9,  stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->r10, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->r11, stack_shift)) != SUCCESS ||
	    (err = snapshot_push_on_stack(&rsp, regs->rcx, stack_shift)) != SUCCESS)
		return err;

	/* push address of return stub */
	err = snapshot_push_on_stack(&rsp, (unsigned long)fake_return_stub,
				stack_shift);

	return err;
}

static err_t fix_snapshot(void)
{
	struct breakpoint *bp[] = {
		&bp_do_exit,
		&bp_schedule_end,
		&bp_schedule_tail_end,
		&bp_prepare_binprm,
		&bp_vt_console_print,
		&bp_process_one_work,
		NULL,
	};
	unsigned char instr;
	int i, stack_shift;
	size_t len;
	err_t err;

	/* set guest breakpoints */
	instr = INSTR_INT3;
	len = sizeof(instr);
	for (i = 0; bp[i] != NULL; i++) {
		err = modify_snapshot((void *)bp[i]->addr, &instr, len);
		if (err != SUCCESS)
			return err;
	}

	instr = INSTR_RET;
	err = modify_snapshot(apic->write, &instr, sizeof(instr));
	if (err != SUCCESS)
		return err;

	err = modify_snapshot(apic->read, &instr, sizeof(instr));
	if (err != SUCCESS)
		return err;

	err = erase_module_memory();
	if (err != SUCCESS)
		return err;

	/* set a negative return value for VMCALL_SNAPSHOT to tell
	 * channel_snapshot() that it is executed in a capsule */
	snapshot.ctx.regs.rax = -1;

	stack_shift = 0;
	err = fake_method_call(snapshot.rip, snapshot.ctx.regs.rsp,
			       &stack_shift);
	if (err != SUCCESS)
		return err;

	snapshot.ctx.regs.rsp -= stack_shift;

	return SUCCESS;
}

void delete_snapshot(void)
{
	struct page *page;
	int i;

	if (!snapshot_done)
		return;

	for (i = 0; i < snapshot.npages; i++) {
		page = pfn_to_page(snapshot.copy_pfn[i]);
		__free_page(page);
	}

	kfree(snapshot.orig_pfn);
	kfree(snapshot.pte);
	kfree(snapshot.copy_pfn);
	free_process_bitmap();

	snapshot_done = 0;
}

static err_t snapshot_set_pfn(struct list_head *bitmaps, unsigned long pfn)
{
	struct snapshot_bitmap *bm, *new;

	list_for_each_entry(bm, bitmaps, list) {
		if (pfn >= bm->start_pfn && pfn < bm->end_pfn)
			goto insert_pfn;
	}

	new = kmalloc(sizeof(*new), GFP_ATOMIC);
	if (new == NULL)
		return ERROR_SNAP_SET_PFN_ALLOC_FAILED;

	new->data = (void *)get_zeroed_page(GFP_ATOMIC);
	if (new->data == NULL) {
		kfree(new);
		return ERROR_SNAP_SET_PFN_ALLOC_FAILED;
	}

	INIT_LIST_HEAD(&new->list);
	new->start_pfn = pfn & ~(BITS_PER_BITMAP - 1);
	new->end_pfn = new->start_pfn + BITS_PER_BITMAP;

	list_add_tail(&new->list, &bm->list);
	bm = new;

	//hv_dbg("new bm = %p (%p %lx - %lx)", bm,
	//       bm->data, bm->start_pfn, bm->end_pfn);

insert_pfn:
	set_bit(pfn - bm->start_pfn, bm->data);

	return SUCCESS;
}

/* return 1 if pfn found, 0 otherwise */
static int snapshot_unset_pfn(struct list_head *bitmaps, unsigned long pfn)
{
	struct snapshot_bitmap *bm;
	int bit;

	list_for_each_entry(bm, bitmaps, list) {
		if (pfn >= bm->start_pfn && pfn < bm->end_pfn) {
			bit = pfn - bm->start_pfn;
			return __test_and_clear_bit(bit, bm->data);
		}
	}

	return 0;
}

static unsigned long snapshot_next_pfn(struct bitmap_position *pos)
{
	struct snapshot_bitmap *bm;
	unsigned long bit;

	bm = pos->bm;
	do {
		ASSERT(bm != NULL);
		ASSERT(pos != NULL);
		ASSERT(bm->data != NULL);
		bit = find_next_bit(bm->data, BITS_PER_BITMAP, pos->offset);
		if (bit < BITS_PER_BITMAP) {
			/* if offset is greater than or equal to
			 * BITS_PER_BITMAP, find_next_bit() returns directly */
			pos->offset = bit + 1;
			return bm->start_pfn + bit;
		} else {
			bm = list_next_entry(bm, list);
			pos->bm = bm;
			pos->offset = 0;
		}
	} while (&bm->list != pos->first_bitmap);

	return BITMAP_END;
}

static void reset_position(struct bitmap_position *pos,
			struct list_head *bitmaps)
{
	struct snapshot_bitmap *bm;

	bm = list_first_entry(bitmaps, struct snapshot_bitmap, list);
	pos->first_bitmap = bitmaps;
	pos->bm = bm;
	pos->offset = 0;
}

static void save_vmcs_fields(struct vcpu *vcpu)
{
	struct vmcs_segment *s;
	int i;

	snapshot.cr3 = cpu_vmcs_readl(GUEST_CR3);
	snapshot.rip = cpu_vmcs_readl(GUEST_RIP);
	snapshot.rflags = cpu_vmcs_readl(GUEST_RFLAGS);
	memcpy(&snapshot.ctx.regs, &vcpu->regs, sizeof(snapshot.ctx.regs));
	init_autoload_msr(snapshot.ctx.autoload_msr);

	for (i = 0; i < NSEGREG; i++) {
		s = &snapshot.segs[i];
		s->selector = cpu_vmcs_read16(GUEST_ES_SELECTOR + i * 2);
		s->limit = cpu_vmcs_read32(GUEST_ES_LIMIT + i * 2);
		s->ar_bytes = cpu_vmcs_read32(GUEST_ES_AR_BYTES + i * 2);
		s->base = cpu_vmcs_read64(GUEST_ES_BASE + i * 2);
	}
}

static err_t create_snapshot(struct vcpu *vcpu, struct list_head *orig_bitmaps,
			struct list_head *copy_bitmaps, unsigned int npages)
{
	struct bitmap_position copy_pos, orig_pos;
	struct page *to, *from;
	enum pg_level level;
	err_t err;
	int i;

	save_vmcs_fields(vcpu);

	snapshot.npages = npages;

	snapshot.orig_pfn = kmalloc_array(npages, sizeof(unsigned long), GFP_ATOMIC);
	if (snapshot.orig_pfn == NULL) {
		err = ERROR_SNAP_CREATE_SNAP_ALLOC_FAILED;
		goto kmalloc_orig_pfn_failed;
	}

	snapshot.pte = kmalloc_array(npages, sizeof(*snapshot.pte), GFP_ATOMIC);
	if (snapshot.pte == NULL) {
		err = ERROR_SNAP_CREATE_SNAP_ALLOC_FAILED;
		goto kmalloc_pte_failed;
	}

	snapshot.copy_pfn = kmalloc_array(npages, sizeof(unsigned long), GFP_ATOMIC);
	if (snapshot.copy_pfn == NULL) {
		err = ERROR_SNAP_CREATE_SNAP_ALLOC_FAILED;
		goto kmalloc_copy_pfn_failed;
	}

	reset_position(&orig_pos, orig_bitmaps);
	reset_position(&copy_pos, copy_bitmaps);

	for (i = 0; i < snapshot.npages; i++) {
		snapshot.orig_pfn[i] = snapshot_next_pfn(&orig_pos);
		snapshot.copy_pfn[i] = snapshot_next_pfn(&copy_pos);

		ASSERT(snapshot.orig_pfn[i] != BITMAP_END);
		ASSERT(snapshot.copy_pfn[i] != BITMAP_END);

		/* page protection, page level */
		snapshot.pte[i] = get_host_pte(snapshot.orig_pfn[i], &level);
		if (PTE_IS_INVALID(snapshot.pte[i])) {
			err = ERROR_SNAP_INVALID_PTE;
			goto invalid_pte;
		}

		/* fix level */
		if (set_pte_level(&snapshot.pte[i], level) != 0) {
			err = ERROR_SNAP_PTE_LEVEL_SET;
			goto invalid_pte;
		}

		/* use copy pfn */
		snapshot_fix_pfn(&snapshot.pte[i], snapshot.copy_pfn[i]);

		to = pfn_to_page(snapshot.copy_pfn[i]);
		from = pfn_to_page(snapshot.orig_pfn[i]);
		copy_page(page_address(to), page_address(from));
	}

	snapshot_done = 1;

	return SUCCESS;

invalid_pte:
	kfree(snapshot.copy_pfn);
kmalloc_copy_pfn_failed:
	kfree(snapshot.pte);
kmalloc_pte_failed:
	kfree(snapshot.orig_pfn);
kmalloc_orig_pfn_failed:
	return err;
}

static void free_snapshot_bitmaps(struct list_head *bitmaps)
{
	struct snapshot_bitmap *bm, *tmp;

	list_for_each_entry_safe(bm, tmp, bitmaps, list) {
		free_page((unsigned long)bm->data);
		kfree(bm);
	}
}

static bool _kernel_page_present(struct page *page)
{
	unsigned int level;
	pte_t *pte;

	if (PageHighMem(page))
		return false;

	pte = lookup_address((unsigned long)page_address(page), &level);
	if (pte == NULL)
		return false;

	return (pte_val(*pte) & _PAGE_PRESENT);
}

struct nosave_region {
	struct list_head list;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

static int in_nosave_region(unsigned long pfn)
{
	struct nosave_region *region;

	if (list_empty(_nosave_regions))
		return 0;

	list_for_each_entry(region, _nosave_regions, list) {
		if (pfn >= region->start_pfn && pfn < region->end_pfn)
			return 1;
	}

	return 0;
}

static int saveable_page(struct zone *zone, unsigned long pfn)
{
	struct page *page;

	if (!pfn_valid(pfn))
		return 0;

	page = pfn_to_page(pfn);
	if (page_zone(page) != zone)
		return 0;

	if (PageHighMem(page))
		return 0;

	if (PageReserved(page) &&
		(!kernel_page_present(page) || _pfn_is_nosave(pfn)))
		return 0;

	if (page_is_guard(page))
		return 0;

	//if (atomic_read(&page->_count) == 0)
	//	return 0;

	/* XXX */
	if (!_kernel_page_present(page))
		return 0;

	if (in_nosave_region(pfn))
		return 0;

	/*if (page_address(page) >= (void *)VMEMMAP_START &&
		page_address(page) < (void *)__START_KERNEL_map)
		return 0;*/

	return 1;
}

#define _for_each_populated_zone(zone)				\
	for (zone = (_first_online_pgdat())->node_zones;	\
	     zone;						\
	     zone = _next_zone(zone))				\
		if (!populated_zone(zone))			\
			; /* do nothing */			\
		else

static err_t count_data_pages(struct list_head *orig_bitmaps, unsigned int *res)
{
	unsigned long pfn, max_zone_pfn;
	struct list_head *curr;
	int found, order, t;
	struct zone *zone;
	unsigned long i;
	unsigned int n;
	err_t err;

	n = 0;
	*res = 0;
	_for_each_populated_zone(zone) {
		if (is_highmem(zone))
			continue;

		if (zone->spanned_pages == 0)
			continue;

		max_zone_pfn = zone_end_pfn(zone);
		for (pfn = zone->zone_start_pfn; pfn < max_zone_pfn; pfn++) {
			if (saveable_page(zone, pfn)) {
				/* XXX: ensure that pfn is not already set,
				 * otherwise n is too large */
				err = snapshot_set_pfn(orig_bitmaps, pfn);
				if (err != SUCCESS)
					return err;
				n++;
			}
		}
	}

	_for_each_populated_zone(zone) {
		for_each_migratetype_order(order, t) {
			list_for_each(curr, &zone->free_area[order].free_list[t]) {
				pfn = page_to_pfn(list_entry(curr, struct page, lru));
				for (i = 0; i < (1UL << order); i++) {
					found = snapshot_unset_pfn(orig_bitmaps, pfn+i);
					if (found)
						n--;
				}
			}
		}
	}

	*res = n;
	return SUCCESS;
}

static void copy_pages_error(struct list_head *copy_bitmaps, int i)
{
	struct bitmap_position copy_pos;
	struct page *page;
	unsigned long pfn;

	reset_position(&copy_pos, copy_bitmaps);
	while (i-- > 0) {
		pfn = snapshot_next_pfn(&copy_pos);
		ASSERT(pfn != BITMAP_END);
		page = pfn_to_page(pfn);
		__free_page(page);
	}
}

static err_t alloc_copy_pages(struct list_head *copy_bitmaps,
			      unsigned int npages)
{
	struct page *page;
	unsigned long pfn;
	unsigned int i;
	err_t err;

	for (i = 0; i < npages; i++) {
		page = alloc_page(GFP_ATOMIC);
		if (page == NULL) {
			copy_pages_error(copy_bitmaps, i);
			return ERROR_SNAP_ALLOC_COPY_PAGES;
		}

		pfn = page_to_pfn(page);
		err = snapshot_set_pfn(copy_bitmaps, pfn);
		if (err != SUCCESS) {
			__free_page(page);
			copy_pages_error(copy_bitmaps, i);
			return err;
		}
	}

	return SUCCESS;
}

struct filter_pfn {
	struct list_head *bitmaps;
	unsigned long huge_pages;	/* for info purposes */
	unsigned long npages;
};

static void filter_pte_entry(pte_t *pte, struct mm_walk *walk)
{
	struct filter_pfn *filter_pfn;
	struct page *page;
	unsigned long pfn;

	pfn = pte_pfn(*pte);

	/* may happen for Xorg on /dev/dri/card0 VMAs for example */
	if (!pfn_valid(pfn))
		return;

	page = pfn_to_page(pfn);
	if (page == NULL)
		return;

	if (PageSlab(page))
		return;

	if (page_mapcount(page) == 1) {
		filter_pfn = walk->private;
		if (snapshot_unset_pfn(filter_pfn->bitmaps, pfn))
			filter_pfn->npages++;
	}
}

/* filter huge PMD: unset each PFN belonging to this 2M page */
static void filter_huge_pmd_entry(pmd_t *pmd, struct mm_walk *walk)
{
	struct filter_pfn *filter_pfn;
	struct page *page;
	unsigned long pfn;
	int i;

	pfn = pmd_pfn(*pmd);
	if (!pfn_valid(pfn))
		return;

	page = pfn_to_page(pfn);
	if (page == NULL)
		return;

	if (page_mapcount(page) == 1) {
		filter_pfn = walk->private;
		for (i = 0; i < PTRS_PER_PMD; i++) {
			if (snapshot_unset_pfn(filter_pfn->bitmaps, pfn)) {
				filter_pfn->npages++;
				filter_pfn->huge_pages++;
			}
			pfn++;
		}
	}
}

static int filter_pte_range(pmd_t *pmd,
			    unsigned long addr,
			    unsigned long end,
			    struct mm_walk *walk)
{
	pte_t *pte;

	if (pmd_large(*pmd)) {
		/* end - addr == 2M */
		filter_huge_pmd_entry(pmd, walk);
		return 0;
	}

	pte = pte_offset_map(pmd, addr);
	while (1) {
		filter_pte_entry(pte, walk);
		addr += PAGE_SIZE;
		if (addr == end)
			break;
		pte++;
	}
	pte_unmap(pte);

	return 0;
}

/* Unset PFNs of pages belonging to userland process which doesn't run in
 * capsule.
 *
 * We could think by intuition that all the mapped PFNs are backed with page
 * structures. This isn't true for VM_PFNMAP vma's and hugetlb vma's. Thus we
 * can't walk directly through each process page tables, VMA's must be used...
 * Hopefuly, this is exactly what walk_page_range() does.
 *
 * Nevertheless, mm_walk.pte_entry can't be used, because interrupts may be
 * disabled by walk_pmd_range() if mm_walk.pte_entry is set: spin_unlock()
 * (which disables interrupts) is called by split_huge_page_pmd(). This is why
 * PMDs are walked by filter_pte_range().
 *
 * At the moment, only pages used by a process but not shared with any other
 * process is removed.
 *
 * Returns the number of PFNs which were unset. */
static unsigned long filter_userland_pfns(struct list_head *orig_bitmaps)
{
	struct task_struct *g, *p, *snap[3];
	struct filter_pfn filter_pfn;
	struct vm_area_struct *vma;
	unsigned long start, end;
	struct mm_struct *mm;
	struct mm_walk walk;
	int ret;

	filter_pfn.bitmaps = orig_bitmaps;
	filter_pfn.huge_pages = 0;
	filter_pfn.npages = 0;

	memset(&walk, 0, sizeof(walk));
	walk.pmd_entry = filter_pte_range;
	walk.private = &filter_pfn;

	/* snapshot process and its parents */
	snap[0] = current;
	snap[1] = current->parent;
	snap[2] = (current->parent != NULL) ? current->parent->parent : NULL;

	do_each_thread(g, p) {
		/* memory of userland process running in capsule is always
		 * kept */
		if (keep_userland_process(p) ||
		    p == snap[0] || p == snap[1] || p == snap[2])
			continue;

		/* Some lock functions can't be called because they might sleep.
		 * It doesn't matter since irq are disabled during snapshot. */
		//mm = get_task_mm(p);
		mm = p->mm;
		if (mm == NULL)
			continue;

		/* down_read can't be called because it might sleep */
		//down_read(&mm->mmap_sem);
		walk.mm = mm;
		for (vma = mm->mmap; vma != NULL; vma = vma->vm_next) {
			start = vma->vm_start;
			end = vma->vm_end;
			ret = _walk_page_range(start, end, &walk);
		}
		//up_read(&mm->mmap_sem);

		/* mmput can't be called because it might sleep */
		//mmput(mm);
	} while_each_thread(g, p);

	hv_dbg("filtered: %ldM (%ldM of huge pages)",
	       filter_pfn.npages * PAGE_SIZE / (1024 * 1024),
	       filter_pfn.huge_pages * PAGE_SIZE / (1024 * 1024));

	return filter_pfn.npages;
}

static err_t memory_snapshot(struct vcpu *vcpu)
{
	struct list_head orig_bitmaps, copy_bitmaps;
	unsigned int npages;
	err_t err;

	hv_info("snapshot start");

	INIT_LIST_HEAD(&orig_bitmaps);
	INIT_LIST_HEAD(&copy_bitmaps);

	err = create_process_bitmap(current);
	if (err != SUCCESS)
		goto out;

	err = count_data_pages(&orig_bitmaps, &npages);
	if (err != SUCCESS)
		goto out_free_process_bitmap;

	npages -= filter_userland_pfns(&orig_bitmaps);
	hv_info("snapshot: %d pages required (%ldM)",
		npages, (npages * PAGE_SIZE) / (1024 * 1024));

	err = alloc_copy_pages(&copy_bitmaps, npages);
	if (err != SUCCESS)
		goto out_free_process_bitmap;

	err = create_snapshot(vcpu, &orig_bitmaps, &copy_bitmaps, npages);

	free_snapshot_bitmaps(&orig_bitmaps);
	free_snapshot_bitmaps(&copy_bitmaps);

	hv_info("snapshot end");

out_free_process_bitmap:
	if (err != SUCCESS)
		free_process_bitmap();
out:
	return err;
}

err_t shrink_memory(void)
{
	struct list_head tmp_bitmaps;
	unsigned int npages;
	err_t err;

	INIT_LIST_HEAD(&tmp_bitmaps);

	err = count_data_pages(&tmp_bitmaps, &npages);
	if (err != SUCCESS)
		return ERROR_SHRINK_MEMORY;

	free_snapshot_bitmaps(&tmp_bitmaps);

	_shrink_all_memory(npages);

	return SUCCESS;
}

/* get physical address of params pages in snapshot process */
static err_t get_params_gpa(unsigned long params_uaddr)
{
	unsigned long cr3, pfn, uaddr;
	int i;

	cr3 = cpu_vmcs_readl(GUEST_CR3);

	params_uaddr = params_uaddr;

	for (i = 0; i < snapshot.params_npages; i++) {
		uaddr = params_uaddr + PAGE_SIZE * i;
		pfn = uaddr_pfn(cr3, uaddr);
		if (pfn == 0)
			return ERROR_SNAP_ARGV_GPA;

		snapshot.params_gpa[i] = pfn << PAGE_SHIFT;
	}

	return SUCCESS;
}

err_t do_snapshot(struct vcpu *vcpu, unsigned long params_uaddr,
		  unsigned int params_size)
{
	unsigned int npages;
	err_t err;

	if (snapshot_done)
		return ERROR_SNAP_ALREADY_DONE;

	if (atomic_read(&vmm.module_being_removed) == 1)
		return ERROR_SNAP_MODULE_BEING_REMOVED;

	/* XXX: protect with get_online_cpus() / put_online_cpus(). Requires
	 * that capsule calls put_online_cpus() in guest_init(). */
	if (num_online_cpus() != 1)
		return ERROR_SNAP_CPUS_ONLINE;

	npages = params_size / PAGE_SIZE;
	if (params_size % PAGE_SIZE != 0)
		npages++;

	if (npages > MAX_PARAMS_NPAGES)
		return ERROR_SNAP_PARAMS_NPAGES_TOO_LARGE;

	/* increase mm_users in guest to avoid mmput(old_mm) */
	atomic_inc(&current->mm->mm_users);
	err = memory_snapshot(vcpu);
	atomic_dec(&current->mm->mm_users);
	if (err != SUCCESS)
		return err;

	hv_dbg("memory snapshot: done");

	err = fix_snapshot();
	if (err != SUCCESS) {
		delete_snapshot();
		return err;
	}

	snapshot.params_npages = npages;
	err = get_params_gpa(params_uaddr);
	if (err != SUCCESS) {
		delete_snapshot();
		return err;
	}

	init_vmcs_capsule_template();

	return SUCCESS;
}
