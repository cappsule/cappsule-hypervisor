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
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/eventfd.h>
#include <uapi/linux/uio.h>
#include <asm/perf_event.h>
#include <asm/syscalls.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <linux/binfmts.h>
#include <linux/hugetlb.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <asm/vmx.h>

#include "host/vmx.h"
#include "common/log.h"
#include "shadow_process.h"
#include "common/exec_policy.h"
#include "common/memory.h"
#include "common/params.h"
#include "host/capsule.h"
#include "host/snapshot.h"
#include "host/symbols.h"
#include "host/time.h"
#include "host/vmcs.h"
#include "host/transition.h"
#include "host/memory.h"
#include "host/vmm.h"
#include "host/xchan.h"
#include "trusted/channel.h"
#include "trusted/time.h"
#include "cuapi/common/kill_msg.h"

struct eptp_bits {
	unsigned memory_type	:3;	/* 0: UC uncacheable, 6: WB writeback */
	unsigned pagewalk_len	:3;	/* value 1 less than EPT page-walk length */
	unsigned dirty		:1;	/* dirty flag */
	unsigned reserved1	:5;
	unsigned long pgd	:40;	/* bit N-1:12 of the physical address of the 4-KByte aligned EPT PML4 table, N=40 */
	unsigned reserved2	:12;
} __attribute__((__packed__));

union eptp {
	struct eptp_bits bits;
	__u64 value;
};

static DEFINE_RWLOCK(capsules_lock);	/* protect following variables */
static LIST_HEAD(capsules);
static unsigned int ncapsule = 0;
static unsigned long id_bitmap[MAX_CAPSULE / BITS_PER_LONG + 1] = {};


/* increment capsule->refcount */
struct capsule *get_capsule_from_id(unsigned int id)
{
	struct capsule *capsule, *res;

	res = NULL;
	read_lock(&capsules_lock);
	list_for_each_entry(capsule, &capsules, list) {
		if (capsule->id == id) {
			if (kref_get_unless_zero(&capsule->refcount))
				res = capsule;
			break;
		}
	}
	read_unlock(&capsules_lock);

	return res;
}

/* doesn't increment capsule->refcount */
struct capsule *capsule_from_id(unsigned int id)
{
	struct capsule *capsule, *res;

	res = NULL;
	read_lock(&capsules_lock);
	list_for_each_entry(capsule, &capsules, list) {
		if (capsule->id == id) {
			res = capsule;
			break;
		}
	}
	read_unlock(&capsules_lock);

	return res;
}

int get_capsule_ids(unsigned int *ids, size_t size)
{
	int res = 0;
	struct capsule *capsule;

	read_lock(&capsules_lock);
	list_for_each_entry(capsule, &capsules, list) {
		if (res * sizeof(*ids) >= size) {
			res = -ENOMEM;
			break;
		}

		ids[res++] = capsule->id;
	}
	read_unlock(&capsules_lock);
	return res;
}

/* Get an id which is not already in use. */
static int get_free_id(void)
{
	static unsigned int next_id = 0;	/* static variable */
	unsigned int id;

	write_lock(&capsules_lock);

	if (ncapsule == MAX_CAPSULE) {
		write_unlock(&capsules_lock);
		return -1;
	}

	id = find_next_zero_bit(id_bitmap, MAX_CAPSULE, next_id);
	if (id == MAX_CAPSULE)
		id = find_next_zero_bit(id_bitmap, MAX_CAPSULE, 0);

	set_bit(id, id_bitmap);
	next_id = (id + 1) % MAX_CAPSULE;
	ncapsule++;

	write_unlock(&capsules_lock);

	return id;
}

/* must be called with capsules_lock held */
static void release_id(unsigned int id)
{
	ncapsule--;
	clear_bit(id, id_bitmap);
}

static void release_id_lock(unsigned int id)
{
	write_lock(&capsules_lock);
	release_id(id);
	write_unlock(&capsules_lock);
}

static void init_capsule_memory(struct guest_memory *memory,
				struct guest_mem *first)
{
	memory->first = first;
	memory->curr = first;
	memory->npages = 0;
}

err_t create_capsule(struct vcpu *vcpu, struct capsule_params *params,
		     struct shadow_process *shadowp)
{
	struct guest_mem *alloc_mem, *pt_mem;
	unsigned long arg, guest_msr;
	struct capsule *capsule;
	union ept_pgd *ept_pgd;
	union eptp eptp;
	err_t err;
	int id;

	if (atomic_read(&vmm.module_being_removed) == 1)
		return ERROR_CREATION_MODULE_BEING_REMOVED;

	id = get_free_id();
	if (id == -1)
		return ERROR_CREATION_MAX_CAPSULE;

	capsule = kzalloc(sizeof(*capsule), GFP_ATOMIC);
	if (capsule == NULL) {
		err = ERROR_CREATION_ALLOC_FAILED;
		goto error_alloc_capsule;
	}

	ept_pgd = (union ept_pgd *)get_zeroed_page(GFP_ATOMIC);
	if (ept_pgd == NULL) {
		err = ERROR_CREATION_ALLOC_FAILED;
		goto error_alloc_pgd;
	}

	alloc_mem = alloc_guest_mem();
	if (alloc_mem == NULL) {
		err = ERROR_CREATION_ALLOC_FAILED;
		goto error_alloc_guest_mem;
	}

	pt_mem = alloc_guest_mem();
	if (pt_mem == NULL) {
		err = ERROR_CREATION_ALLOC_FAILED;
		goto error_alloc_pt_mem;
	}

	/* EPT_POINTER */
	eptp.value = 0;
	eptp.bits.memory_type = 6;
	eptp.bits.pagewalk_len = 3;
	eptp.bits.pgd = __pa(ept_pgd) >> PAGE_SHIFT;

	capsule->fault_address = 0;
	capsule->nfault = 0;

	/* VM_ENTRY_MSR_LOAD_ADDR and VM_EXIT_MSR_STORE_ADDR */
	memcpy(capsule->ctx.autoload_msr, snapshot.ctx.autoload_msr,
		sizeof(capsule->ctx.autoload_msr));
	guest_msr = __pa(capsule->ctx.autoload_msr);
	err = create_capsule_vmcs(&capsule->vmcs,
				  vcpu->trusted_template,
				  eptp.value,
				  guest_msr);
	if (err != SUCCESS)
		goto error_vmcs;

	/* create_vmcs_from_template() set current vmcs to capsule's; revert to
	 * trusted vmcs */
	err = load_trusted_vmcs(vcpu);
	if (err != SUCCESS)
		panic("failed to load trusted vmcs");

	kref_init(&capsule->refcount);
	capsule->vcpu = vcpu;
	capsule->id = id;
	capsule->ept_pgd = ept_pgd;

	capsule->flags = 0;

	/* shadowp->refcount = 2 (hypervisor and shadow process) */
	kref_init(&shadowp->refcount);
	kref_get(&shadowp->refcount);

	capsule->params = params;

	shadowp->capsule_id = id;
	atomic_set(&shadowp->timer_set, 0);
	arg = (unsigned long)shadowp;
	tasklet_init(&shadowp->tasklet, tasklet_wake_up_shadowp, arg);
	shadowp->woken_up = false;
	shadowp->capsule_killed = 0;
	shadowp->kill_reason = MAX_KILL_REASON;
	shadowp->daemon = params->daemon;
	capsule->shadowp = shadowp;

	capsule->fpu_used = 0;

	/* memory_limit is given in MB */
	capsule->memory_max_npages = \
		(params->memory_limit * 1024 * 1024) / PAGE_SIZE;

	init_capsule_memory(&capsule->pt_mem, pt_mem);
	init_capsule_memory(&capsule->alloc_mem, alloc_mem);

	capsule->intr.bitmap = 0;

	init_clock_timer(capsule);

	memset(&capsule->xchan.events, 0, sizeof(capsule->xchan.events));

	write_lock(&capsules_lock);
	list_add(&capsule->list, &capsules);
	write_unlock(&capsules_lock);

	cpsl_info(capsule->id, "process encapsulated");

	return SUCCESS;

error_vmcs:
	free_guest_mem(pt_mem);
error_alloc_pt_mem:
	free_guest_mem(alloc_mem);
error_alloc_guest_mem:
	free_page((unsigned long)ept_pgd);
error_alloc_pgd:
	kfree(capsule);
error_alloc_capsule:
	release_id_lock(id);
	return err;
}

static void decapsulate(struct kref *kref)
{
	struct capsule *capsule;
	unsigned int id;
	int i;

	capsule = container_of(kref, struct capsule, refcount);
	id = capsule->id;

	for (i = 0; i < ARRAY_SIZE(capsule->xchan.events); i++) {
		if (capsule->xchan.events[i] != NULL) {
			eventfd_ctx_put(capsule->xchan.events[i]);
			capsule->xchan.events[i] = NULL;
		}
	}

	free_capsule_mem(capsule);

	kref_put(&capsule->shadowp->refcount, free_shadowp);

	kfree(capsule->params->info_pages);
	kfree(capsule->params);

	/* remove capsule from capsules list */
	write_lock(&capsules_lock);
	list_del(&capsule->list);
	release_id(capsule->id);
	write_unlock(&capsules_lock);

	poison(capsule, 0x90, sizeof(*capsule));
	kfree(capsule);

	cpsl_info(id, "process decapsulated");
}

/* Must only be called if guest is:
 *  - a capsule,
 *  - a shadow process. */
void kill_s(struct capsule *capsule, kill_t reason)
{
	unsigned long rip;
	struct vcpu *vcpu;
	struct regs regs;
	unsigned int id;
	int fpu_used;

	id = capsule->id;
	vcpu = capsule->vcpu;

	/* force shadow process to exit if it didn't receive a fatal signal */
	if (reason != KILL_VMCALL_FATAL_SIGNAL)
		capsule->shadowp->capsule_killed = 1;

	hrtimer_cancel(&capsule->clock_timer);

	rip = cpu_vmcs_readl(GUEST_RIP);
	cpu_vmcs_clear(capsule->vmcs);
	free_page((unsigned long)capsule->vmcs);
	capsule->vmcs = NULL;
	capsule->shadowp->kill_reason = reason;

	fpu_used = capsule->fpu_used;

	capsule->flags |= CPSL_EXITED;
	kref_put(&capsule->refcount, decapsulate);

	/* capsule has been freed. don't use it anymore */

	cpsl_info(id, "kill capsule (rip=%016lx, reason: " KILL_MSG_FMT ")",
		  rip, kill_msg(reason));

	if (vcpu->guest == GUEST_TRUSTED) {
		memcpy(&regs, &vcpu->regs, sizeof(regs));
	} else {
		restore_context(&vcpu->trusted_ctx, &regs);
		if (load_trusted_vmcs(vcpu) != SUCCESS)
			panic("failed to load trusted vmcs");
	}

	/* Don't know if it's necessary, since capsule FPU registers will not be
	 * used anymore. Nevertheless, trusted guest kernel mights want to know
	 * that FPU registers were modified. */
	if (fpu_used)
		force_shadow_process_fpu_usage();

	cpu_vmx_resume(&regs);
}

void kill(struct vcpu *vcpu, kill_t reason)
{
	kill_s(current_capsule(vcpu), reason);
}

/* Increment shadow process task usage and return task struct. Callee is
 * responsible of decrementing it. */
struct task_struct *get_shadow_process_task(unsigned int capsule_id)
{
	struct task_struct *task;
	struct capsule *capsule;

	capsule = get_capsule_from_id(capsule_id);
	if (capsule == NULL) {
		tg_err("%s: can't find capsule %d", __func__, capsule_id);
		return NULL;
	}

	task = capsule->shadowp->task;
	get_task_struct(task);

	put_capsule(capsule);

	return task;
}

struct task_struct *get_first_shadow_process_task(bool *woken_up)
{
	struct task_struct *task;
	struct capsule *capsule;

	read_lock(&capsules_lock);
	if (list_empty(&capsules)) {
		task = NULL;
	} else {
		capsule = list_first_entry(&capsules, struct capsule, list);
		task = capsule->shadowp->task;
		get_task_struct(task);
		*woken_up = capsule->shadowp->woken_up;
	}
	read_unlock(&capsules_lock);

	return task;
}

/* all general purpose registers except RIP and RSP are invalid  */
static noinline void launch_failed(void)
{
	struct capsule *capsule;
	__u32 vm_instr_error;
	struct vcpu *vcpu;
	unsigned int cpu;

	cpu = smp_processor_id();
	vcpu = &vmm.vcpus[cpu];
	capsule = current_capsule(vcpu);

	vm_instr_error = cpu_vmcs_read32(VM_INSTRUCTION_ERROR);
	cpsl_err(capsule->id, "capsule vmlaunch failed (error: %d)",
		 vm_instr_error);

	/* handling vmlaunch failure isn't more complicated than calling
	 * kill() because current VMCS is capsule's */
	kill(vcpu, KILL_VMLAUNCH_FAILED);
}

void launch_capsule(struct vcpu *vcpu, struct capsule *capsule)
{
	struct regs regs;

	if (load_capsule_vmcs(vcpu, capsule) != SUCCESS)
		kill_s(capsule, KILL_SWITCH_VM_TO_CAPSULE);

	/* save trusted guest registers */
	save_context(&vcpu->trusted_ctx, &vcpu->regs);

	memcpy(&regs, &snapshot.ctx.regs, sizeof(regs));

	capsule->stats.nr_switches = 1;
	capsule->last_schedule = ktime_get();

	hv_info("launch_capsule %d on cpu %d", capsule->id, smp_processor_id());
	asm volatile (
		"mov %c[rax](%%rcx), %%rax\n"
		"mov %c[rdx](%%rcx), %%rdx\n"
		"mov %c[rbx](%%rcx), %%rbx\n"
		"mov %c[rbp](%%rcx), %%rbp\n"
		"mov %c[rsi](%%rcx), %%rsi\n"
		"mov %c[rdi](%%rcx), %%rdi\n"
		"mov %c[r8](%%rcx),  %%r8\n"
		"mov %c[r9](%%rcx),  %%r9\n"
		"mov %c[r10](%%rcx), %%r10\n"
		"mov %c[r11](%%rcx), %%r11\n"
		"mov %c[r12](%%rcx), %%r12\n"
		"mov %c[r13](%%rcx), %%r13\n"
		"mov %c[r14](%%rcx), %%r14\n"
		"mov %c[r15](%%rcx), %%r15\n"
		"mov %c[rcx](%%rcx), %%rcx\n"
		ASM_VMX_VMLAUNCH "\n"
		: : "c"(&regs),
		  [rax]"i"(offsetof(struct regs, rax)),
		  [rcx]"i"(offsetof(struct regs, rcx)),
		  [rdx]"i"(offsetof(struct regs, rdx)),
		  [rbx]"i"(offsetof(struct regs, rbx)),
		  [rbp]"i"(offsetof(struct regs, rbp)),
		  [rsi]"i"(offsetof(struct regs, rsi)),
		  [rdi]"i"(offsetof(struct regs, rdi)),
		  [r8]"i"(offsetof(struct regs, r8)),
		  [r9]"i"(offsetof(struct regs, r9)),
		  [r10]"i"(offsetof(struct regs, r10)),
		  [r11]"i"(offsetof(struct regs, r11)),
		  [r12]"i"(offsetof(struct regs, r12)),
		  [r13]"i"(offsetof(struct regs, r13)),
		  [r14]"i"(offsetof(struct regs, r14)),
		  [r15]"i"(offsetof(struct regs, r15))
		: "cc", "memory");

	/* never reached, except vmlaunch failed */
	launch_failed();
}

void put_capsule(struct capsule *capsule)
{
	kref_put(&capsule->refcount, decapsulate);
}
