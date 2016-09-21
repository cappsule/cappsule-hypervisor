#include <linux/linkage.h>

		.code64

ENTRY(fake_return_stub)
		pop		%rcx
		pop		%r11
		pop		%r10
		pop		%r9
		pop		%r8
		pop		%rax
		pop		%rdx
		pop		%rsi
		pop		%rdi

		/* This stub returns right after a vmcall instruction. Clear ZF and CF
		 * otherwise guest may think that vmcall failed. */
		test	%rsp, %rsp

		ret
END(fake_return_stub)

ENTRY(guest_schedule_end_stub)
		call	guest_schedule_end
		test	%rax, %rax
		jne		1f
		ret
1:		/* call_schedule_again */
		jmp		*___schedule
END(guest_schedule_end_stub)

ENTRY(guest_schedule_tail_end_stub)
		call	guest_schedule_tail_end
		ret
END(guest_schedule_tail_end_stub)

ENTRY(guest_do_exit_stub)
		push	%rax
		push	%rdi
		call	guest_do_exit
		pop		%rdi
		pop		%rax
		jmp		*%rax
END(guest_do_exit_stub)

ENTRY(guest_prepare_binprm_stub)
		/* hypervisor moved hijacked rip into rax */
		push	%rax
		/* save rdi */
		push	%rdi
		/* call guest_prepare_binprm */
		call	guest_prepare_binprm
		pop		%rdi
		test	%eax, %eax
		jne		1f
		/* jmp to hijacked rip */
		ret
1:		/* execve_forbidden */
		/* don't restore rax: keep return value from guest_prepare_binprm */
		pop		%rdi
		/* hijacked rip was pushed on stack, return to callee */
		ret
END(guest_prepare_binprm_stub)

ENTRY(process_one_work_stub)
		/* save return address given by the hypervisor */
		push	%rax
		/* save arguments */
		push	%rdi
		push	%rsi
		call	filter_workqueue
		/* restore arguments */
		pop		%rsi
		pop		%rdi
		/* get return address */
		pop		%rax
		/* return to process_one_work */
		jmp		*%rax
END(process_one_work_stub)
