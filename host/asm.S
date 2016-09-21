#include <linux/linkage.h>

		.code64

ENTRY(vm_exit_handler)
		push	%r15
		push	%r14
		push	%r13
		push	%r12
		push	%r11
		push	%r10
		push	%r9
		push	%r8
		push	%rdi
		push	%rsi
		push	%rbp
		push	%rbp	# %rsp
		push	%rbx
		push	%rdx
		push	%rcx
		push	%rax

		mov		%rsp, %rdi
		call	_vm_exit_handler

		pop		%rax
		pop		%rcx
		pop		%rdx
		pop		%rbx
		pop		%rbp	# %rsp
		pop		%rbp
		pop		%rsi
		pop		%rdi
		pop		%r8
		pop		%r9
		pop		%r10
		pop		%r11
		pop		%r12
		pop		%r13
		pop		%r14
		pop		%r15

		vmresume
		setna	%al
		test	%al, %al

		call	cpu_vmxerror_error
1:		/* vmresume_fail */
		jmp		1b
END(vm_exit_handler)
