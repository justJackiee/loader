; syscalls_asm.asm
; NASM x64 assembly stub for Hell's Gate
; wSSN is defined in syscalls.c; we reference it as extern here

default rel

[SECTION .text]
	global HellDescent
	extern wSSN

HellDescent:
	mov r10, rcx          ; NT syscall convention: R10 = first arg (RCX is clobbered by syscall)
	mov eax, dword [wSSN] ; Load the SSN into EAX
	syscall               ; Transition to kernel mode
	ret
