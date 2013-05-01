/*
 * Regression tests for KQEMU
 * (c) 2005-2007 Fabrice Bellard
 */
#include "kqemutest.h"

        .globl _start
        
_start:
        .long kernel_exceptions
        .long 0               
        .long kernel_syscall
        .long 0               
        .long kernel_idt
        .long 0               
        .long kernel_gdt
        .long 0               
        .long kernel_ldt
        .long 0               
        .long 0 /* kernel_lstar */
        .long 0
        .long kernel_stack
        .long 0
        
#define EXCEPTION_VECTOR(n, push_0) \
        .align 32 ; \
        push_0 ; \
        pushl %eax ; \
        movl $0x ## n, %eax ; \
        jmp kernel_exception

        .align 32
kernel_exceptions:
        
EXCEPTION_VECTOR(00, pushl $0)
EXCEPTION_VECTOR(01, pushl $0)
EXCEPTION_VECTOR(02, pushl $0)
EXCEPTION_VECTOR(03, pushl $0)
EXCEPTION_VECTOR(04, pushl $0)
EXCEPTION_VECTOR(05, pushl $0)
EXCEPTION_VECTOR(06, pushl $0)
EXCEPTION_VECTOR(07, pushl $0)
EXCEPTION_VECTOR(08, )
EXCEPTION_VECTOR(09, pushl $0)
EXCEPTION_VECTOR(0a, )
EXCEPTION_VECTOR(0b, )
EXCEPTION_VECTOR(0c, )
EXCEPTION_VECTOR(0d, )
EXCEPTION_VECTOR(0e, )
EXCEPTION_VECTOR(0f, pushl $0)
EXCEPTION_VECTOR(10, pushl $0)
EXCEPTION_VECTOR(11, )
EXCEPTION_VECTOR(12, pushl $0)
EXCEPTION_VECTOR(13, pushl $0)

        .align 32
kernel_syscall:
        pushl $0
        pushl %eax
        cld
        pushl %es
        pushl %ds
        pushl %ebp
        pushl %edi
        pushl %esi
        pushl %edx
        pushl %ecx
        pushl %ebx

        movl $KERNEL_DS, %ebp
        movl %ebp, %ds
        movl %ebp, %es

        call do_syscall

//        cli
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %ds
        popl %es
        addl $8, %esp
        iret

kernel_exception:
        cld
        pushl %es
        pushl %ds
        pushl %ebp
        pushl %edi
        pushl %esi
        pushl %edx
        pushl %ecx
        pushl %ebx

        movl $KERNEL_DS, %ebp
        movl %ebp, %ds
        movl %ebp, %es

        pushl %eax
        call do_exception
        addl $4, %esp
        
        popl %ebx
        popl %ecx
        popl %edx
        popl %esi
        popl %edi
        popl %ebp
        popl %ds
        popl %es
        popl %eax
        addl $4, %esp
        iret
