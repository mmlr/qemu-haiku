/*
 * Regression tests for KQEMU
 * (c) 2005-2007 Fabrice Bellard
 */
#include "kqemutest.h"

        .globl _start
        
_start:
        .quad kernel_exceptions
        .quad kernel_syscall
        .quad kernel_idt
        .quad kernel_gdt
        .quad kernel_ldt
        .quad kernel_lstar
        .quad kernel_stack
        
#define EXCEPTION_VECTOR(n, push_0) \
        .align 32 ; \
        push_0 ; \
        push %rax ; \
        mov $0x ## n, %rax ; \
        jmp kernel_exception

        .align 32
kernel_exceptions:
        
EXCEPTION_VECTOR(00, pushq $0)
EXCEPTION_VECTOR(01, pushq $0)
EXCEPTION_VECTOR(02, pushq $0)
EXCEPTION_VECTOR(03, pushq $0)
EXCEPTION_VECTOR(04, pushq $0)
EXCEPTION_VECTOR(05, pushq $0)
EXCEPTION_VECTOR(06, pushq $0)
EXCEPTION_VECTOR(07, pushq $0)
EXCEPTION_VECTOR(08, )
EXCEPTION_VECTOR(09, pushq $0)
EXCEPTION_VECTOR(0a, )
EXCEPTION_VECTOR(0b, )
EXCEPTION_VECTOR(0c, )
EXCEPTION_VECTOR(0d, )
EXCEPTION_VECTOR(0e, )
EXCEPTION_VECTOR(0f, pushq $0)
EXCEPTION_VECTOR(10, pushq $0)
EXCEPTION_VECTOR(11, )
EXCEPTION_VECTOR(12, pushq $0)
EXCEPTION_VECTOR(13, pushq $0)

        .align 32
kernel_syscall:
        pushq $0
        pushq %rax
        cld
        push %rbp
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %rbx
        push %r8
        push %r9
        push %r10
        push %r11
        push %r12
        push %r13
        push %r14
        push %r15

        call do_syscall

        cli
        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %r11
        pop %r10
        pop %r9
        pop %r8
        pop %rbx
        pop %rcx
        pop %rdx
        pop %rsi
        pop %rdi
        pop %rbp
        add $16, %rsp
        iretq

kernel_lstar:
        movq %rsp, kernel_stack + KERNEL_STACK_SIZE - (2 * 8)
        movq $kernel_stack + KERNEL_STACK_SIZE - (5 * 8), %rsp
        movq %r11, kernel_stack + KERNEL_STACK_SIZE - (3 * 8)
        movq %rcx, kernel_stack + KERNEL_STACK_SIZE - (5 * 8)
        pushq $0
        pushq %rax
        cld
        push %rbp
        push %rdi
        push %rsi
        push %rdx
        push %rcx /* eip */
        push %rbx
        push %r8
        push %r9
        push %r10
        push %r11 /* eflags */
        push %r12
        push %r13
        push %r14
        push %r15

        call do_syscall_lstar

        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %r11
        pop %r10
        pop %r9
        pop %r8
        pop %rbx
        pop %rcx
        pop %rdx
        pop %rsi
        pop %rdi
        pop %rbp
        movq kernel_stack + KERNEL_STACK_SIZE - (3 * 8), %r11
        movq kernel_stack + KERNEL_STACK_SIZE - (5 * 8), %rcx
        movq kernel_stack + KERNEL_STACK_SIZE - (2 * 8), %rsp
        sysretq
        
kernel_exception:
#if 0
        movq 8(%rsp), %r8
        movq 16(%rsp), %r9
        movq 24(%rsp), %r10
        movq 40(%rsp), %r11
        movq 48(%rsp), %r12
        hlt
#endif
        cld
        push %rbp
        push %rdi
        push %rsi
        push %rdx
        push %rcx
        push %rbx
        push %r8
        push %r9
        push %r10
        push %r11
        push %r12
        push %r13
        push %r14
        push %r15

        movq %rax, %rdi
        call do_exception
        
exception_return:
        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %r11
        pop %r10
        pop %r9
        pop %r8
        pop %rbx
        pop %rcx
        pop %rdx
        pop %rsi
        pop %rdi
        pop %rbp
        pop %rax
        add $8, %rsp
        iretq
