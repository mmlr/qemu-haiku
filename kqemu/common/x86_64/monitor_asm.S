/*
 * KQEMU
 *
 * Copyright (C) 2004-2008 Fabrice Bellard
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
/* entry / exit from monitor code */
#include "monitor_def.h"
#include "kqemu_int.h"

#define SEG_EXCEPTION(label) \
    .section "seg_ex_table", "a" ; \
    .align 8 ; \
    .quad label ; \
    .previous

/* unsigned long __exec_binary(unsigned long *eflags, int op, 
                               unsigned long a, unsigned long b) */
                        
#define USE_PUSHF

        .globl ASM_NAME(exec_binary)
ASM_NAME(exec_binary):
        shl $4, %rsi
        lea exec_binary_table(%rip), %rax
        add %rax, %rsi
        
        /* set flags */
#ifdef USE_PUSHF
        movl (%rdi), %r8d
        andl $0x8d5, %r8d
        pushf
        pop %rax
        andl $~0x8d5, %eax
        orl %r8d, %eax
        push %rax
        popf
#else
        movb (%rdi), %ah
        .byte 0x9e /* sahf */
#endif
        jmp *%rsi
exec_binary_ret:
        /* read flags */
#ifdef USE_PUSHF
        pushf
        pop %rax
        movl (%rdi), %r8d
        andl $0x8d5, %eax
        andl $~0x8d5, %r8d
        orl %eax, %r8d
        movl %r8d, (%rdi)
#else
        .byte 0x9f /* lahf */
        seto %al
        movl (%rdi), %ecx
        movb %ah, %cl
        shll $3, %eax
        andl $~0x0800, %ecx
        orb %al, %ch
        movl %ecx, (%rdi)
#endif
        mov %rdx, %rax
        retq
        
#define ARITH_OP(s...) \
        .align 16 ; \
        s ; \
        jmp exec_binary_ret

#define ARITH_OP4(op) \
        ARITH_OP(op %cl, %dl) ; \
        ARITH_OP(op %cx, %dx) ; \
        ARITH_OP(op %ecx, %edx) ; \
        ARITH_OP(op %rcx, %rdx)

#define SHIFT_OP4(op) \
        ARITH_OP(op %cl, %dl) ; \
        ARITH_OP(op %cl, %dx) ; \
        ARITH_OP(op %cl, %edx) ; \
        ARITH_OP(op %cl, %rdx)

#define BT_OP4(op) \
        ARITH_OP(nop) ; \
        ARITH_OP(op %cx, %dx) ; \
        ARITH_OP(op %ecx, %edx) ; \
        ARITH_OP(op %rcx, %rdx)

        .align 16
exec_binary_table:
        ARITH_OP4(add)
        ARITH_OP4(or)
        ARITH_OP4(adc)
        ARITH_OP4(sbb)
        ARITH_OP4(and)
        ARITH_OP4(sub)
        ARITH_OP4(xor)
        ARITH_OP4(cmp)

        ARITH_OP(inc %dl)
        ARITH_OP(inc %dx)
        ARITH_OP(inc %edx)
        ARITH_OP(inc %rdx)

        ARITH_OP(dec %dl)
        ARITH_OP(dec %dx)
        ARITH_OP(dec %edx)
        ARITH_OP(dec %rdx)

        SHIFT_OP4(rol)
        SHIFT_OP4(ror)
        SHIFT_OP4(rcl)
        SHIFT_OP4(rcr)
        SHIFT_OP4(shl)
        SHIFT_OP4(shr)
        SHIFT_OP4(shl)
        SHIFT_OP4(sar)
        
        BT_OP4(bt)
        BT_OP4(bts)
        BT_OP4(btr)
        BT_OP4(btc)

        BT_OP4(bsf)
        BT_OP4(bsr)

/* switch to user mode */
        .globl ASM_NAME(goto_user)
ASM_NAME(goto_user):
        mov %rdi, %rbx
        mov %rsi, %rsp
        jmp exception_return

        .globl ASM_NAME(start_func)
ASM_NAME(start_func):
        movq %rdi, %rax
        movq %rsi, %rdi
        movq %rdx, %rsp
        pushq $0   /* invalid return address */
        jmp *%rax
        
/* exception handling */
__monitor_exception:
        cld
        push %r14
        push %r13
        push %r12
        push %r11
        push %r10
        push %r9
        push %r8
        push %rdi
        push %rsi
        push %rbp
        push $0 /* place holder for %rsp */
        push %rbx
        push %rdx
        push %rcx
        push %rax

        /* put esp at the right place */
        movq 20 * 8(%rsp), %rax
        movq %rax, 4 * 8(%rsp)

        lea _end(%rip), %rbx
        
        /* modify SS to restore null value */
        movw KQEMU_STATE_monitor_ss_null_sel(%rbx), %ax
        cmpw %ax, 21 * 8(%rsp)
        jne 1f
        movw $3, 21 * 8(%rsp)
1:
                
        mov %rbx, %rdi
        call *%r15

exception_return:
        /* do not restore regs1.esp if returning to kernel code */
        testl $3, 18 * 8(%rsp)
        jz 1f

        /* move %rsp for iret */
        movq 4 * 8(%rsp), %rax
        movq %rax, 20 * 8(%rsp)

        /* modify SS to remove null value */
        cmpw $3, 21 * 8(%rsp)
        jne 1f
        movw KQEMU_STATE_monitor_ss_null_sel(%rbx), %ax
        movw %ax, 21 * 8(%rsp)
1:
                
        lar 18 * 8(%rsp), %eax /* CS.L bit test */
        testl $0x00200000, %eax
        jnz 1f
        lar 21 * 8(%rsp), %eax /* SS.B bit test */
        testl $0x00400000, %eax
        jz exception_return16
1:
        pop %rax
        pop %rcx
        pop %rdx
        pop %rbx
        add $8, %rsp
        pop %rbp
        pop %rsi
        pop %rdi
        pop %r8
        pop %r9
        pop %r10
        pop %r11
        pop %r12
        pop %r13
        pop %r14
        pop %r15
        add $8, %rsp
1:
        iretq
        SEG_EXCEPTION(1b)

exception_return16:
        /* 16 bit ESP hack */

/* transform the return info for the 32 bit iret */
        movl 17 * 8(%rsp), %eax /* EIP */
        movl %eax, (22 * 8) + 4(%rsp)
        movl 18 * 8(%rsp), %eax /* CS */
        movl %eax, (22 * 8) + 8(%rsp)
        movl 19 * 8(%rsp), %eax /* EFLAGS */
        movl %eax, (22 * 8) + 12(%rsp)
        movl 20 * 8(%rsp), %eax /* ESP */
        movl %eax, (22 * 8) + 16(%rsp)
        movl 21 * 8(%rsp), %eax /* SS */
        movl %eax, (22 * 8) + 20(%rsp)

/* prepare the return to the 32 bit CPL=0 compatibility code */
        lea exception_return16_32(%rip), %rax /* EIP */
        movq %rax, 17 * 8(%rsp) 
        movw KQEMU_STATE_monitor_cs32_sel(%rbx), %ax /* CS32, RPL=0 */
        movw %ax, 18 * 8(%rsp)
        pushfq  /* EFLAGS */
        pop %rax
        movq %rax, 19 * 8(%rsp) 
        lea 22*8(%rsp), %rax /* ESP */
        movq %rax, 20 * 8(%rsp)
        movw KQEMU_STATE_monitor_ss16_sel(%rbx), %ax /* SS16 */
        movw %ax, 21 * 8(%rsp)
        
/* prepare the temporary ESP value */
        lea 22*8 + 4(%rsp), %rax
        movw %ax, 22 * 8(%rsp)
        movw (22 * 8) + 18(%rsp), %ax /* high 16 bits of ESP */
        movw %ax, 22 * 8 + 2(%rsp)

/* return */
        pop %rax
        pop %rcx
        pop %rdx
        pop %rbx
        add $8, %rsp
        pop %rbp
        pop %rsi
        pop %rdi
        pop %r8
        pop %r9
        pop %r10
        pop %r11
        pop %r12
        pop %r13
        pop %r14
        pop %r15
        add $8, %rsp
        iretq
exception_return16_32:
        /* warning: the following code is really 32 bit code */
        pop %rsp
1:
        iret
        SEG_EXCEPTION(1b)
        
#define EXCEPTION_VECTOR(n, push_0) \
        .align 16 ; \
        push_0 ; \
        push %r15 ; \
        lea ASM_NAME(kqemu_exception_ ## n)(%rip), %r15 ; \
        jmp __monitor_exception

/* hardware interrupts */
__monitor_interrupt:
        cld
        push %r15
        push %r14
        push %r13
        push %r12
        push %r11
        push %r10
        push %r9
        push %r8
        push %rdi
        push %rsi
        push %rbp
        push $0 /* place holder for %rsp */
        push %rbx
        push %rdx
        push %rcx
        push %rax
        
        /* put esp at the right place */
        movq 20 * 8(%rsp), %rax
        movq %rax, 4 * 8(%rsp)

        lea _end(%rip), %rbx

        /* modify SS to restore null value */
        movw KQEMU_STATE_monitor_ss_null_sel(%rbx), %ax
        cmpw %ax, 21 * 8(%rsp)
        jne 1f
        movw $3, 21 * 8(%rsp)
1:

        mov %rbx, %rdi
        call ASM_NAME(monitor_interrupt)

        jmp exception_return

#define IRQ(n) \
        .align 16               ; \
        push $n ; \
        jmp __monitor_interrupt   ; 

        .align 16
        .globl ASM_NAME(interrupt_table)
        
ASM_NAME(interrupt_table):                
        
EXCEPTION_VECTOR(00, push $0)
EXCEPTION_VECTOR(01, push $0)
IRQ(0x02) /* NMI */
EXCEPTION_VECTOR(03, push $0)
EXCEPTION_VECTOR(04, push $0)
EXCEPTION_VECTOR(05, push $0)
EXCEPTION_VECTOR(06, push $0)
EXCEPTION_VECTOR(07, push $0)
EXCEPTION_VECTOR(08, )
EXCEPTION_VECTOR(09, push $0)
EXCEPTION_VECTOR(0a, )
EXCEPTION_VECTOR(0b, )
EXCEPTION_VECTOR(0c, )
EXCEPTION_VECTOR(0d, )
EXCEPTION_VECTOR(0e, )
EXCEPTION_VECTOR(0f, push $0)
EXCEPTION_VECTOR(10, push $0)
EXCEPTION_VECTOR(11, )
EXCEPTION_VECTOR(12, push $0)
EXCEPTION_VECTOR(13, push $0)

DUP4(IRQ, 0x14)        
DUP4(IRQ, 0x18)        
DUP4(IRQ, 0x1c)        
DUP16(IRQ, 0x20)
DUP16(IRQ, 0x30)
DUP64(IRQ, 0x40)
DUP64(IRQ, 0x80)
DUP64(IRQ, 0xc0)

