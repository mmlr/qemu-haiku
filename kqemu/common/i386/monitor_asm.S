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

/* unsigned long exec_binary(unsigned long *eflags, int op, 
                             unsigned long a, unsigned long b) */
//#define USE_PUSHF
                
        .globl ASM_NAME(exec_binary)
ASM_NAME(exec_binary):
        pushl %ebx
        pushl %esi
        movl 12(%esp), %ebx

        /* insn address */
        movl 16(%esp), %esi
        shl $4, %esi
        call 1f
1:
        popl %edx
        addl $exec_binary_table - 1b, %edx
        addl %edx, %esi

#ifdef USE_PUSHF
        /* set flags */
        movl (%ebx), %edx
        andl $0x8d5, %edx
        pushf 
        pop %ecx
        andl $~0x8d5, %ecx
        orl %edx, %ecx
        pushl %ecx
        popf
#else
        movb (%ebx), %ah
        sahf
#endif
        movl 20(%esp), %edx
        movl 24(%esp), %ecx
        jmp *%esi
exec_binary_ret:
        /* read flags */
#ifdef USE_PUSHF
        movl %edx, %eax
        pushf
        pop %ecx
        andl $0x8d5, %ecx
        movl (%ebx), %edx
        andl $~0x8d5, %edx
        orl %ecx, %edx
        movl %edx, (%ebx)
#else
        lahf
        seto %al
        movl (%ebx), %ecx
        movb %ah, %cl
        shll $3, %eax
        andl $~0x0800, %ecx
        orb %al, %ch
        movl %ecx, (%ebx)
        movl %edx, %eax
#endif
        popl %esi
        popl %ebx
        ret
        
#define ARITH_OP(s...) \
        .align 16 ; \
        s ; \
        jmp exec_binary_ret

#define ARITH_OP4(op) \
        ARITH_OP(op %cl, %dl) ; \
        ARITH_OP(op %cx, %dx) ; \
        ARITH_OP(op %ecx, %edx) ; \
        ARITH_OP(nop)

#define SHIFT_OP4(op) \
        ARITH_OP(op %cl, %dl) ; \
        ARITH_OP(op %cl, %dx) ; \
        ARITH_OP(op %cl, %edx) ; \
        ARITH_OP(nop)

#define BT_OP4(op) \
        ARITH_OP(nop) ; \
        ARITH_OP(op %cx, %dx) ; \
        ARITH_OP(op %ecx, %edx) ; \
        ARITH_OP(nop)

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
        ARITH_OP(nop)

        ARITH_OP(dec %dl)
        ARITH_OP(dec %dx)
        ARITH_OP(dec %edx)
        ARITH_OP(nop)

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

        .globl ASM_NAME(start_func)
ASM_NAME(start_func):
        movl %ecx, %esp
        pushl %edx /* parameter */
        pushl $0   /* invalid return address */
        jmp *%eax
                        
#define SEG_EXCEPTION(label) \
    .section "seg_ex_table", "a" ; \
    .long label ; \
    .previous

#ifdef USE_SEG_GP        
/* %ebx contains the kqemu_state pointer, %eax the selector, 
   %esi is preserved */
#define LOAD_SEG_CACHE(seg, seg_reg, cs_sel_offset)\
        movzwl %ax, %ecx        ; \
        orl $3, %ecx            ; \
        cmpl $3, %ecx           ; \
        je 1f                   ; \
        cmpw %cx, cs_sel_offset (%esp) ; \
        je 1f                   ; \
        cmpw %cx, cs_sel_offset + 3 * 4 (%esp) ; \
        je 1f                   ; \
\
/* set the segment descriptor entry */\
        movl %ecx, %edx         ; \
        andl $4, %edx           ; \
        andl $~7, %ecx          ; \
        shl $14, %edx           ; \
        addl %edx, %ecx         ; \
        leal KQEMU_STATE_dt_table(%ebx,%ecx), %edi ; \
        leal KQEMU_STATE_seg_desc_cache + 8 * seg_reg(%ebx), %ebp ; \
        movl (%ebp), %ecx       ; \
        movl 4(%ebp), %edx      ; \
        ss movl %ecx, (%edi)    ; \
        ss movl %edx, 4(%edi)   ; \
\
        /* load the segment */\
2:                              ; \
        mov %eax, seg           ; \
        SEG_EXCEPTION(2b)       ; \
\
        /* reset the segment descriptor entry */\
        xorl %ecx, %ecx         ; \
        ss movl %ecx, (%edi)    ; \
        ss movl %ecx, 4(%edi)   ; \
        jmp 3f                  ; \
1:                              ; \
        mov %eax, seg           ; \
        SEG_EXCEPTION(1b)       ; \
3:      
#endif
        
/* switch to user mode */
        .globl ASM_NAME(goto_user)
ASM_NAME(goto_user):
        movl %eax, %ebx
        movl %edx, %esp
        jmp exception_return
                
/* exception handling */
__monitor_exception:
        cld
        pushl %esi
        pushl %ebp
        pushl $0 /* place holder for %esp */
        pushl %ebx
        pushl %edx
        pushl %ecx
        pushl %eax
        pushl %es
        pushl %ds

/* compute the address of the monitor context */
        call 1f
1:
        pop %ebx
        add $ _end - 1b, %ebx

        cs movw KQEMU_STATE_monitor_ds_sel(%ebx), %cx
        movl %ecx, %ds
        movl %ecx, %es

/* adjust the stack if using a 16 bit stack segment (it can happen if
   an exception occurs in the lss insn of the 16 bit hack) */
        movl %ss, %edx
        cmpw KQEMU_STATE_monitor_ss16_sel(%ebx), %dx
        jz exception_return_fix_stack
exception_return_fix_stack_ret:

/* put %esp at the right position (NOTE: doing it even if coming from
   kernel cause no harm */
        movl 14 * 4 (%esp), %ecx
        movl %ecx, 6 * 4(%esp)
        
        pushl %ebx
        call *%edi
        addl $4, %esp
        
exception_return:

/* If returning to kernel code (rare case), we must not test for 16 bit SS or
   restore ESP */
        testl $3, 12 * 4(%esp)
        jz exception_return_to_monitor
        
/* move %esp for iret */
        movl 6 * 4(%esp), %ecx
        movl %ecx, 14 * 4 (%esp)


/* restore DS and ES segments */
#ifdef USE_SEG_GP        
        cmpb $3, KQEMU_STATE_cpu_state_cpl(%ebx)
        je normal_seg_load
        popl %eax
        LOAD_SEG_CACHE(%ds, R_DS, (11 * 4))
        popl %eax
        LOAD_SEG_CACHE(%es, R_ES, (10 * 4))
        jmp 2f
normal_seg_load:        
#endif        
1:
        popl %ds
        SEG_EXCEPTION(1b)
1:
        popl %es
        SEG_EXCEPTION(1b)
2:      
                
/* test if 16 bit SS segment to fix the 16 bit ESP bug */        
        larl 13 * 4(%esp), %eax
        jnz 3f /* exception will occur on iret anyway */
        testl $0x00400000, %eax
        jz exception_return16
3:
        popl %eax
        popl %ecx
        popl %edx
        popl %ebx
        addl $4, %esp
        popl %ebp
        popl %esi
        popl %edi
        addl $4, %esp
1:
        iret
SEG_EXCEPTION(1b)

exception_return_to_monitor:
1:
        popl %ds
        SEG_EXCEPTION(1b)
1:
        popl %es
        SEG_EXCEPTION(1b)
        popl %eax
        popl %ecx
        popl %edx
        popl %ebx
        addl $4, %esp
        popl %ebp
        popl %esi
        popl %edi
        addl $4, %esp
1:
        iret
SEG_EXCEPTION(1b)

exception_return_fix_stack:
        movl %ecx, %ss
        leal KQEMU_STATE_stack(%ebx), %ecx
        andl $0xffff0000, %ecx
        andl $0x0000ffff, %esp
        orl %ecx, %esp
        jmp exception_return_fix_stack_ret

exception_return16:
/* setup SS:ESP for 16 bit stack */
        leal 9 * 4(%esp), %eax
        movw %ax, 14 * 4(%esp)
        movw 12 * 4 + 2(%esp), %ax
        movw %ax, 14 * 4 + 2(%esp)
        ss movw KQEMU_STATE_monitor_ss16_sel(%ebx), %ax
        movl %eax, 15 * 4(%esp)

/* pop regs */
        popl %eax
        popl %ecx
        popl %edx
        popl %ebx
        addl $4, %esp
        popl %ebp
        popl %esi
        popl %edi
        addl $4, %esp
        lss 5 * 4(%esp), %esp
1:
        iret
        SEG_EXCEPTION(1b)

#define EXCEPTION_VECTOR(n, push_0) \
        .align 16 ; \
        push_0 ; \
        pushl %edi ; \
        movl $ASM_NAME(kqemu_exception_ ## n), %edi ; \
        jmp __monitor_exception

/* hardware interrupts */
__monitor_interrupt:
        cld
        pushl %edi
        pushl %esi
        pushl %ebp
        pushl $0 /* place holder for %esp */
        pushl %ebx
        pushl %edx
        pushl %ecx
        pushl %eax
        pushl %es
        pushl %ds
        
/* compute the address of the monitor context */
        call 1f
1:
        pop %ebx
        add $ _end - 1b, %ebx

        cs movw KQEMU_STATE_monitor_ds_sel(%ebx), %cx
        movl %ecx, %ds
        movl %ecx, %es

/* put %esp at the right position */         
        movl 14 * 4 (%esp), %ecx
        movl %ecx, 6 * 4(%esp)
        
        pushl %ebx
        call ASM_NAME(monitor_interrupt)
        addl $4, %esp

        jmp exception_return

#define IRQ(n) \
        .align 16               ; \
        push $n ; \
        jmp __monitor_interrupt   ; 

        .align 16
        .globl ASM_NAME(interrupt_table)
        
ASM_NAME(interrupt_table):                
        
EXCEPTION_VECTOR(00, pushl $0)
EXCEPTION_VECTOR(01, pushl $0)
IRQ(0x02) /* NMI */
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

DUP4(IRQ, 0x14)        
DUP4(IRQ, 0x18)        
DUP4(IRQ, 0x1c)        
DUP16(IRQ, 0x20)
DUP16(IRQ, 0x30)
DUP64(IRQ, 0x40)
DUP64(IRQ, 0x80)
DUP64(IRQ, 0xc0)

