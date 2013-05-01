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

.globl ASM_NAME(kernel2monitor)
.globl ASM_NAME(monitor2kernel)
.globl ASM_NAME(kernel2monitor_jmp_offset)
.globl ASM_NAME(monitor2kernel_jmp_offset)
.global _start
        
_start:
        .long ASM_NAME(kernel2monitor) - _start
        .long ASM_NAME(interrupt_table) - _start
        .long ASM_NAME(kernel2monitor_jmp_offset) - _start
        .long ASM_NAME(monitor2kernel_jmp_offset) - _start
        .long ASM_NAME(monitor_exec) - _start
/*
 * Assumptions when entering kernel2monitor:      
 * %rdi = kqemu_state, and set at the end of the function to the new kqemu_state
 * %cs in long mode
 * IRQ disabled        
 */
ASM_NAME(kernel2monitor):
        push %rbp
        mov %rsp, %rbp
        push %rbx
        push %r12
        push %r13
        push %r14
        push %r15
                                        
        str  KQEMU_STATE_kernel_tr_sel(%rdi)
        sidt KQEMU_STATE_kernel_idt(%rdi)
        sgdt KQEMU_STATE_kernel_gdt(%rdi)
        sldt KQEMU_STATE_kernel_ldt_sel(%rdi)
        movw %cs, KQEMU_STATE_kernel_cs_sel(%rdi)
        
        movw %ss, KQEMU_STATE_kernel_ss_sel(%rdi)
        mov %rsp, KQEMU_STATE_kernel_esp(%rdi)

        mov %cr0, %rax
        mov %rax, KQEMU_STATE_kernel_cr0(%rdi)
        mov %cr3, %rax
        mov %rax, KQEMU_STATE_kernel_cr3(%rdi)
        mov %cr4, %rax
        mov %rax, KQEMU_STATE_kernel_cr4(%rdi)

        /* switch to the monitor address space (we switch %cr4 first
    	   to disable global pages) */
        mov %rax, %rcx
        or $CR4_PGE_MASK, %rcx
        and $~(CR4_PGE_MASK), %rax
        mov %rax, %cr4

        mov KQEMU_STATE_monitor_cr3(%rdi), %rax
        mov KQEMU_STATE_monitor_data_vaddr(%rdi), %rdi
        mov %rax, %cr3
        mov %rcx, %cr4
                 
        lidt KQEMU_STATE_monitor_idt(%rdi)
        lgdt KQEMU_STATE_monitor_gdt(%rdi)

        mov KQEMU_STATE_monitor_esp(%rdi), %rsp

        /* change CS */
        movzwq KQEMU_STATE_monitor_cs_sel(%rdi), %rax
        push %rax
        mov KQEMU_STATE_monitor_jmp(%rdi), %rax
        push %rax
        lretq
ASM_NAME(kernel2monitor_jmp_offset):

        lldt KQEMU_STATE_monitor_ldt_sel(%rdi)

        movw KQEMU_STATE_monitor_tr_sel(%rdi), %ax
        movl %eax, %ecx
        andl $0xfff8, %ecx
        add (KQEMU_STATE_monitor_gdt + 2)(%rdi), %rcx
        movq (%rcx), %r12
        movq 8(%rcx), %r13
        movq KQEMU_STATE_tr_desc_cache(%rdi), %rdx
        movq %rdx, (%rcx)
        movq KQEMU_STATE_tr_desc_cache + 8(%rdi), %rdx
        movq %rdx, 8(%rcx)
        ltr %ax
        movq %r12, (%rcx)
        movq %r13, 8(%rcx)
        
        movw KQEMU_STATE_monitor_ds_sel(%rdi), %ss

        /* load debug register if needed */
        mov KQEMU_STATE_monitor_dr7(%rdi), %rax
        test %rax, %rax
        je 2f
        mov %rax, %dr7
2:
        
        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %rbx
        pop %rbp
        ret

/*
 * Assumptions when entering monitor2kernel:
 * IRQ disabled
 */
ASM_NAME(monitor2kernel):
        push %rbp
        mov %rsp, %rbp
        push %rbx
        push %r12
        push %r13
        push %r14
        push %r15

        mov %rsp, KQEMU_STATE_monitor_esp(%rdi)

        /* clear the debug register if needed */
        mov KQEMU_STATE_monitor_dr7(%rdi), %rax
        test %rax, %rax
        je 2f
        xor %rax, %rax
        mov %rax, %dr7
2:
                
        mov KQEMU_STATE_nexus_kaddr(%rdi), %rax
        add $monitor2kernel_jmp_offset1 - _start, %rax
        jmp *%rax
monitor2kernel_jmp_offset1:     
        
        /* restore %cr4 */
        mov KQEMU_STATE_kernel_cr4(%rdi), %rcx
        mov %rcx, %rax
        and $~CR4_PGE_MASK, %rax
        mov %rax, %cr4
        
        /* switch address space */
        mov KQEMU_STATE_kernel_cr3(%rdi), %rax
        mov KQEMU_STATE_monitor_data_kaddr(%rdi), %rdi
        mov %rax, %cr3
        mov %rcx, %cr4
        
        lidt KQEMU_STATE_kernel_idt(%rdi)
        lgdt KQEMU_STATE_kernel_gdt(%rdi)
        lldt KQEMU_STATE_kernel_ldt_sel(%rdi)

        mov KQEMU_STATE_kernel_esp(%rdi), %rsp

        /* change CS */
        movzwq KQEMU_STATE_kernel_cs_sel(%rdi), %rax
        push %rax
        lea ASM_NAME(monitor2kernel_jmp_offset)(%rip), %rax
        push %rax
        lretq
ASM_NAME(monitor2kernel_jmp_offset):

        /* restore TR and clear BUSY bit */
        movw KQEMU_STATE_kernel_tr_sel(%rdi), %ax
        movl %eax, %ecx
        andl $0xfff8, %ecx
        add (KQEMU_STATE_kernel_gdt + 2)(%rdi), %rcx
        andl $0xfffffdff, 4(%rcx)
        ltr %ax

        /* cr0 needs to be restored because of the TS and AM bits */
        mov KQEMU_STATE_kernel_cr0(%rdi), %rax
        mov %rax, %cr0

        movw KQEMU_STATE_kernel_ss_sel(%rdi), %ss

        pop %r15
        pop %r14
        pop %r13
        pop %r12
        pop %rbx
        pop %rbp
        ret
