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
 * %ss, %ds, %es, %cs are 4G flat 32 bit segments
 * IRQ disabled        
 */
ASM_NAME(kernel2monitor):
        pushl %ebp
        movl %esp, %ebp
        pushl %ebx
        pushl %esi
        pushl %edi
                                        
        pushl %ds
        pushl %es

        movl 8(%ebp), %ebx
        
        str  KQEMU_STATE_kernel_tr_sel(%ebx)
        sidt KQEMU_STATE_kernel_idt(%ebx)
        sgdt KQEMU_STATE_kernel_gdt(%ebx)
        sldt KQEMU_STATE_kernel_ldt_sel(%ebx)
        movw %cs, KQEMU_STATE_kernel_cs_sel(%ebx)
        
        movw %ss, KQEMU_STATE_kernel_ss_sel(%ebx)
        movl %esp, KQEMU_STATE_kernel_esp(%ebx)

        movl %cr0, %eax
        movl %eax, KQEMU_STATE_kernel_cr0(%ebx)
        movl %cr3, %eax
        movl %eax, KQEMU_STATE_kernel_cr3(%ebx)
        movl %cr4, %eax
        movl %eax, KQEMU_STATE_kernel_cr4(%ebx)

        /* switch to the monitor address space (we switch %cr4 first
    	   to disable global pages) */
        movl %eax, %ecx
        testl $CPUID_PGE, KQEMU_STATE_cpuid_features(%ebx)
        je 1f
        orl $CR4_PGE_MASK, %ecx
1:
        andl $~(CR4_PGE_MASK), %eax
        movl %eax, %cr4
        
        movl KQEMU_STATE_monitor_cr3(%ebx), %eax
        movl KQEMU_STATE_monitor_data_vaddr(%ebx), %ebx
        movl %eax, %cr3
        movl %ecx, %cr4
                 
        lidt KQEMU_STATE_monitor_idt(%ebx)
        lgdt KQEMU_STATE_monitor_gdt(%ebx)

        ljmp *KQEMU_STATE_monitor_jmp(%ebx)
ASM_NAME(kernel2monitor_jmp_offset):

        lldt KQEMU_STATE_monitor_ldt_sel(%ebx)

        /* load the TR desc cache without modifying the GDT */
        movw KQEMU_STATE_monitor_tr_sel(%ebx), %ax
        movl %eax, %ecx
        andl $0xfff8, %ecx
        addl (KQEMU_STATE_monitor_gdt + 2)(%ebx), %ecx
        movl (%ecx), %esi
        movl 4(%ecx), %edi
        movl KQEMU_STATE_tr_desc_cache(%ebx), %edx
        movl %edx, (%ecx)
        movl KQEMU_STATE_tr_desc_cache + 4(%ebx), %edx
        movl %edx, 4(%ecx)
        ltr %ax
        movl %esi, (%ecx)
        movl %edi, 4(%ecx)
                                        
        movw KQEMU_STATE_monitor_ds_sel(%ebx), %ax
        movw %ax, %ss
        movw %ax, %es
        movw %ax, %ds

        movl KQEMU_STATE_monitor_esp(%ebx), %esp

        /* load debug register if needed */
        movl KQEMU_STATE_monitor_dr7(%ebx), %eax
        testl %eax, %eax
        je 2f
        movl %eax, %dr7
2:
        
        popl %edi
        popl %esi
        popl %ebx
        popl %ebp
        ret

/*
 * Assumptions when entering monitor2kernel:
 * IRQ disabled
 */
ASM_NAME(monitor2kernel):
        pushl %ebp
        movl %esp, %ebp
        pushl %ebx
        pushl %esi
        pushl %edi

        movl 8(%ebp), %ebx
        
        movl %esp, KQEMU_STATE_monitor_esp(%ebx)

        /* clear the debug register if needed */
        movl KQEMU_STATE_monitor_dr7(%ebx), %eax
        testl %eax, %eax
        je 2f
        xor %eax, %eax
        movl %eax, %dr7
2:

        movl KQEMU_STATE_nexus_kaddr(%ebx), %eax
        addl $monitor2kernel_jmp_offset1 - _start, %eax
        jmp *%eax
monitor2kernel_jmp_offset1:     
        
        /* restore %cr4 */
        movl KQEMU_STATE_kernel_cr4(%ebx), %ecx
        movl %ecx, %eax
        andl $~CR4_PGE_MASK, %eax
        movl %eax, %cr4
        
        /* switch address space */
        movl KQEMU_STATE_kernel_cr3(%ebx), %eax
        movl KQEMU_STATE_monitor_data_kaddr(%ebx), %ebx
        movl %eax, %cr3
        movl %ecx, %cr4

        lidt KQEMU_STATE_kernel_idt(%ebx)
        lgdt KQEMU_STATE_kernel_gdt(%ebx)
        lldt KQEMU_STATE_kernel_ldt_sel(%ebx)

        ljmp *KQEMU_STATE_kernel_jmp(%ebx)
ASM_NAME(monitor2kernel_jmp_offset):

        /* restore TR and clear BUSY bit */
        movw KQEMU_STATE_kernel_tr_sel(%ebx), %ax
        movl %eax, %ecx
        andl $0xfff8, %ecx
        addl (KQEMU_STATE_kernel_gdt + 2)(%ebx), %ecx
        andl $0xfffffdff, 4(%ecx)
        ltr %ax

        /* cr0 needs to be restored because of the TS and AM bits */
        movl KQEMU_STATE_kernel_cr0(%ebx), %eax
        movl %eax, %cr0

        lss KQEMU_STATE_kernel_esp(%ebx), %esp

        popl %es
        popl %ds
        
        popl %edi
        popl %esi
        popl %ebx
        popl %ebp
        ret
