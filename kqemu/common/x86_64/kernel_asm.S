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
#include "kqemu_int.h"

.globl ASM_NAME(exec_irq)
.globl ASM_NAME(exec_exception)
        
ASM_NAME(exec_irq):
        shll $2, %edi
        add $irq_table, %rdi
        jmp *%rdi
        .align 4        
irq_table:

#define IRQ(n) sti ; .byte 0xcd ; .byte n ; ret ;

DUP256(IRQ, 0)

ASM_NAME(exec_exception):
        shll $2, %edi
        add $exception_table, %rdi
        jmp *%rdi
        .align 4        
exception_table:

#define EXCEPTION(n) .byte 0xcd ; .byte n ; ret ; nop ;

DUP16(EXCEPTION, 0)
DUP16(EXCEPTION, 16)
