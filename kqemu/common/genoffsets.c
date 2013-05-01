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
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#define NO_STD_TYPES
#include "kqemu_int.h"

#define OFFSET(x) \
printf("#define KQEMU_STATE_%s %d\n", \
       #x, (int)offsetof(struct kqemu_state, x))

#define OFFSET1(x, name) \
printf("#define KQEMU_STATE_%s %d\n", \
       name, (int)offsetof(struct kqemu_state, x))

int main(int argc, char **argv)
{
    OFFSET(monitor_idt);
    OFFSET(monitor_gdt);
    OFFSET(monitor_tr_sel);
    OFFSET(monitor_ldt_sel);
    OFFSET(monitor_ds_sel);
    OFFSET(monitor_ss16_sel);
    OFFSET(monitor_cs_sel);
    OFFSET(monitor_vaddr);
    OFFSET(monitor_data_vaddr);
    OFFSET(monitor_data_kaddr);
    OFFSET(monitor_selector_base);
    OFFSET(monitor_jmp);
    OFFSET(monitor_cr3);
    OFFSET(monitor_dr7);
    OFFSET(monitor_esp);

    OFFSET(kernel_idt);
    OFFSET(kernel_gdt);
    OFFSET(kernel_tr_sel);
    OFFSET(kernel_ldt_sel);
    OFFSET(kernel_esp);
    OFFSET(kernel_ss_sel);
    OFFSET(kernel_jmp);
    OFFSET(kernel_cs_sel);
    OFFSET(kernel_cr0);
    OFFSET(kernel_cr3);
    OFFSET(kernel_cr4);
    OFFSET(kernel_esp);

    OFFSET(nexus_orig_pte);
    OFFSET(nexus_pte);
    OFFSET(nexus_kaddr);
    OFFSET(nexus_kaddr_vptep);
#ifdef __x86_64__
    OFFSET(monitor_cs32_sel);
    OFFSET(monitor_ss_null_sel);
#else
    OFFSET(use_pae);
#endif
    OFFSET(dt_table);
#ifdef USE_SEG_GP
    OFFSET(seg_desc_cache);
#endif
    OFFSET(tr_desc_cache);
    OFFSET(cpuid_features);

    OFFSET1(cpu_state.cpl, "cpu_state_cpl");

    OFFSET(stack);
    return 0;
}
