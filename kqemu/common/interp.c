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
#ifdef __x86_64__
register unsigned long pc asm("%r12");
#else
register unsigned long pc asm("%esi");
#endif

#include "kqemu_int.h"

/*
 * TODO:
 * - do not use cs.base for CS64 code
 * - test all segment limits in 16/32 bit mode
 */

//#define DEBUG_LRET
//#define DEBUG_INTERP
//#define DEBUG_SEG

#ifdef USE_HARD_MMU
static inline uint32_t lduw_kernel1(struct kqemu_state *s, unsigned long addr)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return lduw_mem(s, addr);
    } else {
        return lduw_fast(s, addr, 0);
    }
}

static inline uint32_t ldl_kernel1(struct kqemu_state *s, unsigned long addr)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return ldl_mem(s, addr);
    } else {
        return ldl_fast(s, addr, 0);
    }
}

#if defined (__x86_64__)
static inline uint64_t ldq_kernel1(struct kqemu_state *s, unsigned long addr)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return ldq_mem(s, addr);
    } else {
        return ldq_fast(s, addr, 0);
    }
}
#endif

static inline void stw_kernel1(struct kqemu_state *s, unsigned long addr, uint32_t val)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return stw_mem(s, addr, val);
    } else {
        return stw_fast(s, addr, val, 0);
    }
}

static inline void stl_kernel1(struct kqemu_state *s, unsigned long addr, uint32_t val)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return stl_mem(s, addr, val);
    } else {
        return stl_fast(s, addr, val, 0);
    }
}

#if defined (__x86_64__)
static inline void stq_kernel1(struct kqemu_state *s, unsigned long addr, uint64_t val)
{
    if (likely(s->cpu_state.cpl != 3)) {
        return stq_mem(s, addr, val);
    } else {
        return stq_fast(s, addr, val, 0);
    }
}
#endif

#define ldq_kernel(addr) ldq_kernel1(s, addr)
#define ldl_kernel(addr) ldl_kernel1(s, addr)
#define lduw_kernel(addr) lduw_kernel1(s, addr)
#define stq_kernel(addr, val) stq_kernel1(s, addr, val)
#define stl_kernel(addr, val) stl_kernel1(s, addr, val)
#define stw_kernel(addr, val) stw_kernel1(s, addr, val)

#define ldub(s, addr) ldub_mem(s, addr)
#define lduw(s, addr) lduw_mem(s, addr)
#define ldl(s, addr) ldl_mem(s, addr)
#define ldq(s, addr) ldq_mem(s, addr)
#define stb(s, addr, val) stb_mem(s, addr, val)
#define stw(s, addr, val) stw_mem(s, addr, val)
#define stl(s, addr, val) stl_mem(s, addr, val)
#define stq(s, addr, val) stq_mem(s, addr, val)
#else
#define ldq_kernel(addr) ldq_fast(s, addr, 0)
#define ldl_kernel(addr) ldl_fast(s, addr, 0)
#define lduw_kernel(addr) lduw_fast(s, addr, 0)
#define stq_kernel(addr, val) stq_fast(s, addr, val, 0)
#define stl_kernel(addr, val) stl_fast(s, addr, val, 0)
#define stw_kernel(addr, val) stw_fast(s, addr, val, 0)

#define ldub(s, addr) ldub_fast(s, addr, (s->cpu_state.cpl == 3))
#define lduw(s, addr) lduw_fast(s, addr, (s->cpu_state.cpl == 3))
#define ldl(s, addr) ldl_fast(s, addr, (s->cpu_state.cpl == 3))
#define ldq(s, addr) ldq_fast(s, addr, (s->cpu_state.cpl == 3))
#define stb(s, addr, val) stb_fast(s, addr, val, (s->cpu_state.cpl == 3))
#define stw(s, addr, val) stw_fast(s, addr, val, (s->cpu_state.cpl == 3))
#define stl(s, addr, val) stl_fast(s, addr, val, (s->cpu_state.cpl == 3))
#define stq(s, addr, val) stq_fast(s, addr, val, (s->cpu_state.cpl == 3))
#endif /* !USE_HARD_MMU */

#ifdef __x86_64__
#define CODE64(s) ((s)->cpu_state.segs[R_CS].flags & DESC_L_MASK)
#define REX_R(s) ((s)->rex_r)
#define REX_X(s) ((s)->rex_x)
#define REX_B(s) ((s)->rex_b)
#else
#define CODE64(s) 0
#define REX_R(s) 0
#define REX_X(s) 0
#define REX_B(s) 0
#endif

#define PREFIX_REPZ   0x01
#define PREFIX_REPNZ  0x02
#define PREFIX_LOCK   0x04
#define PREFIX_REX    0x08

static inline unsigned int get_sp_mask(unsigned int e2)
{
    if (e2 & DESC_B_MASK)
        return 0xffffffff;
    else
        return 0xffff;
}

/* XXX: add a is_user flag to have proper security support */
#define PUSHW(ssp, sp, sp_mask, val)\
{\
    sp -= 2;\
    stw_kernel((ssp) + (sp & (sp_mask)), (val));\
}

#define PUSHL(ssp, sp, sp_mask, val)\
{\
    sp -= 4;\
    stl_kernel((ssp) + (sp & (sp_mask)), (val));\
}

#define POPW(ssp, sp, sp_mask, val)\
{\
    val = lduw_kernel((ssp) + (sp & (sp_mask)));\
    sp += 2;\
}

#define POPL(ssp, sp, sp_mask, val)\
{\
    val = (uint32_t)ldl_kernel((ssp) + (sp & (sp_mask)));\
    sp += 4;\
}

#define PUSHQ(sp, val)\
{\
    sp -= 8;\
    stq_kernel(sp, (val));\
}

#define POPQ(sp, val)\
{\
    val = ldq_kernel(sp);\
    sp += 8;\
}

#define ESP (s->regs1.esp)
#define EIP (s->regs1.eip)

static inline unsigned int get_seg_sel(struct kqemu_state *s, int seg_reg)
{
    unsigned int val;
    switch(seg_reg) {
    case R_CS:
        val = (s->regs1.cs_sel & ~3) | s->cpu_state.cpl;
        break;
    case R_SS:
        val = (s->regs1.ss_sel & ~3) | s->cpu_state.cpl;
        break;
#ifdef __x86_64__
    case R_DS:
        asm volatile ("mov %%ds, %0" : "=r" (val));
        val &= 0xffff; /* XXX: see if it is really necessary */
        break;
    case R_ES:
        asm volatile ("mov %%es, %0" : "=r" (val));
        val &= 0xffff; /* XXX: see if it is really necessary */
        break;
#else
    case R_DS:
        val = s->regs1.ds_sel;
        break;
    case R_ES:
        val = s->regs1.es_sel;
        break;
#endif
    case R_FS:
        asm volatile ("mov %%fs, %0" : "=r" (val));
        val &= 0xffff; /* XXX: see if it is really necessary */
        break;
    default:
    case R_GS:
        asm volatile ("mov %%gs, %0" : "=r" (val));
        val &= 0xffff; /* XXX: see if it is really necessary */
        break;
    }
    return val;
}

#ifdef USE_SEG_GP
static inline void set_seg_desc_cache(struct kqemu_state *s,
                                      int seg_reg)
{
    struct kqemu_segment_cache *sc;
    uint32_t e1, e2;
    unsigned long base, limit;

    sc = &s->cpu_state.segs[seg_reg];
    limit = sc->limit;
    base = sc->base;
    e2 = (sc->flags & 0x0070ff00) | (3 << DESC_DPL_SHIFT) | 
        DESC_S_MASK | DESC_A_MASK;
    if (limit > 0xfffff) {
        limit >>= 12;
        e2 |= DESC_G_MASK;
    }
    e1 = (base << 16) | (limit & 0xffff);
    e2 |= ((base >> 16) & 0xff) | (base & 0xff000000) | (limit & 0x000f0000);
    s->seg_desc_cache[seg_reg][0] = e1;
    s->seg_desc_cache[seg_reg][1] = e2;
}

/* seg_reg must be R_CS or R_SS */
static inline void set_descriptor_entry(struct kqemu_state *s,
                                        int seg_reg, int selector)
{
    uint32_t sel;
    uint8_t *ptr;

    /* reset the previous one */
    sel = s->seg_desc_entries[seg_reg - R_CS];
    ptr = (uint8_t *)s->dt_table + sel;
    *(uint64_t *)(ptr) = 0;

    if ((selector & 0xfffc) != 0) {
        sel = (selector & ~7) | ((selector & 4) << 14);
	ptr = (uint8_t *)s->dt_table + sel;
	*(uint32_t *)(ptr) = s->seg_desc_cache[seg_reg][0];
	*(uint32_t *)(ptr + 4) = s->seg_desc_cache[seg_reg][1];
    } else {
        sel = 0;
    }
    s->seg_desc_entries[seg_reg - R_CS] = sel;
}
#endif

/* NOTE: in the interpreter we only need the base value and flags for
   CS and SS. The selector is loaded at its real place (either real
   segment or regs) */
static void cpu_x86_load_seg_cache(struct kqemu_state *s, 
                                   int seg_reg, unsigned int selector,
                                   uint32_t base, unsigned int limit, 
                                   uint32_t e1, uint32_t e2)
{
    struct kqemu_segment_cache *sc;
#if 0
    monitor_log(s, "%08x: load_seg_cache seg_reg=%d sel=0x%04x e2=0x%08x\n",
                s->regs1.eip, seg_reg, selector, e2);
#endif
    sc = &s->cpu_state.segs[seg_reg];
    sc->flags = e2;
    sc->base = base;
    sc->limit = limit;
    
    /* update CPU state if needed */
#ifdef USE_SEG_GP
    if (s->cpu_state.cpl != 3) {
        switch(seg_reg) {
	case R_CS:
            s->regs1.cs_sel = selector | 3;
            set_seg_desc_cache(s, R_CS);
            set_descriptor_entry(s, R_CS, selector);
            break;
	case R_SS:
            s->regs1.ss_sel = selector | 3;
            set_seg_desc_cache(s, R_SS);
            set_descriptor_entry(s, R_SS, selector);
            break;
#ifdef __x86_64__
	case R_DS:
            set_seg_desc_cache(s, R_DS);
            set_cpu_seg_cache(s, R_DS, selector);
            break;
	case R_ES:
            set_seg_desc_cache(s, R_ES);
            set_cpu_seg_cache(s, R_ES, selector);
            break;
#else
	case R_DS:
            s->regs1.ds_sel = selector;
            set_seg_desc_cache(s, R_DS);
            break;
	case R_ES:
            s->regs1.es_sel = selector;
            set_seg_desc_cache(s, R_ES);
            break;
#endif
	case R_FS:
            set_seg_desc_cache(s, R_FS);
            set_cpu_seg_cache(s, R_FS, selector);
            break;
	case R_GS:
            set_seg_desc_cache(s, R_GS);
            set_cpu_seg_cache(s, R_GS, selector);
            break;
	}
    } else 
#endif
    {
        switch(seg_reg) {
	case R_CS:
            s->regs1.cs_sel = selector | 3;
            break;
	case R_SS:
            s->regs1.ss_sel = selector | 3;
            break;
#ifdef __x86_64__
	case R_DS:
            LOAD_SEG(ds, selector);
            break;
	case R_ES:
	  LOAD_SEG(es, selector);
	  break;
#else
	case R_DS:
            s->regs1.ds_sel = selector;
            break;
	case R_ES:
            s->regs1.es_sel = selector;
            break;
#endif
	case R_FS:
            LOAD_SEG(fs, selector);
            break;
	case R_GS:
            LOAD_SEG(gs, selector);
            break;
	}
    }
}

void update_seg_desc_caches(struct kqemu_state *s)
{
#ifdef USE_SEG_GP
    if (s->cpu_state.cpl != 3) {
        /* update the seg caches */
        set_seg_desc_cache(s, R_CS);
        set_descriptor_entry(s, R_CS, s->regs1.cs_sel);

        set_seg_desc_cache(s, R_SS);
        set_descriptor_entry(s, R_SS, s->regs1.ss_sel);

        set_seg_desc_cache(s, R_DS);
        set_seg_desc_cache(s, R_ES);
        set_seg_desc_cache(s, R_FS);
        set_seg_desc_cache(s, R_GS);
    }
#endif
}

#define REG_PTR(reg) (&s->regs1.eax + (reg))

static inline unsigned long get_regb(struct kqemu_state *s, int reg)
{
    unsigned long val;
#ifdef __x86_64__
    if (s->prefix & PREFIX_REX) {
        val = *(uint8_t *)REG_PTR(reg);
    } else
#endif
    {
        val = *((uint8_t *)REG_PTR(reg & 3) + (reg >> 2));
    }
    return val;
}

static inline unsigned long get_reg(struct kqemu_state *s, int reg)
{
    return *(unsigned long *)REG_PTR(reg);
}

static inline void set_reg(struct kqemu_state *s, int reg, unsigned long val)
{
    *(unsigned long *)REG_PTR(reg) = val;
}

static inline void set_regl(struct kqemu_state *s, int reg, uint32_t val)
{
    *(unsigned long *)REG_PTR(reg) = val;
}

static inline void set_regw(struct kqemu_state *s, int reg, uint32_t val)
{
    *(uint16_t *)REG_PTR(reg) = val;
}

static inline void set_regb(struct kqemu_state *s, int reg, uint32_t val)
{
#ifdef __x86_64__
     if (s->prefix & PREFIX_REX) {
         *(uint8_t *)REG_PTR(reg) = val;
     } else
#endif
     {
         *((uint8_t *)REG_PTR(reg & 3) + (reg >> 2)) = val;
     }
}

static inline unsigned long ldS(struct kqemu_state *s, int bsize, 
                                unsigned long addr)
{
    unsigned long val;
    switch(bsize) {
    case 0:
        val = ldub(s, addr);
        break;
    case 1:
        val = lduw(s, addr);
        break;
#ifndef __x86_64__
    default:
#endif
    case 2:
        val = ldl(s, addr);
        break;
#ifdef __x86_64__
    default:
    case 3:
        val = ldq(s, addr);
        break;
#endif
    }
    return val;
}

static inline void stS(struct kqemu_state *s, int bsize, unsigned long addr, 
                       unsigned long val)
{
    switch(bsize) {
    case 0:
        stb(s, addr, val);
        break;
    case 1:
        stw(s, addr, val);
        break;
#ifndef __x86_64__
    default:
#endif
    case 2:
        stl(s, addr, val);
        break;
#ifdef __x86_64__
    default:
    case 3:
        stq(s, addr, val);
        break;
#endif
    }
}

static inline unsigned long get_regS(struct kqemu_state *s, int bsize,
                                     int reg)
{
    unsigned long val;
    if (bsize == 0) {
        val = get_regb(s, reg);
    } else {
        val = get_reg(s, reg);
    }
    return val;
}
#ifdef __x86_64__
#define QO(x...) x
#else
#define QO(x...)
#endif


static inline void set_regS(struct kqemu_state *s, int bsize,
                            int reg, unsigned long val)
{
    if (bsize == 0) {
        set_regb(s, reg, val);
    } else if (bsize == 1) {
        *(uint16_t *)REG_PTR(reg) = val;
    }
#ifdef __x86_64__
    else if (bsize == 3) {
        *(unsigned long *)REG_PTR(reg) = val;\
    }
#endif
    else {
        *(unsigned long *)REG_PTR(reg) = (uint32_t)val;
    }
}


static inline unsigned long stack_pop(struct kqemu_state *s)
{
    unsigned long addr, sp_mask, val;

#ifdef __x86_64__
    if (CODE64(s)) {
        addr = s->regs1.esp;
        if (s->dflag) {
            val = ldq(s, addr);
        } else {
            val = lduw(s, addr);
        }
    } else 
#endif
    {
        sp_mask = get_sp_mask(s->cpu_state.segs[R_SS].flags);
        addr = (s->regs1.esp & sp_mask) + s->cpu_state.segs[R_SS].base;
        if (s->dflag) {
            val = ldl(s, addr);
        } else {
            val = lduw(s, addr);
        }
    }
    return val;
}

static inline void sp_add(struct kqemu_state *s, long addend)
{
#ifdef __x86_64__
    if (CODE64(s)) {
        s->regs1.esp += addend;
    } else 
#endif
    {
        if (s->cpu_state.segs[R_SS].flags & DESC_B_MASK)
            s->regs1.esp = (uint32_t)(s->regs1.esp + addend);
        else
            *(uint16_t *)&s->regs1.esp += addend;
    }
}

static inline void stack_pop_update(struct kqemu_state *s)
{
    int val;
#ifdef __x86_64__
    if (CODE64(s)) {
        if (s->dflag) {
            val = 8;
        } else {
            val = 2;
        }
    } else 
#endif
    {
        val = 2 << s->dflag;
    }
    sp_add(s, val);
}


static inline void stack_pushS(struct kqemu_state *s, unsigned long val,
                               int dflag)
{
    unsigned long addr, sp_mask, sp;

#ifdef __x86_64__
    if (CODE64(s)) {
        addr = s->regs1.esp;
        if (dflag) {
            addr -= 8;
            stq(s, addr, val);
        } else {
            addr -= 2;
            stw(s, addr, val);
        }
        s->regs1.esp = addr;
    } else 
#endif
    {
        sp_mask = get_sp_mask(s->cpu_state.segs[R_SS].flags);
        if (dflag) {
            sp = (s->regs1.esp - 4) & sp_mask;
            addr = sp + s->cpu_state.segs[R_SS].base;
            stl(s, addr, val);
        } else {
            sp = (s->regs1.esp - 2) & sp_mask;
            addr = sp + s->cpu_state.segs[R_SS].base;
            stw(s, addr, val);
        }
        s->regs1.esp = sp | (s->regs1.esp & ~sp_mask);
    }
}

static inline void stack_push(struct kqemu_state *s, unsigned long val)
{
    stack_pushS(s, val, s->dflag);
}

static inline int get_jcc_cond(unsigned long eflags, int b)
{
    switch(b) {
    case 0x0:
        return eflags & CC_O;
    case 0x1:
        return (eflags ^ CC_O) & CC_O;
    case 0x2:
        return eflags & CC_C;
    case 0x3:
        return (eflags ^ CC_C) & CC_C;
    case 0x4:
        return eflags & CC_Z;
    case 0x5:
        return (eflags ^ CC_Z) & CC_Z;
    case 0x6:
        return ((eflags >> 6) | eflags) & 1;
    case 0x7:
        return (((eflags >> 6) | eflags) & 1) ^ 1;
    case 0x8:
        return eflags & CC_S;
    case 0x9:
        return (eflags ^ CC_S) & CC_S;
    case 0xa:
        return eflags & CC_P;
    case 0xb:
        return (eflags ^ CC_P) & CC_P;
    case 0xc:
        return ((eflags >> 4) ^ eflags) & CC_S;
    case 0xd:
        return (((eflags >> 4) ^ eflags) ^ CC_S) & CC_S;
    case 0xe:
        return (((eflags >> 4) ^ eflags) | (eflags << 1)) & CC_S;
    default:
    case 0xf:
        return ((((eflags >> 4) ^ eflags) | (eflags << 1)) ^ CC_S) & CC_S;
    }
}

static inline unsigned long compute_eflags(struct kqemu_state *s)
{
    return (s->comm_page.virt_eflags & EFLAGS_MASK) | 
        (s->regs1.eflags & ~EFLAGS_MASK);
}

static inline void set_eflags(struct kqemu_state *s, unsigned long val)
{
    s->comm_page.virt_eflags = val & EFLAGS_MASK;
    s->regs1.eflags = compute_eflags_user(s, val);
}

static inline void load_eflags(struct kqemu_state *s,
                               unsigned long val, unsigned long update_mask)
{
    unsigned long org_eflags;

    update_mask |= 0xcff; /* DF + all condition codes */
    org_eflags = compute_eflags(s);
    val = (val & update_mask) | (org_eflags & ~update_mask);
    set_eflags(s, val);
}

static inline void set_reset_eflags(struct kqemu_state *s, 
                                    unsigned long set_val, 
                                    unsigned long reset_val)
{
    unsigned long val;
    val = compute_eflags(s);
    val = (val | set_val) & ~reset_val;
    set_eflags(s, val);
}

static inline int get_eflags_iopl(struct kqemu_state *s)
{
    return (s->comm_page.virt_eflags >> IOPL_SHIFT) & 3;
}

/* return IF_MASK or 0 */
static inline int get_eflags_if(struct kqemu_state *s)
{
    return (s->comm_page.virt_eflags & IF_MASK);
}

/* return VM_MASK or 0 */
static inline int get_eflags_vm(struct kqemu_state *s)
{
    return 0; /* currently VM_MASK cannot be set */
}

/* return NT_MASK or 0 */
static inline int get_eflags_nt(struct kqemu_state *s)
{
    return s->regs1.eflags & NT_MASK;
}

static void cpu_x86_set_cpl(struct kqemu_state *s, int cpl)
{
    int is_user;

#ifdef USE_SEG_GP
    /* update GDT/LDT cache for cpl == 3 because GDT and LDT could
       have been modified by guest kernel code */
    if (cpl == 3)
        update_gdt_ldt_cache(s);
#endif

    /* switch the address space */
    is_user = (cpl == 3);
    s->monitor_cr3 = s->pgds_cr3[is_user];
    asm volatile ("mov %0, %%cr3" : : "r" (s->monitor_cr3));

    s->cpu_state.cpl = cpl;
    
    /* just needed for AM bit */
    update_host_cr0(s);

    /* may be needed for TSD */
    update_host_cr4(s);

    update_seg_desc_caches(s);

    /* switch the GDT and the LDT */
#ifdef USE_SEG_GP
    s->monitor_gdt.base = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, dt_table) + 0x20000 * is_user;
#else
    s->monitor_gdt.base = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, dt_table) + 0x20000 * cpl;
#endif
    /* XXX: check op size for x86_64 */
    asm volatile ("lgdt %0" : "=m" (s->monitor_gdt));
    asm volatile ("lldt %0" : "=m" (s->monitor_ldt_sel));
}

/* load a segment descriptor */
static void load_seg_desc(struct kqemu_state *s, 
                          int seg_reg, uint16_t selector)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int index;
    unsigned long ptr;
    struct kqemu_segment_cache *dt;
    uint32_t e1, e2;
    int cpl, dpl, rpl;

#ifdef DEBUG_SEG
    monitor_log(s, "load_seg_desc: reg=%d sel=0x%04x\n", seg_reg, selector);
#endif
    if (selector >= s->monitor_selector_base &&
        selector <= (s->monitor_selector_base + MONITOR_SEL_RANGE)) {
        monitor_panic(s, "Trying to load a reserved selector\n");
    }

    if ((selector & 0xfffc) == 0) {
        if (seg_reg == R_SS
#ifdef __x86_64__
            && (!(env->segs[R_CS].flags & DESC_L_MASK) || env->cpl == 3)
#endif
            )
            raise_exception_err(s, EXCP0D_GPF, 0);
        cpu_x86_load_seg_cache(s, seg_reg, selector, 0, 0, 0, 0);
    } else {
        if (selector & 0x4)
            dt = &env->ldt;
        else
            dt = &env->gdt;
        index = selector & ~7;
        if ((index + 7) > dt->limit)
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        ptr = dt->base + index;
        e1 = ldl_kernel(ptr);
        e2 = ldl_kernel(ptr + 4);
        
        if (!(e2 & DESC_S_MASK))
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        rpl = selector & 3;
        dpl = (e2 >> DESC_DPL_SHIFT) & 3;
        cpl = env->cpl;
        if (seg_reg == R_SS) {
            /* must be writable segment */
            if ((e2 & DESC_CS_MASK) || !(e2 & DESC_W_MASK))
                raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            if (rpl != cpl || dpl != cpl)
                raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        } else if (seg_reg == R_CS) {
            if (!(e2 & DESC_CS_MASK))
                raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            if (e2 & DESC_C_MASK) {
                if (dpl > rpl)
                    raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            } else {
                if (dpl != rpl)
                    raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            }
        } else {
            /* must be readable segment */
            if ((e2 & (DESC_CS_MASK | DESC_R_MASK)) == DESC_CS_MASK)
                raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            
            if (!(e2 & DESC_CS_MASK) || !(e2 & DESC_C_MASK)) {
                /* if not conforming code, test rights */
                if (dpl < cpl || dpl < rpl)
                    raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
            }
        }

        if (!(e2 & DESC_P_MASK)) {
            if (seg_reg == R_SS)
                raise_exception_err(s, EXCP0C_STACK, selector & 0xfffc);
            else
                raise_exception_err(s, EXCP0B_NOSEG, selector & 0xfffc);
        }

#if 0
        /* set the access bit if not already set */
        if (!(e2 & DESC_A_MASK)) {
            e2 |= DESC_A_MASK;
            stl_kernel(ptr + 4, e2);
        }
#endif
#ifdef __x86_64__
        /* reset the long mode bit if we are in legacy mode */
        if (seg_reg == R_CS && !(env->efer & MSR_EFER_LMA))
            e2 &= ~DESC_L_MASK;
#endif
        cpu_x86_load_seg_cache(s, seg_reg, selector, get_seg_base(e1, e2), 
                               get_seg_limit(e1, e2), e1, e2);
    }
}

/* return non zero if error */
static inline int load_segment(struct kqemu_state *s, 
                               uint32_t *e1_ptr, uint32_t *e2_ptr,
                               int selector)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    struct kqemu_segment_cache *dt;
    int index;
    unsigned long ptr;

    if (selector & 0x4)
        dt = &env->ldt;
    else
        dt = &env->gdt;
    index = selector & ~7;
    if ((index + 7) > dt->limit)
        return -1;
    ptr = dt->base + index;
    *e1_ptr = ldl_kernel(ptr);
    *e2_ptr = ldl_kernel(ptr + 4);
    return 0;
}

static inline void get_ss_esp_from_tss(struct kqemu_state *s,
                                       uint32_t *ss_ptr, 
                                       uint32_t *esp_ptr, int dpl)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int type, index, shift;
#if 0    
    if (!(env->tr.flags & DESC_P_MASK))
        cpu_abort(env, "invalid tss");
#endif
    type = (env->tr.flags >> DESC_TYPE_SHIFT) & 0xf;
#if 0
    if ((type & 7) != 1)
        cpu_abort(env, "invalid tss type");
#endif
    shift = type >> 3;
    index = (dpl * 4 + 2) << shift;
    if (index + (4 << shift) - 1 > env->tr.limit)
        raise_exception_err(s, EXCP0A_TSS, env->tr.selector & 0xfffc);
    if (shift == 0) {
        *esp_ptr = lduw_kernel(env->tr.base + index);
        *ss_ptr = lduw_kernel(env->tr.base + index + 2);
    } else {
        *esp_ptr = ldl_kernel(env->tr.base + index);
        *ss_ptr = lduw_kernel(env->tr.base + index + 4);
    }
}

/* protected mode interrupt */
static void do_interrupt_protected(struct kqemu_state *s,
                                   int intno, int is_int, int error_code,
                                   unsigned int next_eip, int is_hw)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    struct kqemu_segment_cache *dt;
    unsigned long ptr, ssp;
    int type, dpl, selector, ss_dpl, cpl, sp_mask;
    int has_error_code, new_stack, shift;
    uint32_t e1, e2, offset, ss, esp, ss_e1, ss_e2;
    uint32_t old_eip;

    has_error_code = 0;
    if (!is_int && !is_hw) {
        switch(intno) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            has_error_code = 1;
            break;
        }
    }
    if (is_int)
        old_eip = next_eip;
    else
        old_eip = EIP;

    dt = &env->idt;
    if (intno * 8 + 7 > dt->limit)
        raise_exception_err(s, EXCP0D_GPF, intno * 8 + 2);
    ptr = dt->base + intno * 8;
    e1 = ldl_kernel(ptr);
    e2 = ldl_kernel(ptr + 4);
    /* check gate type */
    type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
    switch(type) {
    case 5: /* task gate */
        raise_exception(s, KQEMU_RET_SOFTMMU);
        return;
    case 6: /* 286 interrupt gate */
    case 7: /* 286 trap gate */
    case 14: /* 386 interrupt gate */
    case 15: /* 386 trap gate */
        break;
    default:
        raise_exception_err(s, EXCP0D_GPF, intno * 8 + 2);
        break;
    }
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->cpl;
    /* check privledge if software int */
    if (is_int && dpl < cpl)
        raise_exception_err(s, EXCP0D_GPF, intno * 8 + 2);
    /* check valid bit */
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(s, EXCP0B_NOSEG, intno * 8 + 2);
    selector = e1 >> 16;
    offset = (e2 & 0xffff0000) | (e1 & 0x0000ffff);
    if ((selector & 0xfffc) == 0)
        raise_exception_err(s, EXCP0D_GPF, 0);

    if (load_segment(s, &e1, &e2, selector) != 0)
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_S_MASK) || !(e2 & (DESC_CS_MASK)))
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (dpl > cpl)
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(s, EXCP0B_NOSEG, selector & 0xfffc);
    if (!(e2 & DESC_C_MASK) && dpl < cpl) {
        /* to inner priviledge */
        get_ss_esp_from_tss(s, &ss, &esp, dpl);
        if ((ss & 0xfffc) == 0)
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        if ((ss & 3) != dpl)
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        if (load_segment(s, &ss_e1, &ss_e2, ss) != 0)
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        ss_dpl = (ss_e2 >> DESC_DPL_SHIFT) & 3;
        if (ss_dpl != dpl)
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        if (!(ss_e2 & DESC_S_MASK) ||
            (ss_e2 & DESC_CS_MASK) ||
            !(ss_e2 & DESC_W_MASK))
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        if (!(ss_e2 & DESC_P_MASK))
            raise_exception_err(s, EXCP0A_TSS, ss & 0xfffc);
        new_stack = 1;
        sp_mask = get_sp_mask(ss_e2);
        ssp = get_seg_base(ss_e1, ss_e2);
    } else if ((e2 & DESC_C_MASK) || dpl == cpl) {
        /* to same priviledge */
        if (get_eflags_vm(s))
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0;
        sp_mask = get_sp_mask(env->segs[R_SS].flags);
        ssp = env->segs[R_SS].base;
        esp = ESP;
        dpl = cpl;
	ss_e1 = ss_e2 = ss = 0; /* avoid warning */
    } else {
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0; /* avoid warning */
        sp_mask = 0; /* avoid warning */
        ssp = 0; /* avoid warning */
        esp = 0; /* avoid warning */
    }

    shift = type >> 3;

#if 0
    /* XXX: check that enough room is available */
    push_size = 6 + (new_stack << 2) + (has_error_code << 1);
    if (env->eflags & VM_MASK)
        push_size += 8;
    push_size <<= shift;
#endif
    if (shift == 1) {
        if (new_stack) {
            if (get_eflags_vm(s)) {
                PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_GS));
                PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_FS));
                PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_DS));
                PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_ES));
            }
            PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_SS));
            PUSHL(ssp, esp, sp_mask, ESP);
        }
        PUSHL(ssp, esp, sp_mask, compute_eflags(s));
        PUSHL(ssp, esp, sp_mask, get_seg_sel(s, R_CS));
        PUSHL(ssp, esp, sp_mask, old_eip);
        if (has_error_code) {
            PUSHL(ssp, esp, sp_mask, error_code);
        }
    } else {
        if (new_stack) {
            if (get_eflags_vm(s)) {
                PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_GS));
                PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_FS));
                PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_DS));
                PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_ES));
            }
            PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_SS));
            PUSHW(ssp, esp, sp_mask, ESP);
        }
        PUSHW(ssp, esp, sp_mask, compute_eflags(s));
        PUSHW(ssp, esp, sp_mask, get_seg_sel(s, R_CS));
        PUSHW(ssp, esp, sp_mask, old_eip);
        if (has_error_code) {
            PUSHW(ssp, esp, sp_mask, error_code);
        }
    }
    
    cpu_x86_set_cpl(s, dpl);
    if (new_stack) {
        if (get_eflags_vm(s)) {
            cpu_x86_load_seg_cache(s, R_ES, 0, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(s, R_DS, 0, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(s, R_FS, 0, 0, 0, 0, 0);
            cpu_x86_load_seg_cache(s, R_GS, 0, 0, 0, 0, 0);
        }
        ss = (ss & ~3) | dpl;
        cpu_x86_load_seg_cache(s, R_SS, ss, 
                               ssp, get_seg_limit(ss_e1, ss_e2), ss_e1, ss_e2);
    }
    ESP = (ESP & ~sp_mask) | (esp & sp_mask);

    selector = (selector & ~3) | dpl;
    cpu_x86_load_seg_cache(s, R_CS, selector, 
                           get_seg_base(e1, e2),
                           get_seg_limit(e1, e2),
                           e1, e2);
    EIP = offset;

    /* interrupt gate clear IF mask */
    if ((type & 1) == 0) {
        set_reset_eflags(s, 0, IF_MASK);
    }
    set_reset_eflags(s, 0, VM_MASK | RF_MASK | TF_MASK | NT_MASK);
}

#ifdef __x86_64__

static inline unsigned long get_rsp_from_tss(struct kqemu_state *s, int level)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int index;
    
#if 0
    printf("TR: base=" TARGET_FMT_lx " limit=%x\n", 
           env->tr.base, env->tr.limit);
#endif

#if 0    
    if (!(env->tr.flags & DESC_P_MASK))
        cpu_abort(env, "invalid tss");
#endif
    index = 8 * level + 4;
    if ((index + 7) > env->tr.limit)
        raise_exception_err(s, EXCP0A_TSS, env->tr.selector & 0xfffc);
    return ldq_kernel(env->tr.base + index);
}

/* 64 bit interrupt */
static void do_interrupt64(struct kqemu_state *s,
                           int intno, int is_int, int error_code,
                           unsigned long next_eip, int is_hw)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    struct kqemu_segment_cache *dt;
    unsigned long ptr;
    int type, dpl, selector, cpl, ist;
    int has_error_code, new_stack;
    uint32_t e1, e2, e3, ss;
    unsigned long old_eip, esp, offset;

    has_error_code = 0;
    if (!is_int && !is_hw) {
        switch(intno) {
        case 8:
        case 10:
        case 11:
        case 12:
        case 13:
        case 14:
        case 17:
            has_error_code = 1;
            break;
        }
    }
    if (is_int)
        old_eip = next_eip;
    else
        old_eip = EIP;

    dt = &env->idt;
    if (intno * 16 + 15 > dt->limit)
        raise_exception_err(s, EXCP0D_GPF, intno * 16 + 2);
    ptr = dt->base + intno * 16;
    e1 = ldl_kernel(ptr);
    e2 = ldl_kernel(ptr + 4);
    e3 = ldl_kernel(ptr + 8);
    /* check gate type */
    type = (e2 >> DESC_TYPE_SHIFT) & 0x1f;
    switch(type) {
    case 14: /* 386 interrupt gate */
    case 15: /* 386 trap gate */
        break;
    default:
        raise_exception_err(s, EXCP0D_GPF, intno * 16 + 2);
        break;
    }
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    cpl = env->cpl;
    /* check privledge if software int */
    if (is_int && dpl < cpl)
        raise_exception_err(s, EXCP0D_GPF, intno * 16 + 2);
    /* check valid bit */
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(s, EXCP0B_NOSEG, intno * 16 + 2);
    selector = e1 >> 16;
    offset = ((unsigned long)e3 << 32) | (e2 & 0xffff0000) | (e1 & 0x0000ffff);
    ist = e2 & 7;
    if ((selector & 0xfffc) == 0)
        raise_exception_err(s, EXCP0D_GPF, 0);

    if (load_segment(s, &e1, &e2, selector) != 0)
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_S_MASK) || !(e2 & (DESC_CS_MASK)))
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (dpl > cpl)
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(s, EXCP0B_NOSEG, selector & 0xfffc);
    if (!(e2 & DESC_L_MASK) || (e2 & DESC_B_MASK))
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
    if ((!(e2 & DESC_C_MASK) && dpl < cpl) || ist != 0) {
        /* to inner priviledge */
        if (ist != 0)
            esp = get_rsp_from_tss(s, ist + 3);
        else
            esp = get_rsp_from_tss(s, dpl);
        esp &= ~0xfLL; /* align stack */
        ss = 0;
        new_stack = 1;
    } else if ((e2 & DESC_C_MASK) || dpl == cpl) {
        /* to same priviledge */
        if (env->eflags & VM_MASK)
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0;
        if (ist != 0)
            esp = get_rsp_from_tss(s, ist + 3);
        else
            esp = ESP;
        esp &= ~0xfLL; /* align stack */
        dpl = cpl;
    } else {
        raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        new_stack = 0; /* avoid warning */
        esp = 0; /* avoid warning */
    }

    PUSHQ(esp, get_seg_sel(s, R_SS));
    PUSHQ(esp, ESP);
    PUSHQ(esp, compute_eflags(s));
    PUSHQ(esp, get_seg_sel(s, R_CS));
    PUSHQ(esp, old_eip);
    if (has_error_code) {
        PUSHQ(esp, error_code);
    }
    
    cpu_x86_set_cpl(s, dpl);
    if (new_stack) {
        ss = 0 | dpl;
        cpu_x86_load_seg_cache(s, R_SS, ss, 0, 0, 0, 0);
    }
    ESP = esp;

    selector = (selector & ~3) | dpl;
    cpu_x86_load_seg_cache(s, R_CS, selector, 
                           get_seg_base(e1, e2),
                           get_seg_limit(e1, e2),
                           e1, e2);
    EIP = offset;

    /* interrupt gate clear IF mask */
    if ((type & 1) == 0) {
        set_reset_eflags(s, 0, IF_MASK);
    }
    set_reset_eflags(s, 0, VM_MASK | RF_MASK | TF_MASK | NT_MASK);
}
#endif

static void do_interrupt(struct kqemu_state *s,
                         int intno, int is_int, int error_code,
                         unsigned long next_eip, int is_hw)
{
#ifdef __x86_64__
    if (s->cpu_state.efer & MSR_EFER_LMA) {
        do_interrupt64(s, intno, is_int, error_code, next_eip, is_hw);
    } else 
#endif
    {
        do_interrupt_protected(s, intno, is_int, error_code, next_eip, is_hw);
    }
}

static inline void validate_seg(struct kqemu_state *s, int seg_reg, int cpl)
{
    int dpl;
    uint32_t e2;
    
    e2 = s->cpu_state.segs[seg_reg].flags;
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (!(e2 & DESC_CS_MASK) || !(e2 & DESC_C_MASK)) {
        /* data or non conforming code segment */
        if (dpl < cpl) {
            cpu_x86_load_seg_cache(s, seg_reg, 0, 0, 0, 0, 0);
        }
    }
}

/* protected mode iret */
static inline void helper_ret_protected(struct kqemu_state *s,
                                        int shift, int is_iret, int addend)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    uint32_t new_cs, new_eflags, new_ss;
    uint32_t e1, e2, ss_e1, ss_e2;
    int cpl, dpl, rpl, eflags_mask, iopl;
    unsigned long ssp, sp, new_eip, new_esp, sp_mask;
    
#ifdef __x86_64__
    if (shift == 2)
        sp_mask = -1;
    else
#endif
        sp_mask = get_sp_mask(env->segs[R_SS].flags);
    sp = ESP;
    /* XXX: ssp is zero in 64 bit ? */
    ssp = env->segs[R_SS].base;
    new_eflags = 0; /* avoid warning */
#ifdef __x86_64__
    if (shift == 2) {
        POPQ(sp, new_eip);
        POPQ(sp, new_cs);
        new_cs &= 0xffff;
        if (is_iret) {
            POPQ(sp, new_eflags);
        }
    } else
#endif
    if (shift == 1) {
        /* 32 bits */
        POPL(ssp, sp, sp_mask, new_eip);
        POPL(ssp, sp, sp_mask, new_cs);
        new_cs &= 0xffff;
        if (is_iret) {
            POPL(ssp, sp, sp_mask, new_eflags);
            if (new_eflags & VM_MASK)
                goto return_to_vm86;
        }
    } else {
        /* 16 bits */
        POPW(ssp, sp, sp_mask, new_eip);
        POPW(ssp, sp, sp_mask, new_cs);
        if (is_iret)
            POPW(ssp, sp, sp_mask, new_eflags);
    }
#ifdef DEBUG_LRET
    monitor_log(s, "lret new %04x:" FMT_lx " s=%d addend=0x%x\n",
                new_cs, new_eip, shift, addend);
#endif
    if ((new_cs & 0xfffc) == 0)
        raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    if (load_segment(s, &e1, &e2, new_cs) != 0)
        raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    if (!(e2 & DESC_S_MASK) ||
        !(e2 & DESC_CS_MASK))
        raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    cpl = env->cpl;
    rpl = new_cs & 3; 
    if (rpl < cpl)
        raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    dpl = (e2 >> DESC_DPL_SHIFT) & 3;
    if (e2 & DESC_C_MASK) {
        if (dpl > rpl)
            raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    } else {
        if (dpl != rpl)
            raise_exception_err(s, EXCP0D_GPF, new_cs & 0xfffc);
    }
    if (!(e2 & DESC_P_MASK))
        raise_exception_err(s, EXCP0B_NOSEG, new_cs & 0xfffc);
    
    sp += addend;
    if (rpl == cpl && (!CODE64(s) || 
                       (CODE64(s) && !is_iret))) {
        /* return to same priledge level */
        cpu_x86_load_seg_cache(s, R_CS, new_cs, 
                               get_seg_base(e1, e2),
                               get_seg_limit(e1, e2),
                               e1, e2);
    } else {
        /* return to different priviledge level */
#ifdef __x86_64__
        if (shift == 2) {
            POPQ(sp, new_esp);
            POPQ(sp, new_ss);
            new_ss &= 0xffff;
        } else
#endif
        if (shift == 1) {
            /* 32 bits */
            POPL(ssp, sp, sp_mask, new_esp);
            POPL(ssp, sp, sp_mask, new_ss);
            new_ss &= 0xffff;
        } else {
            /* 16 bits */
            POPW(ssp, sp, sp_mask, new_esp);
            POPW(ssp, sp, sp_mask, new_ss);
        }
#ifdef DEBUG_PCALL
        if (loglevel & CPU_LOG_PCALL) {
            fprintf(logfile, "new ss:esp=%04x:" TARGET_FMT_lx "\n",
                    new_ss, new_esp);
        }
#endif
        if ((new_ss & 0xfffc) == 0) {
#ifdef __x86_64__
            /* NULL ss is allowed in long mode if cpl != 3*/
            if ((env->efer & MSR_EFER_LMA) && rpl != 3) {
                cpu_x86_set_cpl(s, rpl);
                cpu_x86_load_seg_cache(s, R_SS, new_ss, 
                                       0, 0xffffffff,
                                       0xffff, 
                                       DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                                       DESC_S_MASK | (rpl << DESC_DPL_SHIFT) |
                                       DESC_W_MASK | DESC_A_MASK | 0x000f0000);
                ss_e2 = DESC_B_MASK; /* XXX: should not be needed ? */
            } else 
#endif
            {
                raise_exception_err(s, EXCP0D_GPF, 0);
            }
        } else {
            if ((new_ss & 3) != rpl)
                raise_exception_err(s, EXCP0D_GPF, new_ss & 0xfffc);
            if (load_segment(s, &ss_e1, &ss_e2, new_ss) != 0)
                raise_exception_err(s, EXCP0D_GPF, new_ss & 0xfffc);
            if (!(ss_e2 & DESC_S_MASK) ||
                (ss_e2 & DESC_CS_MASK) ||
                !(ss_e2 & DESC_W_MASK))
                raise_exception_err(s, EXCP0D_GPF, new_ss & 0xfffc);
            dpl = (ss_e2 >> DESC_DPL_SHIFT) & 3;
            if (dpl != rpl)
                raise_exception_err(s, EXCP0D_GPF, new_ss & 0xfffc);
            if (!(ss_e2 & DESC_P_MASK))
                raise_exception_err(s, EXCP0B_NOSEG, new_ss & 0xfffc);
            cpu_x86_set_cpl(s, rpl);
            cpu_x86_load_seg_cache(s, R_SS, new_ss, 
                                   get_seg_base(ss_e1, ss_e2),
                                   get_seg_limit(ss_e1, ss_e2),
                                   ss_e1, ss_e2);
        }

        cpu_x86_load_seg_cache(s, R_CS, new_cs, 
                               get_seg_base(e1, e2),
                               get_seg_limit(e1, e2),
                               e1, e2);
        sp = new_esp;
#ifdef __x86_64__
        if (shift == 2)
            sp_mask = -1;
        else
#endif
            sp_mask = get_sp_mask(ss_e2);

        /* validate data segments */
        validate_seg(s, R_ES, cpl);
        validate_seg(s, R_DS, cpl);
        validate_seg(s, R_FS, cpl);
        validate_seg(s, R_GS, cpl);

        sp += addend;
    }
    ESP = (ESP & ~sp_mask) | (sp & sp_mask);
    EIP = new_eip;
    if (is_iret) {
        /* NOTE: 'cpl' is the _old_ CPL */
        eflags_mask = TF_MASK | AC_MASK | ID_MASK | RF_MASK | NT_MASK;
        if (cpl == 0)
            eflags_mask |= IOPL_MASK;
        iopl = get_eflags_iopl(s);
        if (cpl <= iopl)
            eflags_mask |= IF_MASK;
        if (shift == 0)
            eflags_mask &= 0xffff;
        load_eflags(s, new_eflags, eflags_mask);
    }
    return;

 return_to_vm86:
    raise_exception(s, KQEMU_RET_SOFTMMU);
}

void helper_iret_protected(struct kqemu_state *s, int shift)
{
    /* specific case for TSS */
    if (get_eflags_nt(s)) {
#ifdef __x86_64__
        if (s->cpu_state.efer & MSR_EFER_LMA)
            raise_exception_err(s, EXCP0D_GPF, 0);
#endif
        raise_exception(s, KQEMU_RET_SOFTMMU);
    } else {
        helper_ret_protected(s, shift, 1, 0);
    }
}

void helper_lret_protected(struct kqemu_state *s, int shift, int addend)
{
    helper_ret_protected(s, shift, 0, addend);
}

void do_int(struct kqemu_state *s, int intno)
{
    unsigned long next_eip;
    next_eip = pc;
    if (s->cpu_state.user_only) {
        s->cpu_state.next_eip = next_eip;
        raise_exception(s, KQEMU_RET_INT + intno);
    } else {
        do_interrupt(s, intno, 1, 0, next_eip, 0);
    }
}

static void helper_syscall(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int selector;

    if (!(env->efer & MSR_EFER_SCE)) {
        raise_exception_err(s, EXCP06_ILLOP, 0);
    }
    if (env->user_only) {
        env->next_eip = pc;
        raise_exception(s, KQEMU_RET_SYSCALL);
    }

    selector = (env->star >> 32) & 0xffff;
#ifdef __x86_64__
    if (env->efer & MSR_EFER_LMA) {
        int code64;

        s->regs1.ecx = pc;
        s->regs1.r11 = compute_eflags(s);

        code64 = CODE64(s);

        cpu_x86_set_cpl(s, 0);
        cpu_x86_load_seg_cache(s, R_CS, selector & 0xfffc, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK | DESC_L_MASK);
        cpu_x86_load_seg_cache(s, R_SS, (selector + 8) & 0xfffc, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_W_MASK | DESC_A_MASK);
        set_reset_eflags(s, 0, env->fmask);
        if (code64)
            EIP = env->lstar;
        else
            EIP = env->cstar;
    } else 
#endif
    {
        s->regs1.ecx = (uint32_t)(pc);
        
        cpu_x86_set_cpl(s, 0);
        cpu_x86_load_seg_cache(s, R_CS, selector & 0xfffc, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
        cpu_x86_load_seg_cache(s, R_SS, (selector + 8) & 0xfffc, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK |
                               DESC_W_MASK | DESC_A_MASK);
        set_reset_eflags(s, 0, IF_MASK | RF_MASK | VM_MASK);
        EIP = (uint32_t)env->star;
    }
}

static void helper_sysret(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int selector;

    if (!(env->efer & MSR_EFER_SCE)) {
        raise_exception_err(s, EXCP06_ILLOP, 0);
    }
    if (!(env->cr0 & CR0_PE_MASK) || env->cpl != 0) {
        raise_exception_err(s, EXCP0D_GPF, 0);
    }
    selector = (env->star >> 48) & 0xffff;
#ifdef __x86_64__
    if (env->efer & MSR_EFER_LMA) {
        cpu_x86_set_cpl(s, 3);
        if (s->dflag == 2) {
            cpu_x86_load_seg_cache(s, R_CS, (selector + 16) | 3, 
                                   0, 0xffffffff,  0,
                                   DESC_G_MASK | DESC_P_MASK |
                                   DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK | 
                                   DESC_L_MASK);
            EIP = s->regs1.ecx;
        } else {
            cpu_x86_load_seg_cache(s, R_CS, selector | 3, 
                                   0, 0xffffffff, 0,
                                   DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                                   DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                                   DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
            EIP = (uint32_t)s->regs1.ecx;
        }
        cpu_x86_load_seg_cache(s, R_SS, selector + 8, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                               DESC_W_MASK | DESC_A_MASK);
        load_eflags(s, (uint32_t)(s->regs1.r11), TF_MASK | AC_MASK | ID_MASK | 
                    IF_MASK | IOPL_MASK | VM_MASK | RF_MASK | NT_MASK);
    } else 
#endif
    {
        cpu_x86_set_cpl(s, 3);
        cpu_x86_load_seg_cache(s, R_CS, selector | 3, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                               DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
        EIP = (uint32_t)s->regs1.ecx;
        cpu_x86_load_seg_cache(s, R_SS, selector + 8, 
                               0, 0xffffffff, 0,
                               DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                               DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                               DESC_W_MASK | DESC_A_MASK);
        set_reset_eflags(s, IF_MASK, 0);
    }
}

static void helper_sysenter(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;

    if (env->user_only)
        raise_exception(s, KQEMU_RET_SOFTMMU);
    if (env->sysenter_cs == 0) {
        raise_exception_err(s, EXCP0D_GPF, 0);
    }
    set_reset_eflags(s, 0, VM_MASK | IF_MASK | RF_MASK);
    cpu_x86_set_cpl(s, 0);
    cpu_x86_load_seg_cache(s, R_CS, env->sysenter_cs & 0xfffc, 
                           0, 0xffffffff, 
                           0,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK |
                           DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(s, R_SS, (env->sysenter_cs + 8) & 0xfffc, 
                           0, 0xffffffff,
                           0, 
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK |
                           DESC_W_MASK | DESC_A_MASK);
    ESP = env->sysenter_esp;
    EIP = env->sysenter_eip;
}

static void helper_sysexit(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    int cpl;

    cpl = env->cpl;
    if (env->sysenter_cs == 0 || cpl != 0) {
        raise_exception_err(s, EXCP0D_GPF, 0);
    }
    cpu_x86_set_cpl(s, 3);
    cpu_x86_load_seg_cache(s, R_CS, ((env->sysenter_cs + 16) & 0xfffc) | 3, 
                           0, 0xffffffff, 
                           0,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                           DESC_CS_MASK | DESC_R_MASK | DESC_A_MASK);
    cpu_x86_load_seg_cache(s, R_SS, ((env->sysenter_cs + 24) & 0xfffc) | 3, 
                           0, 0xffffffff,
                           0,
                           DESC_G_MASK | DESC_B_MASK | DESC_P_MASK |
                           DESC_S_MASK | (3 << DESC_DPL_SHIFT) |
                           DESC_W_MASK | DESC_A_MASK);
    ESP = s->regs1.ecx;
    EIP = s->regs1.edx;
}

static inline void load_seg_cache_raw_dt(struct kqemu_segment_cache *sc, 
                                         uint32_t e1, uint32_t e2)
{
    sc->base = get_seg_base(e1, e2);
    sc->limit = get_seg_limit(e1, e2);
    sc->flags = e2;
}

void helper_lldt(struct kqemu_state *s, int selector)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    struct kqemu_segment_cache *dt;
    uint32_t e1, e2;
    int index, entry_limit;
    unsigned long ptr;
    
    if ((selector & 0xfffc) == 0) {
        /* XXX: NULL selector case: invalid LDT */
        env->ldt.base = 0;
        env->ldt.limit = 0;
    } else {
        if (selector & 0x4)
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        dt = &env->gdt;
        index = selector & ~7;
#ifdef __x86_64__
        if (env->efer & MSR_EFER_LMA)
            entry_limit = 15;
        else
#endif            
            entry_limit = 7;
        if ((index + entry_limit) > dt->limit)
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        ptr = dt->base + index;
        e1 = ldl_kernel(ptr);
        e2 = ldl_kernel(ptr + 4);
        if ((e2 & DESC_S_MASK) || ((e2 >> DESC_TYPE_SHIFT) & 0xf) != 2)
            raise_exception_err(s, EXCP0D_GPF, selector & 0xfffc);
        if (!(e2 & DESC_P_MASK))
            raise_exception_err(s, EXCP0B_NOSEG, selector & 0xfffc);
#ifdef __x86_64__
        if (env->efer & MSR_EFER_LMA) {
            uint32_t e3;
            e3 = ldl_kernel(ptr + 8);
            load_seg_cache_raw_dt(&env->ldt, e1, e2);
            env->ldt.base |= (unsigned long)e3 << 32;
        } else
#endif
        {
            load_seg_cache_raw_dt(&env->ldt, e1, e2);
        }
    }
    env->ldt.selector = selector;
}

static void helper_wrmsr(struct kqemu_state *s)
{
#ifdef __x86_64__
    struct kqemu_cpu_state *env = &s->cpu_state;
#endif
    uint64_t val;

    val = ((uint32_t)s->regs1.eax) | 
        ((uint64_t)((uint32_t)s->regs1.edx) << 32);

    switch((uint32_t)s->regs1.ecx) {
#ifdef __x86_64__
    case MSR_FSBASE:
        env->segs[R_FS].base = val;
        wrmsrl(MSR_FSBASE, val);
        break;
    case MSR_GSBASE:
        env->segs[R_GS].base = val;
        wrmsrl(MSR_GSBASE, val);
        break;
    case MSR_KERNELGSBASE:
        env->kernelgsbase = val;
        break;
#endif
    default:
        raise_exception(s, KQEMU_RET_SOFTMMU);
    }
}

static void helper_rdmsr(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    uint64_t val;

    switch((uint32_t)s->regs1.ecx) {
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
#ifdef __x86_64__
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
#endif
    default:
        raise_exception(s, KQEMU_RET_SOFTMMU);
    }
    s->regs1.eax = (uint32_t)(val);
    s->regs1.edx = (uint32_t)(val >> 32);
}

#ifdef __x86_64__
static void helper_swapgs(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    uint64_t val;
    val = env->kernelgsbase;
    env->kernelgsbase = env->segs[R_GS].base;
    env->segs[R_GS].base = val;

    wrmsrl(MSR_GSBASE, val);
}
#endif

/* XXX: optimize by reloading just the needed fields ? */
static inline void reload_seg_cache2(struct kqemu_state *s, int seg_reg, 
                                     unsigned int selector)
{
    struct kqemu_segment_cache *sc;
    uint32_t e1, e2, sel;
    uint8_t *ptr;
    
    sel = (selector & ~7) | ((selector & 4) << 14);
    ptr = (uint8_t *)s->dt_table + ((NB_DT_TABLES - 1) << 17) + sel;
#ifndef USE_SEG_GP
    e1 = *(uint16_t *)(ptr + 2);
    e2 = *(uint32_t *)(ptr + 4);
    sc = &s->cpu_state.segs[seg_reg];
    /* only useful for SS and CS */
    if (seg_reg == R_CS || seg_reg == R_SS)
        sc->flags = e2;
    sc->base = (e1 | ((e2 & 0xff) << 16) | (e2 & 0xff000000));
    /* limit not needed */
#else
    e1 = *(uint32_t *)(ptr);
    e2 = *(uint32_t *)(ptr + 4);
    sc = &s->cpu_state.segs[seg_reg];
    sc->flags = e2;
    sc->base = get_seg_base(e1, e2);
    sc->limit = get_seg_limit(e1, e2);
#endif
}

#ifdef USE_SEG_GP
static inline void reload_seg_cache3(struct kqemu_state *s, int seg_reg, 
                                     unsigned int selector)
{
    struct kqemu_segment_cache *sc;
    unsigned int sel1, sel;
    uint32_t e1, e2;
    uint8_t *ptr;

    sc = &s->cpu_state.segs[seg_reg];
    sel1 = selector | 3;
    if (sel1 != 3) {
        if (sel1 == s->regs1.cs_sel || sel1 == s->regs1.ss_sel) {
            sel = (selector & ~7) | ((selector & 4) << 14);
            ptr = (uint8_t *)s->dt_table + sel;
            e1 = *(uint32_t *)(ptr);
            e2 = *(uint32_t *)(ptr + 4);
        } else {
            e1 = s->seg_desc_cache[seg_reg][0];
            e2 = s->seg_desc_cache[seg_reg][1];
        }
        sc->flags = e2;
        sc->base = get_seg_base(e1, e2);
        sc->limit = get_seg_limit(e1, e2);
    } else {
        sc->flags = 0;
        sc->base = 0;
        sc->limit = 0;
    }
}
#endif

void update_seg_cache(struct kqemu_state *s)
{
    uint16_t sel;

    /* we must reload the segment caches to have all the necessary
       values. Another solution could be to reload them on demand */
#ifdef USE_SEG_GP
    if (s->cpu_state.cpl != 3) {
        reload_seg_cache3(s, R_CS, s->regs1.cs_sel);
        reload_seg_cache3(s, R_SS, s->regs1.ss_sel);
#ifdef __x86_64__
        asm volatile ("mov %%ds, %0" : "=r" (sel));
#else
        sel = s->regs1.ds_sel;
#endif
        reload_seg_cache3(s, R_DS, sel);
#ifdef __x86_64__
        asm volatile ("mov %%es, %0" : "=r" (sel));
#else
        sel = s->regs1.es_sel;
#endif
        reload_seg_cache3(s, R_ES, sel);
        asm volatile ("mov %%fs, %0" : "=r" (sel));
        reload_seg_cache3(s, R_FS, sel);
        asm volatile ("mov %%gs, %0" : "=r" (sel));
        reload_seg_cache3(s, R_GS, sel);
    } else
#endif /* USE_SEG_GP */
    {
        reload_seg_cache2(s, R_CS, s->regs1.cs_sel);
        reload_seg_cache2(s, R_SS, s->regs1.ss_sel);
#ifdef __x86_64__
        {
            int sel;
            asm volatile ("mov %%ds, %0" : "=r" (sel));
            reload_seg_cache2(s, R_DS, sel);
            asm volatile ("mov %%es, %0" : "=r" (sel));
            reload_seg_cache2(s, R_ES, sel);
        }
#else
        reload_seg_cache2(s, R_DS, s->regs1.ds_sel);
        reload_seg_cache2(s, R_ES, s->regs1.es_sel);
#endif
        asm volatile ("mov %%fs, %0" : "=r" (sel));
        reload_seg_cache2(s, R_FS, sel);
        asm volatile ("mov %%gs, %0" : "=r" (sel));
        reload_seg_cache2(s, R_GS, sel);
    }
#ifdef __x86_64__
    rdmsrl(MSR_FSBASE, s->cpu_state.segs[R_FS].base);
    rdmsrl(MSR_GSBASE, s->cpu_state.segs[R_GS].base);
#endif
    s->seg_cache_loaded = 1;
    s->insn_count = MAX_INSN_COUNT;
}

/* handle the exception in the monitor */
void raise_exception_interp(void *opaque)
{
    struct kqemu_state *s = opaque;
    int intno = s->arg0;
#ifdef PROFILE_INTERP2
    int64_t ti;
#endif

#ifdef PROFILE_INTERP2
    ti = getclock();
#endif
    if (!s->seg_cache_loaded)
        update_seg_cache(s);

    /* the exception handling counts as one instruction so that we can
       detect exception loops */
    /* XXX: it would be better to detect double or triple faults */
    if (unlikely(--s->insn_count <= 0))
        raise_exception(s, KQEMU_RET_SOFTMMU);

    do_interrupt(s, intno, 0, s->cpu_state.error_code, 0, 0);

    if (!get_eflags_if(s)) {
        insn_interp(s);
    }
#ifdef PROFILE_INTERP2
    s->interp_interrupt_count++;
    s->interp_interrupt_cycles += (getclock() - ti);
#endif
    goto_user(s, s->regs);
}

#define MAX_INSN_LEN 15

static inline uint32_t ldub_code(struct kqemu_state *s)
{
    uint32_t val;

    val = ldub_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
    pc++;
    return val;
}

static inline uint32_t lduw_code(struct kqemu_state *s)
{
    uint32_t val;

    val = lduw_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
    pc += 2;
    return val;
}

static inline uint32_t ldl_code(struct kqemu_state *s)
{
    uint32_t val;

    val = ldl_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
    pc += 4;
    return val;
}

static inline uint64_t ldq_code(struct kqemu_state *s)
{
    uint64_t val;

    val = ldl_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
    val |= (uint64_t)ldl_mem_fast(s, pc + s->cpu_state.segs[R_CS].base + 4) << 32;
    pc += 8;
    return val;
}

static unsigned long __attribute__((regparm(2))) get_modrm(struct kqemu_state *s, int modrm)
{
    unsigned long disp, addr;
    int base;
    int index;
    int scale;
    int mod, rm, code, override;
    static const void *modrm_table32[0x88] = {
        [0x00] = &&modrm32_00,
        [0x01] = &&modrm32_01,
        [0x02] = &&modrm32_02,
        [0x03] = &&modrm32_03,
        [0x04] = &&modrm32_04,
        [0x05] = &&modrm32_05,
        [0x06] = &&modrm32_06,
        [0x07] = &&modrm32_07,

        [0x40] = &&modrm32_40,
        [0x41] = &&modrm32_41,
        [0x42] = &&modrm32_42,
        [0x43] = &&modrm32_43,
        [0x44] = &&modrm32_44,
        [0x45] = &&modrm32_45,
        [0x46] = &&modrm32_46,
        [0x47] = &&modrm32_47,
        
        [0x80] = &&modrm32_80,
        [0x81] = &&modrm32_81,
        [0x82] = &&modrm32_82,
        [0x83] = &&modrm32_83,
        [0x84] = &&modrm32_84,
        [0x85] = &&modrm32_85,
        [0x86] = &&modrm32_86,
        [0x87] = &&modrm32_87,
    };

    if (likely(s->aflag)) {
#if 1
        goto *modrm_table32[modrm & 0xc7];
    modrm32_44:
        /* sib, most common case ? */
        code = ldub_code(s);
        addr = (int8_t)ldub_code(s);
    do_sib:
        base = (code & 7) | REX_B(s);
        addr += get_reg(s, base);
        index = ((code >> 3) & 7) | REX_X(s);
        if (index != 4) {
            scale = (code >> 6);
            addr += get_reg(s, index) << scale;
        }
        goto next;
        
    modrm32_04:
        /* sib */
        code = ldub_code(s);
        base = (code & 7);
        if (base == 5) {
            addr = (int32_t)ldl_code(s);
            base = 0; /* force DS override */
        } else {
            base |= REX_B(s);
            addr = get_reg(s, base);
        }
        index = ((code >> 3) & 7) | REX_X(s);
        if (index != 4) {
            scale = (code >> 6);
            addr += get_reg(s, index) << scale;
        }
        goto next;
        
    modrm32_84:
        /* sib */
        code = ldub_code(s);
        addr = (int32_t)ldl_code(s);
        goto do_sib;
        
    modrm32_05:
        addr = (int32_t)ldl_code(s);
        base = 0; /* force DS override */
        if (CODE64(s)) 
            addr += pc + s->rip_offset;
        goto next;
    modrm32_00:
    modrm32_01:
    modrm32_02:
    modrm32_03:
    modrm32_06:
    modrm32_07:
        base = (modrm & 7) | REX_B(s);
        addr = get_reg(s, base);
        goto next;
        
    modrm32_40:
    modrm32_41:
    modrm32_42:
    modrm32_43:
    modrm32_45:
    modrm32_46:
    modrm32_47:
        addr = (int8_t)ldub_code(s);
        base = (modrm & 7) | REX_B(s);
        addr += get_reg(s, base);
        goto next;
    modrm32_80:
    modrm32_81:
    modrm32_82:
    modrm32_83:
    modrm32_85:
    modrm32_86:
    modrm32_87:
        addr = (int32_t)ldl_code(s);
        base = (modrm & 7) | REX_B(s);
        addr += get_reg(s, base);
    next:
        if (unlikely(s->popl_esp_hack)) {
            if (base == 4)
                addr += s->popl_esp_hack;
        }
#else
        int havesib;
        
        mod = (modrm >> 6) & 3;
        rm = modrm & 7;
        havesib = 0;
        base = rm;
        index = 0;
        scale = 0;
        
        if (base == 4) {
            havesib = 1;
            code = ldub_code(s);
            scale = (code >> 6) & 3;
            index = ((code >> 3) & 7) | REX_X(s);
            base = (code & 7);
        }
        base |= REX_B(s);

        switch (mod) {
        case 0:
            if ((base & 7) == 5) {
                base = -1;
                disp = (int32_t)ldl_code(s);
                if (CODE64(s) && !havesib) {
                    disp += pc + s->rip_offset;
                }
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)ldub_code(s);
            break;
        default:
        case 2:
            disp = (int32_t)ldl_code(s);
            break;
        }
        
        addr = disp;
        if (base >= 0) {
            /* for correct popl handling with esp */
            if (base == 4 && s->popl_esp_hack)
                addr += s->popl_esp_hack;
            addr += get_reg(s, base);
        }
        /* XXX: index == 4 is always invalid */
        if (havesib && (index != 4 || scale != 0)) {
            addr += get_reg(s, index) << scale;
        }
#endif
        override = s->override;
        if (CODE64(s)) {
            if (override == R_FS || override == R_GS)
                addr += s->cpu_state.segs[override].base;
            if (s->aflag != 2)
                addr = (uint32_t)addr;
        } else {
            if (override != -2) {
                if (override < 0) {
                    if (base == R_EBP || base == R_ESP)
                        override = R_SS;
                    else
                        override = R_DS;
                }
                addr += s->cpu_state.segs[override].base;
            }
            addr = (uint32_t)addr;
        }
    } else {
        mod = (modrm >> 6) & 3;
        rm = modrm & 7;
        switch (mod) {
        case 0:
            if (rm == 6) {
                disp = lduw_code(s);
                addr = disp;
                rm = 0; /* avoid SS override */
                goto no_rm;
            } else {
                disp = 0;
            }
            break;
        case 1:
            disp = (int8_t)ldub_code(s);
            break;
        default:
        case 2:
            disp = lduw_code(s);
            break;
        }
        switch(rm) {
        case 0:
            addr = s->regs1.ebx + s->regs1.esi;
            break;
        case 1:
            addr = s->regs1.ebx + s->regs1.edi;
            break;
        case 2:
            addr = s->regs1.ebp + s->regs1.esi;
            break;
        case 3:
            addr = s->regs1.ebp + s->regs1.edi;
            break;
        case 4:
            addr = s->regs1.esi;
            break;
        case 5:
            addr = s->regs1.edi;
            break;
        case 6:
            addr = s->regs1.ebp;
            break;
        default:
        case 7:
            addr = s->regs1.ebx;
            break;
        }
        addr += disp;
        addr &= 0xffff;
    no_rm:
        override = s->override;
        if (override != -2) {
            if (override < 0) {
                if (rm == 2 || rm == 3 || rm == 6)
                    override = R_SS;
                else
                    override = R_DS;
            }
            addr += s->cpu_state.segs[override].base;
        }
    }
#ifdef DEBUG_INTERP    
    monitor_log(s, "get_modrm: addr=%08lx\n", addr);
#endif
    return addr;
}

/* operand size */
enum {
    OT_BYTE = 0,
    OT_WORD,
    OT_LONG, 
    OT_QUAD,
};

static inline int insn_const_size(unsigned int ot)
{
    if (ot <= OT_LONG)
        return 1 << ot;
    else
        return 4;
}

static inline int insn_get(struct kqemu_state *s, int ot)
{
    int ret;

    switch(ot) {
    case OT_BYTE:
        ret = ldub_code(s);
        break;
    case OT_WORD:
        ret = lduw_code(s);
        break;
    default:
    case OT_LONG:
        ret = ldl_code(s);
        break;
    }
    return ret;
}

#define EB_ADD (0 * 4)
#define EB_AND (4 * 4)
#define EB_SUB (5 * 4)
#define EB_INC (8 * 4)
#define EB_DEC (9 * 4)
#define EB_ROL (10 * 4)
#define EB_BT  (18 * 4)
#define EB_BSF (22 * 4)

#ifdef __x86_64__
#define UPDATE_CODE32()\
{\
    if (CODE64(s)) {\
        code32 = 1;\
        flags_initval = 0x00ff0201;\
    } else {\
        code32 = (s->cpu_state.segs[R_CS].flags >> DESC_B_SHIFT) & 1;\
        flags_initval = code32 | (code32 << 8) | 0x00ff0000;\
    }\
}
#else
#define UPDATE_CODE32()\
{\
    code32 = (s->cpu_state.segs[R_CS].flags >> DESC_B_SHIFT) & 1;\
    flags_initval = code32 | (code32 << 8) | 0x00ff0000;\
}
#endif

#ifdef __x86_64__

#define LOAD_CC()\
        "push %%rcx\n"\
        "andl $0x8d5, %%ecx\n"\
        "pushf\n"\
        "pop %%rax\n"\
        "andl $~0x8d5, %%eax\n"\
        "orl %%ecx, %%eax\n"\
        "pop %%rcx\n"\
        "push %%rax\n"\
        "popf\n"

#define SAVE_CC()\
        "pushf\n"\
        "pop %%rax\n"\
        "andl $0x8d5, %%eax\n"\
        "andl $~0x8d5, %%ecx\n"\
        "orl %%eax, %%ecx\n"

#define SAVE_CC_LOGIC() SAVE_CC()

/* XXX: suppress */
#define SAHF ".byte 0x9e"
#define LAHF ".byte 0x9f"

#else

#ifdef __x86_64__
#define SAHF ".byte 0x9e"
#define LAHF ".byte 0x9f"
#else
#define SAHF "sahf"
#define LAHF "lahf"
#endif

#define LOAD_CC()\
    "movb %%cl, %%ah\n"\
    SAHF "\n"

#define SAVE_CC()\
    LAHF "\n"\
    "seto %%al\n"\
    "movb %%ah, %%cl\n"\
    "shll $3, %%eax\n"\
    "andl $~0x0800, %%ecx\n"\
    "orb %%al, %%ch\n"

#define SAVE_CC_LOGIC()\
    LAHF "\n"\
    "movb %%ah, %%cl\n"\
    "andl $~0x0800, %%ecx\n"

#endif /* !__x86_64__ */

/* return -1 if unsupported insn */
int insn_interp(struct kqemu_state *s)
{
    int b, sel, ot;
    int modrm, mod, op, code32, reg, rm, iopl;
    long val, val2;
    unsigned long next_eip, addr, saved_pc, eflags;
    uint32_t flags_initval;
#ifdef PROFILE_INSN
    int opcode;
    int64_t ti;
#endif

#ifdef __x86_64__
#define NB_INSN_TABLES 3
#else
#define NB_INSN_TABLES 2
#endif
    static const void *insn_table[NB_INSN_TABLES][512] = {
        {
#define INSN(x) &&insn_ ## x,
#define INSN_S(x) &&insn_ ## x ## w,
#include "insn_table.h"
#undef INSN_S
#undef INSN
        },
        {
#define INSN(x) &&insn_ ## x,
#define INSN_S(x) &&insn_ ## x ## l,
#include "insn_table.h"
#undef INSN_S
#undef INSN
        },
#ifdef __x86_64__
        {
#define INSN(x) &&insn_ ## x,
#define INSN_S(x) &&insn_ ## x ## q,
#include "insn_table.h"
#undef INSN_S
#undef INSN
        },
#endif
    };

#define LABEL(x) insn_ ## x: asm volatile(".globl insn_" #x " ; insn_" #x ":\n") ; 

    saved_pc = pc; /* save register variable */
#ifdef PROFILE_INTERP2
    s->total_interp_count++;
#endif
    s->popl_esp_hack = 0;
    s->rip_offset = 0; /* for relative ip address */
    UPDATE_CODE32();
    pc = s->regs1.eip;
    goto insn_next2;
 insn_next:
    s->regs1.eip = pc;
    if (unlikely(get_eflags_if(s)))
        goto the_end;
    /* XXX: since we run with the IRQs disabled, it is better to
       stop executing after a few instructions */
 insn_next3:
    if (unlikely(--s->insn_count <= 0))
        raise_exception(s, KQEMU_RET_SOFTMMU);
 insn_next2:
#if defined(DEBUG_INTERP)
    monitor_log(s, "%05d: %04x:" FMT_lx " %04x:" FMT_lx " eax=" FMT_lx "\n",
                s->insn_count,
                get_seg_sel(s, R_CS),
                (long)s->regs1.eip, 
                get_seg_sel(s, R_SS),
                (long)s->regs1.esp, 
                (long)s->regs1.eax);
#endif
#ifdef __x86_64__
    *(uint64_t *)&s->dflag = flags_initval;
#else
    *(uint32_t *)&s->dflag = flags_initval;
#endif
#ifdef PROFILE_INSN
    ti = getclock();
#endif
 next_byte:
    /* XXX: more precise test */
    if (unlikely((pc - (unsigned long)&_start) < MONITOR_MEM_SIZE))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    b = ldub_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
    pc++;
 reswitch:
#ifdef PROFILE_INSN
    opcode = b;
#endif
    goto *insn_table[s->dflag][b];

    /* prefix processing */
        LABEL(f3)
            s->prefix |= PREFIX_REPZ;
            goto next_byte;
        LABEL(f2)
            s->prefix |= PREFIX_REPNZ;
            goto next_byte;
        LABEL(f0)
            s->prefix |= PREFIX_LOCK;
            goto next_byte;
        LABEL(2e)
            s->override = R_CS;
            goto next_byte;
        LABEL(36)
            s->override = R_SS;
            goto next_byte;
        LABEL(3e)
            s->override = R_DS;
            goto next_byte;
        LABEL(26)
            s->override = R_ES;
            goto next_byte;
        LABEL(64)
            s->override = R_FS;
            goto next_byte;
        LABEL(65)
            s->override = R_GS;
            goto next_byte;
        LABEL(66)
            s->dflag = !code32;
            goto next_byte;
        LABEL(67)
            if (CODE64(s))
                s->aflag = 1;
            else
                s->aflag = !code32;
            goto next_byte;

#ifdef __x86_64__
        rex_prefix:
            {
                int rex_w;
                /* REX prefix */
                rex_w = (b >> 3) & 1;
                s->rex_r = (b & 0x4) << 1;
                s->rex_x = (b & 0x2) << 2;
                s->rex_b = (b & 0x1) << 3;
                s->prefix |= PREFIX_REX;
                
                /* we suppose, as in the AMD spec, that it comes after the
                   legacy prefixes */
                if (rex_w == 1) {
                    /* 0x66 is ignored if rex.w is set */
                    s->dflag = 2;
                }
            }
            goto next_byte;
#endif
        LABEL(0f)
            /**************************/
            /* extended op code */
            b = ldub_code(s) | 0x100;
            goto reswitch;

        /**************************/
        /* arith & logic */

#define ARITH_OP(op, eflags, val, val2)\
                asm volatile(op "\n"\
                              SAVE_CC()\
                             : "=c" (eflags),\
                               "=q" (val)\
                             : "0" (eflags),\
                               "1" (val),\
                               "q" (val2)\
                             : "%eax");\

#define ARITH_OPC(op, eflags, val, val2)\
                asm volatile(LOAD_CC() \
                              op "\n"\
                              SAVE_CC()\
                             : "=c" (eflags),\
                               "=q" (val)\
                             : "0" (eflags),\
                               "1" (val),\
                               "q" (val2)\
                             : "%eax");

#define LOGIC_OP(op, eflags, val, val2)\
                asm volatile(op "\n"\
                              SAVE_CC_LOGIC()\
                             : "=c" (eflags),\
                               "=q" (val)\
                             : "0" (eflags),\
                               "1" (val),\
                               "q" (val2)\
                             : "%eax");

#define ARITH_EXEC(eflags, op, ot, val, val2)\
            switch(ot) {\
            case OT_BYTE:\
                switch(op) {\
                case 0: ARITH_OP("addb %b4, %b1", eflags, val, val2); break;\
                case 1: LOGIC_OP("orb %b4, %b1", eflags, val, val2); break;\
                case 2: ARITH_OPC("adcb %b4, %b1", eflags, val, val2); break;\
                case 3: ARITH_OPC("sbbb %b4, %b1", eflags, val, val2); break;\
                case 4: LOGIC_OP("andb %b4, %b1", eflags, val, val2); break;\
                case 5: ARITH_OP("subb %b4, %b1", eflags, val, val2); break;\
                case 6: LOGIC_OP("xorb %b4, %b1", eflags, val, val2); break;\
                default: ARITH_OP("cmpb %b4, %b1", eflags, val, val2); break;\
                }\
                break;\
            case OT_WORD:\
                switch(op) {\
                case 0: ARITH_OP("addw %w4, %w1", eflags, val, val2); break;\
                case 1: LOGIC_OP("orw %w4, %w1", eflags, val, val2); break;\
                case 2: ARITH_OPC("adcw %w4, %w1", eflags, val, val2); break;\
                case 3: ARITH_OPC("sbbw %w4, %w1", eflags, val, val2); break;\
                case 4: LOGIC_OP("andw %w4, %w1", eflags, val, val2); break;\
                case 5: ARITH_OP("subw %w4, %w1", eflags, val, val2); break;\
                case 6: LOGIC_OP("xorw %w4, %w1", eflags, val, val2); break;\
                default: ARITH_OP("cmpw %w4, %w1", eflags, val, val2); break;\
                }\
                break;\
            case OT_LONG:\
                switch(op) {\
                case 0: ARITH_OP("addl %k4, %k1", eflags, val, val2); break;\
                case 1: LOGIC_OP("orl %k4, %k1", eflags, val, val2); break;\
                case 2: ARITH_OPC("adcl %k4, %k1", eflags, val, val2); break;\
                case 3: ARITH_OPC("sbbl %k4, %k1", eflags, val, val2); break;\
                case 4: LOGIC_OP("andl %k4, %k1", eflags, val, val2); break;\
                case 5: ARITH_OP("subl %k4, %k1", eflags, val, val2); break;\
                case 6: LOGIC_OP("xorl %k4, %k1", eflags, val, val2); break;\
                default: ARITH_OP("cmpl %k4, %k1", eflags, val, val2); break;\
                }\
                break;\
            QO(case OT_QUAD:\
                switch(op) {\
                case 0: ARITH_OP("addq %4, %1", eflags, val, val2); break;\
                case 1: LOGIC_OP("orq %4, %1", eflags, val, val2); break;\
                case 2: ARITH_OPC("adcq %4, %1", eflags, val, val2); break;\
                case 3: ARITH_OPC("sbbq %4, %1", eflags, val, val2); break;\
                case 4: LOGIC_OP("andq %4, %1", eflags, val, val2); break;\
                case 5: ARITH_OP("subq %4, %1", eflags, val, val2); break;\
                case 6: LOGIC_OP("xorq %4, %1", eflags, val, val2); break;\
                default: ARITH_OP("cmpq %4, %1", eflags, val, val2); break;\
                }\
                break;)\
            }

#define ARITH_Ev_Gv(op, ot) \
                    { int modrm, reg, mod; unsigned long val, val2, eflags;\
                    modrm = ldub_code(s);\
                    reg = ((modrm >> 3) & 7) | REX_R(s);\
                    mod = (modrm >> 6);\
                    val2 = get_regS(s, ot, reg);\
                    if (mod != 3) {\
                        addr = get_modrm(s, modrm);\
                        val = ldS(s, ot, addr);\
                        eflags = s->regs1.eflags;\
                        ARITH_EXEC(eflags, op, ot, val, val2);\
                        if (op != 7)\
                            stS(s, ot, addr, val);\
                        s->regs1.eflags = eflags;\
                    } else {\
                        rm = (modrm & 7) | REX_B(s);\
                        val = get_regS(s, ot, rm);\
                        ARITH_EXEC(s->regs1.eflags, op, ot, val, val2);\
                        if (op != 7)\
                            set_regS(s, ot, rm, val);\
                    }\
                    }\
                    goto insn_next;

#define ARITH_Gv_Ev(op, ot)\
                    modrm = ldub_code(s);\
                    mod = (modrm >> 6);\
                    reg = ((modrm >> 3) & 7) | REX_R(s);\
                    if (mod != 3) {\
                        addr = get_modrm(s, modrm);\
                        val2 = ldS(s, ot, addr);\
                    } else {\
                        rm = (modrm & 7) | REX_B(s);\
                        val2 = get_regS(s, ot, rm);\
                    }\
                    val = get_regS(s, ot, reg);\
                    ARITH_EXEC(s->regs1.eflags, op, ot, val, val2);\
                    if (op != 7)\
                        set_regS(s, ot, reg, val);\
                    goto insn_next;

#define ARITH_A_Iv(op, ot)\
                    if (ot == 0)\
                        val2 = (int8_t)ldub_code(s);\
                    else if (ot == 1)\
                        val2 = (int16_t)lduw_code(s);\
                    else\
                        val2 = (int32_t)ldl_code(s);\
                    val = s->regs1.eax;\
                    ARITH_EXEC(s->regs1.eflags, op, ot, val, val2);\
                    if (op != 7)\
                        set_regS(s, ot, R_EAX, val);\
                    goto insn_next;


        LABEL(00) ARITH_Ev_Gv(0, OT_BYTE);
        LABEL(01w) ARITH_Ev_Gv(0, OT_WORD);
        LABEL(01l) ARITH_Ev_Gv(0, OT_LONG);
    QO( LABEL(01q) ARITH_Ev_Gv(0, OT_QUAD); )
        LABEL(02) ARITH_Gv_Ev(0, OT_BYTE);
        LABEL(03w)  ARITH_Gv_Ev(0, OT_WORD);
        LABEL(03l)  ARITH_Gv_Ev(0, OT_LONG);
    QO( LABEL(03q)  ARITH_Gv_Ev(0, OT_QUAD); )
        LABEL(04) ARITH_A_Iv(0, OT_BYTE);
        LABEL(05w) ARITH_A_Iv(0, OT_WORD);
        LABEL(05l) ARITH_A_Iv(0, OT_LONG);
    QO( LABEL(05q) ARITH_A_Iv(0, OT_QUAD); )

        LABEL(08) ARITH_Ev_Gv(1, OT_BYTE);
        LABEL(09w) ARITH_Ev_Gv(1, OT_WORD);
        LABEL(09l) ARITH_Ev_Gv(1, OT_LONG);
    QO( LABEL(09q) ARITH_Ev_Gv(1, OT_QUAD); )
        LABEL(0a) ARITH_Gv_Ev(1, OT_BYTE);
        LABEL(0bw)  ARITH_Gv_Ev(1, OT_WORD);
        LABEL(0bl)  ARITH_Gv_Ev(1, OT_LONG);
    QO( LABEL(0bq)  ARITH_Gv_Ev(1, OT_QUAD); )
        LABEL(0c) ARITH_A_Iv(1, OT_BYTE);
        LABEL(0dw) ARITH_A_Iv(1, OT_WORD);
        LABEL(0dl) ARITH_A_Iv(1, OT_LONG);
    QO( LABEL(0dq) ARITH_A_Iv(1, OT_QUAD); )

        LABEL(10) ARITH_Ev_Gv(2, OT_BYTE);
        LABEL(11w) ARITH_Ev_Gv(2, OT_WORD);
        LABEL(11l) ARITH_Ev_Gv(2, OT_LONG);
    QO( LABEL(11q) ARITH_Ev_Gv(2, OT_QUAD); )
        LABEL(12) ARITH_Gv_Ev(2, OT_BYTE);
        LABEL(13w)  ARITH_Gv_Ev(2, OT_WORD);
        LABEL(13l)  ARITH_Gv_Ev(2, OT_LONG);
    QO( LABEL(13q)  ARITH_Gv_Ev(2, OT_QUAD); )
        LABEL(14) ARITH_A_Iv(2, OT_BYTE);
        LABEL(15w) ARITH_A_Iv(2, OT_WORD);
        LABEL(15l) ARITH_A_Iv(2, OT_LONG);
    QO( LABEL(15q) ARITH_A_Iv(2, OT_QUAD); )

        LABEL(18) ARITH_Ev_Gv(3, OT_BYTE);
        LABEL(19w) ARITH_Ev_Gv(3, OT_WORD);
        LABEL(19l) ARITH_Ev_Gv(3, OT_LONG);
    QO( LABEL(19q) ARITH_Ev_Gv(3, OT_QUAD); )
        LABEL(1a) ARITH_Gv_Ev(3, OT_BYTE);
        LABEL(1bw)  ARITH_Gv_Ev(3, OT_WORD);
        LABEL(1bl)  ARITH_Gv_Ev(3, OT_LONG);
    QO( LABEL(1bq)  ARITH_Gv_Ev(3, OT_QUAD); )
        LABEL(1c) ARITH_A_Iv(3, OT_BYTE);
        LABEL(1dw) ARITH_A_Iv(3, OT_WORD);
        LABEL(1dl) ARITH_A_Iv(3, OT_LONG);
    QO( LABEL(1dq) ARITH_A_Iv(3, OT_QUAD); )

        LABEL(20) ARITH_Ev_Gv(4, OT_BYTE);
        LABEL(21w) ARITH_Ev_Gv(4, OT_WORD);
        LABEL(21l) ARITH_Ev_Gv(4, OT_LONG);
    QO( LABEL(21q) ARITH_Ev_Gv(4, OT_QUAD); )
        LABEL(22) ARITH_Gv_Ev(4, OT_BYTE);
        LABEL(23w)  ARITH_Gv_Ev(4, OT_WORD);
        LABEL(23l)  ARITH_Gv_Ev(4, OT_LONG);
    QO( LABEL(23q)  ARITH_Gv_Ev(4, OT_QUAD); )
        LABEL(24) ARITH_A_Iv(4, OT_BYTE);
        LABEL(25w) ARITH_A_Iv(4, OT_WORD);
        LABEL(25l) ARITH_A_Iv(4, OT_LONG);
    QO( LABEL(25q) ARITH_A_Iv(4, OT_QUAD); )

        LABEL(28) ARITH_Ev_Gv(5, OT_BYTE);
        LABEL(29w) ARITH_Ev_Gv(5, OT_WORD);
        LABEL(29l) ARITH_Ev_Gv(5, OT_LONG);
    QO( LABEL(29q) ARITH_Ev_Gv(5, OT_QUAD); )
        LABEL(2a) ARITH_Gv_Ev(5, OT_BYTE);
        LABEL(2bw)  ARITH_Gv_Ev(5, OT_WORD);
        LABEL(2bl)  ARITH_Gv_Ev(5, OT_LONG);
    QO( LABEL(2bq)  ARITH_Gv_Ev(5, OT_QUAD); )
        LABEL(2c) ARITH_A_Iv(5, OT_BYTE);
        LABEL(2dw) ARITH_A_Iv(5, OT_WORD);
        LABEL(2dl) ARITH_A_Iv(5, OT_LONG);
    QO( LABEL(2dq) ARITH_A_Iv(5, OT_QUAD); )

        LABEL(30) ARITH_Ev_Gv(6, OT_BYTE);
        LABEL(31w) ARITH_Ev_Gv(6, OT_WORD);
        LABEL(31l) ARITH_Ev_Gv(6, OT_LONG);
    QO( LABEL(31q) ARITH_Ev_Gv(6, OT_QUAD); )
        LABEL(32) ARITH_Gv_Ev(6, OT_BYTE);
        LABEL(33w)  ARITH_Gv_Ev(6, OT_WORD);
        LABEL(33l)  ARITH_Gv_Ev(6, OT_LONG);
    QO( LABEL(33q)  ARITH_Gv_Ev(6, OT_QUAD); )
        LABEL(34) ARITH_A_Iv(6, OT_BYTE);
        LABEL(35w) ARITH_A_Iv(6, OT_WORD);
        LABEL(35l) ARITH_A_Iv(6, OT_LONG);
    QO( LABEL(35q) ARITH_A_Iv(6, OT_QUAD); )

        LABEL(38) ARITH_Ev_Gv(7, OT_BYTE);
        LABEL(39w) ARITH_Ev_Gv(7, OT_WORD);
        LABEL(39l) ARITH_Ev_Gv(7, OT_LONG);
    QO( LABEL(39q) ARITH_Ev_Gv(7, OT_QUAD); )
        LABEL(3a) ARITH_Gv_Ev(7, OT_BYTE);
        LABEL(3bw)  ARITH_Gv_Ev(7, OT_WORD);
        LABEL(3bl)  ARITH_Gv_Ev(7, OT_LONG);
    QO( LABEL(3bq)  ARITH_Gv_Ev(7, OT_QUAD); )
        LABEL(3c) ARITH_A_Iv(7, OT_BYTE);
        LABEL(3dw) ARITH_A_Iv(7, OT_WORD);
        LABEL(3dl) ARITH_A_Iv(7, OT_LONG);
    QO( LABEL(3dq) ARITH_A_Iv(7, OT_QUAD); )

#define ARITH_GRP1(b, ot) \
            modrm = ldub_code(s);\
            mod = (modrm >> 6);\
            op = (modrm >> 3) & 7;\
            if (mod != 3) {\
                if (b == 0x83)\
                    s->rip_offset = 1;\
                else\
                    s->rip_offset = insn_const_size(ot);\
                addr = get_modrm(s, modrm);\
                s->rip_offset = 0;\
                val = ldS(s, ot, addr);\
                switch(b) {\
                default:\
                case 0x80:\
                case 0x81:\
                case 0x82:\
                    val2 = insn_get(s, ot);\
                    break;\
                case 0x83:\
                    val2 = (int8_t)ldub_code(s);\
                    break;\
                }\
                eflags = s->regs1.eflags;\
                ARITH_EXEC(eflags, op, ot, val, val2);\
                if (op != 7)\
                    stS(s, ot, addr, val);\
                s->regs1.eflags = eflags;\
            } else {\
                rm = (modrm & 7) | REX_B(s);\
                val = get_regS(s, ot, rm);\
                switch(b) {\
                default:\
                case 0x80:\
                case 0x81:\
                case 0x82:\
                    val2 = insn_get(s, ot);\
                    break;\
                case 0x83:\
                    val2 = (int8_t)ldub_code(s);\
                    break;\
                }\
                ARITH_EXEC(s->regs1.eflags, op, ot, val, val2);\
                if (op != 7)\
                    set_regS(s, ot, rm, val);\
            }\
            goto insn_next;
            
        LABEL(80) /* GRP1 */
        LABEL(82)
            ARITH_GRP1(0x80, OT_BYTE);
        LABEL(81w) ARITH_GRP1(0x81, OT_WORD);
        LABEL(81l) ARITH_GRP1(0x81, OT_LONG);
    QO( LABEL(81q) ARITH_GRP1(0x81, OT_QUAD); )
        LABEL(83w) ARITH_GRP1(0x83, OT_WORD);
        LABEL(83l) ARITH_GRP1(0x83, OT_LONG);
    QO( LABEL(83q) ARITH_GRP1(0x83, OT_QUAD); )

        LABEL(84) /* test Ev, Gv */
        LABEL(85) 
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                val = ldS(s, ot, addr);
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
            }
            reg = ((modrm >> 3) & 7) | REX_R(s);
            val2 = get_regS(s, ot, reg);
            exec_binary(&s->regs1.eflags, 
                        EB_AND + ot, 
                        val, val2);
            goto insn_next;

        LABEL(a8) /* test eAX, Iv */
        LABEL(a9)
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            val2 = insn_get(s, ot);

            val = get_regS(s, ot, R_EAX);
            exec_binary(&s->regs1.eflags, 
                        EB_AND + ot, 
                        val, val2);
            goto insn_next;
            
        LABEL(40) /* inc Gv */
        LABEL(41)
        LABEL(42)
        LABEL(43)
        LABEL(44)
        LABEL(45)
        LABEL(46)
        LABEL(47)

        LABEL(48) /* dec Gv */
        LABEL(49)
        LABEL(4a)
        LABEL(4b)
        LABEL(4c)
        LABEL(4d)
        LABEL(4e)
        LABEL(4f)
#ifdef __x86_64__
            if (CODE64(s))
                goto rex_prefix;
#endif
            ot = s->dflag + OT_WORD;
            reg = b & 7;
            val = get_regS(s, ot, reg);
            val = exec_binary(&s->regs1.eflags, 
                              EB_INC + ((b >> 1) & 4) + ot, 
                              val, 0);
            set_regS(s, ot, reg, val);
            goto insn_next;

        LABEL(f6) /* GRP3 */
        LABEL(f7)
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            rm = (modrm & 7) | REX_B(s);
            op = (modrm >> 3) & 7;

            switch(op) {
            case 0: /* test */
                if (mod != 3) {
                    s->rip_offset = insn_const_size(ot);
                    addr = get_modrm(s, modrm);
                    s->rip_offset = 0;
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                val2 = insn_get(s, ot);
                exec_binary(&s->regs1.eflags, 
                            EB_AND + ot, 
                            val, val2);
                break;
            case 2: /* not */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                    val = ~val;
                    stS(s, ot, addr, val);
                } else {
                    val = get_regS(s, ot, rm);
                    val = ~val;
                    set_regS(s, ot, rm, val);
                }
                break;
            case 3: /* neg */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                    eflags = s->regs1.eflags;
                    val = exec_binary(&eflags, EB_SUB + ot, 
                                      0, val);
                    stS(s, ot, addr, val);
                    s->regs1.eflags = eflags;
                } else {
                    val = get_regS(s, ot, rm);
                    val = exec_binary(&s->regs1.eflags, EB_SUB + ot, 
                                      0, val);
                    set_regS(s, ot, rm, val);
                }
                break;
            case 4: /* mul */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                switch(ot) {
                case OT_BYTE:
                    asm volatile(LOAD_CC()
                                 "movb %1, %%al\n"
                                 "mulb %4\n"
                                 "movw %%ax, %1\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax");
                    break;
                case OT_WORD:
                    asm volatile(LOAD_CC()
                                 "movw %1, %%ax\n"
                                 "mulw %5\n"
                                 "movw %%ax, %1\n"
                                 "movw %%dx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
                case OT_LONG:
                    asm volatile(LOAD_CC()
                                 "movl %1, %%eax\n"
                                 "mull %5\n"
                                 "movl %%eax, %1\n"
                                 "movl %%edx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
#ifdef __x86_64__
                case OT_QUAD:
                    asm volatile(LOAD_CC()
                                 "movq %1, %%rax\n"
                                 "mulq %5\n"
                                 "movq %%rax, %1\n"
                                 "movq %%rdx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%rax", "%rdx");
                    break;
#endif
                }
                break;
            case 5: /* imul */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                switch(ot) {
                case OT_BYTE:
                    asm volatile(LOAD_CC()
                                 "movb %1, %%al\n"
                                 "imulb %4\n"
                                 "movw %%ax, %1\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax");
                    break;
                case OT_WORD:
                    asm volatile(LOAD_CC()
                                 "movw %1, %%ax\n"
                                 "imulw %5\n"
                                 "movw %%ax, %1\n"
                                 "movw %%dx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
                case OT_LONG:
                    asm volatile(LOAD_CC()
                                 "movl %1, %%eax\n"
                                 "imull %5\n"
                                 "movl %%eax, %1\n"
                                 "movl %%edx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
#ifdef __x86_64__
                case OT_QUAD:
                    asm volatile(LOAD_CC()
                                 "movq %1, %%rax\n"
                                 "imulq %5\n"
                                 "movq %%rax, %1\n"
                                 "movq %%rdx, %2\n"
                                 SAVE_CC()
                                 : "=c" (s->regs1.eflags),
                                   "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "0" (s->regs1.eflags),
                                   "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%rax", "%rdx");
                    break;
#endif
                }
                break;
            case 6: /* div */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                switch(ot) {
                case OT_BYTE:
                    asm volatile("movw %0, %%ax\n"
                                 "1: divb %2\n"
                                 SEG_EXCEPTION(1b)
                                 "movw %%ax, %0\n"
                                 : "=m" (s->regs1.eax)
                                 : "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax");
                    break;
                case OT_WORD:
                    asm volatile("movw %0, %%ax\n"
                                 "movw %1, %%dx\n"
                                 "1: divw %4\n"
                                 SEG_EXCEPTION(1b)
                                 "movw %%ax, %0\n"
                                 "movw %%dx, %1\n"
                                 : "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "m" (s->regs1.eax),
                                   "m" (s->regs1.edx),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
                case OT_LONG:
                    asm volatile("1: divl %4\n"
                                 SEG_EXCEPTION(1b)
                                 : "=a" (s->regs1.eax),
                                   "=d" (s->regs1.edx)
                                 : "0" (s->regs1.eax),
                                   "1" (s->regs1.edx),
                                   "m" (val));
                    break;
#ifdef __x86_64__
                case OT_QUAD:
                    asm volatile("movq %0, %%rax\n"
                                 "movq %1, %%rdx\n"
                                 "1: divq %4\n"
                                 SEG_EXCEPTION(1b)
                                 "movq %%rax, %0\n"
                                 "movq %%rdx, %1\n"
                                 : "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "m" (s->regs1.eax),
                                   "m" (s->regs1.edx),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
#endif
                }
                break;
            case 7: /* idiv */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                switch(ot) {
                case OT_BYTE:
                    asm volatile("movw %0, %%ax\n"
                                 "1: idivb %2\n"
                                 SEG_EXCEPTION(1b)
                                 "movw %%ax, %0\n"
                                 : "=m" (s->regs1.eax)
                                 : "m" (s->regs1.eax),
                                   "m" (val)
                                 : "%eax");
                    break;
                case OT_WORD:
                    asm volatile("movw %0, %%ax\n"
                                 "movw %1, %%dx\n"
                                 "1: idivw %4\n"
                                 SEG_EXCEPTION(1b)
                                 "movw %%ax, %0\n"
                                 "movw %%dx, %1\n"
                                 : "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "m" (s->regs1.eax),
                                   "m" (s->regs1.edx),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
                case OT_LONG:
                    asm volatile("1: idivl %4\n"
                                 SEG_EXCEPTION(1b)
                                 : "=a" (s->regs1.eax),
                                   "=d" (s->regs1.edx)
                                 : "0" (s->regs1.eax),
                                   "1" (s->regs1.edx),
                                   "m" (val));
                    break;
#ifdef __x86_64__
                case OT_QUAD:
                    asm volatile("movq %0, %%rax\n"
                                 "movq %1, %%rdx\n"
                                 "1: idivq %4\n"
                                 SEG_EXCEPTION(1b)
                                 "movq %%rax, %0\n"
                                 "movq %%rdx, %1\n"
                                 : "=m" (s->regs1.eax),
                                   "=m" (s->regs1.edx)
                                 : "m" (s->regs1.eax),
                                   "m" (s->regs1.edx),
                                   "m" (val)
                                 : "%eax", "%edx");
                    break;
#endif
                }
                break;
            default:
                goto illegal_op;
            }
            goto insn_next;

        LABEL(69) /* imul Gv, Ev, I */
        LABEL(6b)
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            if (mod != 3) {
                if (b == 0x69)
                    s->rip_offset = insn_const_size(ot);
                else
                    s->rip_offset = 1;
                addr = get_modrm(s, modrm);
                s->rip_offset = 0;
                val = ldS(s, ot, addr);
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
            }
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (b == 0x69) {
                val2 = insn_get(s, ot);
            } else {
                val2 = (int8_t)ldub_code(s);
            }
            reg = ((modrm >> 3) & 7) | REX_R(s);
            goto do_imul;
        LABEL(1af) /* imul Gv, Ev */
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                val = ldS(s, ot, addr);
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
            }
            reg = ((modrm >> 3) & 7) | REX_R(s);
            val2 = get_regS(s, ot, reg);
        do_imul:
            switch(ot) {
            case OT_WORD:
                asm volatile(LOAD_CC()
                             "imulw %w4, %w1\n"
                             SAVE_CC()
                             : "=c" (s->regs1.eflags),
                               "=r" (val)
                             : "0" (s->regs1.eflags),
                               "1" (val),
                               "r" (val2)
                             : "%eax");
                    break;
            case OT_LONG:
                asm volatile(LOAD_CC()
                             "imull %k4, %k1\n"
                             SAVE_CC()
                             : "=c" (s->regs1.eflags),
                               "=r" (val)
                             : "0" (s->regs1.eflags),
                               "1" (val),
                               "r" (val2)
                             : "%eax");
                    break;
#ifdef __x86_64__
            case OT_QUAD:
                asm volatile(LOAD_CC()
                             "imulq %4, %1\n"
                             SAVE_CC()
                             : "=c" (s->regs1.eflags),
                               "=r" (val)
                             : "0" (s->regs1.eflags),
                               "1" (val),
                               "r" (val2)
                             : "%eax");
                break;
#endif
            }
            set_regS(s, ot, reg, val);
            goto insn_next;

        LABEL(fe) /* GRP4 */
        LABEL(ff) /* GRP5 */
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            rm = (modrm & 7) | REX_B(s);
            op = (modrm >> 3) & 7;
            
            switch(op) {
            case 0: /* inc Ev */
            case 1: /* dec Ev */
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                    eflags = s->regs1.eflags;
                    val = exec_binary(&eflags, 
                                      EB_INC + (op << 2) + ot, 
                                      val, 0);
                    stS(s, ot, addr, val);
                    s->regs1.eflags = eflags;
                } else {
                    val = get_regS(s, ot, rm);
                    val = exec_binary(&s->regs1.eflags, 
                                      EB_INC + (op << 2) + ot, 
                                      val, 0);
                    set_regS(s, ot, rm, val);
                }
                break;
            case 2: /* call Ev */
                if (ot == OT_BYTE)
                    goto illegal_op;
                if (CODE64(s))
                    ot = OT_QUAD;
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                if (ot == OT_WORD)
                    val &= 0xffff;
                next_eip = pc;
                stack_push(s, next_eip);
                pc = val;
                goto insn_next;
            case 4: /* jmp Ev */
                if (ot == OT_BYTE)
                    goto illegal_op;
                if (CODE64(s))
                    ot = OT_QUAD;
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                if (ot == OT_WORD)
                    val &= 0xffff;
                pc = val;
                goto insn_next;
            case 3: /* lcall Ev */
            case 5: /* ljmp Ev */
                if (ot == OT_BYTE)
                    goto illegal_op;
                raise_exception(s, KQEMU_RET_SOFTMMU);
                
            case 6: /* push Ev */
                if (ot == OT_BYTE)
                    goto illegal_op;
                if (CODE64(s) && s->dflag)
                    ot = OT_QUAD;
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                } else {
                    val = get_regS(s, ot, rm);
                }
                stack_push(s, val);
                break;
            default:
                goto unhandled_op;
            }
            goto insn_next;

        LABEL(50w) /* push w */
        LABEL(51w)
        LABEL(52w)
        LABEL(53w)
        LABEL(54w)
        LABEL(55w)
        LABEL(56w)
        LABEL(57w)
            reg = (b & 7) | REX_B(s);
            stack_pushS(s, get_reg(s, reg), 0);
            goto insn_next;

        LABEL(50l) /* push l */
        LABEL(51l)
        LABEL(52l)
        LABEL(53l)
        LABEL(54l)
        LABEL(55l)
        LABEL(56l)
        LABEL(57l)
#ifdef __x86_64__
        LABEL(50q) /* push l */
        LABEL(51q)
        LABEL(52q)
        LABEL(53q)
        LABEL(54q)
        LABEL(55q)
        LABEL(56q)
        LABEL(57q)
#endif
            reg = (b & 7) | REX_B(s);
            stack_pushS(s, get_reg(s, reg), 1);
            goto insn_next;

        LABEL(58) /* pop */
        LABEL(59)
        LABEL(5a)
        LABEL(5b)
        LABEL(5c)
        LABEL(5d)
        LABEL(5e)
        LABEL(5f)
            reg = (b & 7) | REX_B(s);
            if (likely(!CODE64(s) && s->dflag == 1 && 
                       (s->cpu_state.segs[R_SS].flags & DESC_B_MASK))) {
                addr = s->regs1.esp + s->cpu_state.segs[R_SS].base;
                val = ldl(s, addr);
                /* NOTE: order is important for pop %sp */
                s->regs1.esp += 4;
                set_regl(s, reg, val);
            } else {
                val = stack_pop(s);
                /* NOTE: order is important for pop %sp */
                stack_pop_update(s);
                if (CODE64(s)) {
                    if (s->dflag)
                        set_reg(s, reg, val);
                    else
                        set_regw(s, reg, val);
                } else {
                    if (s->dflag)
                        set_regl(s, reg, val);
                    else
                        set_regw(s, reg, val);
                }
            }
            goto insn_next;

        LABEL(68) /* push Iv */
            if (s->dflag)
                val = (int32_t)ldl_code(s);
            else
                val = lduw_code(s);
            stack_push(s, val);
            goto insn_next;
        LABEL(6a) /* push Iv */
            val = (int8_t)ldub_code(s);
            stack_push(s, val);
            goto insn_next;
        LABEL(8f) /* pop Ev */
            if (CODE64(s) && s->dflag)
                s->dflag = 2;
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            val = stack_pop(s);
            if (mod == 3) {
                /* NOTE: order is important for pop %sp */
                stack_pop_update(s);
                rm = (modrm & 7) | REX_B(s);
                set_regS(s, ot, rm, val);
            } else {
                /* NOTE: order is important too for MMU exceptions */
                s->popl_esp_hack = 1 << ot;
                addr = get_modrm(s, modrm);
                s->popl_esp_hack = 0;
                stS(s, ot, addr, val);
                stack_pop_update(s);
            }
            goto insn_next;
        LABEL(06) /* push es */
        LABEL(0e) /* push cs */
        LABEL(16) /* push ss */
        LABEL(1e) /* push ds */
            if (CODE64(s))
                goto illegal_op;
        do_push_seg:
            reg = (b >> 3) & 7;
            val = get_seg_sel(s, reg);
            stack_push(s, val);
            goto insn_next;
        LABEL(1a0) /* push fs */
        LABEL(1a8) /* push gs */
            goto do_push_seg;
            
        LABEL(07) /* pop es */
        LABEL(17) /* pop ss */
        LABEL(1f) /* pop ds */
            if (CODE64(s))
                goto illegal_op;
        do_pop_seg:
            val = stack_pop(s);
            reg = (b >> 3) & 7;
            load_seg_desc(s, reg, val & 0xffff);
            stack_pop_update(s);
            goto insn_next;
        LABEL(1a1) /* pop fs */
        LABEL(1a9) /* pop gs */
            goto do_pop_seg;

        LABEL(c9) /* leave */
            if (CODE64(s)) {
                set_reg(s, R_ESP, s->regs1.ebp);
            } else if (s->cpu_state.segs[R_SS].flags & DESC_B_MASK) {
                set_regl(s, R_ESP, s->regs1.ebp);
            } else {
                set_regw(s, R_ESP, s->regs1.ebp);
            }
            val = stack_pop(s);
            if (CODE64(s) && s->dflag) {
                set_reg(s, R_EBP, val);
            } else if (s->dflag) {
                set_regl(s, R_EBP, val);
            } else {
                set_regw(s, R_EBP, val);
            }
            stack_pop_update(s);
            goto insn_next;
        /**************************/
        /* mov */

#define MOV_Gv_Ev(ot)\
            modrm = ldub_code(s);\
            reg = ((modrm >> 3) & 7) | REX_R(s);\
            val = get_regS(s, ot, reg);\
            mod = (modrm >> 6);\
            if (mod == 3) {\
                rm = (modrm & 7) | REX_B(s);\
                set_regS(s, ot, rm, val);\
            } else {\
                addr = get_modrm(s, modrm);\
                stS(s, ot, addr, val);\
            }\
            goto insn_next;

        /* mov Gv, Ev */
        LABEL(88) MOV_Gv_Ev(OT_BYTE);
        LABEL(89w) MOV_Gv_Ev(OT_WORD);
        LABEL(89l) MOV_Gv_Ev(OT_LONG);
    QO( LABEL(89q) MOV_Gv_Ev(OT_QUAD); )

#define MOV_Ev_Iv(ot)\
            modrm = ldub_code(s);\
            mod = (modrm >> 6);\
            if (mod != 3) {\
                s->rip_offset = insn_const_size(ot);\
                addr = get_modrm(s, modrm);\
                s->rip_offset = 0;\
                val = insn_get(s, ot);\
                stS(s, ot, addr, val);\
            } else {\
                val = insn_get(s, ot);\
                rm = (modrm & 7) | REX_B(s);\
                set_regS(s, ot, rm, val);\
            }\
            goto insn_next;

        LABEL(c6) MOV_Ev_Iv(OT_BYTE);
        LABEL(c7w) MOV_Ev_Iv(OT_WORD);
        LABEL(c7l) MOV_Ev_Iv(OT_LONG);
    QO( LABEL(c7q) MOV_Ev_Iv(OT_QUAD); )

#define MOV_Ev_Gv(ot)\
            modrm = ldub_code(s);\
            reg = ((modrm >> 3) & 7) | REX_R(s);\
            mod = (modrm >> 6);\
            if (mod == 3) {\
                rm = (modrm & 7) | REX_B(s);\
                val = get_regS(s, ot, rm);\
            } else {\
                addr = get_modrm(s, modrm);\
                val = ldS(s, ot, addr);\
            }\
            set_regS(s, ot, reg, val);\
            goto insn_next;

        /* mov Ev, Gv */
        LABEL(8a) MOV_Ev_Gv(OT_BYTE);
        LABEL(8bw) MOV_Ev_Gv(OT_WORD);
        LABEL(8bl) MOV_Ev_Gv(OT_LONG);
    QO( LABEL(8bq) MOV_Ev_Gv(OT_QUAD); )

        LABEL(8e) /* mov seg, Gv */
            modrm = ldub_code(s);
            reg = (modrm >> 3) & 7;
            if (reg >= 6 || reg == R_CS)
                goto illegal_op;
            mod = (modrm >> 6);
            if (mod == 3) {
                val = get_reg(s, modrm & 7) & 0xffff;
            } else {
                addr = get_modrm(s, modrm);
                val = lduw(s, addr);
            }
            load_seg_desc(s, reg, val);
            goto insn_next;
        LABEL(8c) /* mov Gv, seg */
            modrm = ldub_code(s);
            reg = (modrm >> 3) & 7;
            mod = (modrm >> 6);
            if (reg >= 6)
                goto illegal_op;
            val = get_seg_sel(s, reg);
            if (mod == 3) {
                ot = OT_WORD + s->dflag;
                rm = (modrm & 7) | REX_B(s);
                set_regS(s, ot, rm, val);
            } else {
                addr = get_modrm(s, modrm);
                stw(s, addr, val);
            }
            goto insn_next;

        LABEL(b0) /* mov R, Ib */
        LABEL(b1)
        LABEL(b2)
        LABEL(b3)
        LABEL(b4)
        LABEL(b5)
        LABEL(b6)
        LABEL(b7)
            val = ldub_code(s);
            reg = (b & 7) | REX_B(s);
            set_regb(s, reg, val);
            goto insn_next;

#if defined(__x86_64__)
        LABEL(b8q) /* mov R, Iv */
        LABEL(b9q)
        LABEL(baq)
        LABEL(bbq)
        LABEL(bcq)
        LABEL(bdq)
        LABEL(beq)
        LABEL(bfq)
            reg = (b & 7) | REX_B(s);
            val = ldq_code(s);
            set_reg(s, reg, val);
            goto insn_next;
#endif

        LABEL(b8l) /* mov R, Iv */
        LABEL(b9l)
        LABEL(bal)
        LABEL(bbl)
        LABEL(bcl)
        LABEL(bdl)
        LABEL(bel)
        LABEL(bfl)
            reg = (b & 7) | REX_B(s);
            val = ldl_code(s);
            set_regl(s, reg, val);
            goto insn_next;
            
        LABEL(b8w) /* mov R, Iv */
        LABEL(b9w)
        LABEL(baw)
        LABEL(bbw)
        LABEL(bcw)
        LABEL(bdw)
        LABEL(bew)
        LABEL(bfw)
            reg = (b & 7) | REX_B(s);
            val = lduw_code(s);
            set_regw(s, reg, val);
            goto insn_next;

        LABEL(91) /* xchg R, EAX */
        LABEL(92)
        LABEL(93)
        LABEL(94)
        LABEL(95)
        LABEL(96)
        LABEL(97)
            ot = s->dflag + OT_WORD;
            reg = (b & 7) | REX_B(s);
            rm = R_EAX;
            goto do_xchg_reg;
        LABEL(86)
        LABEL(87) /* xchg Ev, Gv */
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            mod = (modrm >> 6) & 3;
            if (mod == 3) {
                rm = (modrm & 7) | REX_B(s);
            do_xchg_reg:
                val = get_regS(s, ot, reg);
                val2 = get_regS(s, ot, rm);
                set_regS(s, ot, rm, val);
                set_regS(s, ot, reg, val2);
            } else {
                /* XXX: lock for SMP */
                addr = get_modrm(s, modrm);
                val = get_regS(s, ot, reg);
                val2 = ldS(s, ot, addr);
                stS(s, ot, addr, val);
                set_regS(s, ot, reg, val2);
            }
            goto insn_next;

#define MOVZS(sgn, ot, d_ot)\
            {\
                /* d_ot is the size of destination */\
                /* ot is the size of source */\
                modrm = ldub_code(s);\
                reg = ((modrm >> 3) & 7) | REX_R(s);\
                mod = (modrm >> 6);\
                rm = (modrm & 7) | REX_B(s);\
                if (mod == 3) {\
                    val = get_regS(s, ot, rm);\
                    switch(ot | (sgn << 3)) {\
                    case OT_BYTE:\
                        val = (uint8_t)val;\
                        break;\
                    case OT_BYTE | 8:\
                        val = (int8_t)val;\
                        break;\
                    case OT_WORD:\
                        val = (uint16_t)val;\
                        break;\
                    default:\
                    case OT_WORD | 8:\
                        val = (int16_t)val;\
                        break;\
QO(                 case OT_LONG | 8:\
                        val = (int32_t)val;\
                        break;)\
                    }\
                } else {\
                    addr = get_modrm(s, modrm);\
                    switch(ot | (sgn << 3)) {\
                    case OT_BYTE:\
                        val = ldub(s, addr);\
                        break;\
                    case OT_BYTE | 8:\
                        val = (int8_t)ldub(s, addr);\
                        break;\
                    case OT_WORD:\
                        val = (uint16_t)lduw(s, addr);\
                        break;\
                    default:\
                    case OT_WORD | 8:\
                        val = (int16_t)lduw(s, addr);\
                        break;\
QO(                 case OT_LONG | 8:\
                        val = (int32_t)ldl(s, addr);\
                        break;)\
                    }\
                }\
                set_regS(s, d_ot, reg, val);\
            }\
            goto insn_next;

        /* movzbS Gv, Eb */
        LABEL(1b6w) MOVZS(0, OT_BYTE, OT_WORD);
        LABEL(1b6l) MOVZS(0, OT_BYTE, OT_LONG);
    QO( LABEL(1b6q) MOVZS(0, OT_BYTE, OT_QUAD); )

        /* movzwS Gv, Eb */
        LABEL(1b7w) MOVZS(0, OT_WORD, OT_WORD);
        LABEL(1b7l) MOVZS(0, OT_WORD, OT_LONG);
    QO( LABEL(1b7q) MOVZS(0, OT_WORD, OT_QUAD); )

        /* movsbS Gv, Eb */
        LABEL(1bew) MOVZS(1, OT_BYTE, OT_WORD);
        LABEL(1bel) MOVZS(1, OT_BYTE, OT_LONG);
    QO( LABEL(1beq) MOVZS(1, OT_BYTE, OT_QUAD); )

        /* movswS Gv, Eb */
        LABEL(1bfw) MOVZS(1, OT_WORD, OT_WORD);
        LABEL(1bfl) MOVZS(1, OT_WORD, OT_LONG);
    QO( LABEL(1bfq) MOVZS(1, OT_WORD, OT_QUAD); )

        /* movslS Gv, Eb */
        LABEL(63w)
            if (!CODE64(s)) 
                goto unhandled_op; 
            MOVZS(1, OT_LONG, OT_WORD);
        LABEL(63l)
            if (!CODE64(s)) 
                goto unhandled_op; 
            MOVZS(1, OT_LONG, OT_LONG);
    QO( LABEL(63q) MOVZS(1, OT_LONG, OT_QUAD); )

#define LEA(ot)\
            modrm = ldub_code(s);\
            mod = (modrm >> 6);\
            if (mod == 3)\
                goto illegal_op;\
            reg = ((modrm >> 3) & 7) | REX_R(s);\
            s->override = -2;\
            addr = get_modrm(s, modrm);\
            set_regS(s, ot, reg, addr);\
            goto insn_next;
            
        /* lea */
        LABEL(8dw) LEA(OT_WORD);
        LABEL(8dl) LEA(OT_LONG);
    QO( LABEL(8dq) LEA(OT_QUAD); )

        LABEL(a0) /* mov EAX, Ov */
        LABEL(a1)
        LABEL(a2) /* mov Ov, EAX */
        LABEL(a3)
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
#ifdef __x86_64__
            if (s->aflag == 2) {
                addr = ldq_code(s);
                if (s->override == R_FS || s->override == R_GS)
                    addr += s->cpu_state.segs[s->override].base;
            } else
#endif
            {
                int override;
                if (s->aflag) {
                    addr = ldl_code(s);
                } else {
                    addr = lduw_code(s);
                }
                override = s->override;
                if (override < 0)
                    override = R_DS;
                addr = (uint32_t)(addr + s->cpu_state.segs[override].base);
            }
            if ((b & 2) == 0) {
                val = ldS(s, ot, addr);
                set_regS(s, ot, R_EAX, val);
            } else {
                val = get_regS(s, ot, R_EAX);
                stS(s, ot, addr, val);
            }
            goto insn_next;
            
        /************************/
        /* flags */
        LABEL(9c) /* pushf */
            iopl = get_eflags_iopl(s);
            if (get_eflags_vm(s) && iopl != 3)
                raise_exception_err(s, EXCP0D_GPF, 0);
            val = compute_eflags(s);
            val &= ~(VM_MASK | RF_MASK);
            stack_push(s, val);
            goto insn_next;
        LABEL(9d) /* popf */
            {
                long mask;
                iopl = get_eflags_iopl(s);
                if (get_eflags_vm(s) && iopl != 3)
                    raise_exception_err(s, EXCP0D_GPF, 0);
                if (s->cpu_state.cpl == 0) {
                    mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK | IF_MASK | IOPL_MASK;
                } else {
                    if (s->cpu_state.cpl <= iopl) {
                        mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK | IF_MASK;
                    } else {
                        mask = TF_MASK | AC_MASK | ID_MASK | NT_MASK;
                    }
                }
                if (s->dflag == 0)
                    mask &= 0xffff;
                val = stack_pop(s);
                load_eflags(s, val, mask);
                stack_pop_update(s);
            }
            goto insn_next;
        LABEL(f5) /* cmc */
            s->regs1.eflags ^= CC_C;
            goto insn_next;
        LABEL(f8) /* clc */
            s->regs1.eflags &= ~CC_C;
            goto insn_next;
        LABEL(f9) /* stc */
            s->regs1.eflags |= CC_C;
            goto insn_next;
        LABEL(fc) /* cld */
            s->regs1.eflags &= ~DF_MASK;
            goto insn_next;
        LABEL(fd) /* std */
            s->regs1.eflags |= DF_MASK;
            goto insn_next;

        /************************/
        /* bit operations */
        LABEL(1ba) /* bt/bts/btr/btc Gv, im */
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            op = (modrm >> 3) & 7;
            if (op < 4)
                goto illegal_op;
            op -= 4;
            mod = (modrm >> 6);
            rm = (modrm & 7) | REX_B(s);
            if (mod != 3) {
                s->rip_offset = 1;
                addr = get_modrm(s, modrm);
                s->rip_offset = 0;
                val2 = ldub_code(s);
                val = ldS(s, ot, addr);
                eflags = s->regs1.eflags;
                val = exec_binary(&eflags, EB_BT + (op << 2) + ot, 
                                  val, val2);
                if (op != 0) 
                    stS(s, ot, addr, val);
                s->regs1.eflags = eflags;
            } else {
                val2 = ldub_code(s);
                val = get_regS(s, ot, rm);
                val = exec_binary(&s->regs1.eflags, EB_BT + (op << 2) + ot, 
                                  val, val2);
                if (op != 0) 
                    set_regS(s, ot, rm, val);
            }
            goto insn_next;
        LABEL(1a3) /* bt Gv, Ev */
            op = 0;
            goto do_btx;
        LABEL(1ab) /* bts */
            op = 1;
            goto do_btx;
        LABEL(1b3) /* btr */
            op = 2;
            goto do_btx;
        LABEL(1bb) /* btc */
            op = 3;
        do_btx:
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            mod = (modrm >> 6);
            rm = (modrm & 7) | REX_B(s);
            val2 = get_regS(s, ot, reg);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                /* add the offset */
                switch(ot) {
                case OT_WORD:
                    addr += ((int16_t)val2 >> 4) << 1;
                    break;
                case OT_LONG:
                    addr += ((int32_t)val2 >> 5) << 2;
                    break;
                default:
                case OT_QUAD:
                    addr += ((long)val2 >> 6) << 3;
                    break;
                }
                val = ldS(s, ot, addr);
                eflags = s->regs1.eflags;
                val = exec_binary(&eflags, EB_BT + (op << 2) + ot, 
                                  val, val2);
                if (op != 0) 
                    stS(s, ot, addr, val);
                s->regs1.eflags = eflags;
            } else {
                val = get_regS(s, ot, rm);
                val = exec_binary(&s->regs1.eflags, EB_BT + (op << 2) + ot, 
                                  val, val2);
                if (op != 0) 
                    set_regS(s, ot, rm, val);
            }
            goto insn_next;
        LABEL(1bc) /* bsf */
        LABEL(1bd) /* bsr */
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            val = get_regS(s, ot, reg);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                val2 = ldS(s, ot, addr);
            } else {
                val2 = get_regS(s, ot, rm);
            }
            op = b & 1;
            val = exec_binary(&s->regs1.eflags, EB_BSF + (op << 2) + ot, 
                              val, val2);
            set_regS(s, ot, reg, val);
            goto insn_next;
            
        /************************/
        /* control */
        LABEL(c2) /* ret im */
            {
                long addend;
                addend = (int16_t)lduw_code(s);
                val = stack_pop(s);
                if (s->dflag == 0)
                    val &= 0xffff;
                if (CODE64(s) && s->dflag)
                    s->dflag = 2;
                sp_add(s, addend + (2 << s->dflag));
                pc = val;
            }
            goto insn_next;
        LABEL(c3) /* ret */
            val = stack_pop(s);
            if (s->dflag == 0)
                val &= 0xffff;
            stack_pop_update(s);
            pc = val;
            goto insn_next;
        LABEL(ca) /* lret im */
            val = (int16_t)lduw_code(s);
            helper_lret_protected(s, s->dflag, val);
            goto ljmp_op;
        LABEL(cb) /* lret */
            helper_lret_protected(s, s->dflag, 0);
            goto ljmp_op;
        LABEL(cf) /* iret */
            helper_iret_protected(s, s->dflag);
            goto ljmp_op;
        LABEL(e8) /* call im */
            if (s->dflag)
                val = (int32_t)ldl_code(s);
            else
                val = (int16_t)lduw_code(s);
            next_eip = pc;
            val += next_eip;
            if (s->dflag == 0)
                val &= 0xffff;
            stack_push(s, next_eip);
            pc = val;
            goto insn_next;
        LABEL(e9) /* jmp im */
            if (s->dflag)
                val = (int32_t)ldl_code(s);
            else
                val = (int16_t)lduw_code(s);
        do_jmp:
            next_eip = pc;
            val += next_eip;
            if (s->dflag == 0)
                val &= 0xffff;
            pc = val;
            goto insn_next;
        LABEL(eb) /* jmp Jb */
            val = (int8_t)ldub_code(s);
            goto do_jmp;

#define JCC(ot, v)\
        {\
            if (ot == OT_BYTE)\
                val = (int8_t)ldub_code(s);\
            else if (ot == OT_WORD)\
                val = (int16_t)lduw_code(s);\
            else\
                val = (int32_t)ldl_code(s);\
            if (get_jcc_cond(s->regs1.eflags, v))\
                goto do_jmp;\
            goto insn_next;\
        }\
        /* jcc Jb */
            
        LABEL(70) JCC(OT_BYTE, 0x0)
        LABEL(71) JCC(OT_BYTE, 0x1)
        LABEL(72) JCC(OT_BYTE, 0x2)
        LABEL(73) JCC(OT_BYTE, 0x3)
        LABEL(74) JCC(OT_BYTE, 0x4)
        LABEL(75) JCC(OT_BYTE, 0x5)
        LABEL(76) JCC(OT_BYTE, 0x6)
        LABEL(77) JCC(OT_BYTE, 0x7)
        LABEL(78) JCC(OT_BYTE, 0x8)
        LABEL(79) JCC(OT_BYTE, 0x9)
        LABEL(7a) JCC(OT_BYTE, 0xa)
        LABEL(7b) JCC(OT_BYTE, 0xb)
        LABEL(7c) JCC(OT_BYTE, 0xc)
        LABEL(7d) JCC(OT_BYTE, 0xd)
        LABEL(7e) JCC(OT_BYTE, 0xe)
        LABEL(7f) JCC(OT_BYTE, 0xf)

        /* jcc Jv */
        LABEL(180w) JCC(OT_WORD, 0x0)
        LABEL(181w) JCC(OT_WORD, 0x1)
        LABEL(182w) JCC(OT_WORD, 0x2)
        LABEL(183w) JCC(OT_WORD, 0x3)
        LABEL(184w) JCC(OT_WORD, 0x4)
        LABEL(185w) JCC(OT_WORD, 0x5)
        LABEL(186w) JCC(OT_WORD, 0x6)
        LABEL(187w) JCC(OT_WORD, 0x7)
        LABEL(188w) JCC(OT_WORD, 0x8)
        LABEL(189w) JCC(OT_WORD, 0x9)
        LABEL(18aw) JCC(OT_WORD, 0xa)
        LABEL(18bw) JCC(OT_WORD, 0xb)
        LABEL(18cw) JCC(OT_WORD, 0xc)
        LABEL(18dw) JCC(OT_WORD, 0xd)
        LABEL(18ew) JCC(OT_WORD, 0xe)
        LABEL(18fw) JCC(OT_WORD, 0xf)

        
        QO(LABEL(180q)) LABEL(180l) JCC(OT_LONG, 0x0)
        QO(LABEL(181q)) LABEL(181l) JCC(OT_LONG, 0x1)
        QO(LABEL(182q)) LABEL(182l) JCC(OT_LONG, 0x2)
        QO(LABEL(183q)) LABEL(183l) JCC(OT_LONG, 0x3)
        QO(LABEL(184q)) LABEL(184l) JCC(OT_LONG, 0x4)
        QO(LABEL(185q)) LABEL(185l) JCC(OT_LONG, 0x5)
        QO(LABEL(186q)) LABEL(186l) JCC(OT_LONG, 0x6)
        QO(LABEL(187q)) LABEL(187l) JCC(OT_LONG, 0x7)
        QO(LABEL(188q)) LABEL(188l) JCC(OT_LONG, 0x8)
        QO(LABEL(189q)) LABEL(189l) JCC(OT_LONG, 0x9)
        QO(LABEL(18aq)) LABEL(18al) JCC(OT_LONG, 0xa)
        QO(LABEL(18bq)) LABEL(18bl) JCC(OT_LONG, 0xb)
        QO(LABEL(18cq)) LABEL(18cl) JCC(OT_LONG, 0xc)
        QO(LABEL(18dq)) LABEL(18dl) JCC(OT_LONG, 0xd)
        QO(LABEL(18eq)) LABEL(18el) JCC(OT_LONG, 0xe)
        QO(LABEL(18fq)) LABEL(18fl) JCC(OT_LONG, 0xf)

        LABEL(190) /* setcc Gv */
        LABEL(191)
        LABEL(192)
        LABEL(193)
        LABEL(194)
        LABEL(195)
        LABEL(196)
        LABEL(197)
        LABEL(198)
        LABEL(199)
        LABEL(19a)
        LABEL(19b)
        LABEL(19c)
        LABEL(19d)
        LABEL(19e)
        LABEL(19f)
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            val = (get_jcc_cond(s->regs1.eflags, b & 0xf) != 0);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                stS(s, OT_BYTE, addr, val);
            } else {
                rm = (modrm & 7) | REX_B(s);
                set_regS(s, OT_BYTE, rm, val);
            }
            goto insn_next;
        LABEL(140) /* cmov Gv, Ev */
        LABEL(141)
        LABEL(142)
        LABEL(143)
        LABEL(144)
        LABEL(145)
        LABEL(146)
        LABEL(147)
        LABEL(148)
        LABEL(149)
        LABEL(14a)
        LABEL(14b)
        LABEL(14c)
        LABEL(14d)
        LABEL(14e)
        LABEL(14f)
            ot = s->dflag + OT_WORD;
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                val = ldS(s, ot, addr);
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
            }
            if (get_jcc_cond(s->regs1.eflags, b & 0xf)) {
                set_regS(s, ot, reg, val);
            }
            goto insn_next;
            
        LABEL(c4) /* les Gv */
            op = R_ES;
            goto do_lxx;
        LABEL(c5) /* lds Gv */
            op = R_DS;
            goto do_lxx;
        LABEL(1b2) /* lss Gv */
            op = R_SS;
            goto do_lxx;
        LABEL(1b4) /* lfs Gv */
            op = R_FS;
            goto do_lxx;
        LABEL(1b5) /* lgs Gv */
            op = R_GS;
        do_lxx:
            modrm = ldub_code(s);
            reg = ((modrm >> 3) & 7);
            mod = (modrm >> 6);
            if (mod == 3)
                goto illegal_op;
            addr = get_modrm(s, modrm);
            if (s->dflag) {
                val = ldl(s, addr);
                addr += 4;
            } else {
                val = lduw(s, addr);
                addr += 2;
            }
            sel = lduw(s, addr);
            load_seg_desc(s, op, sel);
            if (s->dflag)
                set_regl(s, reg, val);
            else
                set_regw(s, reg, val);
            goto insn_next;

        /************************/
        /* shifts */
        LABEL(c0)
        LABEL(c1)
            /* shift Ev,Ib */
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            op = (modrm >> 3) & 7;
            if (mod != 3) {
                s->rip_offset = 1;
                addr = get_modrm(s, modrm);
                s->rip_offset = 0;
                val = ldS(s, ot, addr);
                val2 = ldub_code(s);
                eflags = s->regs1.eflags;
                val = exec_binary(&eflags,
                                  EB_ROL + (op << 2) + ot, 
                                  val, val2);
                stS(s, ot, addr, val);
                s->regs1.eflags = eflags;
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
                val2 = ldub_code(s);
                val = exec_binary(&s->regs1.eflags,
                                  EB_ROL + (op << 2) + ot, 
                                  val, val2);
                set_regS(s, ot, rm, val);
            }
            goto insn_next;
        LABEL(d0)
        LABEL(d1)
            /* shift Ev,1 */
            val2 = 1;
        grp2:
            if ((b & 1) == 0)
                ot = OT_BYTE;
            else
                ot = s->dflag + OT_WORD;
            
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            op = (modrm >> 3) & 7;
            if (mod != 3) {
                addr = get_modrm(s, modrm);
                val = ldS(s, ot, addr);
                eflags = s->regs1.eflags;
                val = exec_binary(&eflags,
                                  EB_ROL + (op << 2) + ot, 
                                  val, val2);
                stS(s, ot, addr, val);
                s->regs1.eflags = eflags;
            } else {
                rm = (modrm & 7) | REX_B(s);
                val = get_regS(s, ot, rm);
                val = exec_binary(&s->regs1.eflags,
                                  EB_ROL + (op << 2) + ot, 
                                  val, val2);
                set_regS(s, ot, rm, val);
            }
            goto insn_next;
        LABEL(d2)
        LABEL(d3)
            /* shift Ev,cl */
            val2 = s->regs1.ecx;
            goto grp2;

#ifdef __x86_64__
#define SHIFTD1(op, eflags, val, val2, shift) \
                asm volatile( op "\n"\
        "pushf\n"\
        "pop %%rax\n"\
        "andl $0x8d5, %%eax\n"\
        "andl $~0x8d5, %%ebx\n"\
        "orl %%eax, %%ebx\n"\
                             : "=b" (eflags),\
                               "=r" (val)\
                             : "0" (eflags),\
                               "1" (val),\
                               "r" (val2),\
                               "c" (shift)\
                             : "%eax");
#else
#define SHIFTD1(op, eflags, val, val2, shift) \
                asm volatile( op "\n"\
                             LAHF "\n"\
                             "seto %%al\n"\
                             "movb %%ah, %%bl\n"\
                             "shll $3, %%eax\n"\
                             "andl $~0x0800, %%ebx\n"\
                             "orb %%al, %%bh\n"\
                             : "=b" (eflags),\
                               "=r" (val)\
                             : "0" (eflags),\
                               "1" (val),\
                               "r" (val2),\
                               "c" (shift)\
                             : "%eax");
#endif

#define SHIFTD(eflags, op, val, val2, shift) \
                switch(op) {\
                case 1: SHIFTD1("shld %%cl, %w4, %w1", eflags, val, val2, shift); break;\
                case 2: SHIFTD1("shld %%cl, %k4, %k1", eflags, val, val2, shift); break;\
                QO(case 3: SHIFTD1("shld %%cl, %4, %1", eflags, val, val2, shift); break;)\
                case 5: SHIFTD1("shrd %%cl, %w4, %w1", eflags, val, val2, shift); break;\
                case 6: SHIFTD1("shrd %%cl, %k4, %k1", eflags, val, val2, shift); break;\
                QO(case 7: SHIFTD1("shrd %%cl, %4, %1", eflags, val, val2, shift); break;)\
                }

        LABEL(1a4) /* shld imm */
            op = 0;
            goto do_shiftd_imm;
        LABEL(1ac) /* shrd imm */
            op = 1;
        do_shiftd_imm:
            {
                long shift;
                ot = s->dflag + OT_WORD;
                modrm = ldub_code(s);
                mod = (modrm >> 6);
                reg = ((modrm >> 3) & 7) | REX_R(s);
                val2 = get_regS(s, ot, reg);
                if (mod != 3) {
                    s->rip_offset = 1;
                    addr = get_modrm(s, modrm);
                    s->rip_offset = 0;
                    val = ldS(s, ot, addr);
                    shift = ldub_code(s);
                    if (ot == OT_QUAD)
                        shift &= 0x3f;
                    else
                        shift &= 0x1f;
                    eflags = s->regs1.eflags;
                    if (shift != 0) {
                        SHIFTD(eflags, (op << 2) + ot, val, val2, shift);
                    }
                    stS(s, ot, addr, val);
                    s->regs1.eflags = eflags;
                } else {
                    rm = (modrm & 7) | REX_B(s);
                    val = get_regS(s, ot, rm);
                    shift = ldub_code(s);
                    if (ot == OT_QUAD)
                        shift &= 0x3f;
                    else
                        shift &= 0x1f;
                    if (shift != 0) {
                        SHIFTD(eflags, (op << 2) + ot, val, val2, shift);
                    }
                    set_regS(s, ot, rm, val);
                }
            }
            goto insn_next;

        LABEL(1a5) /* shld cl */
            op = 0;
            goto do_shiftd;
        LABEL(1ad) /* shrd cl */
            op = 1;
        do_shiftd:
            {
                long shift;
                ot = s->dflag + OT_WORD;
                modrm = ldub_code(s);
                mod = (modrm >> 6);
                reg = ((modrm >> 3) & 7) | REX_R(s);
                val2 = get_regS(s, s->dflag + OT_WORD, reg);
                shift = s->regs1.ecx;
                if (ot == OT_QUAD)
                    shift &= 0x3f;
                else
                    shift &= 0x1f;
                if (mod != 3) {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, ot, addr);
                    eflags = s->regs1.eflags;
                    if (shift != 0) {
                        SHIFTD(eflags, (op << 2) + ot, val, val2, shift);
                    }
                    stS(s, ot, addr, val);
                    s->regs1.eflags = eflags;
                } else {
                    rm = (modrm & 7) | REX_B(s);
                    val = get_regS(s, ot, rm);
                    if (shift != 0) {
                        SHIFTD(eflags, (op << 2) + ot, val, val2, shift);
                    }
                    set_regS(s, ot, rm, val);
                }
            }
            goto insn_next;

        LABEL(cd) /* int N */
            val = ldub_code(s);
            do_int(s, val);
            goto ljmp_op;
        LABEL(f4) /* hlt */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            raise_exception(s, KQEMU_RET_SOFTMMU);
            goto insn_next;
        LABEL(100)
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            op = (modrm >> 3) & 7;
            switch(op) {
            case 0: /* sldt */
            if (!(s->cpu_state.cr0 & CR0_PE_MASK) || get_eflags_vm(s))
                goto illegal_op;
            raise_exception(s, KQEMU_RET_SOFTMMU);
            break;
            case 2: /* lldt */
                if (!(s->cpu_state.cr0 & CR0_PE_MASK) || get_eflags_vm(s))
                    goto illegal_op;
                if (s->cpu_state.cpl != 0) 
                    raise_exception_err(s, EXCP0D_GPF, 0);
#ifdef USE_SEG_GP
                if (mod == 3) {
                    rm = (modrm & 7) | REX_B(s);
                    val = get_regS(s, OT_WORD, rm) & 0xffff;
                } else {
                    addr = get_modrm(s, modrm);
                    val = ldS(s, OT_WORD, addr);
                }
                helper_lldt(s, val);
#else
                raise_exception(s, KQEMU_RET_SOFTMMU);
#endif
                break;
            case 1: /* str */
                if (!(s->cpu_state.cr0 & CR0_PE_MASK) || get_eflags_vm(s))
                    goto illegal_op;
                raise_exception(s, KQEMU_RET_SOFTMMU);
                break;
            case 3: /* ltr */
                if (!(s->cpu_state.cr0 & CR0_PE_MASK) || get_eflags_vm(s))
                    goto illegal_op;
                if (s->cpu_state.cpl != 0) 
                    raise_exception_err(s, EXCP0D_GPF, 0);
                raise_exception(s, KQEMU_RET_SOFTMMU);
                break;
            case 4: /* verr */
            case 5: /* verw */
                if (!(s->cpu_state.cr0 & CR0_PE_MASK) || get_eflags_vm(s))
                    goto illegal_op;
                raise_exception(s, KQEMU_RET_SOFTMMU);
                break;
            default:
                goto illegal_op;
            }
            goto insn_next;
        LABEL(101)
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            op = (modrm >> 3) & 7;
            switch(op) {
            case 0: /* sgdt */
                if (mod == 3)
                    goto illegal_op;
                raise_exception(s, KQEMU_RET_SOFTMMU);
            case 1: 
                if (mod == 3) {
                    rm = modrm & 7;
                    switch(rm) {
                    case 0: /* monitor */
                        if (/* !(s->cpuid_ext_features & CPUID_EXT_MONITOR) || */
                            s->cpu_state.cpl != 0)
                            goto illegal_op;
                        if ((uint32_t)s->regs1.ecx != 0)
                            raise_exception_err(s, EXCP0D_GPF, 0);
                        break;
                    default:
                        goto illegal_op;
                    }
                } else {
                    /* sidt */
                    raise_exception(s, KQEMU_RET_SOFTMMU);
                }
                break;
            case 2: /* lgdt */
            case 3: /* lidt */
                if (mod == 3)
                    goto illegal_op;
                if (s->cpu_state.cpl != 0) 
                    raise_exception_err(s, EXCP0D_GPF, 0);
                raise_exception(s, KQEMU_RET_SOFTMMU);
            case 4: /* smsw */
                raise_exception(s, KQEMU_RET_SOFTMMU);
            case 6: /* lmsw */
                if (s->cpu_state.cpl != 0) 
                    raise_exception_err(s, EXCP0D_GPF, 0);
                raise_exception(s, KQEMU_RET_SOFTMMU);
            case 7: /* invlpg/swapgs */
                if (s->cpu_state.cpl != 0) 
                    raise_exception_err(s, EXCP0D_GPF, 0);
                if (mod == 3) {
#ifdef __x86_64__
                    if (CODE64(s) && (modrm & 7) == 0) {
                        helper_swapgs(s);
                    } else 
#endif
                    {
                        goto illegal_op;
                    }
                } else {
                    addr = get_modrm(s, modrm);
                    do_invlpg(s, addr);
                }
                break;
            default:
                goto illegal_op;
            }
            goto insn_next;
        LABEL(108) /* invd */
        LABEL(109) /* wbinvd */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            goto insn_next;
        LABEL(121) /* mov reg, drN */
        LABEL(123) /* mov drN, reg */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            modrm = ldub_code(s);
            if ((modrm & 0xc0) != 0xc0)
                goto illegal_op;
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (CODE64(s))
                ot = OT_QUAD;
            else
                ot = OT_LONG;
            if (b & 2) {
                val = get_reg(s, rm);
                if (ot == OT_LONG)
                    val = (uint32_t)val;
                switch(reg) {
                case 0:
                case 1:
                case 2:
                case 3:
                case 6:
                    raise_exception(s, KQEMU_RET_SOFTMMU);
                case 7:
                    /* better than nothing: do nothing if no change */
                    if (val != s->cpu_state.dr7)
                        raise_exception(s, KQEMU_RET_SOFTMMU);
                    break;
                default:
                    goto illegal_op;
                }
            } else {
                switch(reg) {
                case 0:
                    val = s->cpu_state.dr0;
                    break;
                case 1:
                    val = s->cpu_state.dr1;
                    break;
                case 2:
                    val = s->cpu_state.dr2;
                    break;
                case 3:
                    raise_exception(s, KQEMU_RET_SOFTMMU);
                    goto insn_next;
                    val = s->cpu_state.dr3;
                    break;
                case 6:
                    val = s->cpu_state.dr6;
                    break;
                case 7:
                    val = s->cpu_state.dr7;
                    break;
                default:
                    goto illegal_op;
                }
                set_regS(s, ot, rm, val);
            }
            goto insn_next;
        LABEL(106) /* clts */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            do_update_cr0(s, s->cpu_state.cr0 & ~CR0_TS_MASK);
            goto insn_next;

        LABEL(118)
            modrm = ldub_code(s);
            mod = (modrm >> 6);
            op = (modrm >> 3) & 7;
            switch(op) {
            case 0: /* prefetchnta */
            case 1: /* prefetchnt0 */
            case 2: /* prefetchnt0 */
            case 3: /* prefetchnt0 */
                if (mod == 3)
                    goto illegal_op;
                addr = get_modrm(s, modrm);
                /* nothing more to do */
                break;
            default: /* nop (multi byte) */
                addr = get_modrm(s, modrm);
                break;
            }
            goto insn_next;

        LABEL(119) /* nop (multi byte) */
        LABEL(11a)
        LABEL(11b)
        LABEL(11c)
        LABEL(11d)
        LABEL(11e)
        LABEL(11f)
            modrm = ldub_code(s);
            addr = get_modrm(s, modrm);
            goto insn_next;
            
        LABEL(120) /* mov reg, crN */
        LABEL(122) /* mov crN, reg */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            modrm = ldub_code(s);
            if ((modrm & 0xc0) != 0xc0)
                goto illegal_op;
            rm = (modrm & 7) | REX_B(s);
            reg = ((modrm >> 3) & 7) | REX_R(s);
            if (b & 2) {
                val = get_reg(s, rm);
                switch(reg) {
                case 0:
                    do_update_cr0(s, val);
                    break;
                case 3:
                    do_update_cr3(s, val);
                    break;
                case 4:
                    do_update_cr4(s, val);
                    break;
                case 2:
                case 8:
                    raise_exception(s, KQEMU_RET_SOFTMMU);
                default:
                    goto illegal_op;
                }
            } else {
                switch(reg) {
                case 0:
                    set_reg(s, rm, s->cpu_state.cr0);
                    break;
                case 2:
                    set_reg(s, rm, s->cpu_state.cr2);
                    break;
                case 3:
                    set_reg(s, rm, s->cpu_state.cr3);
                    break;
                case 4:
                    set_reg(s, rm, s->cpu_state.cr4);
                    break;
                case 8:
                    raise_exception(s, KQEMU_RET_SOFTMMU);
                default:
                    goto illegal_op;
                }
            }
            goto insn_next;
        LABEL(130) /* wrmsr */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            helper_wrmsr(s);
            goto insn_next;
        LABEL(132) /* rdmsr */
            if (s->cpu_state.cpl != 0) 
                raise_exception_err(s, EXCP0D_GPF, 0);
            helper_rdmsr(s);
            goto insn_next;
        LABEL(fa) /* cli */
            iopl = get_eflags_iopl(s);
            if (likely(s->cpu_state.cpl <= iopl)) {
                set_reset_eflags(s, 0, IF_MASK);
            } else {
                raise_exception_err(s, EXCP0D_GPF, 0);
            }
            goto insn_next;
        LABEL(fb) /* sti */
            iopl = get_eflags_iopl(s);
            if (likely(s->cpu_state.cpl <= iopl)) {
                set_reset_eflags(s, IF_MASK, 0);
            } else {
                raise_exception_err(s, EXCP0D_GPF, 0);
            }
            /* NOTE: irq should be disabled for the instruction after
               STI. As it would be too complicated to ensure this, we
               handle the "sti ; sysenter" case found in XP
               specifically. XXX: see why we cannot execute the
               next insn in every case. */
            val = lduw_mem_fast(s, pc + s->cpu_state.segs[R_CS].base);
            if (val == 0x350f) {
                /* sysexit */
                s->regs1.eip = pc;
                goto insn_next3;
            } else {
                goto insn_next;
            }

        LABEL(90) /* nop */
            goto insn_next;
        LABEL(131) /* rdtsc */
            {
                uint32_t low, high;
                if ((s->cpu_state.cr4 & CR4_TSD_MASK) && 
                    s->cpu_state.cpl != 0) {
                    raise_exception_err(s, EXCP0D_GPF, 0);
                }
                asm volatile("rdtsc" : "=a" (low), "=d" (high));
                s->regs1.eax = low;
                s->regs1.edx = high;
            }
            goto insn_next;

        LABEL(105) /* syscall */
            helper_syscall(s);
            goto ljmp_op;

        LABEL(107) /* sysret */
            helper_sysret(s);
            goto ljmp_op;

        LABEL(134) /* sysenter */
            if (CODE64(s))
                goto illegal_op;
            helper_sysenter(s);
            goto ljmp_op;

        LABEL(135) /* sysexit */
            if (CODE64(s))
                goto illegal_op;
            helper_sysexit(s);
            goto ljmp_op;

        LABEL(9a) /* lcall im */
        LABEL(ea) /* ljmp im */

        LABEL(e4) /* in im */
        LABEL(e5)
        LABEL(e6) /* out im */
        LABEL(e7)
        LABEL(ec) /* in dx */
        LABEL(ed)
        LABEL(ee) /* out dx */
        LABEL(ef) 
        LABEL(6c) /* insS */
        LABEL(6d)
        LABEL(6e) /* outS */
        LABEL(6f)
            raise_exception(s, KQEMU_RET_SOFTMMU);
    
        LABEL(a4) /* movs */
        LABEL(a5)
            {
                unsigned long saddr, daddr, incr, mask;
                int override;

                if ((b & 1) == 0)
                    ot = OT_BYTE;
                else
                    ot = s->dflag + OT_WORD;
                
                if (s->aflag == 2)
                    mask = -1;
                else if (s->aflag)
                    mask = 0xffffffff;
                else
                    mask = 0xffff;
                if (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) {
                    if ((s->regs1.ecx & mask) == 0)
                        goto insn_next;
                }

                incr = (1 - (2 * ((s->regs1.eflags >> 10) & 1))) << ot;
#ifdef __x86_64__
                if (s->aflag == 2) {
                    saddr = s->regs1.esi;
                    if (s->override == R_FS || s->override == R_GS)
                        saddr += s->cpu_state.segs[s->override].base;
                    
                    daddr = s->regs1.edi;
                    
                    s->regs1.esi += incr;
                    s->regs1.edi += incr;
                } else 
#endif
                {
                    saddr = s->regs1.esi & mask;
                    override = s->override;
                    if (override < 0)
                        override = R_DS;
                    saddr = (uint32_t)(saddr + s->cpu_state.segs[override].base);

                    daddr = s->regs1.edi & mask;
                    daddr = (uint32_t)(daddr + s->cpu_state.segs[R_ES].base);
                    
                    val = s->regs1.esi + incr;
                    s->regs1.esi = (s->regs1.esi & ~mask) | (val & mask);
                    val = s->regs1.edi + incr;
                    s->regs1.edi = (s->regs1.edi & ~mask) | (val & mask);
                }
                val = ldS(s, ot, saddr);
                stS(s, ot, daddr, val);

                if (s->prefix & (PREFIX_REPZ | PREFIX_REPNZ)) {
                    val = s->regs1.ecx - 1;
                    s->regs1.ecx = (s->regs1.ecx & ~mask) | (val & mask);
                    pc = s->regs1.eip;
                }
            }
            goto insn_next;

    LABEL(98)  /* CWDE/CBW */
#ifdef __x86_64__
        if (s->dflag == 2) {
            s->regs1.eax = (int32_t)s->regs1.eax;
        } else 
#endif
        if (s->dflag) {
            s->regs1.eax = (uint32_t)((int16_t)s->regs1.eax);
        } else {
            s->regs1.eax = (s->regs1.eax & ~0xffff) | 
                ((int8_t)s->regs1.eax & 0xffff);
        }
        goto insn_next;

    LABEL(99) /* cltd */
#ifdef __x86_64__
        if (s->dflag == 2) {
            s->regs1.edx = (int64_t)s->regs1.eax >> 63;
        } else 
#endif
        if (s->dflag) {
            s->regs1.edx = (uint32_t)((int32_t)s->regs1.eax >> 31);
        } else {
            s->regs1.edx = (s->regs1.edx & ~0xffff) | 
                (((int16_t)s->regs1.eax >> 15) & 0xffff);
        }
        goto insn_next;

    LABEL(1c0) /* xadd */
    LABEL(1c1)
        if ((b & 1) == 0)
            ot = OT_BYTE;
        else
            ot = s->dflag + OT_WORD;
            
        modrm = ldub_code(s);
        mod = (modrm >> 6);
        reg = ((modrm >> 3) & 7) | REX_R(s);
        val = get_regS(s, ot, reg);
        if (mod == 3) {
            rm = (modrm & 7) | REX_B(s);
            val2 = get_regS(s, ot, rm);
            val = exec_binary(&s->regs1.eflags, 
                              EB_ADD + ot, 
                              val, val2);
            set_regS(s, ot, rm, val);
            set_regS(s, ot, reg, val2);
        } else {
            addr = get_modrm(s, modrm);
            val2 = ldS(s, ot, addr);
            eflags = s->regs1.eflags;
            val = exec_binary(&eflags, 
                              EB_ADD + ot, 
                              val, val2);
            stS(s, ot, addr, val);
            set_regS(s, ot, reg, val2);
            s->regs1.eflags = eflags;
        }
        goto insn_next;
    LABEL(1ae)
        modrm = ldub_code(s);
        mod = (modrm >> 6);
        op = (modrm >> 3) & 7;
        switch(op) {
        case 0: /* fxsave */
            if (mod == 3 || !(s->cpuid_features & CPUID_FXSR))
                goto illegal_op;
            addr = get_modrm(s, modrm);
            if (unlikely((addr - ((unsigned long)&_start - 511)) < 
                         (MONITOR_MEM_SIZE + 511)))
                raise_exception(s, KQEMU_RET_SOFTMMU);
#ifdef __x86_64__
            if (s->dflag == 2) {
                asm volatile("1:\n"
                             "rex64 ; fxsave (%0)\n" 
                             MMU_EXCEPTION(1b)
                             : : "r" (addr) : "memory");
            } else
#endif
            {
                asm volatile("1:\n"
                             "fxsave (%0)\n" 
                             MMU_EXCEPTION(1b)
                             : : "r" (addr) : "memory");
            }
            break;
        case 1: /* fxrstor */
            if (mod == 3 || !(s->cpuid_features & CPUID_FXSR))
                goto illegal_op;
            addr = get_modrm(s, modrm);
            if (unlikely((addr - ((unsigned long)&_start - 511)) < 
                         (MONITOR_MEM_SIZE + 511)))
                raise_exception(s, KQEMU_RET_SOFTMMU);
#ifdef __x86_64__
            if (s->dflag == 2) {
                asm volatile("1:\n"
                             "rex64 ; fxrstor (%0)\n" 
                             MMU_EXCEPTION(1b)
                             : : "r" (addr));
            } else
#endif
            {
                asm volatile("1:\n"
                             "fxrstor (%0)\n" 
                             MMU_EXCEPTION(1b)
                             : : "r" (addr));
            }
            break;
        case 5: /* lfence */
        case 6: /* mfence */
            if ((modrm & 0xc7) != 0xc0 || !(s->cpuid_features & CPUID_SSE))
                goto illegal_op;
            break;
        case 7: /* sfence / clflush */
            if ((modrm & 0xc7) == 0xc0) {
                /* sfence */
                if (!(s->cpuid_features & CPUID_SSE))
                    goto illegal_op;
            } else {
                /* clflush */
                if (!(s->cpuid_features & CPUID_CLFLUSH))
                    goto illegal_op;
                addr = get_modrm(s, modrm);
            }
            break;
        default:
            raise_exception(s, KQEMU_RET_SOFTMMU);
        }
        goto insn_next;
    LABEL(e3) /* jecxz */
        val = (int8_t)ldub_code(s);
        val2 = s->regs1.ecx;
        if (s->aflag == 0)
            val2 = (uint16_t)val2;
#ifdef __x86_64__
        else if (s->aflag == 1) 
            val2 = (uint32_t)val2;
#endif
        if (val2 == 0)
            goto do_jmp;
        goto insn_next;

    LABEL(1ff)
    LABEL(1fe)
    LABEL(1fd)
    LABEL(1fc)
    LABEL(1fb)
    LABEL(1fa)
    LABEL(1f9)
    LABEL(1f8)
    LABEL(1f7)
    LABEL(1f6)
    LABEL(1f5)
    LABEL(1f4)
    LABEL(1f3)
    LABEL(1f2)
    LABEL(1f1)
    LABEL(1f0)
    LABEL(1ef)
    LABEL(1ee)
    LABEL(1ed)
    LABEL(1ec)
    LABEL(1eb)
    LABEL(1ea)
    LABEL(1e9)
    LABEL(1e8)
    LABEL(1e7)
    LABEL(1e6)
    LABEL(1e5)
    LABEL(1e4)
    LABEL(1e3)
    LABEL(1e2)
    LABEL(1e1)
    LABEL(1e0)
    LABEL(1df)
    LABEL(1de)
    LABEL(1dd)
    LABEL(1dc)
    LABEL(1db)
    LABEL(1da)
    LABEL(1d9)
    LABEL(1d8)
    LABEL(1d7)
    LABEL(1d6)
    LABEL(1d5)
    LABEL(1d4)
    LABEL(1d3)
    LABEL(1d2)
    LABEL(1d1)
    LABEL(1d0)
    LABEL(1cf)
    LABEL(1ce)
    LABEL(1cd)
    LABEL(1cc)
    LABEL(1cb)
    LABEL(1ca)
    LABEL(1c9)
    LABEL(1c8)
    LABEL(1c7)
    LABEL(1c6)
    LABEL(1c5)
    LABEL(1c4)
    LABEL(1c3)
    LABEL(1c2)
    LABEL(1b9)
    LABEL(1b8)
    LABEL(1b1)
    LABEL(1b0)
    LABEL(1aa)
    LABEL(1a7)
    LABEL(1a6)
    LABEL(1a2)
    LABEL(17f)
    LABEL(17e)
    LABEL(17d)
    LABEL(17c)
    LABEL(17b)
    LABEL(17a)
    LABEL(179)
    LABEL(178)
    LABEL(177)
    LABEL(176)
    LABEL(175)
    LABEL(174)
    LABEL(173)
    LABEL(172)
    LABEL(171)
    LABEL(170)
    LABEL(16f)
    LABEL(16e)
    LABEL(16d)
    LABEL(16c)
    LABEL(16b)
    LABEL(16a)
    LABEL(169)
    LABEL(168)
    LABEL(167)
    LABEL(166)
    LABEL(165)
    LABEL(164)
    LABEL(163)
    LABEL(162)
    LABEL(161)
    LABEL(160)
    LABEL(15f)
    LABEL(15e)
    LABEL(15d)
    LABEL(15c)
    LABEL(15b)
    LABEL(15a)
    LABEL(159)
    LABEL(158)
    LABEL(157)
    LABEL(156)
    LABEL(155)
    LABEL(154)
    LABEL(153)
    LABEL(152)
    LABEL(151)
    LABEL(150)
    LABEL(13f)
    LABEL(13e)
    LABEL(13d)
    LABEL(13c)
    LABEL(13b)
    LABEL(13a)
    LABEL(139)
    LABEL(138)
    LABEL(137)
    LABEL(136)
    LABEL(133)
    LABEL(12f)
    LABEL(12e)
    LABEL(12d)
    LABEL(12c)
    LABEL(12b)
    LABEL(12a)
    LABEL(129)
    LABEL(128)
    LABEL(127)
    LABEL(126)
    LABEL(125)
    LABEL(124)
    LABEL(117)
    LABEL(116)
    LABEL(115)
    LABEL(114)
    LABEL(113)
    LABEL(112)
    LABEL(111)
    LABEL(110)
    LABEL(10f)
    LABEL(10e)
    LABEL(10d)
    LABEL(10c)
    LABEL(10b)
    LABEL(10a)
    LABEL(104)
    LABEL(103)
    LABEL(102)
    LABEL(f1)
    LABEL(e2)
    LABEL(e1)
    LABEL(e0)
    LABEL(df)
    LABEL(de)
    LABEL(dd)
    LABEL(dc)
    LABEL(db)
    LABEL(da)
    LABEL(d9)
    LABEL(d8)
    LABEL(d7)
    LABEL(d6)
    LABEL(d5)
    LABEL(d4)
    LABEL(ce)
    LABEL(cc)
    LABEL(c8)
    LABEL(af)
    LABEL(ae)
    LABEL(ad)
    LABEL(ac)
    LABEL(ab)
    LABEL(aa)
    LABEL(a7)
    LABEL(a6)
    LABEL(9f)
    LABEL(9e)
    LABEL(9b)
    LABEL(62)
    LABEL(61)
    LABEL(60)
    LABEL(3f)
    LABEL(37)
    LABEL(2f)
    LABEL(27)
    goto unhandled_op;
 unhandled_op:
 illegal_op:
    raise_exception(s, KQEMU_RET_SOFTMMU);
 ljmp_op:
    /* instruction modifying CS:EIP */
    if (get_eflags_if(s))
        goto the_end;
    pc = s->regs1.eip;
    UPDATE_CODE32();
    goto insn_next;
 the_end:
    pc = saved_pc;
    return 0;
}

#ifdef PROFILE_INSN
        {
            int n;
            n = getclock() - ti;
            s->tab_insn_count[opcode]++;
            s->tab_insn_cycles[opcode] += n;
            if (n < s->tab_insn_cycles_min[opcode])
                s->tab_insn_cycles_min[opcode] = n;
            if (n > s->tab_insn_cycles_max[opcode])
                s->tab_insn_cycles_max[opcode] = n;
        }
#endif
