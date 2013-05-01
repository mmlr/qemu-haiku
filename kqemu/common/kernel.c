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

#include "monitor-image.h"

//#define DEBUG
//#define DEBUG_INVALIDATE

static int mon_set_pte(struct kqemu_state *s, unsigned long vaddr, 
                       unsigned long page_index, uint32_t pte_flags);
static void *mon_alloc_page(struct kqemu_state *s, 
                            unsigned long *ppage_index);

#include "common.c"

void *memcpy(void *d1, const void *s1, size_t len)
{
    uint8_t *d = d1;
    const uint8_t *s = s1;

    while (len--) {
        *d++ = *s++;
    }
    return d1;
}

void *memset(void *d1, int val, size_t len)
{
    uint8_t *d = d1;

    while (len--) {
        *d++ = val;
    }
    return d1;
}

static void set_seg(uint32_t *p, unsigned long addr, unsigned long limit, 
                    int flags)
{
    unsigned int e1, e2;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000) |
        (flags << 8);
    p[0] = e1;
    p[1] = e2;
}

#ifdef __x86_64__
static void set_seg64(uint32_t *p, unsigned long addr, unsigned long limit, 
                      int flags)
{
    unsigned int e1, e2;
    e1 = (addr << 16) | (limit & 0xffff);
    e2 = ((addr >> 16) & 0xff) | (addr & 0xff000000) | (limit & 0x000f0000) |
        (flags << 8);
    p[0] = e1;
    p[1] = e2;
    p[2] = addr >> 32;
    p[3] = 0;
}
#endif

static void set_gate(uint32_t *p, unsigned int type, unsigned int dpl, 
                     unsigned long addr, unsigned int sel)
{
    unsigned int e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p[0] = e1;
    p[1] = e2;
#ifdef __x86_64__
    p[2] = addr >> 32;
    p[3] = 0;
#endif
}

#if 0
static void set_trap_gate(struct kqemu_state *s, int n, int dpl, void *addr)
{
    set_gate((uint32_t *)(s->idt_table + IDT_ENTRY_SIZE * n),
             15, dpl, (unsigned long )addr, s->monitor_cs_sel);
}
#endif

static void set_intr_gate(struct kqemu_state *s, int n, int dpl, unsigned long addr)
{
    set_gate((uint32_t *)(s->idt_table + IDT_ENTRY_SIZE * n),
             14, dpl, addr, s->monitor_cs_sel);
}

static void mon_set_interrupt(struct kqemu_state *s, int intno, int is_int)
{
    const struct monitor_code_header *m = (void *)monitor_code;
    int dpl;

    switch(intno) {
    case 3:
    case 4:
    case 5:
        dpl = 3;
        break;
    default:
        dpl = 0;
        break;
    }
    set_intr_gate(s, intno, dpl, m->interrupt_table + 
                  INTERRUPT_ENTRY_SIZE * intno + s->monitor_vaddr);
}


/* only used during init */

static void mon_map_page_init(struct kqemu_state *s)
{
    int i;

    s->first_mapped_page = (s->monitor_end_vaddr - s->monitor_vaddr) >> PAGE_SHIFT;
    for(i = s->first_mapped_page; i < MAX_MAPPED_PAGES - 1; i++) {
        s->mapped_pages[i].next = i + 1;
    }
    s->mapped_pages[MAX_MAPPED_PAGES - 1].next = -1;
    for(i = 0; i < MAX_MAPPED_PAGES; i++) {
        s->mapped_pages[i].page_index = -1;
        s->mapped_pages[i].host_page = NULL;
    }
}

/* return NULL if error */
static void *mon_alloc_page(struct kqemu_state *s, 
                            unsigned long *ppage_index)
{
    unsigned long vaddr, page_index;
    struct kqemu_page *host_page;
    host_page = kqemu_alloc_zeroed_page(&page_index);
    if (!host_page) {
#ifdef DEBUG
        kqemu_log("mon_alloc_page: NULL\n");
#endif
        return NULL;
    }
    vaddr = get_vaddr(s);
    set_vaddr_page_index(s, vaddr, page_index, host_page, 0);
    /* avoid recursion during init */
    if (!s->in_page_init)
        mon_set_pte(s, vaddr, page_index, PG_PRESENT_MASK | PG_GLOBAL(s) | PG_RW_MASK);
#ifdef DEBUG
    kqemu_log("mon_alloc_page: vaddr=%p page_index=%08lx\n",
              (void *)vaddr, (void *)page_index);
#endif
    if (ppage_index)
        *ppage_index = page_index;
    return (void *)vaddr;
}

static int mon_set_pte(struct kqemu_state *s, unsigned long vaddr, 
                       unsigned long page_index, uint32_t pte_flags)
{
#ifdef DEBUG
    kqemu_log("mon_set_pte: vaddr=0x%lx page_index=0x%lx pte_flags=0x%x\n",
              vaddr, page_index, pte_flags);
#endif
    if (USE_PAE(s)) {
        uint64_t *ptep;
        ptep = mon_get_ptep_l3(s, 0, vaddr, 1, NULL);
        if (!ptep)
            return -1;
        *ptep = ((uint64_t)page_index << PAGE_SHIFT) | pte_flags;
    } else {
        uint32_t *ptep;
        ptep = mon_get_ptep_l2(s, 0, vaddr, 1, NULL);
        if (!ptep)
            return -1;
        *ptep = (page_index << PAGE_SHIFT) | pte_flags;
    }
    return 0;
}

/* return NULL if error */
static void *mon_user_map(struct kqemu_state *s, void *uaddr, int size, 
                          int pte_flags)
{
    unsigned long page_index, vaddr, i;
    void *ptr = NULL;
    struct kqemu_user_page *host_page;

    size = PAGE_ALIGN(size);
    
    /* NOTE: we use the fact that getvaddr returns contiguous pages */
    for(i = 0; i < size; i += 4096) {
        host_page = kqemu_lock_user_page(&page_index, 
                                         (unsigned long)uaddr + i);
        if (!host_page)
            return NULL;
        vaddr = get_vaddr(s);
        set_vaddr_page_index(s, vaddr, page_index, host_page, 1);
        mon_set_pte(s, vaddr, page_index, 
                    PG_PRESENT_MASK | PG_GLOBAL(s) | pte_flags);
        if (i == 0)
            ptr = (void *)vaddr;
    }
    return ptr;
}

#define cpuid(index, eax, ebx, ecx, edx) \
  asm volatile ("cpuid" \
                : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) \
                : "0" (index))

#ifdef __x86_64__
static int is_cpuid_supported(void)
{
    return 1;
}
#else
static int is_cpuid_supported(void)
{
    int v0, v1;
    asm volatile ("pushf\n"
                  "popl %0\n"
                  "movl %0, %1\n"
                  "xorl $0x00200000, %0\n"
                  "pushl %0\n"
                  "popf\n"
                  "pushf\n"
                  "popl %0\n"
                  : "=a" (v0), "=d" (v1)
                  :
                  : "cc");
    return (v0 != v1);
}
#endif

static void get_cpuid_features(struct kqemu_state *s)
{
    uint32_t eax, ebx, ecx, edx;
    int is_intel;

    if (!is_cpuid_supported()) {
        s->cpuid_features = 0;
        return;
    } else {
        cpuid(0, eax, ebx, ecx, edx);
        is_intel = (ebx == 0x756e6547 && edx == 0x49656e69 && 
                    ecx == 0x6c65746e);
        cpuid(1, eax, ebx, ecx, edx);
        /* SEP is buggy on some pentium pros */
        if (is_intel && (edx & CPUID_SEP) &&
            (eax & 0xfff) < 0x633) {
            edx &= ~CPUID_SEP;
        }
        s->cpuid_features = edx;

        s->cpuid_ext2_features = 0;
        cpuid(0x80000000, eax, ebx, ecx, edx);
        if (eax >= 0x80000001) {
            cpuid(0x80000001, eax, ebx, ecx, edx);
            s->cpuid_ext2_features = edx;
        }
    }
}

/* per instance locked ram page allocation logic */
static void kqemu_update_locked_ram_pages(struct kqemu_global_state *g)
{
    struct kqemu_state *s;
    unsigned long total_ram_pages, max_locked_ram_pages;

    total_ram_pages = 0;
    for(s = g->first_state; s != NULL; s = s->next_state) {
        total_ram_pages += s->nb_ram_pages;
    }

    /* XXX: better logic to guaranty no overflow ? */
    for(s = g->first_state; s != NULL; s = s->next_state) {
        max_locked_ram_pages = (g->max_locked_ram_pages * s->nb_ram_pages) / 
            total_ram_pages;
        if (max_locked_ram_pages < MIN_LOCKED_RAM_PAGES)
            max_locked_ram_pages = MIN_LOCKED_RAM_PAGES;
        s->max_locked_ram_pages = max_locked_ram_pages;
#ifdef DEBUG
        kqemu_log("state %p: max locked ram=%d KB\n", 
                  s, s->max_locked_ram_pages * 4);
#endif
    }
}

static int kqemu_add_state(struct kqemu_global_state *g, 
                           struct kqemu_state *s)
{
    int ret;

    spin_lock(&g->lock);
    if (((g->nb_kqemu_states + 1) * MIN_LOCKED_RAM_PAGES) > 
        g->max_locked_ram_pages) {
        ret = -1;
    } else {
        s->global_state = g;
        s->next_state = g->first_state;
        g->first_state = s;
        g->nb_kqemu_states++;
        kqemu_update_locked_ram_pages(g);
        ret = 0;
    }
    spin_unlock(&g->lock);
    return ret;
}

static void kqemu_del_state(struct kqemu_state *s)
{
    struct kqemu_global_state *g = s->global_state;
    struct kqemu_state **ps;

    if (g) {
        spin_lock(&g->lock);
        for(ps = &g->first_state; *ps != NULL; ps = &(*ps)->next_state) {
            if (*ps == s) {
                *ps = s->next_state;
                break;
            }
        }
        g->nb_kqemu_states--;
        kqemu_update_locked_ram_pages(g);
        spin_unlock(&g->lock);
    }
}

struct kqemu_global_state *kqemu_global_init(int max_locked_pages)
{
    struct kqemu_global_state *g;
    
    g = kqemu_vmalloc(PAGE_ALIGN(sizeof(struct kqemu_global_state)));
    if (!g)
        return NULL;
    memset(g, 0, sizeof(struct kqemu_global_state));
    spin_lock_init(&g->lock);
    g->max_locked_ram_pages = max_locked_pages;
    return g;
}

void kqemu_global_delete(struct kqemu_global_state *g)
{
    /* XXX: free all existing states ? */
    kqemu_vfree(g);
}

struct kqemu_state *kqemu_init(struct kqemu_init *d, 
                               struct kqemu_global_state *g)
{
    struct kqemu_state *s;
    const struct monitor_code_header *m = (void *)monitor_code;
    unsigned long vaddr;
    const uint8_t *kernel_vaddr;
    int i, j, n, kqemu_state_size;
    uint8_t *s1;
    uint64_t *dt_table;

    /* some consistency checks */
    if (((unsigned long)d->ram_base & ~PAGE_MASK) != 0 ||
        ((unsigned long)d->ram_dirty & ~PAGE_MASK) != 0 ||
        (d->ram_size & ~PAGE_MASK) != 0 ||
        d->ram_size >= 0x7ffff000 ||
        ((unsigned long)d->pages_to_flush & ~PAGE_MASK) != 0 ||
        ((unsigned long)d->ram_pages_to_update & ~PAGE_MASK) != 0 ||
        ((unsigned long)d->modified_ram_pages & ~PAGE_MASK) != 0) {
        kqemu_log("Invalid kqemu_init data alignment\n");
        return NULL;
    }

    n = d->ram_size >> PAGE_SHIFT;
    kqemu_state_size = PAGE_ALIGN(sizeof(monitor_code)) + 
        PAGE_ALIGN(sizeof(struct kqemu_state) + 
                   n * sizeof(struct kqemu_ram_page));
    s1 = kqemu_vmalloc(kqemu_state_size);
    if (!s1)
        return NULL;
    memset(s1, 0, kqemu_state_size);
    memcpy(s1, monitor_code, sizeof(monitor_code));
    s = (void *)(s1 + PAGE_ALIGN(sizeof(monitor_code)));
    
#ifndef __x86_64__
    /* check PAE state */
    {
        unsigned long host_cr4;
        asm volatile ("movl %%cr4, %0" : "=r" (host_cr4));
        s->use_pae = (host_cr4 & CR4_PAE_MASK) != 0;
    }
#endif

    /* the following can be initialized with any value */
#ifdef __x86_64__
    //    s->monitor_vaddr = 0xffff900000000000;
    /* must stay in low 4GB for easier 16 bit ESP fix */
    s->monitor_vaddr = 0xf0000000;
#else
    s->monitor_vaddr = 0xf0000000;
#endif
    s->monitor_selector_base = 0xf180;
#ifdef DEBUG
    kqemu_log("kqemu_init monitor_vaddr=0x%08lx sel_base=0x%04x\n", 
              s->monitor_vaddr, s->monitor_selector_base);
#endif
    
    /* selectors */
    s->monitor_cs_sel = s->monitor_selector_base + (0 << 3);
#ifdef __x86_64__
    s->monitor_ds_sel = 0; /* no need for a specific data segment */
    /* used for 16 bit esp fix */
    s->monitor_cs32_sel = (s->monitor_selector_base + (7 << 3)) | 1;
    s->monitor_ss16_sel = (s->monitor_selector_base + (6 << 3)) | 1;
    s->monitor_ss_null_sel = (s->monitor_selector_base + (1 << 3)) | 3;
#else
    s->monitor_ds_sel = s->monitor_selector_base + (1 << 3);
    s->monitor_ss16_sel = s->monitor_selector_base + (6 << 3);
#endif
    s->monitor_ldt_sel = s->monitor_selector_base + (2 << 3);

    s->monitor_data_vaddr = s->monitor_vaddr + 
        PAGE_ALIGN(sizeof(monitor_code));
    s->monitor_end_vaddr = s->monitor_vaddr + kqemu_state_size;
    s->monitor_to_kernel_offset = (unsigned long)s - s->monitor_data_vaddr;

    /* must be done easly so that 'fail' case works */
    lock_ram_init(s);

    /* IDT init */
    s->monitor_idt.base = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, idt_table);
    s->monitor_idt.limit = sizeof(s->idt_table) - 1;

    /* we use interrupt gates to disable IF */
    for(i = 0; i <= 0x13; i++) {
        mon_set_interrupt(s, i, 0);
    }
    for(i = 0x14; i < 256; i++) {
        mon_set_interrupt(s, i, 1);
    }

    /* GDT init */
    s->monitor_gdt.limit = 0xffff;

    /* TSS init */
#ifdef __x86_64__
    s->monitor_tss.rsp0 = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, regs1.dummy[0]);
    s->monitor_tss.bitmap = 0x8000; /* no I/O permitted */
#else
    /* TSS init */
    s->monitor_tss.esp0 = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, regs1.dummy[0]);
    s->monitor_tss.ss0 = s->monitor_ds_sel;
    s->monitor_tss.bitmap = 0x8000; /* no I/O permitted */
    s->monitor_tss.back_link = 0xffff; /* generates error if iret with
                                          NT bit */
#endif

#ifdef __x86_64__
    set_seg64(s->tr_desc_cache,
              s->monitor_data_vaddr + 
              offsetof(struct kqemu_state, monitor_tss),
              sizeof(struct kqemu_tss) - 1, 0x89);
#else
    set_seg(s->tr_desc_cache,
            s->monitor_data_vaddr + 
            offsetof(struct kqemu_state, monitor_tss),
            235, 0x89);
#endif

    /* for each CPL we create a LDT and GDT */
    for(i = 0; i < NB_DT_TABLES; i++) {
        unsigned long ldt_addr;
        dt_table = s->dt_table + i * 16384;
        ldt_addr = s->monitor_data_vaddr + 
            offsetof(struct kqemu_state, dt_table) + 0x10000 + 0x20000 * i;
#ifdef __x86_64__
        set_seg64((uint32_t *)(dt_table + (s->monitor_ldt_sel >> 3)),
                  ldt_addr, 0xffff, 0x82);
        set_seg((uint32_t *)(dt_table + (s->monitor_cs_sel >> 3)),
                0, 0xfffff, 0xa09a); /* long mode segment */
        set_seg((uint32_t *)(dt_table + (s->monitor_ss16_sel >> 3)),
                (s->monitor_data_vaddr + offsetof(struct kqemu_state, stack)) & ~0xffff, 
                0xffff, 0x00b2); /* SS16 segment for 16 bit ESP fix */
        set_seg((uint32_t *)(dt_table + (s->monitor_cs32_sel >> 3)),
                0, 0xfffff, 0xc0ba); /* CS32 segment for 16 bit ESP fix */
        set_seg((uint32_t *)(dt_table + (s->monitor_ss_null_sel >> 3)),
                0, 0, 0x40f2); /* substitute for null SS segment */
#else
        set_seg((uint32_t *)(dt_table + (s->monitor_ldt_sel >> 3)),
                ldt_addr, 0xffff, 0x82);
        set_seg((uint32_t *)(dt_table + (s->monitor_cs_sel >> 3)),
                0, 0xfffff, 0xc09a);
        set_seg((uint32_t *)(dt_table + (s->monitor_ds_sel >> 3)),
                0, 0xfffff, 0xc092);
        set_seg((uint32_t *)(dt_table + (s->monitor_ss16_sel >> 3)),
                (s->monitor_data_vaddr + offsetof(struct kqemu_state, stack)) & ~0xffff, 
                0xffff, 0x0092);
#endif
    }
    
    /* page table init */
    mon_map_page_init(s);

    s->in_page_init = 1; /* avoid recursion in page allocator */

    /* make sure we allocate enough PTE for the monitor itself (2 MB
       is OK for both PAE and normal MMU) */
    for(i = 0; i < MONITOR_MEM_SIZE; i += 2048 * 1024) {
        mon_set_pte(s, s->monitor_vaddr + i, 0, 0);
    }

    /* set the pte of the allocated pages (no page_alloc is needed) */
    for(i = 0; i < MAX_MAPPED_PAGES; i++) {
        unsigned long page_index;
        page_index = s->mapped_pages[i].page_index;
        if (page_index != -1) {
            mon_set_pte(s, s->monitor_vaddr + ((unsigned long)i << PAGE_SHIFT), 
                        page_index, 
                        PG_PRESENT_MASK | PG_GLOBAL(s) | PG_RW_MASK);
        }
    }
    s->in_page_init = 0;

    kernel_vaddr = s1;
    for(vaddr = s->monitor_vaddr; vaddr < s->monitor_data_vaddr;
        vaddr += PAGE_SIZE) {
        /* XXX: RW because of data, need to set it only to the right
           pages */
        mon_set_pte(s, vaddr, kqemu_vmalloc_to_phys(kernel_vaddr), 
                    PG_PRESENT_MASK | PG_GLOBAL(s) | PG_RW_MASK);
        kernel_vaddr += PAGE_SIZE;
    }
    for(; vaddr < s->monitor_end_vaddr;
        vaddr += PAGE_SIZE) {
        mon_set_pte(s, vaddr, kqemu_vmalloc_to_phys(kernel_vaddr), 
                    PG_PRESENT_MASK | PG_GLOBAL(s) | PG_RW_MASK);
        kernel_vaddr += PAGE_SIZE;
    }

    /* clone the monitor PTE pages in each address space */
    for(i = 1; i < NB_ADDRESS_SPACES; i++) {
        if (USE_PAE(s)) {
            uint64_t *pdep, *pdep1;
            for(j = 0; j < MONITOR_MEM_SIZE; j += 2048 * 1024) {
                vaddr = s->monitor_vaddr + j;
                pdep = mon_get_ptep_l3(s, 0, vaddr, 2, NULL);
                pdep1 = mon_get_ptep_l3(s, i, vaddr, 2, NULL);
                *pdep1 = *pdep;
            }
        } else {
            uint32_t *pdep, *pdep1;
            for(j = 0; j < MONITOR_MEM_SIZE; j += 4096 * 1024) {
                vaddr = s->monitor_vaddr + j;
                pdep = mon_get_ptep_l2(s, 0, vaddr, 2, NULL);
                pdep1 = mon_get_ptep_l2(s, i, vaddr, 2, NULL);
                *pdep1 = *pdep;
            }
        }
    }

    /* set the cr3 register of each address space */
    for(i = 0; i < NB_ADDRESS_SPACES; i++) {
        unsigned long pfn;

        pfn = kqemu_vmalloc_to_phys(&s->pgds[i]);
    /* sanity check */
#ifndef __x86_64__
        if (pfn >= (1 << (32 - PAGE_SHIFT))) {
            kqemu_log("Error: invalid cr3 (%p)\n", (void *)pfn);
            goto fail;
        }
#endif
        s->pgds_cr3[i] = pfn << PAGE_SHIFT;
#ifdef DEBUG
        kqemu_log("pgds_cr3[%d] = %p\n", i, (void *)s->pgds_cr3[i]);
        {
            int start, end;
            start = s->monitor_vaddr >> 22;
            end = start + (MONITOR_MEM_SIZE >> 22);
            for(j=start;j<end;j++) {
                kqemu_log("%03x: %08x\n", j, s->pgds[i].l2[j]);
            }
        }
#endif
    }

    /* prepare nexus page switch logic */
    {
        unsigned long monitor_page;
        
        s->nexus_kaddr = (unsigned long)s1;
        monitor_page = kqemu_vmalloc_to_phys((void *)s->nexus_kaddr);
        if (USE_PAE(s)) {
            s->nexus_pte = ((uint64_t)monitor_page << PAGE_SHIFT) | 
                PG_PRESENT_MASK | PG_GLOBAL(s);
            for(i = 0; i < NB_ADDRESS_SPACES; i++) {
                s->nexus_kaddr_ptep[i] =
                    mon_get_ptep_l3(s, i, s->nexus_kaddr, 1, 
                                    (unsigned long *)&s->nexus_kaddr_vptep[i]);
            }
        } else {
            s->nexus_pte = (monitor_page << PAGE_SHIFT) | 
                PG_PRESENT_MASK | PG_GLOBAL(s);
            for(i = 0; i < NB_ADDRESS_SPACES; i++) {
                s->nexus_kaddr_ptep[i] = 
                    mon_get_ptep_l2(s, i, s->nexus_kaddr, 1, 
                                    (unsigned long *)&s->nexus_kaddr_vptep[i]);
            }
        }
#ifdef DEBUG
        kqemu_log("nexus_kaddr=%p nexus_pte=0x%08x vptep0=%p vptep1=%p\n", 
                  (void *)s->nexus_kaddr, 
                  (int)s->nexus_pte, 
                  (void *)s->nexus_kaddr_vptep[0], 
                  (void *)s->nexus_kaddr_vptep[1]);
#endif
    }
    s->monitor_data_kaddr = (unsigned long)s;
    s->monitor_jmp = m->kernel2monitor_jmp_offset + s->monitor_vaddr;
    s->kernel_jmp = m->monitor2kernel_jmp_offset + (unsigned long)s1;

    /* communication page */
    s->comm_page_index = kqemu_vmalloc_to_phys(&s->comm_page);

    /* physical RAM */
    {
        int i;
        struct kqemu_ram_page *p;

        s->ram_size = d->ram_size;
        s->nb_ram_pages = s->ram_size >> PAGE_SHIFT;
        s->ram_base_uaddr = (unsigned long)d->ram_base;
#ifdef DEBUG
        kqemu_log("nb_ram_pages=%d\n", s->nb_ram_pages);
#endif
        p = s->ram_pages;
        for(i = 0; i < s->nb_ram_pages; i++) {
            p[i].paddr = -1;
            p[i].vaddr = -1;
        }
        
        /* init mapped ram page list */
        map_ram_init(s);
    }

    s->ram_dirty = mon_user_map(s, d->ram_dirty, s->ram_size >> PAGE_SHIFT,
                                PG_RW_MASK);
    if (!s->ram_dirty)
        goto fail;
    
    s->pages_to_flush = mon_user_map(s, d->pages_to_flush, PAGE_SIZE, 
                                     PG_RW_MASK);
    if (!s->pages_to_flush)
        goto fail;

    s->ram_pages_to_update = mon_user_map(s, d->ram_pages_to_update, 
                                          PAGE_SIZE, 0);
    if (!s->ram_pages_to_update)
        goto fail;

    s->modified_ram_pages = mon_user_map(s, d->modified_ram_pages, 
                                          PAGE_SIZE, PG_RW_MASK);
    if (!s->modified_ram_pages)
        goto fail;

    for(i = 0;i < RAM_PAGE_CACHE_SIZE;i++) {
        vaddr = get_vaddr(s);
        if (i == 0)
            s->ram_page_cache_base = vaddr;
    }
    for(i = 0;i < RAM_PAGE_CACHE_SIZE;i++) {
        s->slot_to_ram_addr[i] = -1;
    }

    soft_tlb_flush(s);

    get_cpuid_features(s);

    /* disable SEP code if sysenter is not supported by the CPU or not
       used by the OS */
    s->use_sep = 0;
    if (s->cpuid_features & CPUID_SEP) {
        uint32_t dummy, cs_val;
        rdmsr(MSR_IA32_SYSENTER_CS, cs_val, dummy);
        if (cs_val != 0) {
            s->use_sep = 1;
        }
    }
    /* syscall support */
    s->use_syscall = 0;
    if (s->cpuid_ext2_features & CPUID_EXT2_SYSCALL) {
        uint32_t efer_low, efer_high;
        rdmsr(MSR_EFER, efer_low, efer_high);
        if (efer_low & MSR_EFER_SCE) {
            s->use_syscall = 1;
        }
    }
    /* apic to disable NMI if required */
    s->use_apic = 0;
    if (s->cpuid_features & CPUID_APIC) {
        uint32_t apic_base, apic_baseh;
        rdmsr(MSR_IA32_APICBASE, apic_base, apic_baseh);
        if (apic_base & MSR_IA32_APICBASE_ENABLE) {
            apic_base = apic_base & MSR_IA32_APICBASE_BASE;
            s->apic_regs = kqemu_io_map(apic_base >> PAGE_SHIFT, PAGE_SIZE);
            if (s->apic_regs) {
                s->apic_lvt_max = (s->apic_regs[APIC_LVR >> 2] >> 16) & 0xff;
                if (s->apic_lvt_max < 3)
                    s->apic_lvt_max = 3;
                else if (s->apic_lvt_max > 5)
                    s->apic_lvt_max = 5;
                s->use_apic = 1;
#if defined(DEBUG)
                kqemu_log("apic_base=%p (virt=%p) apic_lvt_max=%d\n", 
                          (void *)apic_base, (void *)s->apic_regs,
                          s->apic_lvt_max);
#endif
            }
        }
    }

#ifndef __x86_64__
    /* PGE support */
    s->pg_global_mask = 0;
    if (s->cpuid_features & CPUID_PGE)
        s->pg_global_mask = PG_GLOBAL_MASK;
#endif
        
#ifdef PROFILE_INSN
    {
        for(i=0;i<512;i++) {
            s->tab_insn_cycles_min[i] = 0x7fffffff;
        }
    }
#endif
    if (kqemu_add_state(g, s) < 0)
        goto fail;
    return s;
 fail:
    kqemu_delete(s);
    return NULL;
}

int kqemu_set_phys_mem(struct kqemu_state *s,
                       const struct kqemu_phys_mem *kphys_mem)
{
    uint64_t start, size, end, addr;
    uint32_t ram_addr, ram_end, *ptr, pd, io_index;
    
    start = kphys_mem->phys_addr;
    size = kphys_mem->size;
    end = start + size;
    if ((start & ~PAGE_MASK) != 0 || (end & ~PAGE_MASK) != 0)
        return -1;
    /* XXX: we only support 32 bit physical address space */
    if ((start & ~0xffffffffULL) != 0 ||
        ((end - 1) & ~0xffffffffULL) != 0)
        return -1;
    io_index = kphys_mem->io_index;
    if (io_index > KQEMU_IO_MEM_UNASSIGNED)
        return -1;
    pd = io_index;
    if (io_index <= KQEMU_IO_MEM_ROM) {
        ram_addr = kphys_mem->ram_addr;
        if ((ram_addr & ~PAGE_MASK) != 0) 
            return -1;
        ram_end = ram_addr + size;
        /* check overflow */
        if (ram_end < ram_addr) 
            return -1;
        if (ram_end > s->ram_size) 
            return -1;
        pd |= (ram_addr & PAGE_MASK);
    }
    for(addr = start; addr != end; addr += PAGE_SIZE) {
        ptr = phys_page_findp(s, addr >> PAGE_SHIFT, 1);
        if (!ptr)
            return -1;
        *ptr = pd;
        if (io_index <= KQEMU_IO_MEM_ROM)
            pd += PAGE_SIZE;
    }
    return 0;
}

#ifdef PROFILE_INTERP2

#ifdef __x86_64__
static inline unsigned int lldiv(uint64_t a, uint64_t b)
{
    int q;
    if (b == 0) {
        q = 0;
    } else {
        q = a / b;
    }
    return q;
}
#else
static unsigned int lldiv(uint64_t a, uint64_t b)
{
    uint32_t b32;
    unsigned int q, r;

    if (b == 0) {
        q = 0;
    } else {
        while (b >= 0x100000000LL) {
            b >>= 1;
            a >>= 1;
        }
        b32 = b;
        asm volatile ("divl %2" 
                      : "=a" (q), "=d" (r) 
                      : "m" (b32), "a" ((uint32_t )a), "d" ((uint32_t )(a >> 32)));
    }
    return q;
}
#endif

#define CYCLES_TO_MS(x) lldiv(x, 2400000)
#define EXCP_CYCLES 1200 /* approximate cycles to handle one exception */

static void profile_dump(struct kqemu_state *s)
{
#ifdef PROFILE_INSN
    for(i=0;i<512;i++) {
        if (s->tab_insn_count[i] != 0) {
            kqemu_log("%02x: %9lld %4d %4d %4d %11lld\n", 
                      i,
                      s->tab_insn_count[i],
                      s->tab_insn_cycles_min[i],
                      lldiv(s->tab_insn_cycles[i], s->tab_insn_count[i]),
                      s->tab_insn_cycles_max[i],
                      s->tab_insn_cycles[i]);
        }
    }
#endif
#ifdef PROFILE_INTERP_PC
    {
        int i, j, n;
        ProfileInterpEntry *pe, *pe1, *pe2, tmp;
        int64_t cycles_tot, cycles_sum;

        kqemu_log("Interp PC dump:\n");
        kqemu_log("n: EIP count avg_insn_count avg_cycles cumulative_time\n");

        /* add exception cost */
        for(i = 0; i < s->nb_profile_interp_entries; i++) {
            pe = &s->profile_interp_entries[i];
            pe->cycles += pe->count * EXCP_CYCLES;
        }

        /* sort */
        for(i = 0; i < (s->nb_profile_interp_entries - 1); i++) {
            for(j = i + 1; j < s->nb_profile_interp_entries; j++) {
                pe1 = &s->profile_interp_entries[i];
                pe2 = &s->profile_interp_entries[j];
                if (pe1->cycles < pe2->cycles) {
                    tmp = *pe1;
                    *pe1 = *pe2;
                    *pe2 = tmp;
                }
            }
        }

        cycles_tot = 0;
        for(i = 0; i < s->nb_profile_interp_entries; i++) 
            cycles_tot += s->profile_interp_entries[i].cycles;

        cycles_sum = 0;
        n = s->nb_profile_interp_entries;
        if (n > 50)
            n = 50;
        for(i = 0; i < n; i++) {
            pe = &s->profile_interp_entries[i];
            cycles_sum += pe->cycles;
            kqemu_log("%4d: " FMT_lx " %lld %d %d %d%%\n", 
                      i,
                      pe->eip,
                      pe->count,
                      lldiv(pe->insn_count, pe->count),
                      lldiv(pe->cycles, pe->count),
                      lldiv(cycles_sum * 100, cycles_tot));
        }
    }
#endif
    kqemu_log("Execution statistics:\n");
    kqemu_log("total_interp_count=%lld\n",
              s->total_interp_count);
    kqemu_log("exc_interp: count=%lld avg_insn=%d (%lld)\n",
              s->exc_interp_count, 
              lldiv(s->exc_insn_count, s->exc_interp_count),
              s->exc_insn_count);
    kqemu_log("exc_interp: max=%d EIP=%08lx\n",
              s->exc_insn_count_max,
              s->exc_start_eip_max);
    kqemu_log("exc_seg_cycles=%d cycles/insn=%d (%d ms)\n",
              lldiv(s->exc_seg_cycles, s->exc_interp_count), 
              lldiv(s->exc_interp_cycles, s->exc_insn_count),
              CYCLES_TO_MS(s->exc_interp_cycles + s->exc_seg_cycles + s->exc_interp_count * EXCP_CYCLES));
    kqemu_log("interp_interrupt: count=%lld cycles=%d (%d ms)\n",
              s->interp_interrupt_count,
              lldiv(s->interp_interrupt_cycles, s->interp_interrupt_count),
              CYCLES_TO_MS(s->interp_interrupt_cycles));
              
    kqemu_log("tlb_flush: count=%lld cycles=%d (%d ms)\n",
              s->tlb_flush_count, 
              lldiv(s->tlb_flush_cycles, s->tlb_flush_count),
              CYCLES_TO_MS(s->tlb_flush_cycles));
    kqemu_log("tlb_flush_page: count=%lld cycles=%d (%d ms)\n",
              s->tlb_flush_page_count, 
              lldiv(s->tlb_flush_page_cycles, s->tlb_flush_page_count),
              CYCLES_TO_MS(s->tlb_flush_page_cycles));
    kqemu_log("page faults: total=%lld mmu=%lld cycles=%d (%d ms)\n",
              s->total_page_fault_count,
              s->mmu_page_fault_count,
              lldiv(s->mmu_page_fault_cycles + s->tlb_page_fault_cycles, s->mmu_page_fault_count),
              CYCLES_TO_MS(s->mmu_page_fault_cycles + s->tlb_page_fault_cycles + EXCP_CYCLES * s->total_page_fault_count));
    kqemu_log("page faults tlb: count=%lld (interp_count=%lld) cycles=%d (%d ms)\n", 
              s->tlb_page_fault_count,
              s->tlb_interp_page_fault_count,
              lldiv(s->tlb_page_fault_cycles, s->tlb_page_fault_count),
              CYCLES_TO_MS(s->tlb_page_fault_cycles + EXCP_CYCLES * s->tlb_page_fault_count));
    kqemu_log("exec_init: count=%lld cycles=%d (%d ms)\n", 
              s->exec_init_count, 
              lldiv(s->exec_init_cycles, s->exec_init_count),
              CYCLES_TO_MS(s->exec_init_cycles));
    kqemu_log("hw_interrupt: count=%lld cycles=%d (%d ms)\n", 
              s->hw_interrupt_count, 
              lldiv(s->hw_interrupt_cycles, s->hw_interrupt_count),
              CYCLES_TO_MS(s->hw_interrupt_cycles + EXCP_CYCLES * s->hw_interrupt_count));
    kqemu_log("ram_map: count=%lld miss=%d%%\n",
              s->ram_map_count,
              lldiv(s->ram_map_miss_count * 100, s->ram_map_count));
}
#endif

void kqemu_delete(struct kqemu_state *s)
{
    uint8_t *s1;
    struct kqemu_ram_page *rp;
    struct mapped_page *p;
    int i;

#ifdef PROFILE_INTERP2
    profile_dump(s);
#endif
    /* unlock the user pages */
    for(rp = s->locked_page_head.lock_next; 
        rp != KER_RP_PTR(s, &s->locked_page_head);
        rp = rp->lock_next) {
        rp = MON_RP_PTR(s, rp);
        kqemu_unlock_user_page(rp->host_page);
    }
    
    /* free all user and kernel pages */
    for(i = 0; i < MAX_MAPPED_PAGES; i++) {
        p = &s->mapped_pages[i];
        if (p->host_page != NULL) {
            if (p->user_page) {
                kqemu_unlock_user_page(p->host_page);
            } else {
                kqemu_free_page(p->host_page);
            }
        }
    }
    
    if (s->apic_regs)
        kqemu_io_unmap((void *)s->apic_regs, PAGE_SIZE);

    kqemu_del_state(s);

    s1 = (uint8_t *)s - PAGE_ALIGN(sizeof(monitor_code));
    kqemu_vfree(s1);
}

struct kqemu_cpu_state *kqemu_get_cpu_state(struct kqemu_state *s)
{
    return &s->cpu_state;
}

static inline int apic_check_lvt(struct kqemu_state *s, int lvt)
{
    uint32_t val;
    val = s->apic_regs[(APIC_LVTT >> 2) + lvt * 4];
    if (!(val & APIC_LVT_MASKED) && 
        (val & APIC_DM_MASK) == APIC_DM_NMI) {
        val |= APIC_LVT_MASKED;
        s->apic_regs[(APIC_LVTT >> 2) + lvt * 4] = val;
        return 1 << lvt;
    } else {
        return 0;
    }
}

static inline void apic_restore_lvt(struct kqemu_state *s, int lvt,
                                    int lvt_mask)
{
    if (lvt_mask & (1 << lvt))
        s->apic_regs[(APIC_LVTT >> 2) + lvt * 4] &= ~APIC_LVT_MASKED;
}

static int apic_save_and_disable_nmi(struct kqemu_state *s)
{
    int lvt_mask;

    lvt_mask = 0;
    switch(s->apic_lvt_max) {
    case 5:
    default:
        lvt_mask |= apic_check_lvt(s, 1); /* APIC_LVTTHMR */
        /* fall thru */
    case 4:
        lvt_mask |= apic_check_lvt(s, 2); /* APIC_LVTPC */
        lvt_mask |= apic_check_lvt(s, 2); /* APIC_LVTPC (twice because
                                             could be masked by hardware) */
        /* fall thru */
    case 3:
        lvt_mask |= apic_check_lvt(s, 0); /* APIC_LVTT */
        lvt_mask |= apic_check_lvt(s, 3); /* APIC_LVT0 */
        lvt_mask |= apic_check_lvt(s, 4); /* APIC_LVT1 */
        lvt_mask |= apic_check_lvt(s, 5); /* APIC_LVTERR */
        break;
    }
    return lvt_mask;
}

static void apic_restore_nmi(struct kqemu_state *s, int lvt_mask)
{
    if (lvt_mask) {
        apic_restore_lvt(s, 0, lvt_mask);
        apic_restore_lvt(s, 1, lvt_mask);
        apic_restore_lvt(s, 2, lvt_mask);
        apic_restore_lvt(s, 3, lvt_mask);
        apic_restore_lvt(s, 4, lvt_mask);
        apic_restore_lvt(s, 5, lvt_mask);
    }
}

#define LOAD_DR(n)\
{\
    if ((s->cpu_state.dr ## n - s->monitor_vaddr) < MONITOR_MEM_SIZE) {\
        /* cannot set breakpoint */\
        s->monitor_dr7 &= ~(3 << (2 * n));\
    } else {\
        asm volatile ("mov %0, %%dr" #n : : "r" (s->cpu_state.dr ## n));\
    }\
}

long kqemu_exec(struct kqemu_state *s)
{
    const struct monitor_code_header *m = (void *)monitor_code;
    void (*kernel2monitor)(struct kqemu_state *s) = 
        (void *)(m->kernel2monitor + s->nexus_kaddr);
    unsigned long *ptr;
    int ret, apic_nmi_mask, cpl;
    uint32_t cs_val;
    unsigned long flags;
    uint32_t efer_low, efer_high, efer_low1;
    int is_user;
    uint16_t saved_fs, saved_gs;
#ifdef __x86_64__
    uint16_t saved_ds, saved_es;
    unsigned long fs_base, gs_base;
#endif
    
#ifdef PROFILE
    s->nb_profile_ts = 0;
#endif
    profile_record(s);
    profile_record(s);

    cs_val = 0; /* avoid warning */
    efer_low = 0; /* avoid warning */
    efer_high = 0; /* avoid warning */
    apic_nmi_mask = 0; /* avoid warning */
    
    /* NOTE: we do not abort here because we need to execute the
       various page commands before */
    if ((s->cpu_state.tr.selector & 0xfffc) == 0 ||
        (s->cpu_state.tr.selector & 4) != 0) {
        s->monitor_tr_sel = s->monitor_selector_base + (4 << 3);
    } else {
        s->monitor_tr_sel = s->cpu_state.tr.selector & 0xfff8;
    }

    /* init the initial cr3 */
    cpl = s->cpu_state.cpl;
    cpl &= 3;
    s->cpu_state.cpl = cpl;
    s->monitor_cr3 = s->pgds_cr3[(cpl == 3)];
    /* init the initial GDT */
#ifdef USE_SEG_GP
    s->monitor_gdt.base = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, dt_table) + 0x20000 * (cpl == 3);
#else
    s->monitor_gdt.base = s->monitor_data_vaddr + 
        offsetof(struct kqemu_state, dt_table) + 0x20000 * cpl;
#endif

    /* push stack frame to call monitor_exec() */
    /* reserve space for the registers */
    ptr = (void *)(s->stack_end - sizeof(struct kqemu_exception_regs));
#ifdef __x86_64__
    *--ptr = 0; /* no return addr */
    *--ptr = m->monitor_exec + s->monitor_vaddr;
    *--ptr = 0; /* rbp */
    *--ptr = 0; /* rbx */
    *--ptr = 0; /* r12 */
    *--ptr = 0; /* r13 */
    *--ptr = 0; /* r14 */
    *--ptr = 0; /* r15 */
#else
    *--ptr = s->monitor_data_vaddr; /* parameter = kqemu_state */
    *--ptr = 0; /* no return addr */
    *--ptr = m->monitor_exec + s->monitor_vaddr;
    *--ptr = 0; /* ebp */
    *--ptr = 0; /* ebx */
    *--ptr = 0; /* esi */
    *--ptr = 0; /* edi */
#endif
    s->monitor_esp = s->monitor_data_vaddr + (unsigned long)ptr - 
        (unsigned long)s;
    profile_record(s);
    for(;;) {
        /* currently we execute all the monitor code with interrupt
           masked. It is not optimal but simpler */
        save_flags(flags);
        cli();
        profile_record(s);
        
        if (s->use_apic) {
            apic_nmi_mask = apic_save_and_disable_nmi(s);
        }

        /* load breakpoint registers and avoid setting them if in the
           monitor address space. We suppose that no breakpoints are
           set by the host OS for this process */
        if (s->cpu_state.dr7 & 0xff) {
            s->monitor_dr7 = s->cpu_state.dr7;
            LOAD_DR(0);
            LOAD_DR(1);
            LOAD_DR(2);
            LOAD_DR(3);
            asm volatile ("mov %0, %%dr6" : : "r" (s->cpu_state.dr6));
        } else {
            s->monitor_dr7 = 0;
        }

        profile_record(s);
        if (s->use_sep) {
            uint32_t dummy;
            /* disable SEP */
            rdmsr(MSR_IA32_SYSENTER_CS, cs_val, dummy);
            wrmsr(MSR_IA32_SYSENTER_CS, 0, 0);
        }
        profile_record(s);
        if (s->use_syscall) {
            rdmsr(MSR_EFER, efer_low, efer_high);
            efer_low1 = efer_low & ~MSR_EFER_SCE;
            wrmsr(MSR_EFER, efer_low1, efer_high);
        }
        profile_record(s);
#ifdef __x86_64__
        /* disable syscall/sysret (will generate ILLOP execption) */
        /* save segment registers */
        asm volatile ("movw %%ds, %0" : "=m" (saved_ds));
        asm volatile ("movw %%es, %0" : "=m" (saved_es));
        rdmsrl(MSR_FSBASE, fs_base);
        rdmsrl(MSR_GSBASE, gs_base);
#endif
        asm volatile ("movw %%fs, %0" : "=m" (saved_fs));
        asm volatile ("movw %%gs, %0" : "=m" (saved_gs));
        profile_record(s);
        
        /* write the nexus PTE - we assume the pointer does not change */
        is_user = (s->cpu_state.cpl == 3);
        if (USE_PAE(s)) {
            uint64_t *ptep;
            ptep = s->nexus_kaddr_ptep[is_user];
            s->nexus_orig_pte = *ptep;
            *ptep = s->nexus_pte;
        } else {
            uint32_t *ptep;
            ptep = s->nexus_kaddr_ptep[is_user];
            s->nexus_orig_pte = *ptep;
            *ptep = s->nexus_pte;
        }

        kernel2monitor(s);

        /* restore the original PTE (note that the CPL can change) */
        is_user = (s->cpu_state.cpl == 3);
        if (USE_PAE(s)) {
            uint64_t *ptep;
            ptep = s->nexus_kaddr_ptep[is_user];
            *ptep = s->nexus_orig_pte;
        } else {
            uint32_t *ptep;
            ptep = s->nexus_kaddr_ptep[is_user];
            *ptep = s->nexus_orig_pte;
        }

        profile_record(s);
        /* restore segments */
        asm volatile ("movw %0, %%fs" : : "m" (saved_fs));
        asm volatile ("movw %0, %%gs" : : "m" (saved_gs));
#ifdef __x86_64__
        wrmsrl(MSR_FSBASE, fs_base);
        wrmsrl(MSR_GSBASE, gs_base);
        asm volatile ("movw %0, %%ds" : : "m" (saved_ds));
        asm volatile ("movw %0, %%es" : : "m" (saved_es));
#endif
        profile_record(s);
        if (s->use_syscall) {
            /* restore syscall/sysret */
            wrmsr(MSR_EFER, efer_low, efer_high);
        }
        profile_record(s);
        if (s->use_sep) {
            wrmsr(MSR_IA32_SYSENTER_CS, cs_val, 0);
        }
        profile_record(s);
        if (s->use_apic) {
            apic_restore_nmi(s, apic_nmi_mask);
        }
        profile_record(s);

        if (s->mon_req == MON_REQ_IRQ) {
            struct kqemu_exception_regs *r;
            /* execute the requested host interrupt and then schedule
               in the host OS */
            exec_irq(s->arg0); /* side effect: restore the IRQs */
            r = (void *)((unsigned long)s->regs - s->monitor_data_vaddr + (unsigned long)s);
            if ((r->cs_sel & 3) == 3) {
                /* if interrupting user code, we schedule to give time
                   to the other processes. We can be interrupted by a
                   signal a that case. */
                if (kqemu_schedule()) {
                    restore_cpu_state_from_regs(s, r);
                    ret = KQEMU_RET_INTR;
                    break;
                }
            }
        } else {
            unsigned long page_index;
            
            restore_flags(flags);
            switch(s->mon_req) {
            case MON_REQ_ABORT:
                kqemu_log("aborting: %s", s->log_buf);
                ret = KQEMU_RET_ABORT;
                goto the_end;
            case MON_REQ_EXIT:
                ret = s->arg0;
                if (s->regs) {
                    struct kqemu_exception_regs *r;
                    r = (void *)((unsigned long)s->regs - s->monitor_data_vaddr + (unsigned long)s);
                    restore_cpu_state_from_regs(s, r);
                }
                goto the_end;
            case MON_REQ_LOG:
                kqemu_log("%s", s->log_buf);
                break;
            case MON_REQ_ALLOC_PAGE:
                s->ret = (unsigned long)kqemu_alloc_zeroed_page(&page_index);
                s->ret2 = page_index;
                break;
            case MON_REQ_LOCK_USER_PAGE:
                s->ret = (unsigned long)kqemu_lock_user_page(&page_index,
                                                             s->arg0);
                s->ret2 = page_index;
                break;
            case MON_REQ_UNLOCK_USER_PAGE:
                kqemu_unlock_user_page((struct kqemu_user_page *)s->arg0);
                break;
            case MON_REQ_EXCEPTION:
                exec_exception(s->arg0);
                break;
            default:
                kqemu_log("invalid mon request: %d\n", s->mon_req);
                break;
            }
        }
    }
 the_end:

    profile_record(s);
#ifdef PROFILE
    {
        int i, last, first, overhead;
        first = s->profile_ts[0];
        last = first;
        overhead = s->profile_ts[1] - s->profile_ts[0];
        kqemu_log("profile (overhead=%d):\n", overhead);
        for(i = 1; i < s->nb_profile_ts; i++) {
            kqemu_log("%3d@%4d: %6d %6d\n", 
                      i, s->profile_line[i],
                      s->profile_ts[i] - first - i * overhead, 
                      s->profile_ts[i] - last - overhead);
            last = s->profile_ts[i];
        }
    }
#endif
    s->cpu_state.retval = ret;
    return 0;
}
