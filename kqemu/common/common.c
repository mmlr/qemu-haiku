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
/* common code for the kernel and monitor.  */

#ifdef IN_MONITOR
#define KER_ONLY(x...)
#define MON_MP_PTR(s, x) (x)
#define KER_MP_PTR(s, x) (x)
#define MON_RP_PTR(s, x) (x)
#define KER_RP_PTR(s, x) (x)
#else
#define KER_ONLY(x...) x
#define MON_MP_PTR(s, x) ((struct mapped_page *)((uint8_t *)(x) + (s)->monitor_to_kernel_offset))
#define KER_MP_PTR(s, x) ((struct mapped_page *)((uint8_t *)(x) - (s)->monitor_to_kernel_offset))
#define MON_RP_PTR(s, x) ((struct kqemu_ram_page *)((uint8_t *)(x) + (s)->monitor_to_kernel_offset))
#define KER_RP_PTR(s, x) ((struct kqemu_ram_page *)((uint8_t *)(x) - (s)->monitor_to_kernel_offset))
#endif

/* actualize the segment cache in cpu state from the real segment cpu
   cache (we use the LDT and GDT descriptors) */
static inline void reload_seg_cache(struct kqemu_state *s, int seg_reg, 
                                    uint16_t selector)
{
    struct kqemu_segment_cache *sc;
    uint32_t e1, e2, sel;
    uint8_t *ptr;

#ifdef USE_SEG_GP
    if (s->cpu_state.cpl != 3) {
        uint32_t sel1;
        sel1 = selector | 3;
        if (sel1 != 3) {
            /* XXX: set DPL correctly */
            if (sel1 == s->regs1.cs_sel || sel1 == s->regs1.ss_sel) {
                sel = (selector & ~7) | ((selector & 4) << 14);
                ptr = (uint8_t *)s->dt_table + sel;
                e1 = *(uint32_t *)(ptr);
                e2 = *(uint32_t *)(ptr + 4);
            } else {
                e1 = s->seg_desc_cache[seg_reg][0];
                e2 = s->seg_desc_cache[seg_reg][1];
            }
        } else {
            e1 = 0;
            e2 = 0;
        }
    } else 
#endif
    {
        /* the CPL=3 DT table is not modified */
        sel = (selector & ~7) | ((selector & 4) << 14);
        ptr = (uint8_t *)s->dt_table + ((NB_DT_TABLES - 1) << 17) + sel;
        e1 = *(uint32_t *)(ptr);
        e2 = *(uint32_t *)(ptr + 4);
    }
    sc = &s->cpu_state.segs[seg_reg];
    if (seg_reg == R_CS || seg_reg == R_SS)
        selector = (selector & ~3) | s->cpu_state.cpl;
    sc->selector = selector;
    sc->flags = e2;
#ifdef __x86_64__
    if (seg_reg >= R_FS) {
        /* do nothing: the base is always loaded before with the
           FSBASE and GSBASE MSRs */
    } else
#endif
        sc->base = get_seg_base(e1, e2);
    sc->limit = get_seg_limit(e1, e2);
}

void restore_cpu_state_from_regs(struct kqemu_state *s,
                                 struct kqemu_exception_regs *r)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
#ifdef __x86_64__
    env->regs[R_EAX] = r->eax;
    env->regs[R_ECX] = r->ecx;
    env->regs[R_EDX] = r->edx;
    env->regs[R_EBX] = r->ebx;
    env->regs[R_ESP] = r->esp;
    env->regs[R_EBP] = r->ebp;
    env->regs[R_ESI] = r->esi;
    env->regs[R_EDI] = r->edi;
    env->regs[8] = r->r8;
    env->regs[9] = r->r9;
    env->regs[10] = r->r10;
    env->regs[11] = r->r11;
    env->regs[12] = r->r12;
    env->regs[13] = r->r13;
    env->regs[14] = r->r14;
    env->regs[15] = r->r15;
    env->eip = r->eip;
    env->eflags = (s->comm_page.virt_eflags & EFLAGS_MASK) | (r->eflags & ~EFLAGS_MASK);
    
    reload_seg_cache(s, R_CS, r->cs_sel);
    reload_seg_cache(s, R_SS, r->ss_sel);
    reload_seg_cache(s, R_DS, env->segs[R_DS].selector);
    reload_seg_cache(s, R_ES, env->segs[R_ES].selector);
#else
    env->regs[R_EAX] = r->eax;
    env->regs[R_ECX] = r->ecx;
    env->regs[R_EDX] = r->edx;
    env->regs[R_EBX] = r->ebx;
    env->regs[R_ESP] = r->esp;
    env->regs[R_EBP] = r->ebp;
    env->regs[R_ESI] = r->esi;
    env->regs[R_EDI] = r->edi;
    env->eip = r->eip;
    env->eflags = (s->comm_page.virt_eflags & EFLAGS_MASK) | (r->eflags & ~EFLAGS_MASK);

    reload_seg_cache(s, R_CS, r->cs_sel);
    reload_seg_cache(s, R_SS, r->ss_sel);
    reload_seg_cache(s, R_DS, r->ds_sel);
    reload_seg_cache(s, R_ES, r->es_sel);
#endif
    reload_seg_cache(s, R_FS, env->segs[R_FS].selector);
    reload_seg_cache(s, R_GS, env->segs[R_GS].selector);
}

#if 0
/* return a new virtual address suitable to map a page in it */
static void free_vaddr(struct kqemu_state *s, unsigned long vaddr)
{
    unsigned long page_index;
    page_index = (vaddr - s->monitor_vaddr) >> PAGE_SHIFT;
    if (page_index >= MAX_MAPPED_PAGES)
        return;
    s->mapped_pages[page_index].next = s->first_mapped_page;
    s->first_mapped_page = page_index;
}
#endif

/* return -1 if no virtual address available */
static unsigned long get_vaddr(struct kqemu_state *s)
{
    int page_index;
    page_index = s->first_mapped_page;
    if (page_index == -1)
        return -1;
    s->first_mapped_page = s->mapped_pages[page_index].next;
    return s->monitor_vaddr + ((unsigned long)page_index << PAGE_SHIFT);
}

static inline unsigned int page_index_hash_func(unsigned long page_index)
{
    return (page_index ^ (page_index >> MAPPED_PAGES_HASH_BITS)) & 
        (MAPPED_PAGES_HASH_SIZE - 1);
}

static inline void *page_index_to_virt(struct kqemu_state *s,
                                       unsigned long page_index)
{
    struct mapped_page *p;
    p = s->mapped_pages_hash[page_index_hash_func(page_index)];
    for(;;) {
        if (!p) 
            return NULL;
        p = MON_MP_PTR(s, p);
        if (p->page_index == page_index)
            return (void *)(((p - s->mapped_pages) << PAGE_SHIFT) + 
                            s->monitor_vaddr);
        p = p->hash_next;
    }
}

static inline void *page_index_to_kaddr(struct kqemu_state *s,
                                        unsigned long page_index)
{
    struct mapped_page *p;
    p = s->mapped_pages_hash[page_index_hash_func(page_index)];
    for(;;) {
        if (!p) 
            return NULL;
        p = MON_MP_PTR(s, p);
        if (p->page_index == page_index)
            return kqemu_page_kaddr(p->host_page);
        p = p->hash_next;
    }
}

static inline void set_vaddr_page_index(struct kqemu_state *s,
                                        unsigned long vaddr,
                                        unsigned long page_index,
                                        void *host_page,
                                        int is_user)
{
    struct mapped_page *p, **ph;
    p = &s->mapped_pages[(vaddr - s->monitor_vaddr) >> PAGE_SHIFT];
    p->page_index = page_index;
    p->host_page = host_page;
    p->user_page = is_user;
    ph = &s->mapped_pages_hash[page_index_hash_func(page_index)];
    p->hash_next = *ph;
    *ph = KER_MP_PTR(s, p);
}
                                  

/* PTE access */

#ifdef IN_MONITOR
#define page_index_to_addr(s, x) page_index_to_virt(s, x)
#else
#define page_index_to_addr(s, x) page_index_to_kaddr(s, x)
#endif

#ifdef __x86_64__

/* alloc = 0 : do not allocate PTEs
           1 : allocate up to PTE page
           2 : allocate up to PDE page 
*/
/* PAE x86_64 case */
static inline uint64_t *mon_get_ptep_l3(struct kqemu_state *s, 
                                        int as_index, unsigned long vaddr,
                                        int alloc KER_ONLY(, unsigned long *pvptep))
{
    int pml4e_index, pdpe_index, pde_index, pte_index;
    unsigned long pdp_page_index, pde_page_index, pte_page_index;
    uint64_t pml4e, pdpe, pde;
    uint64_t *pgd_page, *pdp_page, *pde_page, *pte_page;
    void *ptr;
    
    pgd_page = s->pgds[as_index].l4;
    pml4e_index = (vaddr >> 39) & 0x1ff;
    pml4e = pgd_page[pml4e_index];
    if (!(pml4e & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        /* allocage a new page */
        ptr = mon_alloc_page(s, &pdp_page_index);
        if (!ptr)
            return NULL;
        pgd_page[pml4e_index] = ((uint64_t)pdp_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK;
    } else {
        pdp_page_index = pml4e >> PAGE_SHIFT;
    }
    pdp_page = page_index_to_addr(s, pdp_page_index);

    pdpe_index = (vaddr >> 30) & 0x1ff;
    pdpe = pdp_page[pdpe_index];
    if (!(pdpe & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        ptr = mon_alloc_page(s, &pde_page_index);
        if (!ptr)
            return NULL;
        pdp_page[pdpe_index] = ((uint64_t)pde_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK;
    } else {
        pde_page_index = pdpe >> PAGE_SHIFT;
    }
    pde_page = page_index_to_addr(s, pde_page_index);
    
    pde_index = (vaddr >> 21) & 0x1ff;
    if (alloc == 2)
        return pde_page + pde_index;
    pde = pde_page[pde_index];
    if (!(pde & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        ptr = mon_alloc_page(s, &pte_page_index);
        if (!ptr)
            return NULL;
        pde_page[pde_index] = ((uint64_t)pte_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK;
    } else {
        pte_page_index = pde >> PAGE_SHIFT;
    }
    pte_page = page_index_to_addr(s, pte_page_index);
        
    pte_index = (vaddr >> 12) & 0x1ff;
#ifndef IN_MONITOR
    if (pvptep) {
        *pvptep = (unsigned long)((uint64_t *)page_index_to_virt(s, pte_page_index) + pte_index);
    }
#endif
    return pte_page + pte_index;
}

/* just to avoid putting ifdefs */
static inline uint32_t *mon_get_ptep_l2(struct kqemu_state *s, 
                                        int as_index, unsigned long vaddr,
                                        int alloc KER_ONLY(, unsigned long *pvptep))
{
    return NULL;
}

#else
/* PAE case */
static inline uint64_t *mon_get_ptep_l3(struct kqemu_state *s, 
                                        int as_index, unsigned long vaddr,
                                        int alloc KER_ONLY(, unsigned long *pvptep))
{
    int pdpe_index, pde_index, pte_index;
    unsigned long pde_page_index, pte_page_index;
    uint64_t pdpe, pde;
    uint64_t *pgd_page, *pde_page, *pte_page;
    void *ptr;
    
    pgd_page = s->pgds[as_index].l3;
    pdpe_index = vaddr >> 30;
    pdpe = pgd_page[pdpe_index];
    if (!(pdpe & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        /* allocage a new page */
        ptr = mon_alloc_page(s, &pde_page_index);
        if (!ptr)
            return NULL;
        /* no other bit must be set otherwise GPF */
        pgd_page[pdpe_index] = ((uint64_t)pde_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK;
    } else {
        pde_page_index = pdpe >> PAGE_SHIFT;
    }
    pde_page = page_index_to_addr(s, pde_page_index);
    
    pde_index = (vaddr >> 21) & 0x1ff;
    if (alloc == 2)
        return pde_page + pde_index;
    pde = pde_page[pde_index];
    if (!(pde & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        ptr = mon_alloc_page(s, &pte_page_index);
        if (!ptr)
            return NULL;
        pde_page[pde_index] = ((uint64_t)pte_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK;
    } else {
        pte_page_index = pde >> PAGE_SHIFT;
    }
    pte_page = page_index_to_addr(s, pte_page_index);
        
    pte_index = (vaddr >> 12) & 0x1ff;
#ifndef IN_MONITOR
    if (pvptep) {
        *pvptep = (unsigned long)((uint64_t *)page_index_to_virt(s, pte_page_index) + pte_index);
    }
#endif
    return pte_page + pte_index;
}

/* legacy case */
static inline uint32_t *mon_get_ptep_l2(struct kqemu_state *s, 
                                        int as_index, unsigned long vaddr,
                                        int alloc KER_ONLY(, unsigned long *pvptep))
{
    int pde_index, pte_index;
    unsigned long pte_page_index;
    uint32_t pde;
    uint32_t *pgd_page, *pte_page;
    void *ptr;
    
    pgd_page = s->pgds[as_index].l2;
    pde_index = vaddr >> PGD_SHIFT;
    if (alloc == 2)
        return pgd_page + pde_index;
    pde = pgd_page[pde_index];
    if (!(pde & PG_PRESENT_MASK))  {
        if (!alloc)
            return NULL;
        /* allocage a new page */
        ptr = mon_alloc_page(s, &pte_page_index);
        if (!ptr)
            return NULL;
        pgd_page[pde_index] = (pte_page_index << PAGE_SHIFT) | 
            PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK;
    } else {
        pte_page_index = pde >> PAGE_SHIFT;
    }
    pte_page = page_index_to_addr(s, pte_page_index);
    pte_index = (vaddr >> PAGE_SHIFT) & PTE_MASK;
#ifndef IN_MONITOR
    if (pvptep) {
        *pvptep = (unsigned long)((uint32_t *)page_index_to_virt(s, pte_page_index) + pte_index);
    }
#endif
    return pte_page + pte_index;
}
#endif

#ifdef IN_MONITOR
static unsigned long mon_get_pte(struct kqemu_state *s, 
                                 int as_index, unsigned long vaddr)
{
    if (USE_PAE(s)) {
        uint64_t *ptep, pte;
        ptep = mon_get_ptep_l3(s, as_index, vaddr, 0 KER_ONLY(, NULL));
        if (!ptep)
            return -1;
        pte = *ptep;
        if (!(pte & PG_PRESENT_MASK))
            return -1;
        return pte >> PAGE_SHIFT;
    } else {
        uint32_t *ptep, pte;
        ptep = mon_get_ptep_l2(s, as_index, vaddr, 0 KER_ONLY(, NULL));
        if (!ptep)
            return -1;
        pte = *ptep;
        if (!(pte & PG_PRESENT_MASK))
            return -1;
        return pte >> PAGE_SHIFT;
    }
}
#endif

/* RAM page handling */

static inline unsigned int ram_page_hash_func(unsigned long page_index)
{
    return (page_index ^ (page_index >> RAM_PAGE_HASH_BITS)) & 
        (RAM_PAGE_HASH_SIZE - 1);
}

static inline struct kqemu_ram_page *
find_ram_page_from_paddr(struct kqemu_state *s, 
                         unsigned long paddr)
{
    struct kqemu_ram_page *rp;
    rp = s->ram_page_hash[ram_page_hash_func(paddr)];
    while (rp != NULL) {
        rp = MON_RP_PTR(s, rp);
        if (rp->paddr == paddr)
            return rp;
        rp = rp->hash_next;
    }
    return NULL;
}

#ifdef IN_MONITOR

#ifdef __x86_64__
static unsigned long *get_ram_page_next_mapping_alloc(struct kqemu_state *s, 
                                                      int as_index,
                                                      unsigned long vaddr,
                                                      int alloc)
{
    int pml4e_index, pdpe_index, pde_index, pte_index;
    unsigned long ***pml4e, **pdpe, *pde;

    pml4e_index = (vaddr >> 39) & 0x1ff;
    pml4e = s->ram_page_mappings[as_index][pml4e_index];
    if (!pml4e) {
        if (!alloc)
            return NULL;
        pml4e = mon_alloc_page(s, NULL);
        if (!pml4e)
            return NULL;
        s->ram_page_mappings[as_index][pml4e_index] = pml4e;
    }

    pdpe_index = (vaddr >> 30) & 0x1ff;
    pdpe = pml4e[pdpe_index];
    if (!pdpe) {
        if (!alloc)
            return NULL;
        pdpe = mon_alloc_page(s, NULL);
        if (!pdpe)
            return NULL;
        pml4e[pdpe_index] = pdpe;
    }

    pde_index = (vaddr >> 21) & 0x1ff;
    pde = pdpe[pde_index];
    if (!pde) {
        if (!alloc)
            return NULL;
        pde = mon_alloc_page(s, NULL);
        if (!pde)
            return NULL;
        pdpe[pde_index] = pde;
    }
    
    pte_index = (vaddr >> 12) & 0x1ff;
    return pde + pte_index;
}
#else
static unsigned long *get_ram_page_next_mapping_alloc(struct kqemu_state *s, 
                                                      int as_index,
                                                      unsigned long vaddr,
                                                      int alloc)
{
    int pgd_index;
    unsigned long *ptep;
    pgd_index = vaddr >> PGD_SHIFT;
    ptep = s->ram_page_mappings[as_index][pgd_index];
    if (!ptep) {
        if (!alloc)
            return NULL;
        ptep = mon_alloc_page(s, NULL);
        if (!ptep)
            return NULL;
        s->ram_page_mappings[as_index][pgd_index] = ptep;
    }
    ptep += (vaddr >> PAGE_SHIFT) & PTE_MASK;
    return ptep;
}
#endif

static inline unsigned long *get_ram_page_next_mapping(struct kqemu_state *s, 
                                                       int as_index,
                                                       unsigned long vaddr)
{
    return get_ram_page_next_mapping_alloc(s, as_index, vaddr, 0);
}

#define GET_AS(vaddr) ((vaddr >> 1) & 0x7ff)
#define IS_LAST_VADDR(vaddr) ((vaddr & 1) == 0)

/* WARNING: the PTE is not modified */
static void unmap_virtual_ram_page(struct kqemu_state *s, 
                                   int as_index,
                                   unsigned long vaddr1)
{
    struct kqemu_ram_page *rp;
    unsigned long *pvaddr, *ppvaddr, vaddr;
    unsigned long page_index;

#ifdef DEBUG_INVALIDATE
    monitor_log(s, "unmap_virtual_ram_page: as=%d vaddr=%p\n", 
                as_index, (void *)vaddr1);
#endif
    page_index = mon_get_pte(s, as_index, vaddr1);
    if (page_index == -1)
        return;
    rp = find_ram_page_from_paddr(s, page_index);
    if (!rp) {
        return;
    }
    /* should never happen */
    if (rp->vaddr == -1)
        return;
#ifdef DEBUG_INVALIDATE
    monitor_log(s, "rp->vaddr=%p\n", (void *)rp->vaddr);
#endif
    vaddr1 = vaddr1 | (as_index << 1);
    if (rp->vaddr == vaddr1) {
        /* fast case (no other mappings) */
        rp->vaddr = -1;

        /* remove from mapping list */
        MON_RP_PTR(s, rp->map_prev)->map_next = rp->map_next;
        MON_RP_PTR(s, rp->map_next)->map_prev = rp->map_prev;
    } else {
        /* slow case */
        pvaddr = &rp->vaddr; /* current mapping pointer */
        ppvaddr = NULL; /* previous mapping pointer */
        for(;;) {
            vaddr = *pvaddr;
#ifdef DEBUG_INVALIDATE
            monitor_log(s, "vaddr=%p\n", (void *)vaddr);
#endif
            if ((vaddr & ~1) == vaddr1) {
                if (IS_LAST_VADDR(vaddr)) {
                    /* no mapping after : we just modify the last one,
                       if any */
                    if (!ppvaddr)
                        *pvaddr = -1; /* no previous mapping */
                    else
                        *ppvaddr &= ~1;
                } else {
                    /* there is a mapping after */
                    *pvaddr = *get_ram_page_next_mapping(s, GET_AS(vaddr),
                                                         vaddr & ~0xfff);
                }
                break;
            }
            if (IS_LAST_VADDR(vaddr))
                break;
            ppvaddr = pvaddr;
            pvaddr = get_ram_page_next_mapping(s, GET_AS(vaddr), 
                                               vaddr & ~0xfff);
        }
    }
}

/* unmap a ram page (all its mappings are suppressed) */
static void unmap_ram_page(struct kqemu_state *s, 
                           struct kqemu_ram_page *rp)
{
    unsigned long vaddr, addr, k;
    unsigned long *ptep;

    if (rp->vaddr == -1)
        return;
    vaddr = rp->vaddr;
    for(;;) {
#ifdef DEBUG_INVALIDATE
        monitor_log(s, "unram_ram_page: vaddr=%p\n", (void *)vaddr);
#endif
        addr = vaddr & ~0xfff;
        if ((addr - s->ram_page_cache_base) < RAM_PAGE_CACHE_SIZE * PAGE_SIZE) {
            k = (addr - s->ram_page_cache_base) >> PAGE_SHIFT;
            /* invalidate the soft TLB mapping */
            if (k < SOFT_TLB_SIZE) {
                TLBEntry *e;
                e = &s->soft_tlb[k];
                e->vaddr[0] = -1;
                e->vaddr[1] = -1;
                e->vaddr[2] = -1;
                e->vaddr[3] = -1;
            }
            /* invalidate the ram page cache */
            s->slot_to_ram_addr[k] = -1;
        }
        mon_set_pte(s, GET_AS(vaddr), addr, 0, 0);
        if (IS_LAST_VADDR(vaddr))
            break;
        ptep = get_ram_page_next_mapping(s, GET_AS(vaddr), addr);
        vaddr = *ptep;
    }
    rp->vaddr = -1;

    /* remove from mapping list */
    MON_RP_PTR(s, rp->map_prev)->map_next = rp->map_next;
    MON_RP_PTR(s, rp->map_next)->map_prev = rp->map_prev;
}
#endif

/* Note: we use a format close to a real x86 page table. XXX: add more
   physical address bits */
static uint32_t *phys_page_findp(struct kqemu_state *s,
                                 unsigned long page_index, int alloc)
{
    int l1_index, l2_index;
    unsigned long pde, pt_page_index;
    uint32_t *pt_page;
    void *ptr;

    l1_index = (page_index >> 10) & 0x3ff;
    pde = s->phys_to_ram_map_pages[l1_index];
    if (!(pde & PG_PRESENT_MASK)) {
        if (!alloc)
            return NULL;
        ptr = mon_alloc_page(s, &pt_page_index);
        if (!ptr)
            return NULL;
        s->phys_to_ram_map_pages[l1_index] = 
            (pt_page_index << PAGE_SHIFT) | PG_PRESENT_MASK;
    } else {
        pt_page_index = pde >> PAGE_SHIFT;
    }
    pt_page = page_index_to_addr(s, pt_page_index);
    l2_index = page_index & PTE_MASK;
    return pt_page + l2_index;
}

static inline void map_ram_init(struct kqemu_state *s)
{
    struct kqemu_ram_page *rp_head;
    rp_head = &s->mapped_page_head;
    rp_head->map_next = KER_RP_PTR(s, rp_head);
    rp_head->map_prev = KER_RP_PTR(s, rp_head);
}

static void soft_tlb_flush(struct kqemu_state *s)
{
    int i;
    for(i = 0;i < SOFT_TLB_SIZE; i++) {
        s->soft_tlb[i].vaddr[0] = -1;
        s->soft_tlb[i].vaddr[1] = -1;
        s->soft_tlb[i].vaddr[2] = -1;
        s->soft_tlb[i].vaddr[3] = -1;
    }
}

#ifndef IN_MONITOR
static inline void lock_ram_init(struct kqemu_state *s)
{
    struct kqemu_ram_page *rp_head;
    rp_head = &s->locked_page_head;
    rp_head->lock_next = KER_RP_PTR(s, rp_head);
    rp_head->lock_prev = KER_RP_PTR(s, rp_head);
    s->nb_locked_ram_pages = 0;
}
#endif

#ifdef IN_MONITOR
static inline void soft_tlb_invalidate(struct kqemu_state *s, 
                                       unsigned long vaddr)
{
    TLBEntry *e;
    vaddr &= PAGE_MASK;
    e = &s->soft_tlb[(vaddr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (e->vaddr[0] == vaddr ||
        e->vaddr[1] == vaddr ||
        e->vaddr[2] == vaddr ||
        e->vaddr[3] == vaddr) {
        e->vaddr[0] = -1;
        e->vaddr[1] = -1;
        e->vaddr[2] = -1;
        e->vaddr[3] = -1;
    }
}

static void tlb_flush(struct kqemu_state *s, int global)
{
    struct kqemu_ram_page *rp, *rp_next;
#ifdef PROFILE_INTERP2
    int64_t ti;
#endif

#ifdef PROFILE_INTERP2
    ti = getclock();
#endif
    for(rp = s->mapped_page_head.map_next; 
        rp != KER_RP_PTR(s, &s->mapped_page_head); 
        rp = rp_next) {
        rp_next = rp->map_next;
        rp = MON_RP_PTR(s, rp);
        unmap_ram_page(s, rp);
    }
    /* init list */
    map_ram_init(s);
    soft_tlb_flush(s);
#ifdef IN_MONITOR
#ifdef USE_USER_PG_GLOBAL
    if (PG_GLOBAL(s)) {
        unsigned long host_cr4;
        /* flush global pages too */
        asm volatile("mov %%cr4, %0" : "=r" (host_cr4));
        asm volatile ("mov %0, %%cr4" : : "r" (host_cr4 & ~CR4_PGE_MASK));
        asm volatile ("mov %0, %%cr3" : : "r" (s->monitor_cr3));
        asm volatile ("mov %0, %%cr4" : : "r" (host_cr4));
    } else
#endif
    {
        asm volatile ("mov %0, %%cr3" : : "r" (s->monitor_cr3));
    }
#endif
#ifdef PROFILE_INTERP2
    s->tlb_flush_cycles += getclock() - ti;
    s->tlb_flush_count++;
#endif
}

static void tlb_flush_page(struct kqemu_state *s, unsigned long vaddr)
{
#ifdef PROFILE_INTERP2
    int64_t ti;
#endif

#ifdef PROFILE_INTERP2
    ti = getclock();
#endif
    vaddr &= PAGE_MASK;
    if ((vaddr - s->monitor_vaddr) < MONITOR_MEM_SIZE)
        return;
    /* flush user and kernel pages */
    unmap_virtual_ram_page(s, 0, vaddr);
    mon_set_pte(s, 0, vaddr, 0, 0);

    unmap_virtual_ram_page(s, 1, vaddr);
    mon_set_pte(s, 1, vaddr, 0, 0);

    soft_tlb_invalidate(s, vaddr);
#ifdef PROFILE_INTERP2
    s->tlb_flush_page_cycles += getclock() - ti;
    s->tlb_flush_page_count++;
#endif
}

#endif

