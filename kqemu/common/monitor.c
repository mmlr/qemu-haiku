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

//#define DEBUG_TLB
//#define DEBUG_MMU
//#define DEBUG_PHYS_LOAD_STORE
//#define DEBUG_RAM
//#define DEBUG_LOCK
//#define DEBUG_SOFT_TLB
//#define DEBUG_INVALIDATE

//#define PROFILE_SOFTMMU
//#define DEBUG_DT_CACHE

static void mon_set_pte(struct kqemu_state *s, 
                        int as_index, unsigned long vaddr, 
                        unsigned long paddr, int pte_flags);
static void unmap_ram_page(struct kqemu_state *s, 
                           struct kqemu_ram_page *rp);
static void unlock_ram_page(struct kqemu_state *s, 
                            struct kqemu_ram_page *rp);
static void *mon_alloc_page(struct kqemu_state *s, 
                            unsigned long *ppage_index);

#define IN_MONITOR
#include "common.c"

/*
 * Segment state in monitor code:
 *
 * If CPL = 3 or not USE_SEG_GP:
 *   FS, GS are stored in %fs, %gs.
 *   CS, SS, DS, ES are stored in s->reg1.xx_sel
 *   the content of the CPU seg desc caches are consistent with the dt_table
 * 
 * If CPL != 3 and USE_SEG_GP:
 * 
 *   FS, GS are stored in %fs, %gs. If not null and different from
 *   s->reg1.cs_sel and s->reg1.ss_sel, then the content of the CPU
 *   seg desc caches are consistent with s->seg_desc_cache[R_xx]
 * 
 *   DS, ES are stored in s1->reg1.xx_sel. Same remark as FS and FS
 *   for CPU seg desc cache consistency.
 * 
 *   CS, SS are stored in s1->reg1.xx_sel. The content of the CPU seg
 *   desc caches are consistent with the dt_table
 *
 * If seg_cache_loaded is true, then s->cpu_state.segs[].base is
 * updated. For CS and SS, s->cpu_state.segs[].flags is updated too.
 * 
 */

static inline void save_segs(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;

    asm volatile ("movw %%fs, %0" : "=m" (env->segs[R_FS].selector));
    asm volatile ("movw %%gs, %0" : "=m" (env->segs[R_GS].selector));
#ifdef __x86_64__
    rdmsrl(MSR_FSBASE, env->segs[R_FS].base);
    rdmsrl(MSR_GSBASE, env->segs[R_GS].base);
    
    asm volatile ("movw %%ds, %0" : "=m" (env->segs[R_DS].selector));
    asm volatile ("movw %%es, %0" : "=m" (env->segs[R_ES].selector));
#endif
}

static inline void reload_segs(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;

#ifdef USE_SEG_GP
    if (s->cpu_state.cpl != 3) {
        set_cpu_seg_cache(s, R_FS, env->segs[R_FS].selector);
        set_cpu_seg_cache(s, R_GS, env->segs[R_GS].selector);
#ifdef __x86_64__
        set_cpu_seg_cache(s, R_DS, env->segs[R_DS].selector);
        set_cpu_seg_cache(s, R_ES, env->segs[R_ES].selector);
#endif
    } else
#endif
    {
        LOAD_SEG(fs, env->segs[R_FS].selector);
        LOAD_SEG(gs, env->segs[R_GS].selector);
#ifdef __x86_64__
        LOAD_SEG(ds, env->segs[R_DS].selector);
        LOAD_SEG(es, env->segs[R_ES].selector);
#endif
    }
#ifdef __x86_64__
    wrmsrl(MSR_FSBASE, env->segs[R_FS].base);
    wrmsrl(MSR_GSBASE, env->segs[R_GS].base);
#endif
}

void update_host_cr0(struct kqemu_state *s)
{
    unsigned long guest_cr0, host_cr0;

    guest_cr0 = s->cpu_state.cr0;
    host_cr0 = s->kernel_cr0;
    if (guest_cr0 & (CR0_TS_MASK | CR0_EM_MASK)) {
        host_cr0 |= CR0_TS_MASK;
    }
    host_cr0 = (host_cr0 & ~(CR0_MP_MASK)) | (guest_cr0 & CR0_MP_MASK);
    host_cr0 &= ~CR0_AM_MASK;
    if ((guest_cr0 & CR0_AM_MASK) && s->cpu_state.cpl == 3)
        host_cr0 |= CR0_AM_MASK;
    asm volatile ("mov %0, %%cr0" : : "r" (host_cr0));
}

void update_host_cr4(struct kqemu_state *s)
{
    unsigned long guest_cr4, host_cr4, mask;
    asm volatile("mov %%cr4, %0" : "=r" (host_cr4));
    mask = 0;
    if (s->cpuid_features & CPUID_FXSR)
        mask |= CR4_OSFXSR_MASK;
    if (s->cpuid_features & CPUID_SSE)
        mask |= CR4_OSXMMEXCPT_MASK;
    guest_cr4 = s->cpu_state.cr4;
    host_cr4 = (guest_cr4 & mask) | (host_cr4 & ~mask);
    if (s->cpu_state.cpl == 0) {
        host_cr4 &= ~CR4_TSD_MASK; /* rdtsc is enabled */
    } else {
        host_cr4 = (guest_cr4 & CR4_TSD_MASK) | (host_cr4 & ~CR4_TSD_MASK);
    }
    asm volatile ("mov %0, %%cr4" : : "r" (host_cr4));
}

static inline void restore_monitor_nexus_mapping(struct kqemu_state *s)
{
    int is_user;
    /* restore the original mapping */
    is_user = (s->cpu_state.cpl == 3);
    if (USE_PAE(s)) {
        uint64_t *ptep;
        ptep = s->nexus_kaddr_vptep[is_user];
        *ptep = s->nexus_orig_pte;
    } else {
        uint32_t *ptep;
        ptep = s->nexus_kaddr_vptep[is_user];
        *ptep = s->nexus_orig_pte;
    }
    asm volatile ("invlpg (%0)" : : "r" (s->nexus_kaddr));
}

static void monitor2kernel1(struct kqemu_state *s)
{
    struct kqemu_exception_regs *r;
    int is_user;

    r = s->regs;
    if (r) {
        save_segs(s);
    }

    /* map the nexus page to its kernel address */
    is_user = (s->cpu_state.cpl == 3);
    if (USE_PAE(s)) {
        uint64_t *ptep;
        ptep = s->nexus_kaddr_vptep[is_user];
        s->nexus_orig_pte = *ptep;
        *ptep = s->nexus_pte;
    } else {
        uint32_t *ptep;
        ptep = s->nexus_kaddr_vptep[is_user];
        s->nexus_orig_pte = *ptep;
        *ptep = s->nexus_pte;
    }
    asm volatile ("invlpg (%0)" : : "r" (s->nexus_kaddr));

    monitor2kernel(s);

    update_host_cr0(s);

    update_host_cr4(s);

    restore_monitor_nexus_mapping(s);

    if (r) {
        reload_segs(s);
    }
}

void monitor_log(struct kqemu_state *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    mon_vsnprintf(s->log_buf, sizeof(s->log_buf), fmt, ap);
    s->mon_req = MON_REQ_LOG;
    monitor2kernel1(s);
    va_end(ap);
}

void monitor_panic(struct kqemu_state *s, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    mon_vsnprintf(s->log_buf, sizeof(s->log_buf), fmt, ap);
    s->mon_req = MON_REQ_ABORT;
    monitor2kernel1(s);
    /* should never come here */
    while (1);
}

void __attribute__((noreturn, format (printf, 3, 4)))  
monitor_panic_regs(struct kqemu_state *s, struct kqemu_exception_regs *r, 
                   const char *fmt, ...)
{
    va_list ap;
    int len;
    va_start(ap, fmt);
    mon_vsnprintf(s->log_buf, sizeof(s->log_buf), fmt, ap);
    len = strlen(s->log_buf);
    mon_snprintf(s->log_buf + len, sizeof(s->log_buf) - len, 
                 "err=%04x CS:EIP=%04x:" FMT_lx " SS:SP=%04x:" FMT_lx "\n", 
                 (int)r->error_code, r->cs_sel, (long)r->eip, 
                 r->ss_sel, (long)r->esp);
    s->mon_req = MON_REQ_ABORT;
    monitor2kernel1(s);
    /* should never come here */
    while (1);
}

struct kqemu_page *monitor_alloc_page(struct kqemu_state *s, 
                                      unsigned long *ppage_index)
{
    s->mon_req = MON_REQ_ALLOC_PAGE;
    monitor2kernel1(s);
    *ppage_index = s->ret2;
    return (void *)s->ret;
}

static struct kqemu_user_page *monitor_lock_user_page(struct kqemu_state *s,
                                                      unsigned long *ppage_index,
                                                      unsigned long uaddr)
{
    s->mon_req = MON_REQ_LOCK_USER_PAGE;
    s->arg0 = uaddr;
    monitor2kernel1(s);
    *ppage_index = s->ret2;
    return (void *)s->ret;
}

static void monitor_unlock_user_page(struct kqemu_state *s,
                                     struct kqemu_user_page *page)
{
    s->mon_req = MON_REQ_UNLOCK_USER_PAGE;
    s->arg0 = (long)page;
    monitor2kernel1(s);
}

/* return NULL if error */
static void *mon_alloc_page(struct kqemu_state *s, 
                            unsigned long *ppage_index)
{
    unsigned long vaddr, page_index;
    struct kqemu_page *host_page;
    
    host_page = monitor_alloc_page(s, &page_index);
    if (!host_page) {
        return NULL;
    }
    vaddr = get_vaddr(s);
    /* XXX: check error */
    set_vaddr_page_index(s, vaddr, page_index, host_page, 0);
    mon_set_pte(s, 0, vaddr, page_index, 
                PG_PRESENT_MASK | PG_GLOBAL(s) | PG_RW_MASK);
    if (ppage_index)
        *ppage_index = page_index;
    return (void *)vaddr;
}

static void mon_set_pte(struct kqemu_state *s, 
                       int as_index, unsigned long vaddr, 
                       unsigned long page_index, int pte_flags)
{
    if (USE_PAE(s)) {
        uint64_t *ptep;
        ptep = mon_get_ptep_l3(s, as_index, vaddr, 1);
        *ptep = ((uint64_t)page_index << PAGE_SHIFT) | pte_flags;
    } else {
        uint32_t *ptep;
        ptep = mon_get_ptep_l2(s, as_index, vaddr, 1);
        *ptep = (page_index << PAGE_SHIFT) | pte_flags;
    }
    asm volatile("invlpg %0" : : "m" (*(uint8_t *)vaddr));
}

static uint32_t phys_page_find(struct kqemu_state *s, 
                               unsigned long page_index)
{
    uint32_t *ptr, pd;

    ptr = phys_page_findp(s, page_index, 0);
    if (!ptr)
        return KQEMU_IO_MEM_UNASSIGNED;
    pd = *ptr;
#ifdef DEBUG_TLB
    monitor_log(s, "pd=%08x\n", pd);
#endif
    return pd;
}

/* return the ram page only if it is already locked */
static struct kqemu_ram_page *get_locked_ram_page(struct kqemu_state *s, 
                                                  unsigned long ram_addr)
{
    int ram_page_index;
    struct kqemu_ram_page *rp;
    ram_page_index = ram_addr >> PAGE_SHIFT;
    rp = &s->ram_pages[ram_page_index];
    if (rp->paddr == -1) 
        return NULL;
    return rp;
}

/* unlock some pages to be able to allocate at least one page */
static void unlock_pages(struct kqemu_state *s)
{
    while (s->nb_locked_ram_pages >= s->max_locked_ram_pages) {
        /* unlock the least recently used pages */
        unlock_ram_page(s, s->locked_page_head.lock_prev);
    }
}

static struct kqemu_ram_page *lock_ram_page(struct kqemu_state *s, 
                                            unsigned long ram_addr)
{
    int ram_page_index;
    struct kqemu_ram_page *rp, **p, *rp_prev, *rp_next;
    unsigned long uaddr, page_index;
    struct kqemu_user_page *host_page;

    ram_page_index = ram_addr >> PAGE_SHIFT;
    rp = &s->ram_pages[ram_page_index];
    if (rp->paddr == -1) {

        unlock_pages(s);

        uaddr = ram_addr + s->ram_base_uaddr;
        host_page = monitor_lock_user_page(s, &page_index, uaddr);
        if (!host_page)
            monitor_panic(s, "Could not lock user page %p", (void *)uaddr);
        rp->paddr = page_index;
        rp->host_page = host_page;

        /* insert in hash table */
        p = &s->ram_page_hash[ram_page_hash_func(page_index)];
        rp->hash_next = *p;
        *p = rp;

        /* insert at lock list head */
        rp_prev = &s->locked_page_head;
        rp_next = s->locked_page_head.lock_next;
        rp_next->lock_prev = rp;
        rp->lock_next = rp_next;
        rp_prev->lock_next = rp;
        rp->lock_prev = rp_prev;
        s->nb_locked_ram_pages++;
#ifdef DEBUG_LOCK
        monitor_log(s, "lock_ram_page: %p rp=%p\n", (void *)ram_addr, rp);
#endif
    }
    return rp;
}

static void unlock_ram_page(struct kqemu_state *s, 
                            struct kqemu_ram_page *rp)
{
    struct kqemu_ram_page **prp;
 
    if (rp->paddr == -1)
        return;
#ifdef DEBUG_LOCK
    monitor_log(s, "unlock_ram_page: rp=%p\n", rp);
#endif
    unmap_ram_page(s, rp);

    /* remove it from the hash list */
    prp = &s->ram_page_hash[ram_page_hash_func(rp->paddr)];
    for(;;) {
        if (*prp == NULL)
            break;
        if (*prp == rp) {
            *prp = rp->hash_next;
            break;
        }
        prp = &(*prp)->hash_next;
    }
    
    /* unlock it in the kernel */
    monitor_unlock_user_page(s, rp->host_page);
    
    rp->paddr = -1;

    /* remove from lock list */
    rp->lock_prev->lock_next = rp->lock_next;
    rp->lock_next->lock_prev = rp->lock_prev;
    s->nb_locked_ram_pages--;
}

static void map_ram_page(struct kqemu_state *s, 
                         int as_index, unsigned long vaddr,
                         struct kqemu_ram_page *rp, int pte_flags)
{
    unsigned long *rptep;
    struct kqemu_ram_page *rp_prev, *rp_next;

#ifdef DEBUG_RAM
    monitor_log(s, "map_ram_page: vaddr=%p rp=%p pte_flags=0x%x\n", 
                (void *)vaddr, rp, pte_flags);
#endif    
    unmap_virtual_ram_page(s, as_index, vaddr);
    
    mon_set_pte(s, as_index, vaddr, rp->paddr, pte_flags);
    
    if (rp->vaddr == -1) {
        /* most common case */
        rp->vaddr = vaddr | (as_index << 1);

        /* add in mapping list */
        rp_prev = s->mapped_page_head.map_prev;
        rp_next = &s->mapped_page_head;
        rp_next->map_prev = rp;
        rp->map_next = rp_next;
        rp_prev->map_next = rp;
        rp->map_prev = rp_prev;
    } else {
        /* add a new mapping (there is already at least one mapping) */
        rptep = get_ram_page_next_mapping_alloc(s, as_index, vaddr, 1);
        if (!rptep) 
            monitor_panic(s, "next_mapping: could not alloc page");
        *rptep = rp->vaddr;
        rp->vaddr = vaddr | (as_index << 1) | 1;
    }

    /* move to head in locked list */
    rp_prev = &s->locked_page_head;
    if (rp != rp_prev->lock_next) {
        /* delete */
        rp->lock_prev->lock_next = rp->lock_next;
        rp->lock_next->lock_prev = rp->lock_prev;

        /* insert at head */
        rp_next = s->locked_page_head.lock_next;
        rp_next->lock_prev = rp;
        rp->lock_next = rp_next;
        rp_prev->lock_next = rp;
        rp->lock_prev = rp_prev;
    }
}

static unsigned long ram_ptr_to_ram_addr(struct kqemu_state *s, void *ptr)
{
    int slot;
    slot = ((unsigned long)ptr - s->ram_page_cache_base) >> PAGE_SHIFT;
    return s->slot_to_ram_addr[slot];
}

static void *get_ram_ptr_slow(struct kqemu_state *s, int slot,
                              unsigned long ram_addr)
{
    struct kqemu_ram_page *rp;
    unsigned long vaddr;
    void *ptr;
    
#ifdef PROFILE_INTERP2
    s->ram_map_miss_count++;
#endif
    rp = lock_ram_page(s, ram_addr);
    vaddr = (slot << PAGE_SHIFT) + s->ram_page_cache_base;
    /* map the ram page */
    map_ram_page(s, 0, vaddr, rp, 
                 PG_PRESENT_MASK | PG_GLOBAL(s) | 
                 PG_ACCESSED_MASK | PG_DIRTY_MASK | 
                 PG_RW_MASK);
    s->slot_to_ram_addr[slot] = ram_addr;
    ptr = (void *)vaddr;
#if defined(DEBUG_SOFT_TLB)
    monitor_log(s, "get_ram_ptr: slot=%d ram_addr=%p ptr=%p\n", 
                slot, (void *)ram_addr, ptr);
#endif
    return ptr;
}

static inline void *get_ram_ptr(struct kqemu_state *s, int slot,
                                unsigned long ram_addr)
{
    unsigned long vaddr;
#ifdef PROFILE_INTERP2
    s->ram_map_count++;
#endif
    if (likely(s->slot_to_ram_addr[slot] == ram_addr)) {
        vaddr = (slot << PAGE_SHIFT) + s->ram_page_cache_base;
        return (void *)vaddr;
    } else {
        return get_ram_ptr_slow(s, slot, ram_addr);
    }
}

static inline int ram_is_dirty(struct kqemu_state *s, unsigned long ram_addr)
{
    return s->ram_dirty[ram_addr >> PAGE_SHIFT] == 0xff;
}

static inline int ram_get_dirty(struct kqemu_state *s, unsigned long ram_addr,
                                int dirty_flags)
{
    return s->ram_dirty[ram_addr >> PAGE_SHIFT] & dirty_flags;
}

static void ram_set_read_only(struct kqemu_state *s, 
                              unsigned long ram_addr)
{
    struct kqemu_ram_page *rp;
    unsigned long addr, vaddr;
    unsigned long *nptep;
    uint32_t *ptep;

    rp = get_locked_ram_page(s, ram_addr);
    if (rp) {
        vaddr = rp->vaddr;
        if (vaddr == -1)
            return;
        for(;;) {
            addr = vaddr & ~0xfff;
            if ((addr - s->ram_page_cache_base) < SOFT_TLB_SIZE * PAGE_SIZE) {
                /* XXX: do it too */
            } else {
                if (USE_PAE(s))
                    ptep = (uint32_t *)mon_get_ptep_l3(s, 
                                                       GET_AS(vaddr), addr, 0);
                else
                    ptep = mon_get_ptep_l2(s, GET_AS(vaddr), addr, 0);
                *ptep &= ~PG_RW_MASK;
                asm volatile("invlpg %0" : : "m" (*(uint8_t *)addr));
            }
            if (IS_LAST_VADDR(vaddr))
                break;
            nptep = get_ram_page_next_mapping(s, GET_AS(vaddr), addr);
            vaddr = *nptep;
        }
    }
}

/* XXX: need to reset user space structures too */
static void ram_reset_dirty(struct kqemu_state *s, 
                            unsigned long ram_addr, int dirty_flag)
{

    /* we must modify the protection of all the user pages if it is
       not already done */
    if (ram_is_dirty(s, ram_addr)) {
        ram_set_read_only(s, ram_addr);
        /* signal QEMU that it needs to update its TLB info */
        s->cpu_state.nb_ram_pages_to_update = 1;
    }
    s->ram_dirty[ram_addr >> PAGE_SHIFT] &= ~dirty_flag;
}

static inline void *get_phys_mem_ptr(struct kqemu_state *s, 
                                     unsigned long paddr, int write)
{
    int io_index, slot;
    unsigned long pd, ram_addr;
    uint8_t *ptr;

    pd = phys_page_find(s, paddr >> PAGE_SHIFT);
    io_index = (pd & ~PAGE_MASK);
    if (unlikely(io_index != KQEMU_IO_MEM_RAM)) {
        if (io_index != KQEMU_IO_MEM_ROM)
            return NULL;
        if (write)
            return NULL;
    }
    ram_addr = pd & PAGE_MASK;
    slot = (ram_addr >> PAGE_SHIFT);
    slot = slot ^ (slot >> PHYS_SLOT_BITS) ^ (slot >> (2 * PHYS_SLOT_BITS));
    slot = (slot & (PHYS_NB_SLOTS - 1)) + SOFT_TLB_SIZE;
    ptr = get_ram_ptr(s, slot, ram_addr);
#if defined(DEBUG_TLB)
    monitor_log(s, "get_phys_mem_ptr: paddr=%p ram_addr=%p ptr=%p\n",
                (void *)paddr, 
                (void *)ram_addr, 
                (void *)ptr);
#endif
    return ptr + (paddr & ~PAGE_MASK);
}

static uint32_t ldl_phys_mmu(struct kqemu_state *s, unsigned long addr)
{
    uint32_t *ptr;
    uint32_t val;
    ptr = get_phys_mem_ptr(s, addr, 0);
    if (!ptr)
        val = 0;
    else
        val = *ptr;
#ifdef DEBUG_PHYS_LOAD_STORE
    monitor_log(s, "ldl_phys_mmu: %p = 0x%08x\n", (void *)addr, val);
#endif
    return val;
}

/* NOTE: we do not update the dirty bits. This function is only used
   to update the D and A bits, so it is not critical */
static void stl_phys_mmu(struct kqemu_state *s, unsigned long addr, 
                             uint32_t val)
{
    uint32_t *ptr;
#ifdef DEBUG_PHYS_LOAD_STORE
    monitor_log(s, "st_phys_mmu: %p = 0x%08x\n", (void *)addr, val);
#endif
    ptr = get_phys_mem_ptr(s, addr, 1);
    if (ptr)
        *ptr = val;
}

/* return 0 if OK, 2 if the mapping could not be done because I/O
   memory region or monitor memory area */
static long tlb_set_page(struct kqemu_state *s, 
                        unsigned long vaddr, unsigned long paddr, 
                        int prot, int is_softmmu)
{
    unsigned long pd;
    int pte_flags, mask, is_user;
    long ret;
    struct kqemu_ram_page *rp;
    
#ifdef DEBUG_RAM
    monitor_log(s, "tlb_set_page: vaddr=%p paddr=%p prot=0x%02x s=%d\n",
                (void *)vaddr, (void *)paddr, prot, is_softmmu);
#endif
    pd = phys_page_find(s, paddr >> PAGE_SHIFT);
    
    if ((pd & ~PAGE_MASK) > KQEMU_IO_MEM_ROM) {
        if ((pd & ~PAGE_MASK) == KQEMU_IO_MEM_COMM) {
            /* special case: mapping of the kqemu communication page */
            pte_flags = PG_PRESENT_MASK | PG_USER_MASK | 
                PG_ACCESSED_MASK | PG_DIRTY_MASK;
            is_user = (s->cpu_state.cpl == 3);
            if (is_user)
                mask = PAGE_UWRITE;
            else
                mask = PAGE_KWRITE;
            if (prot & mask)
                pte_flags |= PG_ORIG_RW_MASK | PG_RW_MASK;
            mon_set_pte(s, is_user, vaddr, s->comm_page_index, pte_flags);
            ret = 0;
        } else {
            /* IO access: no mapping is done as it will be handled by the
               soft MMU */
            ret = 2;
        }
    } else {
        if (is_softmmu) {
            /* XXX: dirty ram support */
            /* XXX: rom support */
            TLBEntry *e;
            unsigned long vaddr1;
            int slot;
            void *ptr;
            slot = (vaddr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1);
            e = &s->soft_tlb[slot];
            vaddr1 = vaddr & PAGE_MASK;
            if (prot & PAGE_KREAD)
                e->vaddr[0] = vaddr1;
            else
                e->vaddr[0] = -1;
            if (prot & PAGE_KWRITE)
                e->vaddr[1] = vaddr1;
            else
                e->vaddr[1] = -1;
            if (prot & PAGE_UREAD)
                e->vaddr[2] = vaddr1;
            else
                e->vaddr[2] = -1;
            if (prot & PAGE_UWRITE)
                e->vaddr[3] = vaddr1;
            else
                e->vaddr[3] = -1;
            ptr = get_ram_ptr(s, slot, pd & PAGE_MASK);
            e->addend = (unsigned long)ptr - vaddr1;
#ifdef DEBUG_SOFT_TLB
            monitor_log(s, "tlb_set_page: vaddr=%p paddr=%p prot=0x%02x s=%d\n",
                        (void *)vaddr, (void *)paddr, prot, is_softmmu);
#endif
            ret = 0;
        } else if ((vaddr - s->monitor_vaddr) < MONITOR_MEM_SIZE) {
            ret = 2;
        } else {
            pte_flags = PG_PRESENT_MASK | PG_USER_MASK | 
                PG_ACCESSED_MASK | PG_DIRTY_MASK;
#ifdef USE_USER_PG_GLOBAL
            /* user pages are marked as global to stay in TLB when
               switching to kernel mode */
            /* XXX: check WP bit or ensure once that WP is set in
               kqemu */
            if (prot & PAGE_UREAD)
                pte_flags |= PG_GLOBAL(s);
#endif
            is_user = (s->cpu_state.cpl == 3);
            if (is_user)
                mask = PAGE_UWRITE;
            else
                mask = PAGE_KWRITE;
            if (prot & mask) {
                pte_flags |= PG_ORIG_RW_MASK | PG_RW_MASK;
                if ((pd & ~PAGE_MASK) == KQEMU_IO_MEM_ROM || 
                    ((pd & ~PAGE_MASK) == KQEMU_IO_MEM_RAM && 
                     !ram_is_dirty(s, pd))) {
                    pte_flags &= ~PG_RW_MASK;
                }
            }
            rp = lock_ram_page(s, pd & PAGE_MASK);
            map_ram_page(s, is_user, vaddr, rp, pte_flags);
            ret = 0;
        }
    }
    return ret;
}

/* return value:
   0  = nothing more to do 
   1  = generate PF fault
   2  = soft MMU activation required for this block
*/
long cpu_x86_handle_mmu_fault(struct kqemu_state *s, unsigned long addr, 
                              int is_write, int is_user, int is_softmmu)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    uint32_t pdpe_addr, pde_addr, pte_addr;
    uint32_t pde, pte, ptep, pdpe;
    int error_code, is_dirty, prot, page_size;
    unsigned long paddr, page_offset;
    unsigned long vaddr, virt_addr;
    long ret;

#ifdef DEBUG_MMU
    monitor_log(s, "mmu_fault: addr=%08lx w=%d u=%d s=%d\n",
                addr, is_write, is_user, is_softmmu);
#endif

    is_write &= 1;
    
    if (!(env->cr0 & CR0_PG_MASK)) {
        pte = addr;
        virt_addr = addr & PAGE_MASK;
        prot = PAGE_KREAD | PAGE_KWRITE | PAGE_UREAD | PAGE_UWRITE;
        page_size = 4096;
        goto do_mapping;
    }


    if (env->cr4 & CR4_PAE_MASK) {
        /* XXX: we only use 32 bit physical addresses */
#ifdef __x86_64__
        if (env->efer & MSR_EFER_LMA) {
            uint32_t pml4e_addr, pml4e;
            int32_t sext;

            /* XXX: handle user + rw rights */
            /* XXX: handle NX flag */
            /* test virtual address sign extension */
            sext = (int64_t)addr >> 47;
            if (sext != 0 && sext != -1) {
                error_code = 0;
                goto do_fault;
            }
            
            pml4e_addr = ((env->cr3 & ~0xfff) + (((addr >> 39) & 0x1ff) << 3)) & 
                env->a20_mask;
            pml4e = ldl_phys_mmu(s, pml4e_addr);
            if (!(pml4e & PG_PRESENT_MASK)) {
                error_code = 0;
                goto do_fault;
            }
            if (!(pml4e & PG_ACCESSED_MASK)) {
                pml4e |= PG_ACCESSED_MASK;
                stl_phys_mmu(s, pml4e_addr, pml4e);
            }
            
            pdpe_addr = ((pml4e & ~0xfff) + (((addr >> 30) & 0x1ff) << 3)) & 
                env->a20_mask;
            pdpe = ldl_phys_mmu(s, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                error_code = 0;
                goto do_fault;
            }
            if (!(pdpe & PG_ACCESSED_MASK)) {
                pdpe |= PG_ACCESSED_MASK;
                stl_phys_mmu(s, pdpe_addr, pdpe);
            }
        } else 
#endif
        {
            pdpe_addr = ((env->cr3 & ~0x1f) + ((addr >> 30) << 3)) & 
                env->a20_mask;
            pdpe = ldl_phys_mmu(s, pdpe_addr);
            if (!(pdpe & PG_PRESENT_MASK)) {
                error_code = 0;
                goto do_fault;
            }
        }

        pde_addr = ((pdpe & ~0xfff) + (((addr >> 21) & 0x1ff) << 3)) &
            env->a20_mask;
        pde = ldl_phys_mmu(s, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            error_code = 0;
            goto do_fault;
        }
        if (pde & PG_PSE_MASK) {
            /* 2 MB page */
            page_size = 2048 * 1024;
            goto handle_big_page;
        } else {
            /* 4 KB page */
            if (!(pde & PG_ACCESSED_MASK)) {
                pde |= PG_ACCESSED_MASK;
                stl_phys_mmu(s, pde_addr, pde);
            }
            pte_addr = ((pde & ~0xfff) + (((addr >> 12) & 0x1ff) << 3)) &
                env->a20_mask;
            goto handle_4k_page;
        }
    } else {
        /* page directory entry */
        pde_addr = ((env->cr3 & ~0xfff) + ((addr >> 20) & ~3)) & 
            env->a20_mask;
        pde = ldl_phys_mmu(s, pde_addr);
        if (!(pde & PG_PRESENT_MASK)) {
            error_code = 0;
            goto do_fault;
        }
        /* if PSE bit is set, then we use a 4MB page */
        if ((pde & PG_PSE_MASK) && (env->cr4 & CR4_PSE_MASK)) {
            page_size = 4096 * 1024;
        handle_big_page:
            if (is_user) {
                if (!(pde & PG_USER_MASK))
                    goto do_fault_protect;
                if (is_write && !(pde & PG_RW_MASK))
                    goto do_fault_protect;
            } else {
                if ((env->cr0 & CR0_WP_MASK) && 
                    is_write && !(pde & PG_RW_MASK)) 
                    goto do_fault_protect;
            }
            is_dirty = is_write && !(pde & PG_DIRTY_MASK);
            if (!(pde & PG_ACCESSED_MASK) || is_dirty) {
                pde |= PG_ACCESSED_MASK;
                if (is_dirty)
                    pde |= PG_DIRTY_MASK;
                stl_phys_mmu(s, pde_addr, pde);
            }
        
            pte = pde & ~( (page_size - 1) & ~0xfff); /* align to page_size */
            ptep = pte;
            virt_addr = addr & ~(page_size - 1);
        } else {
            if (!(pde & PG_ACCESSED_MASK)) {
                pde |= PG_ACCESSED_MASK;
                stl_phys_mmu(s, pde_addr, pde);
            }

            /* page directory entry */
            pte_addr = ((pde & ~0xfff) + ((addr >> 10) & 0xffc)) & 
                env->a20_mask;
        handle_4k_page:
            pte = ldl_phys_mmu(s, pte_addr);
            if (!(pte & PG_PRESENT_MASK)) {
                error_code = 0;
                goto do_fault;
            }
            /* combine pde and pte user and rw protections */
            ptep = pte & pde;
            if (is_user) {
                if (!(ptep & PG_USER_MASK))
                    goto do_fault_protect;
                if (is_write && !(ptep & PG_RW_MASK))
                    goto do_fault_protect;
            } else {
                if ((env->cr0 & CR0_WP_MASK) &&
                    is_write && !(ptep & PG_RW_MASK)) 
                    goto do_fault_protect;
            }
            is_dirty = is_write && !(pte & PG_DIRTY_MASK);
            if (!(pte & PG_ACCESSED_MASK) || is_dirty) {
                pte |= PG_ACCESSED_MASK;
                if (is_dirty)
                    pte |= PG_DIRTY_MASK;
                stl_phys_mmu(s, pte_addr, pte);
            }
            page_size = 4096;
            virt_addr = addr & ~0xfff;
        }

        /* the page can be put in the TLB */
        prot = PAGE_KREAD;
        if (ptep & PG_USER_MASK)
            prot |= PAGE_UREAD;
        if (pte & PG_DIRTY_MASK) {
            /* only set write access if already dirty... otherwise wait
               for dirty access */
            if (ptep & PG_USER_MASK) {
                if (ptep & PG_RW_MASK)
                    prot |= PAGE_UWRITE;
            }
            if (!(env->cr0 & CR0_WP_MASK) ||
                (ptep & PG_RW_MASK))
                prot |= PAGE_KWRITE;
        }
    }
 do_mapping:
    pte = pte & env->a20_mask;

    /* Even if 4MB pages, we map only one 4KB page in the cache to
       avoid filling it too fast */
    page_offset = (addr & PAGE_MASK) & (page_size - 1);
    paddr = (pte & PAGE_MASK) + page_offset;
    vaddr = virt_addr + page_offset;

    ret = tlb_set_page(s, vaddr, paddr, prot, is_softmmu);
    return ret;

 do_fault_protect:
    error_code = PG_ERROR_P_MASK;
 do_fault:
    env->cr2 = addr;
    env->error_code = (is_write << PG_ERROR_W_BIT) | error_code;
    if (is_user)
        env->error_code |= PG_ERROR_U_MASK;
    return 1;
}

static void soft_tlb_fill(struct kqemu_state *s, unsigned long vaddr,
                          int is_write, int is_user)
{
    long ret;
#ifdef PROFILE_SOFTMMU
    int ti;
    ti = getclock();
#endif
    ret = cpu_x86_handle_mmu_fault(s, vaddr, is_write, is_user, 1);
#ifdef PROFILE_SOFTMMU
    ti = getclock() - ti;
    monitor_log(s, "soft_tlb_fill: w=%d u=%d addr=%p cycle=%d\n",
                is_write, is_user, (void *)vaddr, ti);
#endif
    if (ret == 1)
        raise_exception(s, EXCP0E_PAGE);
    else if (ret == 2)
        raise_exception(s, KQEMU_RET_SOFTMMU);
}

static void *map_vaddr(struct kqemu_state *s, unsigned long addr, 
                       int is_write, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;
    
    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (e->vaddr[(is_user << 1) + is_write] != (addr & PAGE_MASK)) {
        soft_tlb_fill(s, addr, is_write, is_user);
        goto redo;
    } else {
        taddr = e->addend + addr;
    }
    return (void *)taddr;
}

uint32_t ldub_slow(struct kqemu_state *s, unsigned long addr, 
                   int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;
    
    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & PAGE_MASK))) {
        soft_tlb_fill(s, addr, 0, is_user);
        goto redo;
    } else {
        taddr = e->addend + addr;
        val = *(uint8_t *)taddr;
    }
    return val;
}

uint32_t lduw_slow(struct kqemu_state *s, unsigned long addr, 
                   int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 1)))) {
        if (e->vaddr[(is_user << 1)] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 1) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                uint32_t v0, v1;
                /* access spans two pages (rare case) */
                v0 = ldub_slow(s, addr, is_user);
                v1 = ldub_slow(s, addr + 1, is_user);
                val = v0 | (v1 << 8);
            }
        } else {
            soft_tlb_fill(s, addr, 0, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        val = *(uint16_t *)taddr;
    }
    return val;
}

uint32_t ldl_slow(struct kqemu_state *s, unsigned long addr, 
                  int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 3)))) {
        if (e->vaddr[(is_user << 1)] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 3) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                uint32_t v0, v1;
                int shift;
                /* access spans two pages (rare case) */
                shift = (addr & 3) * 8;
                addr &= ~3;
                v0 = ldl_slow(s, addr, is_user);
                v1 = ldl_slow(s, addr + 4, is_user);
                val = (v0 >> shift) | (v1 << (32 - shift));
            }
        } else {
            soft_tlb_fill(s, addr, 0, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        val = *(uint32_t *)taddr;
    }
    return val;
}

uint64_t ldq_slow(struct kqemu_state *s, unsigned long addr, 
                  int is_user)
{
    TLBEntry *e;
    uint64_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 7)))) {
        if (e->vaddr[(is_user << 1)] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 7) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                uint64_t v0, v1;
                int shift;
                /* access spans two pages (rare case) */
                shift = (addr & 7) * 8;
                addr &= ~7;
                v0 = ldq_slow(s, addr, is_user);
                v1 = ldq_slow(s, addr + 8, is_user);
                val = (v0 >> shift) | (v1 << (64 - shift));
            }
        } else {
            soft_tlb_fill(s, addr, 0, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        val = *(uint64_t *)taddr;
    }
    return val;
}

void stb_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;
    
    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & PAGE_MASK))) {
        soft_tlb_fill(s, addr, 1, is_user);
        goto redo;
    } else {
        taddr = e->addend + addr;
        *(uint8_t *)taddr = val;
    }
}

void stw_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 1)))) {
        if (e->vaddr[(is_user << 1) + 1] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 1) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                /* access spans two pages (rare case) */
                stb_slow(s, addr, val, is_user);
                stb_slow(s, addr + 1, val >> 8, is_user);
            }
        } else {
            soft_tlb_fill(s, addr, 1, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        *(uint16_t *)taddr = val;
    }
}

void stl_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 3)))) {
        if (e->vaddr[(is_user << 1) + 1] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 3) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                /* access spans two pages (rare case) */
                stb_slow(s, addr, val, is_user);
                stb_slow(s, addr + 1, val >> 8, is_user);
                stb_slow(s, addr + 2, val >> 16, is_user);
                stb_slow(s, addr + 3, val >> 24, is_user);
            }
        } else {
            soft_tlb_fill(s, addr, 1, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        *(uint32_t *)taddr = val;
    }
}

void stq_slow(struct kqemu_state *s, unsigned long addr, 
              uint64_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
 redo:
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 7)))) {
        if (e->vaddr[(is_user << 1) + 1] == (addr & PAGE_MASK)) {
            /* unaligned access */
            if (((addr + 7) & PAGE_MASK) == (addr & PAGE_MASK)) {
                goto access_ok;
            } else {
                /* access spans two pages (rare case) */
                stb_slow(s, addr, val, is_user);
                stb_slow(s, addr + 1, val >> 8, is_user);
                stb_slow(s, addr + 2, val >> 16, is_user);
                stb_slow(s, addr + 3, val >> 24, is_user);
                stb_slow(s, addr + 4, val >> 32, is_user);
                stb_slow(s, addr + 5, val >> 40, is_user);
                stb_slow(s, addr + 6, val >> 48, is_user);
                stb_slow(s, addr + 7, val >> 56, is_user);
            }
        } else {
            soft_tlb_fill(s, addr, 1, is_user);
            goto redo;
        }
    } else {
    access_ok:
        taddr = e->addend + addr;
        *(uint64_t *)taddr = val;
    }
}

extern unsigned long __start_mmu_ex_table;
extern unsigned long __stop_mmu_ex_table;
int sorted = 0;

void lsort(unsigned long *tab, int n)
{
    int i, j;
    unsigned long tmp;

    for(i = 0; i < n - 1; i++) {
        for(j = i + 1; j < n;j++) {
            if (tab[i] > tab[j]) {
                tmp = tab[i];
                tab[i] = tab[j];
                tab[j] = tmp;
            }
        }
    }
#if 0
    for(i = 0; i < n - 1; i++) {
        if (tab[i] > tab[i + 1])
            asm volatile("ud2");
    }
#endif
}

static int expected_monitor_exception(unsigned long pc)
{
    unsigned long *tab, v;
    int a, b, m;
    if (unlikely(!sorted)) {
        lsort(&__start_mmu_ex_table, 
              &__stop_mmu_ex_table - &__start_mmu_ex_table);
        sorted = 1;
    }
    
    tab = &__start_mmu_ex_table;
    a = 0;
    b = &__stop_mmu_ex_table - &__start_mmu_ex_table - 1;
    while (a <= b) {
        m = (a + b) >> 1;
        v = tab[m];
        if (v == pc)
            return 1;
        else if (v > pc) {
            b = m - 1;
        } else {
            a = m + 1;
        }
    }
    return 0;
}

/* page fault */
void kqemu_exception_0e(struct kqemu_state *s,
                        struct kqemu_exception_regs regs)
{
    unsigned long address;
    int is_write, is_user;
    long ret;
#ifdef PROFILE_INTERP2
    int64_t ti;
#endif
    asm volatile ("mov %%cr2, %0" : "=r" (address));
#ifdef PROFILE_INTERP2
    ti = getclock();
#endif

    if ((regs.cs_sel & 3) != 3) {
        if (!expected_monitor_exception(regs.eip)) {
            /* exception in monitor space - we may accept it someday if it
               is a user access indicated as such */
            monitor_panic_regs(s, &regs, 
                               "Paging exception in monitor address space. CR2=%p\n",
                               (void *)address);
        }
        /* do not reload s->regs because we are already in interpreter */
        s->seg_cache_loaded = 1;
    } else {
        s->regs = &regs;
        s->seg_cache_loaded = 0;
    }
    is_write = (regs.error_code >> 1) & 1;
#ifdef PROFILE_INTERP2
    s->total_page_fault_count++;
#endif
    /* see if the page is write protected -> mark it dirty if needed */
    is_user = (s->cpu_state.cpl == 3);
    if (is_write && (regs.error_code & 1)) {
        uint32_t ram_index, *ptep;
        struct kqemu_ram_page *rp;
        int dirty_mask;

        /* get the original writable flag */
        if (USE_PAE(s)) {
            uint64_t pte;
            ptep = (uint32_t *)mon_get_ptep_l3(s, is_user, address, 0);
            if (!ptep)
                goto fail;
            pte = *(uint64_t *)ptep;
            if (!(pte & PG_PRESENT_MASK))
                goto fail;
            if (!(pte & PG_ORIG_RW_MASK))
                goto fail;
            rp = find_ram_page_from_paddr(s, pte >> PAGE_SHIFT);
        } else {
            uint32_t pte;
            ptep = mon_get_ptep_l2(s, is_user, address, 0);
            if (!ptep)
                goto fail;
            pte = *ptep;
            if (!(pte & PG_PRESENT_MASK))
                goto fail;
            if (!(pte & PG_ORIG_RW_MASK))
                goto fail;
            rp = find_ram_page_from_paddr(s, pte >> PAGE_SHIFT);
        }
        if (!rp)
            goto fail;
        ram_index = rp - s->ram_pages;
        /* cannot write directly on GDT/LDT pages or in pages where
           code was translated  */
        /* XXX: should revalidate or interpret the code to go faster */
#ifdef USE_SEG_GP
        dirty_mask = 0;
        if (s->cpu_state.cpl == 3)
            dirty_mask |= DT_DIRTY_FLAG;
#else
        dirty_mask = DT_DIRTY_FLAG;
#endif
        if ((s->ram_dirty[ram_index] & dirty_mask) != dirty_mask) {
            raise_exception(s, KQEMU_RET_SOFTMMU);
        }
        /* code updates need to be signaled */
        if ((s->ram_dirty[ram_index] & CODE_DIRTY_FLAG) != 
            CODE_DIRTY_FLAG) {
            s->modified_ram_pages[s->cpu_state.nb_modified_ram_pages++] = 
                ram_index << PAGE_SHIFT;
            /* too many modified pages: exit */
            if (s->cpu_state.nb_modified_ram_pages >= 
                KQEMU_MAX_MODIFIED_RAM_PAGES)
                raise_exception(s, KQEMU_RET_SOFTMMU);
        }

        /* set the page as RW and mark the corresponding ram page as
           dirty */
        s->ram_dirty[ram_index] = 0xff;
        *ptep |= PG_RW_MASK;
        asm volatile("invlpg %0" : : "m" (*(uint8_t *)address));
        return;
    fail: ;
    }

#ifdef PROFILE_INTERP2
    s->mmu_page_fault_count++;
#endif
    /* see if it is an MMU fault */
    ret = cpu_x86_handle_mmu_fault(s, address, is_write, is_user, 0);
    switch(ret) {
    case 0:
#ifdef PROFILE_INTERP2
        if ((regs.cs_sel & 3) != 3)
            s->tlb_interp_page_fault_count++;
        s->tlb_page_fault_count++;
        s->tlb_page_fault_cycles += (getclock() - ti);
#endif
        break;
    case 1:
#ifdef PROFILE_INTERP2
        s->mmu_page_fault_cycles += (getclock() - ti);
#endif
        /* real MMU fault */
        raise_exception(s, EXCP0E_PAGE);
    case 2:
    default:
#ifdef PROFILE_INTERP2
        s->mmu_page_fault_cycles += (getclock() - ti);
#endif
        /* cannot map: I/O  */
        raise_exception(s, KQEMU_RET_SOFTMMU);
    }
}

/* exit the virtual cpu by raising an exception */
void raise_exception(struct kqemu_state *s, int intno)
{
    /* XXX: the exclusion of exception GPF is needed for correct
       Windows XP boot. I don't know the precise explanation yet. */
    if (s->cpu_state.user_only || (unsigned int)intno >= 0x20 || 
        intno == 0x0d) {
        /* exit the monitor if user only */
        profile_record(s);
        s->mon_req = MON_REQ_EXIT;
        s->arg0 = intno;
        profile_record(s);
        monitor2kernel1(s);
    } else {
        s->arg0 = intno;
        start_func(raise_exception_interp, s, 
                   s->stack_end - sizeof(struct kqemu_exception_regs));
    }
    /* never returns */
    while (1);
}

void __raise_exception_err(struct kqemu_state *s, 
                           int intno, int error_code)
{
    s->cpu_state.error_code = error_code;
    raise_exception(s, intno);
}

void do_update_cr3(struct kqemu_state *s, unsigned long new_cr3)
{
    if (s->cpu_state.cr0 & CR0_PG_MASK) {
        tlb_flush(s, 1);
        /* indicate that all the pages must be flushed in user space */
        s->cpu_state.nb_pages_to_flush = KQEMU_FLUSH_ALL;
    }
    s->cpu_state.cr3 = new_cr3;
}

#define CR0_UPDATE_MASK (CR0_TS_MASK | CR0_MP_MASK | CR0_EM_MASK | CR0_AM_MASK)

void do_update_cr0(struct kqemu_state *s, unsigned long new_cr0)
{
    if ((new_cr0 & ~CR0_UPDATE_MASK) != 
        (s->cpu_state.cr0 & ~CR0_UPDATE_MASK))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    if ((new_cr0 & CR0_UPDATE_MASK) != 
        (s->cpu_state.cr0 & CR0_UPDATE_MASK)) {
        s->cpu_state.cr0 = new_cr0;
        update_host_cr0(s);
    }
}

#define CR4_UPDATE_MASK (CR4_TSD_MASK | CR4_OSFXSR_MASK | CR4_OSXMMEXCPT_MASK)

void do_update_cr4(struct kqemu_state *s, unsigned long new_cr4)
{
    if ((new_cr4 & ~CR4_UPDATE_MASK) != 
        (s->cpu_state.cr4 & ~CR4_UPDATE_MASK))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    if ((new_cr4 & CR4_UPDATE_MASK) != 
        (s->cpu_state.cr4 & CR4_UPDATE_MASK)) {
        s->cpu_state.cr4 = new_cr4;
        update_host_cr4(s);
    }
}

void do_invlpg(struct kqemu_state *s, unsigned long vaddr)
{
    tlb_flush_page(s, vaddr);
    if (s->cpu_state.nb_pages_to_flush >= KQEMU_MAX_PAGES_TO_FLUSH) {
        s->cpu_state.nb_pages_to_flush = KQEMU_FLUSH_ALL;
    } else {
        s->pages_to_flush[s->cpu_state.nb_pages_to_flush++] = vaddr;
    }
}

extern unsigned long __start_seg_ex_table;
extern unsigned long __stop_seg_ex_table;

static void handle_mon_exception(struct kqemu_state *s, 
                                 struct kqemu_exception_regs *regs,
                                 int intno)
{
    unsigned long pc, *p;
    
    pc = regs->eip;
    for(p = &__start_seg_ex_table; p != &__stop_seg_ex_table; p++) {
        if (*p == pc) goto found;
    }
    monitor_panic_regs(s, regs, 
                       "Unexpected exception 0x%02x in monitor space\n", 
                       intno);
 found:
    if (intno == 0x00) {
        /* division exception from interp */
        /* XXX: verify for fxsave/fxrstor */
        s->regs = &s->regs1;
    } else {
        /* Note: the exception state is reliable only for goto_user
           handling */
        s->regs = NULL;
    }
    raise_exception_err(s, intno, regs->error_code);
}

#ifdef PROFILE_INTERP_PC
static void profile_interp_add(struct kqemu_state *s,
                               unsigned long eip,
                               int64_t cycles,
                               int insn_count)
{
    int h, idx;
    ProfileInterpEntry *pe;

    h = (eip ^ (eip >> PROFILE_INTERP_PC_HASH_BITS) ^ 
         (eip >> (2 * PROFILE_INTERP_PC_HASH_BITS))) & 
        (PROFILE_INTERP_PC_HASH_SIZE - 1);
    idx = s->profile_interp_hash_table[h];
    while (idx != 0) {
        pe = &s->profile_interp_entries[idx - 1];
        if (pe->eip == eip)
            goto found;
        idx = pe->next;
    }
    /* not found */
    if (s->nb_profile_interp_entries >= (PROFILE_INTERP_PC_NB_ENTRIES - 1)) {
        /* too many entries : use last entry */
        if (s->nb_profile_interp_entries < PROFILE_INTERP_PC_NB_ENTRIES)
            s->nb_profile_interp_entries++;
        pe = &s->profile_interp_entries[PROFILE_INTERP_PC_NB_ENTRIES - 1];
    } else {
        /* add one more entry */
        pe = &s->profile_interp_entries[s->nb_profile_interp_entries++];
        pe->next = s->profile_interp_hash_table[h];
        s->profile_interp_hash_table[h] = s->nb_profile_interp_entries;
        pe->eip = eip;
    }
 found:
    pe->count++;
    pe->cycles += cycles;
    pe->insn_count += insn_count;
}
#endif

static inline void kqemu_exception_interp(struct kqemu_state *s, int intno,
                                          struct kqemu_exception_regs *regs)
{
#ifdef PROFILE_INTERP2
    int64_t ti0, ti1, ti2;
    int c1;
    unsigned long start_eip;
    ti0 = getclock();
#endif
    if ((regs->cs_sel & 3) != 3)
        handle_mon_exception(s, regs, intno);

    profile_record(s);

    s->regs = regs;
    
    profile_record(s);
    update_seg_cache(s);
#ifdef PROFILE_INTERP2
    ti1 = getclock();
    c1 = s->insn_count;
    start_eip = s->regs1.eip;
#endif

    insn_interp(s);
#ifdef PROFILE_INTERP2
    ti2 = getclock();
    s->exc_interp_count++;
    s->exc_seg_cycles += ti1 - ti0;
    s->exc_interp_cycles += ti2 - ti1;
    c1 -= s->insn_count;
    s->exc_insn_count += c1;
    if (c1 > s->exc_insn_count_max) {
        s->exc_insn_count_max = c1;
        s->exc_start_eip_max = start_eip;
    }
#ifdef PROFILE_INTERP_PC
    profile_interp_add(s, start_eip, ti2 - ti0, c1 + 1);
#endif
#endif
}

/* XXX: remove L bit on x86_64 in legacy emulation ? */
static void check_dt_entries(uint8_t *d, const uint8_t *s, int n)
{
    int i;
    uint32_t e1, e2;
    for(i = 0; i < n; i++) {
        e1 = ((uint32_t *)s)[0];
        e2 = ((uint32_t *)s)[1];
        if (!(e2 & DESC_S_MASK)) {
            /* not a segment: reset DPL to ensure it cannot be used
               from user space */
            e2 &= ~(3 << DESC_DPL_SHIFT);
#ifndef USE_SEG_GP
            ((uint32_t *)d)[32768 * 0 + 0] = e1; /* CPL = 0 */
            ((uint32_t *)d)[32768 * 0 + 1] = e2;
            ((uint32_t *)d)[32768 * 1 + 0] = e1; /* CPL = 1 */
            ((uint32_t *)d)[32768 * 1 + 1] = e2;
            ((uint32_t *)d)[32768 * 2 + 0] = e1; /* CPL = 2 */
            ((uint32_t *)d)[32768 * 2 + 1] = e2;
#endif
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 0] = e1; /* CPL = 3 */
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 1] = e2;
        } else if (unlikely(((e2 & (DESC_CS_MASK | DESC_C_MASK)) == 
                             (DESC_CS_MASK | DESC_C_MASK)))) {
            /* conforming segment : no need to modify */
#ifndef USE_SEG_GP
            ((uint32_t *)d)[32768 * 0 + 0] = e1; /* CPL = 0 */
            ((uint32_t *)d)[32768 * 0 + 1] = e2;
            ((uint32_t *)d)[32768 * 1 + 0] = e1; /* CPL = 1 */
            ((uint32_t *)d)[32768 * 1 + 1] = e2;
            ((uint32_t *)d)[32768 * 2 + 0] = e1; /* CPL = 2 */
            ((uint32_t *)d)[32768 * 2 + 1] = e2;
#endif
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 0] = e1; /* CPL = 3 */
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 1] = e2;
        } else {
#ifndef USE_SEG_GP
            int dpl;
            uint32_t e2tmp, e2dpl3;

            dpl = (e2 >> DESC_DPL_SHIFT) & 3;
            /* standard segment: need to patch the DPL so that
               if (DPL >= CPL) then DPL = 3 
            */
            e2dpl3 = e2 | (3 << DESC_DPL_SHIFT);
            ((uint32_t *)d)[32768 * 0 + 0] = e1; /* CPL = 0 */
            ((uint32_t *)d)[32768 * 0 + 1] = e2dpl3;

            e2tmp = e2;
            if (dpl >= 1)
                e2tmp = e2dpl3;
            ((uint32_t *)d)[32768 * 1 + 0] = e1; /* CPL = 1 */
            ((uint32_t *)d)[32768 * 1 + 1] = e2tmp;

            e2tmp = e2;
            if (dpl >= 2)
                e2tmp = e2dpl3;
            ((uint32_t *)d)[32768 * 2 + 0] = e1; /* CPL = 2 */
            ((uint32_t *)d)[32768 * 2 + 1] = e2tmp;
#endif
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 0] = e1; /* CPL = 3 */
            ((uint32_t *)d)[32768 * (NB_DT_TABLES - 1) + 1] = e2;

        }
        s += 8;
        d += 8;
    }
}

static void check_dt_entries_page(struct kqemu_state *s, int dt_type,
                                  int sel, int sel_end, const uint8_t *src)
{
    uint8_t *dt;
    int mon_sel_start, mon_sel_end, sel1, sel2;
    
    dt = (uint8_t *)(s->dt_table + (dt_type * 8192));
    if (dt_type == 0) {
        mon_sel_start = s->monitor_selector_base;
        mon_sel_end = s->monitor_selector_base + MONITOR_SEL_RANGE;
        sel1 = sel;
        while (sel1 < sel_end) {
            if (sel1 >= mon_sel_start && sel1 < mon_sel_end)
                sel1 = mon_sel_end;
            if (sel1 < mon_sel_start) {
                sel2 = mon_sel_start;
                if (sel2 > sel_end)
                    sel2 = sel_end;
            } else {
                sel2 = sel_end;
            }
            if (sel1 >= sel2)
                break;
#ifdef DEBUG_DT_CACHE
            monitor_log(s, "check_dt: type=%d sel=%d-%d\n",
                        dt_type, sel1, sel2);
#endif
            check_dt_entries(dt + sel1, 
                             src + sel1 - sel, (sel2 - sel1) >> 3);
            sel1 = sel2;
        }
    } else {
#ifdef DEBUG_DT_CACHE
            monitor_log(s, "check_dt: type=%d sel=%d-%d\n",
                        dt_type, sel, sel_end);
#endif
        check_dt_entries(dt + sel, src, (sel_end - sel) >> 3);
    }
}

static void reset_dt_entries2(void *dt1, int n)
{
    uint32_t *dt = dt1;
#ifndef USE_SEG_GP
    memset(dt + 32768 * 0, 0, n);
    memset(dt + 32768 * 1, 0, n);
    memset(dt + 32768 * 2, 0, n);
#endif
    memset(dt + 32768 * (NB_DT_TABLES - 1), 0, n);
}

static void reset_dt_entries(struct kqemu_state *s, int dt_type,
                             int sel, int sel_end) 
{
    uint8_t *dt;
    int mon_sel_start, mon_sel_end, sel1, sel2;

    dt = (uint8_t *)(s->dt_table + (dt_type * 8192));
    if (dt_type == 0) {
        mon_sel_start = s->monitor_selector_base;
        mon_sel_end = s->monitor_selector_base + MONITOR_SEL_RANGE;
        sel1 = sel;
        while (sel1 < sel_end) {
            if (sel1 >= mon_sel_start && sel1 < mon_sel_end)
                sel1 = mon_sel_end;
            if (sel1 < mon_sel_start) {
                sel2 = mon_sel_start;
                if (sel2 > sel_end)
                    sel2 = sel_end;
            } else {
                sel2 = sel_end;
            }
            if (sel1 >= sel2)
                break;
#ifdef DEBUG_DT_CACHE
            monitor_log(s, "reset_dt: type=%d sel=%d-%d\n",
                        dt_type, sel1, sel2);
#endif
            reset_dt_entries2(dt + sel1, sel2 - sel1);
            sel1 = sel2;
        }
    } else {
#ifdef DEBUG_DT_CACHE
            monitor_log(s, "reset_dt: type=%d sel=%d-%d\n",
                        dt_type, sel, sel_end);
#endif
            reset_dt_entries2(dt + sel, sel_end - sel);
    }
}

/* Note: this function can raise an exception in case of MMU fault or
   unaligned DT table */
static void update_dt_cache(struct kqemu_state *s, int dt_type)
{
    unsigned long base, dt_end, page_end, dt_ptr, ram_addr;
    uint32_t limit;
    uint8_t *ptr;
    int pindex, sel, sel_end, dt_changed, sel2;

    if (dt_type) { 
        /* XXX: check the exact behaviour of zero LDT */
        if ((s->cpu_state.ldt.selector & 0xfffc) == 0) {
            base = 0;
            limit = 0;
        } else {
            base = s->cpu_state.ldt.base;
            limit = s->cpu_state.ldt.limit;
        }
    } else {
        base = s->cpu_state.gdt.base;
        limit = s->cpu_state.gdt.limit;
    }
    dt_changed = (base != s->dt_base[dt_type] ||
                  limit != s->dt_limit[dt_type]);
    
    sel_end = (limit + 1) & ~7;
    dt_end = base + sel_end;
    if (dt_end < base || (base & 7) != 0)
        raise_exception(s, KQEMU_RET_SOFTMMU);
    
    pindex = 0;
    sel = 0;
    while (sel < sel_end) {
        dt_ptr = base + sel;
        page_end = (dt_ptr & PAGE_MASK) + PAGE_SIZE;
        if (page_end > dt_end)
            page_end = dt_end;
        sel2 = sel + (page_end - dt_ptr);
        ptr = map_vaddr(s, dt_ptr, 0, 0);
        ram_addr = ram_ptr_to_ram_addr(s, ptr);
        if (dt_changed || 
            s->dt_ram_addr[dt_type][pindex] != ram_addr ||
            ram_get_dirty(s, ram_addr, DT_DIRTY_FLAG)) {
            s->dt_ram_addr[dt_type][pindex] = ram_addr;
            check_dt_entries_page(s, dt_type, sel, sel2, ptr);
            ram_reset_dirty(s, ram_addr, DT_DIRTY_FLAG);
        }
        sel = sel2;
        pindex++;
    }

    /* reset the remaining DT entries up to the last limit */
    sel_end = (s->dt_limit[dt_type] + 1) & ~7;
    if (sel < sel_end)
        reset_dt_entries(s, dt_type, sel, sel_end);

    s->dt_base[dt_type] = base;
    s->dt_limit[dt_type] = limit;
}

void update_gdt_ldt_cache(struct kqemu_state *s)
{
    update_dt_cache(s, 0);
    update_dt_cache(s, 1);
}

void monitor_exec(struct kqemu_state *s)
{
    struct kqemu_cpu_state *env = &s->cpu_state;
    struct kqemu_exception_regs *r = 
        (void *)(s->stack_end - sizeof(struct kqemu_exception_regs));
#ifdef PROFILE_INTERP2
    int64_t ti = getclock();
#endif
    update_host_cr0(s);

    update_host_cr4(s);

    restore_monitor_nexus_mapping(s);

    s->regs = NULL;

    /* if max_locked_ram_pages was modified because some instances
       were added, we unlock some pages here */
    unlock_pages(s);

    /* first we flush the pages if needed */
    if (env->nb_pages_to_flush != 0) {
        if (env->nb_pages_to_flush > KQEMU_MAX_PAGES_TO_FLUSH) {
            tlb_flush(s, 1);
        } else {
            int i;
            for(i = 0; i < env->nb_pages_to_flush; i++) {
                tlb_flush_page(s, s->pages_to_flush[i]);
            }
        }
        env->nb_pages_to_flush = 0;
    }

    /* XXX: invalidate modified ram pages */
    env->nb_modified_ram_pages = 0;

    /* unmap pages corresponding to notdirty ram pages */
    if (env->nb_ram_pages_to_update != 0) {
        unsigned long ram_addr;
        int i;

        if (env->nb_ram_pages_to_update > KQEMU_MAX_RAM_PAGES_TO_UPDATE) {
            for(ram_addr = 0; ram_addr < s->ram_size; ram_addr += PAGE_SIZE) {
                if (!ram_is_dirty(s, ram_addr)) {
                    ram_set_read_only(s, ram_addr);
                }
            }
        } else {
            for(i = 0; i < env->nb_ram_pages_to_update; i++) {
                ram_addr = s->ram_pages_to_update[i];
                if (ram_addr < s->ram_size && 
                    !ram_is_dirty(s, ram_addr)) {
                    ram_set_read_only(s, ram_addr);
                }
            }
        }
        env->nb_ram_pages_to_update = 0;
    }

#ifdef USE_SEG_GP
    if (s->cpu_state.cpl == 3)
        update_gdt_ldt_cache(s);
#else
    update_gdt_ldt_cache(s);
#endif

#ifdef PROFILE_INTERP2
    s->exec_init_cycles += (getclock() - ti);
    s->exec_init_count++;
#endif

    /* since this is not costly, we ensure here that the CPU state is
       consistent with what we can handle */
    if (!(env->cr0 & CR0_PE_MASK) ||
        (env->eflags & VM_MASK)) {
        raise_exception(s, KQEMU_RET_SOFTMMU);
    }

    r->eip = env->eip;
    r->eflags = compute_eflags_user(s, env->eflags);
    s->comm_page.virt_eflags = env->eflags & EFLAGS_MASK;
    r->cs_sel = env->segs[R_CS].selector | 3;
    r->ss_sel = env->segs[R_SS].selector | 3;

    r->eax = env->regs[R_EAX];
    r->ecx = env->regs[R_ECX];
    r->edx = env->regs[R_EDX];
    r->ebx = env->regs[R_EBX];
    r->esp = env->regs[R_ESP];
    r->ebp = env->regs[R_EBP];
    r->esi = env->regs[R_ESI];
    r->edi = env->regs[R_EDI];
#ifdef __x86_64__
    r->r8 = env->regs[8];
    r->r9 = env->regs[9];
    r->r10 = env->regs[10];
    r->r11 = env->regs[11];
    r->r12 = env->regs[12];
    r->r13 = env->regs[13];
    r->r14 = env->regs[14];
    r->r15 = env->regs[15];
#else
    r->ds_sel = env->segs[R_DS].selector;
    r->es_sel = env->segs[R_ES].selector;
#endif
    
    update_seg_desc_caches(s);

    /* NOTE: exceptions can occur here */
    reload_segs(s);

    /* for consistency, we accept to start the interpreter here if
       needed */
    if (!(s->comm_page.virt_eflags & IF_MASK)) {
        s->regs = r;
        s->seg_cache_loaded = 1;
        s->insn_count = MAX_INSN_COUNT;
        insn_interp(s);
    }

    goto_user(s, r);
}

/* General Protection Fault. In all cases we need to interpret the
   code to know more */
void kqemu_exception_0d(struct kqemu_state *s,
                        struct kqemu_exception_regs regs)
{
    kqemu_exception_interp(s, 0x0d, &regs);
}

/* illegal intruction. We need to interpret just for the syscall case */
void kqemu_exception_06(struct kqemu_state *s,
                        struct kqemu_exception_regs regs)
{
    kqemu_exception_interp(s, 0x06, &regs);
}

/* Coproprocessor emulation fault. We handle here the fact that the
   FPU state can be temporarily stored in the host OS */
void kqemu_exception_07(struct kqemu_state *s,
                        struct kqemu_exception_regs regs)
{
    if ((regs.cs_sel & 3) != 3) {
        if (!expected_monitor_exception(regs.eip)) {
            monitor_panic_regs(s, &regs, "Unexpected exception 0x%02x in monitor space\n", 0x07);
        }
        /* this can happen for fxsave/fxrstor instructions in the
           interpreter */
        s->seg_cache_loaded = 1;
    } else {
        s->seg_cache_loaded = 0;
    }
    s->regs = &s->regs1;
    if (s->cpu_state.cr0 & (CR0_TS_MASK | CR0_EM_MASK)) {
        /* real FPU fault needed */
        raise_exception_err(s, EXCP07_PREX, 0);
    } else {
        /* the host needs to restore the FPU state for us */
        s->mon_req = MON_REQ_EXCEPTION;
        s->arg0 = 0x07;
        monitor2kernel1(s);
    }
}

/* single step/debug */
void kqemu_exception_01(struct kqemu_state *s,
                        struct kqemu_exception_regs regs)
{
    unsigned long dr6, val;

    asm volatile ("mov %%dr6, %0" : "=r" (dr6));
    /* Linux uses lazy dr7 clearing, so we must verify we are in this
       case */
    /* XXX: check that because TF should have the priority */
    if ((dr6 & 0xf) != 0 && !s->monitor_dr7)
        goto clear_dr7;

    if ((regs.cs_sel & 3) != 3)
        monitor_panic_regs(s, &regs, "Unexpected exception 0x%02x in monitor space\n", 0x07);

    s->regs = &regs;
    s->seg_cache_loaded = 0;
    /* update DR6 register */
    s->cpu_state.dr6 = dr6;
    raise_exception_err(s, EXCP01_SSTP, 0);
 clear_dr7:
    val = 0;
    asm volatile ("mov %0, %%dr7" : : "r" (val));
}

#define DEFAULT_EXCEPTION(n) \
void kqemu_exception_ ## n (struct kqemu_state *s, \
                            struct kqemu_exception_regs regs) \
{ \
    if ((regs.cs_sel & 3) != 3)\
        handle_mon_exception(s, &regs, 0x ## n);\
    s->regs = &regs;\
    s->seg_cache_loaded = 0;\
    s->cpu_state.error_code = regs.error_code;\
    raise_exception(s, 0x ## n);\
}

DEFAULT_EXCEPTION(00)
DEFAULT_EXCEPTION(02)
DEFAULT_EXCEPTION(03)
DEFAULT_EXCEPTION(04)
DEFAULT_EXCEPTION(05)
DEFAULT_EXCEPTION(08)
DEFAULT_EXCEPTION(09)
DEFAULT_EXCEPTION(0a)
DEFAULT_EXCEPTION(0b)
DEFAULT_EXCEPTION(0c)
DEFAULT_EXCEPTION(0f)
DEFAULT_EXCEPTION(10)
DEFAULT_EXCEPTION(11)
DEFAULT_EXCEPTION(12)
DEFAULT_EXCEPTION(13)

void monitor_interrupt(struct kqemu_state *s, struct kqemu_exception_regs regs)
{
    int intno;
#ifdef PROFILE_INTERP2
    int64_t ti = getclock();
    s->hw_interrupt_start_count++;
#endif

    intno = regs.error_code;
    
    if ((regs.cs_sel & 3) != 3) {
        monitor_panic_regs(s, &regs, "Interrupt 0x%02x in monitor space\n",
                           intno);
    }

    s->regs = &regs;
    s->seg_cache_loaded = 0;
    /* execute the irq code in kernel space */
    s->mon_req = MON_REQ_IRQ;
    s->arg0 = intno;
    /* NOTE: if interrupting user code, the host kernel will schedule
       and eventually exit from the monitor_exec loop */
    monitor2kernel1(s);
    /* ... and come back to monitor space */

#ifdef PROFILE_INTERP2
    s->hw_interrupt_count++;
    s->hw_interrupt_cycles += (getclock() - ti);
#endif
}
