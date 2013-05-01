/*
 * KQEMU kernel API
 * Copyright (c) 2004-2005 Fabrice Bellard
 */
#ifndef KQEMU_KERNEL_H
#define KQEMU_KERNEL_H

#include "kqemu.h"

struct kqemu_state;
struct kqemu_global_state;

#define CDECL __attribute__((regparm(0)))

struct kqemu_global_state * CDECL kqemu_global_init(int max_locked_pages);
void CDECL kqemu_global_delete(struct kqemu_global_state *g);

struct kqemu_state * CDECL kqemu_init(struct kqemu_init *d, 
                                      struct kqemu_global_state *g);
struct kqemu_cpu_state * CDECL kqemu_get_cpu_state(struct kqemu_state *s);
long CDECL kqemu_exec(struct kqemu_state *s);
int CDECL kqemu_set_phys_mem(struct kqemu_state *s,
                             const struct kqemu_phys_mem *kphys_mem);
void CDECL kqemu_delete(struct kqemu_state *s);

/* callbacks */
struct kqemu_page; /* opaque data for host page */
struct kqemu_user_page; /* opaque data for host user page */

struct kqemu_user_page *CDECL kqemu_lock_user_page(unsigned long *ppage_index,
                                                   unsigned long user_addr);
void CDECL kqemu_unlock_user_page(struct kqemu_user_page *page);

struct kqemu_page *CDECL kqemu_alloc_zeroed_page(unsigned long *ppage_index);
void CDECL kqemu_free_page(struct kqemu_page *page);
void * CDECL kqemu_page_kaddr(struct kqemu_page *page);

void * CDECL kqemu_vmalloc(unsigned int size);
void CDECL kqemu_vfree(void *ptr);
unsigned long CDECL kqemu_vmalloc_to_phys(const void *vaddr);

void * CDECL kqemu_io_map(unsigned long page_index, unsigned int size);
void CDECL kqemu_io_unmap(void *ptr, unsigned int size);

int CDECL kqemu_schedule(void);

void CDECL kqemu_log(const char *fmt, ...);

#endif /* KQEMU_KERNEL_H */
