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
#ifndef __ASSEMBLY__
#include <stddef.h>
#include <stdarg.h>

#ifndef NO_STD_TYPES

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
#if defined (__x86_64__)
typedef unsigned long uint64_t;
#else
typedef unsigned long long uint64_t;
#endif

typedef signed char int8_t;
typedef signed short int16_t;
typedef signed int int32_t;
#if defined (__x86_64__)
typedef signed long int64_t;
#else
typedef signed long long int64_t;
#endif

#ifndef NULL
#define NULL 0
#endif

#endif

#include "kqemu-kernel.h"

#endif /*! __ASSEMBLY__ */

#define USE_SEG_GP
#define USE_HARD_MMU
/* use the PG global bit for guest user pages (need to make benchmark
   to validate) */
#define USE_USER_PG_GLOBAL
//#define PROFILE

//#define PROFILE_INTERP_PC
//#define PROFILE_INTERP2
//#define PROFILE_INSN

#ifdef PAGE_SIZE
#undef PAGE_SIZE
#endif

#define PAGE_SHIFT 12
#define PAGE_SIZE  (1 << PAGE_SHIFT)
#define PAGE_MASK  (~(PAGE_SIZE-1))
#define PAGE_ALIGN(addr)	(((addr)+PAGE_SIZE-1)&PAGE_MASK)

#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
#endif

#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)
#define inline          inline __attribute__((always_inline))

#if defined (__x86_64__)
#define FMT_lx "%016lx"
#else
#define FMT_lx "%08lx"
#endif

#define R_EAX 0
#define R_ECX 1
#define R_EDX 2
#define R_EBX 3
#define R_ESP 4
#define R_EBP 5
#define R_ESI 6
#define R_EDI 7

#define R_ES 0
#define R_CS 1
#define R_SS 2
#define R_DS 3
#define R_FS 4
#define R_GS 5

/* segment descriptor fields */
#define DESC_G_MASK     (1 << 23)
#define DESC_B_SHIFT    22
#define DESC_B_MASK     (1 << DESC_B_SHIFT)
#define DESC_L_SHIFT    21 /* x86_64 only : 64 bit code segment */
#define DESC_L_MASK     (1 << DESC_L_SHIFT)
#define DESC_AVL_MASK   (1 << 20)
#define DESC_P_MASK     (1 << 15)
#define DESC_DPL_SHIFT  13
#define DESC_S_MASK     (1 << 12)
#define DESC_TYPE_SHIFT 8
#define DESC_A_MASK     (1 << 8)

#define DESC_CS_MASK    (1 << 11) /* 1=code segment 0=data segment */
#define DESC_C_MASK     (1 << 10) /* code: conforming */
#define DESC_R_MASK     (1 << 9)  /* code: readable */

#define DESC_E_MASK     (1 << 10) /* data: expansion direction */
#define DESC_W_MASK     (1 << 9)  /* data: writable */

#define DESC_TSS_BUSY_MASK (1 << 9)

#define CC_C   	0x0001
#define CC_P 	0x0004
#define CC_A	0x0010
#define CC_Z	0x0040
#define CC_S    0x0080
#define CC_O    0x0800

#define TF_SHIFT   8
#define IOPL_SHIFT 12
#define VM_SHIFT   17

#define TF_MASK 		0x00000100
#define IF_MASK 		0x00000200
#define DF_MASK 		0x00000400
#define IOPL_MASK		0x00003000
#define NT_MASK	         	0x00004000
#define RF_MASK			0x00010000
#define VM_MASK			0x00020000
#define AC_MASK			0x00040000 
#define VIF_MASK                0x00080000
#define VIP_MASK                0x00100000
#define ID_MASK                 0x00200000

/* these flags are left in cpu_state.eflags */
#define EFLAGS_MASK (IOPL_MASK | IF_MASK)

#define CR0_PE_MASK  (1 << 0)
#define CR0_MP_MASK  (1 << 1)
#define CR0_EM_MASK  (1 << 2)
#define CR0_TS_MASK  (1 << 3)
#define CR0_ET_MASK  (1 << 4)
#define CR0_NE_MASK  (1 << 5)
#define CR0_WP_MASK  (1 << 16)
#define CR0_AM_MASK  (1 << 18)
#define CR0_PG_MASK  (1 << 31)

#define CR4_VME_MASK  (1 << 0)
#define CR4_PVI_MASK  (1 << 1)
#define CR4_TSD_MASK  (1 << 2)
#define CR4_DE_MASK   (1 << 3)
#define CR4_PSE_MASK  (1 << 4)
#define CR4_PAE_MASK  (1 << 5)
#define CR4_PGE_MASK  (1 << 7)
#define CR4_PCE_MASK  (1 << 8)
#define CR4_OSFXSR_MASK (1 << 9)
#define CR4_OSXMMEXCPT_MASK  (1 << 10)

#define PG_PRESENT_BIT	0
#define PG_RW_BIT	1
#define PG_USER_BIT	2
#define PG_PWT_BIT	3
#define PG_PCD_BIT	4
#define PG_ACCESSED_BIT	5
#define PG_DIRTY_BIT	6
#define PG_PSE_BIT	7
#define PG_GLOBAL_BIT	8

#define PG_PRESENT_MASK  (1 << PG_PRESENT_BIT)
#define PG_RW_MASK	 (1 << PG_RW_BIT)
#define PG_USER_MASK	 (1 << PG_USER_BIT)
#define PG_PWT_MASK	 (1 << PG_PWT_BIT)
#define PG_PCD_MASK	 (1 << PG_PCD_BIT)
#define PG_ACCESSED_MASK (1 << PG_ACCESSED_BIT)
#define PG_DIRTY_MASK	 (1 << PG_DIRTY_BIT)
#define PG_PSE_MASK	 (1 << PG_PSE_BIT)
#define PG_GLOBAL_MASK	 (1 << PG_GLOBAL_BIT)

/* for PAE */
#define PG_PAE_ADDR_MASK    ((1LL << 52) - 1)

/* user flags */
#define PG_ORIG_RW_BIT   9
#define PG_ORIG_RW_MASK  (1 << PG_ORIG_RW_BIT)

#define PG_ERROR_W_BIT     1

#define PG_ERROR_P_MASK    0x01
#define PG_ERROR_W_MASK    (1 << PG_ERROR_W_BIT)
#define PG_ERROR_U_MASK    0x04
#define PG_ERROR_RSVD_MASK 0x08

#define MSR_IA32_APICBASE               0x1b
#define MSR_IA32_APICBASE_BSP           (1<<8)
#define MSR_IA32_APICBASE_ENABLE        (1<<11)
#define MSR_IA32_APICBASE_BASE          (0xfffff<<12)

#define	APIC_LVR         0x30
#define	APIC_LVTT	 0x320

#define APIC_DM_MASK     0x00700
#define APIC_DM_NMI      0x00400
#define	APIC_LVT_MASKED	(1<<16)

#define MSR_IA32_SYSENTER_CS            0x174
#define MSR_IA32_SYSENTER_ESP           0x175
#define MSR_IA32_SYSENTER_EIP           0x176

#define MSR_EFER                        0xc0000080
#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_FFXSR (1 << 14)

#define MSR_STAR                        0xc0000081
#define MSR_LSTAR                       0xc0000082
#define MSR_CSTAR                       0xc0000083
#define MSR_FMASK                       0xc0000084
#define MSR_FSBASE                      0xc0000100
#define MSR_GSBASE                      0xc0000101
#define MSR_KERNELGSBASE                0xc0000102

/* cpuid_features bits */
#define CPUID_FP87 (1 << 0)
#define CPUID_VME  (1 << 1)
#define CPUID_DE   (1 << 2)
#define CPUID_PSE  (1 << 3)
#define CPUID_TSC  (1 << 4)
#define CPUID_MSR  (1 << 5)
#define CPUID_PAE  (1 << 6)
#define CPUID_MCE  (1 << 7)
#define CPUID_CX8  (1 << 8)
#define CPUID_APIC (1 << 9)
#define CPUID_SEP  (1 << 11) /* sysenter/sysexit */
#define CPUID_MTRR (1 << 12)
#define CPUID_PGE  (1 << 13)
#define CPUID_MCA  (1 << 14)
#define CPUID_CMOV (1 << 15)
#define CPUID_CLFLUSH (1 << 19)
/* ... */
#define CPUID_MMX  (1 << 23)
#define CPUID_FXSR (1 << 24)
#define CPUID_SSE  (1 << 25)
#define CPUID_SSE2 (1 << 26)

#define CPUID_EXT_SS3      (1 << 0)
#define CPUID_EXT_MONITOR  (1 << 3)
#define CPUID_EXT_CX16     (1 << 13)

#define CPUID_EXT2_SYSCALL (1 << 11)
#define CPUID_EXT2_NX      (1 << 20)
#define CPUID_EXT2_FFXSR   (1 << 25)
#define CPUID_EXT2_LM      (1 << 29)

#define EXCP00_DIVZ	0
#define EXCP01_SSTP	1
#define EXCP02_NMI	2
#define EXCP03_INT3	3
#define EXCP04_INTO	4
#define EXCP05_BOUND	5
#define EXCP06_ILLOP	6
#define EXCP07_PREX	7
#define EXCP08_DBLE	8
#define EXCP09_XERR	9
#define EXCP0A_TSS	10
#define EXCP0B_NOSEG	11
#define EXCP0C_STACK	12
#define EXCP0D_GPF	13
#define EXCP0E_PAGE	14
#define EXCP10_COPR	16
#define EXCP11_ALGN	17
#define EXCP12_MCHK	18

#ifdef _WIN32
#define ASM_NAME(x) _ ## x                
#else
#define ASM_NAME(x) x
#endif
                
#define DUP4(f, n) f(n) f(n + 1) f(n + 2) f(n + 3)
#define DUP16(f, n) DUP4(f, n) DUP4(f, n + 4) DUP4(f, n + 8) DUP4(f, n + 12)
#define DUP64(f, n) DUP16(f, n) DUP16(f, n + 16) DUP16(f, n + 32) DUP16(f, n + 48) 
#define DUP256(f, n) DUP64(f, n) DUP64(f, n + 64) DUP64(f, n + 128) DUP64(f, n + 192)

#ifndef __ASSEMBLY__

/* spinlocks */

typedef struct {
    volatile int lock;
} spinlock_t;

static inline void spin_lock_init(spinlock_t *l)
{
    l->lock = 1;
}

static inline void spin_lock(spinlock_t *l)
{
    asm volatile("1:\n"
                 "lock; decb %0\n"
                 "jns 3f\n"
                 "2:\n"
                 "rep; nop\n"
                 "cmpb $0, %0\n"
                 "jle 2b\n"
                 "jmp 1b\n"
                 "3:\n" 
                 : "=m" (l->lock) 
                 : 
                 : "memory");
}

static inline void spin_unlock(spinlock_t *l)
{
    char val;
    val = 1;

    /* the xchg ensures that the memory I/Os are synchronized */
    asm volatile("xchgb %b0, %1"
                 : "=q" (val), "=m" (l->lock)
                 : "0" (val));
}

/* registers in an exception. Do not modify it without looking at
   monitor_asm.S */
#ifdef __x86_64__
struct kqemu_exception_regs {
    unsigned long eax; /* 0 */
    unsigned long ecx;
    unsigned long edx;
    unsigned long ebx;
    unsigned long esp; /* 4 */
    unsigned long ebp;
    unsigned long esi;
    unsigned long edi;
    unsigned long r8;
    unsigned long r9;
    unsigned long r10;
    unsigned long r11;
    unsigned long r12;
    unsigned long r13;
    unsigned long r14;
    unsigned long r15;
    unsigned long error_code; /* 16 */
    unsigned long eip; /* 17 */
    uint16_t cs_sel; /* 18 */
    uint16_t cs_sel_h[3];
    unsigned long eflags; /* 19 */
    unsigned long esp1; /* 20 */
    uint16_t ss_sel; /* 21 */
    uint16_t ss_sel_h[3];
    /* additionnal space to handle 16 bit return */
    /* NOTE: at this point must be 16 byte aligned */
    unsigned long dummy[4]; /* 22 */
};
#else
struct kqemu_exception_regs {
    uint16_t ds_sel; /* 0 */
    uint16_t ds_sel_h;
    uint16_t es_sel; /* 1 */
    uint16_t es_sel_h;
    uint32_t eax;    /* 2 */
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;  /* 6 */
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint32_t error_code; /* 10 */
    uint32_t eip; /* 11 */
    uint16_t cs_sel; /* 12 */
    uint16_t cs_sel_h;
    unsigned long eflags; /* 13 */
    uint32_t esp1; /* 14 */
    uint16_t ss_sel; /* 15 */
    uint16_t ss_sel_h;
    /* additionnal space to handle 16 bit return */
    uint32_t dummy[2]; 
};
#endif

#define MON_STACK_SIZE 4096

struct __attribute__((packed)) desc {
    uint16_t limit;
    unsigned long base;
};

#ifdef __x86_64__
struct  __attribute__((packed)) kqemu_tss {
    uint32_t reserved_0;
    uint64_t rsp0;
    uint64_t rsp1;
    uint64_t rsp2;
    uint64_t reserved_1;
    uint64_t ist[7];
    uint64_t reserved_2;
    uint16_t res_3;
    uint16_t bitmap;
};
#else
struct kqemu_tss {
    unsigned short	back_link,__blh;
    unsigned long	esp0;
    unsigned short	ss0,__ss0h;
    unsigned long	esp1;
    unsigned short	ss1,__ss1h;
    unsigned long	esp2;
    unsigned short	ss2,__ss2h;
    unsigned long	__cr3;
    unsigned long	eip;
    unsigned long	eflags;
    unsigned long	eax,ecx,edx,ebx;
    unsigned long	esp;
    unsigned long	ebp;
    unsigned long	esi;
    unsigned long	edi;
    unsigned short	es, __esh;
    unsigned short	cs, __csh;
    unsigned short	ss, __ssh;
    unsigned short	ds, __dsh;
    unsigned short	fs, __fsh;
    unsigned short	gs, __gsh;
    unsigned short	ldt, __ldth;
    unsigned short	trace, bitmap;
};
#endif

struct kqemu_ram_page {
    unsigned long paddr; /* physical address on host, -1 if not locked */
    /* first virtual address where it is mapped. if the bit 0 is 1,
       there are additionnal mappings (see ram_page_mappings[]). -1
       if no mappings.  */
    unsigned long vaddr; 
    struct kqemu_user_page *host_page; /* handle for host page */
    struct kqemu_ram_page *hash_next; /* paddr hashing */
    struct kqemu_ram_page *lock_prev, *lock_next; /* LRU handling for
                                                     locking */
    struct kqemu_ram_page *map_prev, *map_next; /* mapped pages list */
    uint32_t mmu_protected;
};

#define MONITOR_MEM_SIZE (32 * 1024 * 1024)
#define MONITOR_SEL_RANGE (8 * 8)

#define RAM_PAGE_HASH_BITS 12
#define RAM_PAGE_HASH_SIZE (1 << RAM_PAGE_HASH_BITS)

#define MAX_MAPPED_PAGES (MONITOR_MEM_SIZE / PAGE_SIZE)

#define MAPPED_PAGES_HASH_BITS 13
#define MAPPED_PAGES_HASH_SIZE (1 << MAPPED_PAGES_HASH_BITS)

struct mapped_page {
    struct mapped_page *hash_next; /* next physical page with same hash */
    /* XXX: redundant field - can get it from PTE */
    unsigned long page_index; /* physical page index corresponding to
                                 this page. -1 if none. */
    void *host_page; /* handle for the kernel, NULL if page not mapped */
    int next; /* next free page (XXX: suppress) */
    int user_page; /* true if user page */
};

struct monitor_code_header {
    unsigned int kernel2monitor;
    unsigned int interrupt_table;
    unsigned int kernel2monitor_jmp_offset;
    unsigned int monitor2kernel_jmp_offset;
    unsigned int monitor_exec;
};

//#define SOFT_TLB_SIZE 16
#define SOFT_TLB_SIZE 128

typedef struct {
    unsigned long vaddr[4]; /* is_user * 2 + is_write, (vaddr &
                               ~PAGE_MASK) != 0 means invalid
                               entry  */
    unsigned long addend; /* addend to get page address in monitor space */
    unsigned long dummy[3]; /* align to 32 bytes */
} TLBEntry;

#define PHYS_SLOT_BITS 7
#define PHYS_NB_SLOTS (1 << PHYS_SLOT_BITS)
#define RAM_PAGE_CACHE_SIZE (SOFT_TLB_SIZE + PHYS_NB_SLOTS)

#define MAX_PROTECTED_MMU_PAGES 1024

#define NB_ADDRESS_SPACES 2

#define MIN_LOCKED_RAM_PAGES 1024

union pgd {
#ifdef __x86_64__
        uint64_t l4[512];
#else
        uint64_t l3[4];
        uint32_t l2[1024];
#endif
};

typedef enum {
    MON_REQ_EXIT = 0,
    MON_REQ_IRQ,
    MON_REQ_LOG,
    MON_REQ_ABORT,
    MON_REQ_ALLOC_PAGE,
    MON_REQ_LOCK_USER_PAGE,
    MON_REQ_UNLOCK_USER_PAGE,
    MON_REQ_EXCEPTION,
} MonitorRequest;

#define INTERRUPT_ENTRY_SIZE 16
#ifdef __x86_64__
#define IDT_ENTRY_SIZE 16
#else
#define IDT_ENTRY_SIZE 8
#endif

#ifdef PROFILE_INTERP_PC
typedef struct ProfileInterpEntry {
    unsigned long eip;
    int64_t cycles, count, insn_count;
    int next;
} ProfileInterpEntry;

#define PROFILE_INTERP_PC_NB_ENTRIES 4096
#define PROFILE_INTERP_PC_HASH_BITS 12
#define PROFILE_INTERP_PC_HASH_SIZE (1 << PROFILE_INTERP_PC_HASH_BITS)
#endif

struct kqemu_global_state {
    struct kqemu_state *first_state;
    int nb_kqemu_states;
    unsigned long max_locked_ram_pages;
    spinlock_t lock;
};

struct kqemu_state {
    unsigned long monitor_vaddr;         /* start of monitor code */
    unsigned long monitor_data_vaddr;    /* kqemu_state address in
                                            monitor virtual memory
                                            space */
    unsigned long monitor_data_kaddr;    /* kqemu_state address in
                                            kernel virtual memory
                                            space */
    unsigned long monitor_end_vaddr;     /* end of initial monitor
                                            memory space / start of
                                            allocated pages */
    unsigned long monitor_to_kernel_offset;  /* offset for pointers */
    uint32_t monitor_selector_base; /* XXX: use 16 bits ? */
    
    struct desc monitor_idt;
    struct desc monitor_gdt;
    uint16_t monitor_ldt_sel;
    uint16_t monitor_ds_sel;
    uint16_t monitor_ss16_sel;
#ifdef __x86_64__
    uint16_t monitor_cs32_sel;
    uint16_t monitor_ss_null_sel;
#endif
    unsigned long monitor_jmp;
    uint16_t monitor_cs_sel;
    uint16_t monitor_tr_sel;
    unsigned long monitor_cr3;
    unsigned long monitor_dr7;
    unsigned long monitor_esp;
    
    /* saved kernel state */
    struct desc kernel_idt;
    struct desc kernel_gdt;
    uint16_t kernel_tr_sel;
    uint16_t kernel_ldt_sel;
    unsigned long kernel_esp;
    uint16_t kernel_ss_sel;
    unsigned long kernel_jmp;
    uint32_t kernel_cs_sel; /* XXX: use 16 bits ? */
    unsigned long kernel_cr0;
    unsigned long kernel_cr3;
    unsigned long kernel_cr4;

    /* host cpu probe */
    uint32_t cpuid_features;
    uint32_t cpuid_ext2_features;
    int use_sep;
    int use_syscall;
    int use_apic;
    int apic_lvt_max;
    volatile uint32_t *apic_regs;

#ifdef __x86_64__
#define USE_PAE(s) 1
#else
#define USE_PAE(s) ((s)->use_pae)
    int use_pae;
#endif
#ifdef __x86_64__
#define PG_GLOBAL(s) PG_GLOBAL_MASK
#else
    uint32_t pg_global_mask;
#define PG_GLOBAL(s) ((s)->pg_global_mask)
#endif

    /* nexus page switching handling */
    uint64_t nexus_orig_pte;   /* original (=monitor) PTE content
                                  for the nexus page */
    uint64_t nexus_pte;   /* PTE content for the nexus page */
    unsigned long nexus_kaddr; /* address of the nexus page in kernel mem space */
    /* corresponding PTE pointer in nexus mem space */
    void *nexus_kaddr_vptep[NB_ADDRESS_SPACES]; 

    /* corresponding PTE pointer in kernel mem space */
    void *nexus_kaddr_ptep[NB_ADDRESS_SPACES]; 

    struct kqemu_tss monitor_tss;

    struct kqemu_cpu_state cpu_state; /* emulated cpu state */
    struct kqemu_exception_regs *regs; /* CPU registers if coming from
                                          an exception */
    uint64_t *pages_to_flush;
    uint64_t *ram_pages_to_update;
    uint64_t *modified_ram_pages;
    
    /* soft TLB */
    TLBEntry soft_tlb[SOFT_TLB_SIZE] __attribute__((aligned(32)));

    /* interpreter private variables */
    /* NOTE: the order of the following 8 fields is important ! */
    int8_t dflag __attribute__((aligned(8)));
    int8_t aflag;
    int8_t override;
    uint8_t prefix;
#ifdef __x86_64__
    uint8_t rex_r, rex_x, rex_b, dummy1;
#endif
    int popl_esp_hack;
    int rip_offset;
    int seg_cache_loaded; /* true if cpu_state.segs[] content is up to date */
    int insn_count; /* interpreted instruction count */
#ifdef USE_SEG_GP
    uint32_t seg_desc_cache[6][2];
    uint32_t seg_desc_entries[2];
#endif
    uint32_t tr_desc_cache[4];
    unsigned long comm_page_index;

#ifdef PROFILE_INTERP2
    int64_t total_interp_count;
    int64_t exc_interp_count, exc_seg_cycles, exc_interp_cycles, exc_insn_count;
    int exc_insn_count_max;
    unsigned long exc_start_eip_max;
    int64_t tlb_flush_count, tlb_flush_cycles;
    int64_t tlb_flush_page_count, tlb_flush_page_cycles;
    int64_t total_page_fault_count;
    int64_t mmu_page_fault_count, mmu_page_fault_cycles;
    int64_t tlb_page_fault_count, tlb_page_fault_cycles;
    int64_t tlb_interp_page_fault_count;
    int64_t exec_init_count, exec_init_cycles;
    int64_t hw_interrupt_start_count, hw_interrupt_count, hw_interrupt_cycles;
    int64_t interp_interrupt_count, interp_interrupt_cycles;
    int64_t ram_map_count, ram_map_miss_count;
#endif
#ifdef PROFILE_INSN
    int64_t tab_insn_cycles[512];
    int tab_insn_cycles_min[512];
    int tab_insn_cycles_max[512];
    int64_t tab_insn_count[512];
#endif
#ifdef PROFILE_INTERP_PC
    int nb_profile_interp_entries;
    ProfileInterpEntry profile_interp_entries[PROFILE_INTERP_PC_NB_ENTRIES];
    int profile_interp_hash_table[PROFILE_INTERP_PC_HASH_SIZE];
#endif

    /* when calling monitor2kernel, a request is indicated here */
    MonitorRequest mon_req;
    long arg0;
    long arg1;
    long ret;
    long ret2;

    char log_buf[1024];

    /* RAM page handling */
    unsigned long ram_size;
    unsigned long ram_base_uaddr;
    int nb_ram_pages;
    int nb_locked_ram_pages;
    int max_locked_ram_pages;
    struct kqemu_state *next_state;
    struct kqemu_global_state *global_state;
    struct kqemu_ram_page locked_page_head;
    /* this structure holds the linked list of virtual mappings for a
       ram page */
#ifdef __x86_64__
    unsigned long ***ram_page_mappings[NB_ADDRESS_SPACES][512];
#else
    unsigned long *ram_page_mappings[NB_ADDRESS_SPACES][1024];
#endif
    struct kqemu_ram_page *ram_page_hash[RAM_PAGE_HASH_SIZE];
    struct kqemu_ram_page mapped_page_head;
    
    /* phys page directory (page_indexes) */
    unsigned long phys_to_ram_map_pages[1024];

    /* dirty pages handling */
    uint8_t *ram_dirty;
    
    /* virtual memory allocator */
    int first_mapped_page; /* -1 if none */
    struct mapped_page mapped_pages[MAX_MAPPED_PAGES];
    struct mapped_page *mapped_pages_hash[MAPPED_PAGES_HASH_SIZE];
    int in_page_init;
    
    /* cache to access to ram pages */
    unsigned long ram_page_cache_base;
    unsigned long slot_to_ram_addr[RAM_PAGE_CACHE_SIZE];

    unsigned long pgds_cr3[NB_ADDRESS_SPACES];
    union pgd __attribute__((aligned(4096))) pgds[NB_ADDRESS_SPACES];
    struct __attribute__((aligned(4096))) {
        /* kqemu store the current IF and IOPL here. The guest OS can
           modify them by writing at this address too. */        
        uint32_t virt_eflags; 
        uint32_t pad0[1024 - 1];
    } comm_page;
    uint8_t idt_table[IDT_ENTRY_SIZE * 256];
#ifdef USE_SEG_GP
#define NB_DT_TABLES 2
#else
#define NB_DT_TABLES 4
#endif
    /* (GDT first, LDT after) for each CPL */
    uint64_t dt_table[16384 * NB_DT_TABLES];

    /* caching of LDT and GDT */
    unsigned long dt_ram_addr[2][32]; /* only 17 entries are used */
    unsigned long dt_base[2];
    uint32_t dt_limit[2];
    
#ifdef PROFILE
#define MAX_PROFILE_TS 128
    uint32_t profile_ts[MAX_PROFILE_TS];
    uint32_t profile_line[MAX_PROFILE_TS];
    int nb_profile_ts;
#endif

    uint8_t __attribute__((aligned(4096))) stack[MON_STACK_SIZE - sizeof(struct kqemu_exception_regs)];
    struct kqemu_exception_regs regs1;
    uint8_t stack_end[0];
    struct kqemu_ram_page ram_pages[0];
};

#define PAGE_KREAD      0x0001
#define PAGE_KWRITE     0x0002
#define PAGE_KEXEC      0x0004
#define PAGE_UREAD      0x0010
#define PAGE_UWRITE     0x0020
#define PAGE_UEXEC      0x0040

#define PGD_SHIFT 22
#define PTE_MASK ((1 << 10) - 1)

#define VGA_DIRTY_FLAG  0x01
#define CODE_DIRTY_FLAG 0x02
#define DT_DIRTY_FLAG   0x04

static inline unsigned int get_seg_limit(uint32_t e1, uint32_t e2)
{
    unsigned int limit;
    limit = (e1 & 0xffff) | (e2 & 0x000f0000);
    if (e2 & DESC_G_MASK)
        limit = (limit << 12) | 0xfff;
    return limit;
}

static inline uint32_t get_seg_base(uint32_t e1, uint32_t e2)
{
    return ((e1 >> 16) | ((e2 & 0xff) << 16) | (e2 & 0xff000000));
}

#define rdmsr(msr, val1, val2) \
     asm volatile("rdmsr" : "=a" (val1), "=d" (val2) : "c" (msr))

#define wrmsr(msr, val1, val2) \
     asm volatile("wrmsr" : : "c" (msr), "a" (val1), "d" (val2))

#define rdmsrl(msr, val) \
do {\
    unsigned long __l, __h;\
    rdmsr(msr, __l, __h);\
    val = __l | ((uint64_t)__h << 32);\
} while (0)

static inline void wrmsrl(unsigned long msr, uint64_t val)
{
    unsigned long l, h;
    l = val;
    h = val >> 32;
    wrmsr(msr, l, h);
}

#ifdef __x86_64__
#define save_flags(x)	 asm volatile("pushfq ; popq %q0" : "=g" (x))
#define restore_flags(x) asm volatile("pushq %q0 ; popfq" : : "g" (x))
#else
#define save_flags(x)	 asm volatile("pushfl ; popl %0" : "=g" (x))
#define restore_flags(x) asm volatile("pushl %0 ; popfl" : : "g" (x))
#endif
#define cli()            asm volatile ("cli");

/* nexus_asm.S */

void kernel2monitor(struct kqemu_state *s);
void monitor2kernel(struct kqemu_state *s);

/* kernel_asm.S */
void __attribute__((regparm(1))) exec_irq(int intno);
void __attribute__((regparm(1))) exec_exception(int intno);

/* monitor-utils.c */
void *memset(void *d1, int val, size_t len);
void *memcpy(void *d1, const void *s1, size_t len);
void *memmove(void *d1, const void *s1, size_t len);
size_t strlen(const char *s);
int mon_vsnprintf(char *buf, int buflen, const char *fmt, va_list args);
int __attribute((format (printf, 3, 4))) mon_snprintf(char *buf, int buflen, const char *fmt, ...);

/* monitor_asm.S */
unsigned long exec_binary(unsigned long *eflags, int op, 
                          unsigned long a, unsigned long b);
void __attribute__((regparm(2))) goto_user(struct kqemu_state *s, void *stack_end);
void __attribute__((regparm(3))) start_func(void (*func)(void *), void *, void *stack_end);

/* monitor.c */
void __attribute__((noreturn, format (printf, 2, 3))) monitor_panic(struct kqemu_state *s, const char *fmt, ...);
void __attribute((format (printf, 2, 3))) monitor_log(struct kqemu_state *s, const char *fmt, ...);

/* common.c */
void restore_cpu_state_from_regs(struct kqemu_state *s,
                                 struct kqemu_exception_regs *r);

#if defined(__x86_64__)
static inline int64_t getclock(void)
{
    uint32_t low, high;
    int64_t val;
    asm volatile("rdtsc" : "=a" (low), "=d" (high));
    val = high;
    val <<= 32;
    val |= low;
    return val;
}
#else
static inline int64_t getclock(void)
{
    int64_t val;
    asm volatile ("rdtsc" : "=A" (val));
    return val;
}
#endif

#ifdef PROFILE
static inline void __profile_record(struct kqemu_state *s, int line)
{
    if (s->nb_profile_ts < MAX_PROFILE_TS) {
        s->profile_line[s->nb_profile_ts] = line;
        s->profile_ts[s->nb_profile_ts++] = getclock();
    }
}

#define profile_record(s) __profile_record(s, __LINE__)

#else

#define profile_record(s)

#endif

/* interp */

void __attribute__((noreturn)) raise_exception(struct kqemu_state *s, int intno);
void __attribute__((noreturn)) __raise_exception_err(struct kqemu_state *s, int intno, int error_code);

#if 0
#define raise_exception_err(s, intno, error_code) \
do { \
    monitor_log(s, "%s:%d: exception 0x%x err=%x\n",\
                __FILE__,\
                __LINE__,\
                intno,\
                (int)error_code);\
    __raise_exception_err(s, intno, error_code);\
} while (0)
#else
#define raise_exception_err(s, intno, error_code) \
    __raise_exception_err(s, intno, error_code)
#endif

uint32_t ldub_slow(struct kqemu_state *s, unsigned long addr, 
                   int is_user);
uint32_t lduw_slow(struct kqemu_state *s, unsigned long addr, 
                   int is_user);
uint32_t ldl_slow(struct kqemu_state *s, unsigned long addr, 
                  int is_user);
uint64_t ldq_slow(struct kqemu_state *s, unsigned long addr, 
                  int is_user);
void stb_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user);
void stw_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user);
void stl_slow(struct kqemu_state *s, unsigned long addr, 
              uint32_t val, int is_user);
void stq_slow(struct kqemu_state *s, unsigned long addr, 
              uint64_t val, int is_user);

static inline uint32_t ldub_fast(struct kqemu_state *s, unsigned long addr, 
                                 int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;
    
    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & PAGE_MASK))) {
        val = ldub_slow(s, addr, is_user);
    } else {
        taddr = e->addend + addr;
        val = *(uint8_t *)taddr;
    }
    return val;
}

static inline uint32_t lduw_fast(struct kqemu_state *s, unsigned long addr, 
                                 int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 1)))) {
        val = lduw_slow(s, addr, is_user);
    } else {
        taddr = e->addend + addr;
        val = *(uint16_t *)taddr;
    }
    return val;
}

static inline uint32_t ldl_fast(struct kqemu_state *s, unsigned long addr, 
                                 int is_user)
{
    TLBEntry *e;
    uint32_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 3)))) {
        val = ldl_slow(s, addr, is_user);
    } else {
        taddr = e->addend + addr;
        val = *(uint32_t *)taddr;
    }
    return val;
}

static inline uint64_t ldq_fast(struct kqemu_state *s, unsigned long addr, 
                                int is_user)
{
    TLBEntry *e;
    uint64_t val;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1)] != (addr & (PAGE_MASK | 7)))) {
        val = ldq_slow(s, addr, is_user);
    } else {
        taddr = e->addend + addr;
        val = *(uint64_t *)taddr;
    }
    return val;
}

static inline void stb_fast(struct kqemu_state *s, unsigned long addr, 
                            uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;
    
    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & PAGE_MASK))) {
        stb_slow(s, addr, val, is_user);
    } else {
        taddr = e->addend + addr;
        *(uint8_t *)taddr = val;
    }
}

static inline void stw_fast(struct kqemu_state *s, unsigned long addr, 
                            uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 1)))) {
        stw_slow(s, addr, val, is_user);
    } else {
        taddr = e->addend + addr;
        *(uint16_t *)taddr = val;
    }
}

static inline void stl_fast(struct kqemu_state *s, unsigned long addr, 
                            uint32_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 3)))) {
        stl_slow(s, addr, val, is_user);
    } else {
        taddr = e->addend + addr;
        *(uint32_t *)taddr = val;
    }
}

static inline void stq_fast(struct kqemu_state *s, unsigned long addr, 
                            uint64_t val, int is_user)
{
    TLBEntry *e;
    unsigned long taddr;

    e = &s->soft_tlb[(addr >> PAGE_SHIFT) & (SOFT_TLB_SIZE - 1)];
    if (unlikely(e->vaddr[(is_user << 1) + 1] != (addr & (PAGE_MASK | 7)))) {
        stq_slow(s, addr, val, is_user);
    } else {
        taddr = e->addend + addr;
        *(uint64_t *)taddr = val;
    }
}

#ifdef __x86_64__
#define MMU_EXCEPTION(label) \
    ".section \"mmu_ex_table\", \"a\"\n"\
    ".quad " #label "\n"\
    ".previous\n"
#else
#define MMU_EXCEPTION(label) \
    ".section \"mmu_ex_table\", \"a\"\n"\
    ".long " #label "\n"\
    ".previous\n"
#endif

extern char _start;

static inline uint32_t ldub_mem(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    if (unlikely((addr - (unsigned long)&_start) < MONITOR_MEM_SIZE))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movzbl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint8_t *)addr));
    return res;
}

static inline uint32_t lduw_mem(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    if (unlikely((addr - ((unsigned long)&_start - 1)) < 
                 (MONITOR_MEM_SIZE + 1)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movzwl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint16_t *)addr));
    return res;
}

static inline uint32_t ldl_mem(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    if (unlikely((addr - ((unsigned long)&_start - 3)) < 
                 (MONITOR_MEM_SIZE + 3)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint32_t *)addr));
    return res;
}

#if defined (__x86_64__)
static inline uint64_t ldq_mem(struct kqemu_state *s, unsigned long addr)
{
    uint64_t res;
    if (unlikely((addr - ((unsigned long)&_start - 7)) < 
                 (MONITOR_MEM_SIZE + 7)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movq %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint64_t *)addr));
    return res;
}
#endif

static inline uint32_t ldub_mem_fast(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    asm volatile("1:\n"
                 "movzbl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint8_t *)addr));
    return res;
}

static inline uint32_t lduw_mem_fast(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    asm volatile("1:\n"
                 "movzwl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint16_t *)addr));
    return res;
}

static inline uint32_t ldl_mem_fast(struct kqemu_state *s, unsigned long addr)
{
    uint32_t res;
    asm volatile("1:\n"
                 "movl %1, %0\n" 
                 MMU_EXCEPTION(1b)
                 : "=r" (res)
                 : "m" (*(uint32_t *)addr));
    return res;
}

static inline void stb_mem(struct kqemu_state *s, unsigned long addr, uint32_t val)
{
    if (unlikely((addr - (unsigned long)&_start) < MONITOR_MEM_SIZE))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movb %b0, %1\n" 
                 MMU_EXCEPTION(1b)
                 : 
                 : "q" (val), "m" (*(uint8_t *)addr));
}

static inline void stw_mem(struct kqemu_state *s, unsigned long addr, uint32_t val)
{
    if (unlikely((addr - ((unsigned long)&_start - 1)) < 
                 (MONITOR_MEM_SIZE + 1)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movw %w0, %1\n" 
                 MMU_EXCEPTION(1b)
                 : 
                 : "r" (val), "m" (*(uint8_t *)addr));
}

static inline void stl_mem(struct kqemu_state *s, unsigned long addr, uint32_t val)
{
    if (unlikely((addr - ((unsigned long)&_start - 3)) < 
                 (MONITOR_MEM_SIZE + 3)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movl %0, %1\n" 
                 MMU_EXCEPTION(1b)
                 : 
                 : "r" (val), "m" (*(uint32_t *)addr));
}

#if defined (__x86_64__)
static inline void stq_mem(struct kqemu_state *s, unsigned long addr, uint64_t val)
{
    if (unlikely((addr - ((unsigned long)&_start - 7)) < 
                 (MONITOR_MEM_SIZE + 7)))
        raise_exception(s, KQEMU_RET_SOFTMMU);
    asm volatile("1:\n"
                 "movq %0, %1\n" 
                 MMU_EXCEPTION(1b)
                 : 
                 : "r" (val), "m" (*(uint64_t *)addr));
}
#endif

int insn_interp(struct kqemu_state *s);
void update_seg_cache(struct kqemu_state *s);
void raise_exception_interp(void *opaque);
void do_update_cr0(struct kqemu_state *s, unsigned long new_cr0);
void do_update_cr3(struct kqemu_state *s, unsigned long new_cr3);
void do_update_cr4(struct kqemu_state *s, unsigned long new_cr4);
void do_invlpg(struct kqemu_state *s, unsigned long vaddr);

#define MAX_INSN_COUNT 1000000

#ifdef __x86_64__
#define SEG_EXCEPTION(label) \
    ".section \"seg_ex_table\", \"a\"\n"\
    ".quad " #label "\n"\
    ".previous\n"
#else
#define SEG_EXCEPTION(label) \
    ".section \"seg_ex_table\", \"a\"\n"\
    ".long " #label "\n"\
    ".previous\n"
#endif

static inline unsigned long compute_eflags_user(struct kqemu_state *s, 
                                                unsigned long eflags)
{
    unsigned long val, iopl;
    val = (eflags | (2 | IF_MASK)) & 
        ~(IOPL_MASK | VM_MASK | VIF_MASK | VIP_MASK);
    /* if IOPL is different for 3, we can put it too */
    iopl = (eflags & IOPL_MASK);
    if (iopl != IOPL_MASK)
        val |= iopl;
    return val;
}

#define LOAD_SEG(seg, selector) \
      asm volatile ("1:\n"\
		    "mov %0, %%" #seg "\n" \
		    SEG_EXCEPTION(1b)\
		    : \
		    : "r" (selector))

#ifdef USE_SEG_GP
static inline void set_cpu_seg_cache(struct kqemu_state *s,
                                     int seg_reg, int selector)
{
    uint32_t sel;
    uint8_t *ptr;

    ptr = NULL;
    if ((selector & 0xfffc) != 0) {
        if ((selector & 0xfffc) != (s->regs1.cs_sel & 0xfffc) &&
            (selector & 0xfffc) != (s->regs1.ss_sel & 0xfffc)) {

            sel = (selector & ~7) | ((selector & 4) << 14);
            ptr = (uint8_t *)s->dt_table + sel;
            *(uint32_t *)(ptr) = s->seg_desc_cache[seg_reg][0];
            *(uint32_t *)(ptr + 4) = s->seg_desc_cache[seg_reg][1];
        }
    }
    switch(seg_reg) {
    case R_DS: LOAD_SEG(ds, selector); break;
    case R_ES: LOAD_SEG(es, selector); break;
    case R_FS: LOAD_SEG(fs, selector); break;
    case R_GS: LOAD_SEG(gs, selector); break;
    }
    if (ptr)
        *(uint64_t *)ptr = 0;
}
#endif /* USE_SEG_GP */

void update_seg_desc_caches(struct kqemu_state *s);
void update_gdt_ldt_cache(struct kqemu_state *s);
void update_host_cr0(struct kqemu_state *s);
void update_host_cr4(struct kqemu_state *s);

#endif /* !__ASSEMBLY__ */
