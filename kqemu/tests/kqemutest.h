/*
 * Regression tests for KQEMU
 * (c) 2005-2007 Fabrice Bellard
 */
#ifndef offsetof
#define offsetof(type, field) ((size_t) &((type *)0)->field)
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

/* eflags masks */
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

#define MSR_EFER_SCE   (1 << 0)
#define MSR_EFER_LME   (1 << 8)
#define MSR_EFER_LMA   (1 << 10)
#define MSR_EFER_NXE   (1 << 11)
#define MSR_EFER_FFXSR (1 << 14)

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

/* must be consistent with QEMU defines */

#define IO_MEM_SHIFT       4

#define IO_MEM_RAM         (0 << IO_MEM_SHIFT) /* hardcoded offset */
#define IO_MEM_ROM         (1 << IO_MEM_SHIFT) /* hardcoded offset */
#define IO_MEM_UNASSIGNED  (2 << IO_MEM_SHIFT)
#define IO_MEM_CODE        (3 << IO_MEM_SHIFT) /* used internally, never use directly */
#define IO_MEM_NOTDIRTY    (4 << IO_MEM_SHIFT) /* used internally, never use directly */

#define USER_CS    0x23
#define USER_DS    0x2b
#define USER_CS64  0x33
#define USER_FS    0x6b
#define USER_GS    0x73
#define USER_SS16  0x43

#define KERNEL_CS  0x50
#define KERNEL_DS  0x58
#define KERNEL_TS  0x80
#define KERNEL_LDT 0x90

#define REG_CR0 0
#define REG_DR0 1
#define REG_DR7 2
#define REG_CR4 3

#define REG_ES  10
#define REG_CS  11
#define REG_SS  12
#define REG_DS  13
#define REG_FS  14
#define REG_GS  15

#define REG_USERONLY 16

#define SYS_putchar 1
#define SYS_exit    2
#define SYS_malloc  3
#define SYS_nop     4
#define SYS_iopl    11
#define SYS_set_tls 12
#define SYS_set_reg 13
#define SYS_get_reg 14
#define SYS_signal  15
#define SYS_kerneltest 16


#ifdef __x86_64__
#define save_flags(x)	 asm volatile("pushfq ; popq %q0" : "=g" (x))
#define restore_flags(x) asm volatile("pushq %q0 ; popfq" : : "g" (x))
#else
#define save_flags(x)	 asm volatile("pushfl ; popl %0" : "=g" (x))
#define restore_flags(x) asm volatile("pushl %0 ; popfl" : : "g" (x))
#endif

#define KERNEL_STACK_SIZE 8192

#ifndef __ASSEMBLY__
struct kernel_header {
    uint64_t kernel_exceptions;
    uint64_t kernel_syscall;
    uint64_t kernel_idt;
    uint64_t kernel_gdt;
    uint64_t kernel_ldt;
    uint64_t kernel_lstar;
    uint64_t kernel_stack;
};
#endif
