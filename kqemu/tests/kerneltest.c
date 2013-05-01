/*
 * Regression tests for KQEMU
 * (c) 2005-2007 Fabrice Bellard
 */
#include <stddef.h>
#include <stdarg.h>

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

#include "kqemutest.h"

#if defined (__x86_64__)
#define FMT_lx "%016lx"
#else
#define FMT_lx "%08lx"
#endif

#ifdef __x86_64__
struct regs {
    unsigned long r15; /* 0 */
    unsigned long r14;
    unsigned long r13;
    unsigned long r12;
    unsigned long r11;
    unsigned long r10;
    unsigned long r9;
    unsigned long r8; /* 7  */
    unsigned long ebx;
    unsigned long ecx;
    unsigned long edx;
    unsigned long esi;
    unsigned long edi;
    unsigned long ebp;
    unsigned long eax; /* 14 */
    unsigned long error_code; /* 15 */
    unsigned long eip; /* 16 */
    uint16_t cs_sel; /* 17 */
    uint16_t cs_sel_h[3];
    unsigned long eflags; /* 18 */
    unsigned long esp; /* 19 */
    uint16_t ss_sel; /* 20 */
    uint16_t ss_sel_h[3];
};
#else
struct regs {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint16_t ds_sel;
    uint16_t ds_sel_h;
    uint16_t es_sel;
    uint16_t es_sel_h;
    uint32_t eax;
    unsigned long error_code;
    unsigned long eip;
    uint16_t cs_sel;
    uint16_t cs_sel_h;
    unsigned long eflags;
    uint32_t esp;
    uint16_t ss_sel;
    uint16_t ss_sel_h;
};
#endif

uint64_t kernel_idt[512] __attribute__((aligned(4096)));
uint64_t kernel_gdt[8192] __attribute__((aligned(4096)));
uint64_t kernel_ldt[7] __attribute__((aligned(4096)));
uint8_t kernel_stack[KERNEL_STACK_SIZE] __attribute__((aligned(4096)));

void putchar(int c)
{
    asm("out %b1, %w0\n" : : "d" (0x80), "a" (c));
}

#include "lib.c"

void __attribute((noreturn, format (printf, 3, 4))) 
     __panic(const char *file, int line, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    printf("kernel panic: %s:%d: ", file, line);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    put_string(buf);
    va_end(ap);
    asm("out %b1, %w0\n" : : "d" (0x81), "a" (1));
    while (1);
}

#define panic(fmt, args...) __panic(__FILE__, __LINE__, fmt, ## args)

uint8_t smc_func_code[] = {
    0xb8, 0x1, 0x00, 0x00, 0x00, /* movl $1, %eax */
    0xc3, /* ret */
};
uint8_t lock1;

int kernel_test(void)
{
    int (*smc_func)(void);
    int ret, i;
    unsigned long flags;

    save_flags(flags);
    asm volatile("cli");

    smc_func = (void *)smc_func_code;
    ret = smc_func();
    for(i = 2; i <= 4; i++) {
        smc_func_code[1] = 1 << i;
        ret |= smc_func();
    }


    restore_flags(flags);
    return ret - 0x1d;
}

long do_syscall1(struct regs *r, long n, long arg0, long arg1)
{
    long ret;
    
    switch(n) {
    case SYS_putchar:
        putchar(arg0);
        ret = 0;
        break;
    case SYS_exit:
        asm("out %b1, %w0\n" : : "d" (0x81), "a" (arg0));
        ret = -1;
        break;
    case SYS_nop:
#if 0
        /* test invalid %ds settings */
        asm volatile("pushf\n"
                     "cli\n"
                     "push %%ds\n"
                     "xorl %%eax, %%eax\n"
                     "mov %%eax, %%ds\n"
                     "pop %%ds\n"
                     "popf\n"
                     : 
                     :
                     : "%eax");
#endif
        asm volatile("rdtsc" : "=a" (ret), "=d" (arg0));
        break;
    case SYS_iopl:
        r->eflags = (r->eflags & ~IOPL_MASK) | 
            ((arg0 & 3) << IOPL_SHIFT);
        ret = 0;
        break;
    case SYS_kerneltest:
        ret = kernel_test();
        break;
    case SYS_set_tls:
        {
            uint32_t *ptr;
            uint16_t sel;

            if (!(arg0 >= 0 && arg0 < 2))
                goto fail;
            sel = USER_FS + arg0 * 8;
            ptr = (uint32_t *)((uint8_t *)kernel_gdt + (sel & ~7));
            ptr[0] = (ptr[0] & 0x0000ffff) | (arg1 << 16);
            ptr[1] = (ptr[1] & 0x00ffff00) | 
                ((arg1 >> 16) & 0xff) | 
                (arg1 & 0xff000000);
            /* reload segment */
            if (arg0 == 0)
                asm volatile("mov %0, %%fs" : : "r" (sel));
            else
                asm volatile("mov %0, %%gs" : : "r" (sel));
            ret = 0;
        }
        break;
    case SYS_get_reg:
        switch(arg0) {
        case REG_CR0:
            asm volatile("mov %%cr0, %0" : "=r" (ret));
            break;
        case REG_CR4:
            asm volatile("mov %%cr4, %0" : "=r" (ret));
            break;
        case REG_USERONLY:
            ret = 0;
            break;
        default:
            goto fail;
        }
        break;
    default:
        fail:
        panic("Invalid pseudo syscall %ld\n", n);
        ret = -1;
        break;
    }
    return ret;
}

/* we do this to avoid gcc 4 optimizations */
long do_syscall(struct regs regs)
{
    return do_syscall1(&regs, regs.eax, regs.ebx, regs.ecx);
}

#if defined (__x86_64__)
long do_syscall_lstar(struct regs regs)
{
    return do_syscall1(&regs, regs.eax, regs.edi, regs.esi);
}
#endif

#ifdef __x86_64__
void show_regs(struct regs *r)
{
    uint16_t ds_sel, es_sel, fs_sel, gs_sel;
    unsigned long cr2, cr0, cr3, cr4;
    uint32_t eflags;

    eflags = r->eflags;
    printf("RAX=%016lx RBX=%016lx RCX=%016lx RDX=%016lx\n"
           "RSI=%016lx RDI=%016lx RBP=%016lx RSP=%016lx\n"
           "R8 =%016lx R9 =%016lx R10=%016lx R11=%016lx\n"
           "R12=%016lx R13=%016lx R14=%016lx R15=%016lx\n"
           "RIP=%016lx RFL=%08x [%c%c%c%c%c%c%c]\n",
           r->eax, 
           r->ebx, 
           r->ecx, 
           r->edx, 
           r->esi, 
           r->edi, 
           r->ebp, 
           r->esp, 
           r->r8, 
           r->r9, 
           r->r10, 
           r->r11, 
           r->r12, 
           r->r13, 
           r->r14, 
           r->r15,
           r->eip,
           eflags,
           eflags & DF_MASK ? 'D' : '-',
           eflags & CC_O ? 'O' : '-',
           eflags & CC_S ? 'S' : '-',
           eflags & CC_Z ? 'Z' : '-',
           eflags & CC_A ? 'A' : '-',
           eflags & CC_P ? 'P' : '-',
           eflags & CC_C ? 'C' : '-');
    asm volatile ("mov %%fs, %0" : "=r" (fs_sel));
    asm volatile ("mov %%gs, %0" : "=r" (gs_sel));
    asm volatile ("mov %%ds, %0" : "=r" (ds_sel));
    asm volatile ("mov %%es, %0" : "=r" (es_sel));
    printf("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x\n",
           r->cs_sel,
           r->ss_sel,
           ds_sel,
           es_sel,
           fs_sel,
           gs_sel);
    asm volatile ("mov %%cr0, %0" : "=r" (cr0));
    asm volatile ("mov %%cr2, %0" : "=r" (cr2));
    asm volatile ("mov %%cr3, %0" : "=r" (cr3));
    asm volatile ("mov %%cr4, %0" : "=r" (cr4));
    printf("CR0=%08lx CR2=%016lx CR3=%016lx CR4=%08lx\n",
           cr0,
           cr2,
           cr3,
           cr4);
}
#else
void show_regs(struct regs *r)
{
    uint16_t ds_sel, es_sel, fs_sel, gs_sel;
    unsigned long cr2;

    printf("EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n"
           "ESI=%08x EDI=%08x EBP=%08x ESP=%08x\n"
           "EIP=%08x EFL=%08x [%c%c%c%c%c%c%c]\n",
           (uint32_t)r->eax, 
           (uint32_t)r->ebx, 
           (uint32_t)r->ecx, 
           (uint32_t)r->edx, 
           (uint32_t)r->esi, 
           (uint32_t)r->edi, 
           (uint32_t)r->ebp, 
           (uint32_t)r->esp, 
           (uint32_t)r->eip, 
           (uint32_t)r->eflags,
           r->eflags & DF_MASK ? 'D' : '-',
           r->eflags & CC_O ? 'O' : '-',
           r->eflags & CC_S ? 'S' : '-',
           r->eflags & CC_Z ? 'Z' : '-',
           r->eflags & CC_A ? 'A' : '-',
           r->eflags & CC_P ? 'P' : '-',
           r->eflags & CC_C ? 'C' : '-');
    asm volatile ("mov %%fs, %0" : "=r" (fs_sel));
    asm volatile ("mov %%gs, %0" : "=r" (gs_sel));
    ds_sel = r->ds_sel;
    es_sel = r->es_sel;
    printf("CS=%04x SS=%04x DS=%04x ES=%04x FS=%04x GS=%04x\n",
           r->cs_sel,
           r->ss_sel,
           ds_sel,
           es_sel,
           fs_sel,
           gs_sel);
    asm volatile ("mov %%cr2, %0" : "=r" (cr2));
    printf("CR2=%08lx\n", cr2);
}
#endif

void do_exception(int intno, struct regs r)
{
    printf("Exception n=0x%x err=" FMT_lx "\n", 
           intno, 
           r.error_code);
    show_regs(&r);
    panic("Exiting\n");
}
