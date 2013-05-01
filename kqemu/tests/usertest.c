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

static inline long syscall0(int n)
{
    long res;
    asm volatile ("int $0x80" : "=a" (res): "a" (n));
    return res;
}
#if defined(__x86_64__) && 0
/* test of the syscall insn */
static inline long syscall1(int n, long arg0)
{
    long res;
    asm volatile ("syscall" 
                  : "=a" (res)
                  : "a" (n), "D" (arg0)
                  : "r11", "rcx", "memory");
    return res;
}
#else
static inline long syscall1(int n, long arg0)
{
    long res;
    asm volatile ("int $0x80" 
                  : "=a" (res)
                  : "a" (n), "b" (arg0));
    return res;
}
#endif

static inline long syscall2(int n, long arg0, long arg1)
{
    long res;
    asm volatile ("int $0x80" 
                  : "=a" (res)
                  : "a" (n), "b" (arg0), "c" (arg1));
    return res;
}

void putchar(int c)
{
    syscall1(SYS_putchar, c);
}

void __attribute__((noreturn)) exit(int val)
{
    syscall1(SYS_exit, val);
    while (1);
}

void *malloc(int size)
{
    return (void *)syscall1(SYS_malloc, size);
}

int nop_syscall(void)
{
    return syscall0(SYS_nop);
}

int set_pte(unsigned long vaddr, unsigned long pte)
{
    return syscall2(5, vaddr, pte);
}

int get_pte(unsigned long vaddr)
{
    return syscall1(6, vaddr);
}

void tlb_invalidate(unsigned long vaddr)
{
    syscall1(7, vaddr);
}

void tlb_flush(int global)
{
    syscall1(8, global);
}

int iopl(int level)
{
    return syscall1(SYS_iopl, level);
}

int set_tls(int index, unsigned long addr)
{
    return syscall2(SYS_set_tls, index, addr);
}

void set_reg(int reg, unsigned long val)
{
    syscall2(SYS_set_reg, reg, val);
}

unsigned long get_reg(int reg)
{
    return syscall1(SYS_get_reg, reg);
}

int signal(int n, unsigned long handler)
{
    return syscall2(SYS_signal, n, handler);
}

#include "lib.c"

void __attribute((noreturn, format (printf, 3, 4))) 
     __panic(const char *file, int line, const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    printf("FATAL: %s:%d: ", file, line);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    put_string(buf);
    va_end(ap);
    exit(1);
}

#define panic(fmt, args...) __panic(__FILE__, __LINE__, fmt, ## args)

#ifdef __x86_64__
static inline int64_t getclock(void)
{
    uint32_t low,high;
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

void test_syscall_speed(void)
{
    int syscall_time, ret_time, ti, ti1, i, ret;
    int syscall_time_min, ret_time_min;
    
    syscall_time_min = 0x7fffffff;
    ret_time_min = 0x7fffffff;
    for(i = 0; i < 100; i++) {
        ti = getclock();
        ret = nop_syscall();
        ti1 = getclock();
        syscall_time = ti1 - ti;
        ret_time = ti1 - ret;
        if (syscall_time < syscall_time_min)
            syscall_time_min = syscall_time;
        if (ret_time < ret_time_min)
            ret_time_min = ret_time;
    }
    printf("nop_syscall cycles: min=%d ret=%d\n", 
           syscall_time_min, 
           ret_time_min);
}

void test_phys_alloc(void)
{
    uint8_t *ptr;
    int size, i, j;

    size = 16 * 1024 * 1024;
    ptr = malloc(size);
    for(j = 0;j < 3; j++) {
        printf("ram loop %d\n", j);
        for(i = 0; i < size; i += 1024)
            ptr[i] = 0;
    }
}

void test_tlb_invalidate(void)
{
    uint8_t *page1, *page2;
    unsigned long pte1, pte2, addr;
    int v1, v2;

    page1 = malloc(4096);
    memset(page1, 0xaa, 4096);
    page2 = malloc(4096);
    memset(page2, 0x55, 4096);

    pte1 = get_pte((unsigned long)page1);
    pte2 = get_pte((unsigned long)page2);

    tlb_invalidate((unsigned long)page1);
    
    v1 = *page1;
    if (v1 != 0xaa)
        panic("mapping error addr=%08lx v1=%02x", (unsigned long)page1, v1);
        
    /* map the page at several addresses */
    for(addr = 0xe0000000; addr < 0xe0008000; addr += 4096)
        set_pte(addr, pte1);
    
    for(addr = 0xe0000000; addr < 0xe0008000; addr += 4096) {
        if (*(uint8_t *)addr != 0xaa)
            panic("mapping error addr=%08lx\n", addr);
    }
    
    for(addr = 0xe0000000; addr < 0xe0008000; addr += 4096) {
        set_pte(addr, pte2);
        /* this may still return 0xaa because no invalidation was done */
        v1 = *(uint8_t *)addr;
    
        tlb_invalidate(addr);
    
        v2 = *(uint8_t *)addr;
        
        if (v2 != 0x55)
            panic("%p: %02x %02x\n", (void *)addr, v1, v2);
    }

    /* now test full invalidation */
    for(addr = 0xe0000000; addr < 0xe0008000; addr += 4096) {
        set_pte(addr, pte1);
    }
    
    tlb_flush(1);
    
    for(addr = 0xe0000000; addr < 0xe0008000; addr += 4096) {
        v2 = *(uint8_t *)addr;
        
        if (v2 != 0xaa)
            panic("tlb_flush");
    }
}

void test_stress(void)
{
    uint8_t *ptr;
    int size, i, j;

    size = 100 * 1024 * 1024;
    ptr = malloc(size);
    for(j = 0;; j++) {
        printf("ram loop %d\n", j);
        for(i = 0; i < size; i += 1024)
            ptr[i] = 0;
    }
}

uint64_t dummy;

extern char am_handler;

void test_cr0_am(void)
{
    unsigned long cr0, flags;
    int val;

    /* should not make a fault */
    asm volatile("movl %1, %0" 
                 : "=r" (val) 
                 : "m" (*(uint32_t *)((char *)&dummy + 1)));
    
    save_flags(flags);
    flags |= AC_MASK;
    restore_flags(flags);
    
    /* should not make a fault */
    asm volatile("movl %1, %0" 
                 : "=r" (val) 
                 : "m" (*(uint32_t *)((char *)&dummy + 1)));

    cr0 = get_reg(REG_CR0);
    cr0 |= CR0_AM_MASK;
    set_reg(REG_CR0, cr0);

    save_flags(flags);
    flags &= ~AC_MASK;
    restore_flags(flags);

    /* should not make a fault */
    asm volatile("movl %1, %0" 
                 : "=r" (val) 
                 : "m" (*(uint32_t *)((char *)&dummy + 1)));

    save_flags(flags);
    flags |= AC_MASK;
    restore_flags(flags);

    signal(EXCP11_ALGN, (long)&am_handler);
    /* should make a fault */
    asm volatile(".globl am_handler\n"
                 "movl %1, %0\n" 
                 "jmp 1f\n"
                 "am_handler:\n"
                 "mov $1, %0\n"
                 "1:\n"
                 : "=r" (val) 
                 : "m" (*(uint32_t *)((char *)&dummy + 1)));
    if (val != 1)
        printf("error: alignment exception expected\n");
    set_reg(REG_CR0, cr0 & ~CR0_AM_MASK);
    signal(EXCP11_ALGN, 0);
}

extern char debug_handler;

void test_debug(void)
{
    int val;

    dummy = 0;
    set_reg(REG_DR0, (unsigned long)&dummy);
    /* data r/w access */
    set_reg(REG_DR7, (3 << 0) | (3 << 16) | (3 << 18));
    signal(EXCP01_SSTP, (long)&debug_handler);
    asm volatile (".globl debug_handler\n"
                  "movl $0, %1\n"
                  "movl $1, %0\n"
                  "jmp 1f\n"
                  "debug_handler:\n"
                  "movl $1, %1\n"
                  "1:\n"
                  : "=m" (dummy), "=r" (val));
    if (val != 1)
        printf("error: debug exception expected\n");
    
    set_reg(REG_DR7, 0);
    signal(EXCP01_SSTP, 0);
}

uint8_t fs_data[32];
uint8_t gs_data[32];

void test_segs(void)
{
    uint8_t *fs_base, *gs_base;
    long b;

    fs_base = fs_data;
    gs_base = gs_data;

    fs_base[0] = 0x88;
    gs_base[0] = 0x99;

    set_tls(0, (long)fs_base);
    set_tls(1, (long)gs_base);
    asm volatile ("fs movzb 0x0, %0" : "=r" (b));
    if (b != 0x88)
        panic("fs_base error");

    asm volatile ("gs movzb 0x0, %0" : "=r" (b));
    if (b != 0x99)
        panic("gs_base error");
}

#ifndef __x86_64__
/* test 16 bit ESP bug */
void test_esp_bug(void)
{
    int esp16, esp32;
    asm volatile ("movl %%ss, %%eax\n"
                  "movl %%esp, %%ebx\n"
                  "movl %2, %%ecx\n"
                  "movl %%ecx, %%ss\n"
                  "pushl %%ecx\n"
                  "popl %%ecx\n"
                  "movl %%esp, %%ecx\n"
                  "movl %%eax, %%ss\n"
                  "movl %%ebx, %%esp\n" 
                  : "=c" (esp16), "=b" (esp32) : "i" (USER_SS16) : "%eax");
    if (esp16 != esp32)
        panic("ESP bug1 not corrected %08x %08x\n", esp16, esp32);
    asm volatile ("movl %%ss, %%eax\n"
                  "movl %%esp, %%ebx\n"
                  "movl %2,%%ecx\n"
                  "movl %%ecx, %%ss\n"

                  "pushl %%eax\n"
                  "movl $4, %%eax\n"
                  "int $0x80\n"
                  "popl %%eax\n"

                  "movl %%esp, %%ecx\n"
                  "movl %%eax, %%ss\n"
                  "movl %%ebx, %%esp\n" 
                  : "=c" (esp16), "=b" (esp32) : "i" (USER_SS16) : "%eax");
    if (esp16 != esp32)
        panic("ESP bug2 not corrected %08x %08x\n", esp16, esp32);
}
#endif

long interp_test1(int a, int b)
{
    long res, i;
    res = a + b;
    for(i = 0; i < 100; i++)
        res += i;
    return res;
}

uint8_t big_array[256*1024] = { 1, 2, 3};

#define FLUSH_NB_INSNS (128 * 1024)

void flush_caches(void)
{
    uint8_t *ptr;
    void (*func)(void);
    printf("flush caches\n");
    memcpy(big_array, big_array + 16, sizeof(big_array) - 16);
    ptr = malloc(FLUSH_NB_INSNS);
    memset(ptr, 0x92, FLUSH_NB_INSNS - 1); /* xchg */
    ptr[FLUSH_NB_INSNS - 1] = 0xc3; /* ret */
    func = (void *)ptr;
    func();
}

void interp_test2(void)
{
}

/* small kqemu interpreter test */
#ifdef __x86_64__
void test_interp(void)
{
    iopl(3);

    asm volatile("cli");

    printf("hello interp world\n");

    /* XXX: still one bug if integer */
    printf("a=%d\n", 1234);

    asm volatile("sti");

    iopl(0);
}

#else
void test_interp(void)
{
    unsigned long res0, res1, res2;
    int duration, overhead, res, i;

    iopl(3);
#if 0
    /* register preservation test */
    {
        unsigned long eax, ebx, ecx, edx;
        unsigned long org_eax, org_ebx, org_ecx, org_edx;
        org_eax = 0x12345678;
        org_ebx = 0x43243243;
        org_ecx = 0xabc12343;
        org_edx = 0xfabababa;
        asm volatile ("cli");
        for(i=0;i<20000000;i++) {
            asm volatile("cli\n"
                         "pushf\n"
                         "call interp_test2\n"
                         "popf\n"
                         //                         "push %%ds\n"
                         //                         "pop %%ds\n"
                         : "=a" (eax),
                         "=b" (ebx),
                         "=c" (ecx),
                         "=d" (edx)
                         : "a" (org_eax),
                         "b" (org_ebx),
                         "c" (org_ecx),
                         "d" (org_edx));
            if (org_eax != eax ||
                org_ebx != ebx ||
                org_ecx != ecx ||
                org_edx != edx)
                panic("register not preserved\n");
        }
        asm volatile ("sti");
    }
#endif
    /* indirect call test */
    asm volatile("cli\n"
                 "call *%0\n"
                 "sti\n"
                 :
                 : "r" (&interp_test2));

    /* pushf/popf tests */
    asm volatile("cli\n"
                 "pushf\n"
                 "popl %0\n"
                 "orl $0x200, %0\n"
                 "pushl %0\n"
                 "popf\n"
                 : "=r" (res1));
    printf("eflags=%08lx\n", res1);

    asm volatile("cli\n"
                 "pushf\n"
                 "popl %0\n"
                 "pushl %0\n"
                 "popf\n"
                 "sti\n"
                 : "=r" (res1));
    printf("eflags=%08lx\n", res1);

    asm volatile ("cli\n");
    asm volatile ("pushl $0x12345678\n"
                  "popl %0\n"
                  : "=r" (res0));

    asm volatile ("pushf\n"
                  "popl %0\n"
                  : "=r" (res1));
    asm volatile ("sti\n");

    printf("eax=%08lx\n", res0);
    printf("eflags=%08lx\n", res1);

    asm volatile ("cli\n");
    res2 = interp_test1(0xabcde0, 0x10) - 1;
    asm volatile ("sti\n");
    printf("res2=%08lx\n", res2);

    asm volatile ("cli\n");
    overhead = 0x7fffffff;
    for(i=0;i<100;i++) {
        asm volatile("rdtsc\n"
                     "movl %%eax, %%ecx\n"
                     "rdtsc\n"
                     "subl %%ecx, %%eax\n"
                     : "=a" (res)
                     : 
                     : "%ecx", "%edx");
        if (res < overhead)
            overhead = res;
    }
    asm volatile ("sti\n");
    //    flush_caches();
    asm volatile ("cli\n");
    duration = 0x7fffffff;
    for(i=0;i<10;i++) {
        asm volatile("rdtsc\n"
                     "movl %%eax, %%ecx\n"
#if 0
#define NB_INSN 4
                     "nop\n"
                     "nop\n"
                     "nop\n"
                     "nop\n"
#endif
#if 0
#define NB_INSN 4
                     "addl %%edx, %%edx\n"
                     "subl %%edx, %%edx\n"
                     "cmpl %%edx, %%edx\n"
                     "xorl %%edx, %%edx\n"
#endif
#if 0
#define NB_INSN 4
    "subl %%ebx, %%edx\n"
    "subl %%edx, %%eax\n"
    "subl %%ebx, %%edx\n"
    "subl %%edx, %%eax\n"
#endif
#if 1
#define NB_INSN 4
                     "movl %1, %%edx\n"
                     "addl %1, %%edx\n"
                     "subl %1, %%edx\n"
                     "orl %1, %%edx\n"
#endif
#if 0
#define NB_INSN 16
                     "pushl %%edx\n"
                     "cmpl $1, %1\n"
                     "movl %1, %%edx\n"
                     "cmpl $0x12345, %1\n"
                     "cmpl $1, %1\n"
                     "popl %%edx\n"
                     "cmpl $0x12345, %1\n"
                     "addl %1, %%edx\n"
                     "movl %1, %%edx\n"
                     "subl %1, %%edx\n"
                     "cmpl %1, %%edx\n"
                     "pushl %%edx\n"
                     "movl %1, %%edx\n"
                     "xorl %1, %%edx\n"
                     "popl %%edx\n"
                     "movl %1, %%edx\n"
#endif
#if 0
#define NB_INSN 4
                     "pushl %%edx\n"
                     "popl %%edx\n"
                     "pushl %%edx\n"
                     "popl %%edx\n"
#endif
                     "rdtsc\n"
                     "subl %%ecx, %%eax\n"
                     : "=a" (res)
                     : "m" (res1)
                     : "%ecx", "%edx");
        if (res < duration)
            duration = res;
    }

    asm volatile ("sti\n");
    duration -= overhead;
    printf("overhead=%d total=%d insn time=%d\n",
           overhead, 
           duration,
           duration / NB_INSN);
    
    asm volatile ("cli\n");
    printf("a=%d\n", 1234);
    asm volatile ("sti\n");

    asm volatile ("cli\n");
    for(i=0;i<128;i++) {
        static const uint32_t table1[4] = {
            0xffffffff,
            0x55555555,
            0xaaaaaaaa,
            0x12345678,
        };
        uint32_t table[4];
        memcpy(table, table1, sizeof(table));
        asm volatile("xor %%eax, %%eax\n"
                     "btc %3, %0\n" 
                     "sbb %%eax, %%eax\n"
                     : "=m" (table[0]), "=a" (res0)
                     : "m" (table[0]), "d" (i) : "memory");
        if (table[i >> 5] != (table1[i >> 5] ^ (1 << (i & 0x1f))))
            panic("btc %d\n", i);
        if (((table1[i >> 5] >> (i & 0x1f)) & 1) != (res0 & 1))
            panic("btc carry %d\n", i);
    }

    asm volatile ("imul $0x12345678, %1, %0\n" 
                  : "=b" (res0) 
                  : "c" (0x23243434));
    if (res0 != (int)(0x23243434LL * 0x12345678LL))
        panic("imul");

    res0 = 0x12345678;
    asm volatile ("shll $1, %0\n" : "=r" (res0) : "0" (res0));
    if (res0 != (0x12345678 << 1))
        panic("shl\n");

    res0 = 0x12345678;
    asm volatile ("shll $3, %0\n" : "=r" (res0) : "0" (res0));
    if (res0 != (0x12345678 << 3))
        panic("shl\n");

    res0 = 0x12345678;
    asm volatile ("shll %%cl, %0\n" : "=m" (res0) : "m" (res0), "c" (3));
    if (res0 != (0x12345678 << 3))
        panic("shl\n");

    res0 = 0x12345678;
    res1 = 0xabcdef01;
    asm volatile ("shld %%cl, %2, %0\n" 
                  : "=r" (res0) 
                  : "0" (res0), "r" (res1), "c" (12));
    if (res0 != 0x45678abc)
        panic("shld\n");

    res0 = 0x12345678;
    res1 = 0xabcdef01;
    asm volatile ("shld $8, %2, %0\n" 
                  : "=r" (res0) 
                  : "0" (res0), "r" (res1));
    if (res0 != 0x345678ab)
        panic("shld\n");

    /* generate an internal page fault */
    big_array[30000] = 1;

    asm volatile ("sti\n");
    

    duration = 0x7fffffff;
    for(i=0;i<1000;i++) {
        asm volatile("rdtsc\n"
                     "movl %%eax, %%ecx\n"
                     "cli\n"
                     "sti\n"
                     "rdtsc\n"
                     "subl %%ecx, %%eax\n"
                     : "=a" (res)
                     : 
                     : "%ecx", "%edx");
        if (res < duration)
            duration = res;
    }

    printf("cli/sti duration=%d\n",
           duration);

    iopl(0);
}
#endif

extern char set_reg_ex_handler;

static long set_reg_ex(int reg, unsigned long val, int ss_sel)
{
    long res;
    asm volatile ("movl %4, %%ss\n"
                  "int $0x80\n" 
                  "set_reg_ex_handler:\n"
                  : "=a" (res)
                  : "a" (SYS_set_reg), "b" (reg), "c" (val), "r" (ss_sel));
    return res;
}

void test_initial_seg_load(void)
{
    signal(EXCP0D_GPF, (long)&set_reg_ex_handler);

    set_reg_ex(REG_DS, 0xe003, USER_DS);
    set_reg_ex(REG_ES, 0xe003, USER_DS);
    set_reg_ex(REG_FS, 0xe003, USER_DS);
    set_reg_ex(REG_GS, 0xe003, USER_DS);
    set_reg_ex(REG_CS, 0xe003, USER_DS);
    set_reg_ex(REG_SS, 0xe003, USER_DS);

    set_reg_ex(REG_DS, 0xe003, USER_SS16);
    set_reg_ex(REG_ES, 0xe003, USER_SS16);
    set_reg_ex(REG_FS, 0xe003, USER_SS16);
    set_reg_ex(REG_GS, 0xe003, USER_SS16);
    set_reg_ex(REG_CS, 0xe003, USER_SS16);
    set_reg_ex(REG_SS, 0xe003, USER_SS16);

    signal(EXCP0D_GPF, 0);
}

int64_t tsc1;

extern char tsd_handler;

void test_rdtsc_tsd(void)
{
    int res;
    unsigned long cr4;
    
    /* here no exception */
    tsc1 = getclock();
    
    signal(EXCP0D_GPF, (long)&tsd_handler);
    cr4 = get_reg(REG_CR4);
    set_reg(REG_CR4, cr4 | CR4_TSD_MASK);

    /* now an exception should come */
    asm volatile("rdtsc\n"
                 "xor %%eax, %%eax\n"
                 "jmp 1f\n"
                 "tsd_handler:\n"
                 "movl $1, %%eax\n"
                 "1:\n"
                 : "=a" (res)
                 :
                 : "%edx" );
    if (res != 1)
        panic("CR4.tsd no supported\n");

    set_reg(REG_CR4, cr4);
    signal(EXCP0D_GPF, 0);
}


#ifndef __x86_64__
extern char divz_handler;

void test_div_exceptions(void)
{
    int res;

    signal(EXCP00_DIVZ, (long)&divz_handler);
    iopl(3);
    
    asm volatile("cli\n"
                 "movl $-1, %%eax\n"
                 "movl $0, %%edx\n"
                 "movl $0, %%ecx\n"
                 "movl %%esp, %%esi\n"
                 "div %%ecx\n"
                 "jmp 1f\n"
                 "divz_handler:\n"
                 "movl $-1, %%eax\n"
                 "1:\n"
                 "sti\n"
                 : "=a" (res)
                 :
                 : "%ecx", "%edx", "%esi");
    if (res != -1)
        panic("div by zero exception not supported\n");
    iopl(0);
    signal(EXCP00_DIVZ, 0);
}
#endif

void smc_test(void)
{
    int ret;
    ret = syscall0(SYS_kerneltest);
    if (ret != 0)
        panic("self modifying code error ret=0x%x\n", ret);
}

void test_str(void)
{
    uint16_t tr;
    asm volatile("str %0" : "=m" (tr));
    if (tr != KERNEL_TS)
        panic("str error\n");
}

int main(void)
{
    uint8_t *ptr;
    int size, i, user_only;

    put_string("Hello World\n");
    
    test_syscall_speed();

    smc_test();

    test_segs();

    test_str();

    user_only = get_reg(REG_USERONLY);
    
    if (!user_only) {
        test_interp();
    } else {
        size = 16 * 1024;
        ptr = malloc(size);
        for(i = 0; i < size; i++)
            ptr[i] = 0;
        
#ifndef __x86_64__
        test_esp_bug();
#endif
        
        test_phys_alloc();
        
        test_tlb_invalidate();
        
        test_cr0_am();
        
        test_debug();
        
        // test_stress();
        
        test_initial_seg_load();
        
        test_rdtsc_tsd();

#ifndef __x86_64__
        test_div_exceptions();
#endif
    }
    
    exit(0);
    return 0;
}
