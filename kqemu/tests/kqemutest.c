/*
 * Regression tests for KQEMU
 * (c) 2005-2008 Fabrice Bellard
 */
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>

#include "kqemu.h"
#include "kqemutest.h"

#define RAM_SIZE (128 * 1024 * 1024)
#define STACK_SIZE  32768

void *alloc_pages(int size)
{
    static int phys_ram_fd = -1;
    static int phys_ram_size = 0;
    const char *tmpdir;
    char phys_ram_file[1024];
    void *ptr;

    if (phys_ram_fd < 0) {
        tmpdir = getenv("QEMU_TMPDIR");
        if (!tmpdir)
            tmpdir = "/tmp";
        snprintf(phys_ram_file, sizeof(phys_ram_file), "%s/vlXXXXXX", tmpdir);
        if (mkstemp(phys_ram_file) < 0) {
            fprintf(stderr, "Could not create temporary memory file '%s'\n", 
                    phys_ram_file);
            exit(1);
        }
        phys_ram_fd = open(phys_ram_file, O_CREAT | O_TRUNC | O_RDWR, 0600);
        if (phys_ram_fd < 0) {
            fprintf(stderr, "Could not open temporary memory file '%s'\n", 
                    phys_ram_file);
            exit(1);
        }
        unlink(phys_ram_file);
    }
    size = (size + 4095) & ~4095;
    ftruncate(phys_ram_fd, phys_ram_size + size);
    ptr = mmap(NULL, 
               size, 
               PROT_WRITE | PROT_READ, MAP_SHARED, 
               phys_ram_fd, phys_ram_size);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "Could not map physical memory\n");
        exit(1);
    }
    phys_ram_size += size;
    return ptr;
}

extern uint8_t ram_start;
extern uint8_t ram_end;

struct i387_fxsave_struct {
	unsigned short	cwd;
	unsigned short	swd;
	unsigned short	twd;
	unsigned short	fop;
	long	fip;
	long	fcs;
	long	foo;
	long	fos;
	long	mxcsr;
	long	reserved;
	long	st_space[32];	/* 8*16 bytes for each FP-reg = 128 bytes */
	long	xmm_space[32];	/* 8*16 bytes for each XMM-reg = 128 bytes */
	long	padding[56];
} __attribute__ ((aligned (16)));

struct __attribute__((packed)) _fpreg {
    uint64_t mant;
    uint16_t exponent;
};

struct __attribute__((packed)) i387_fsave_struct {
    long	cwd;
    long	swd;
    long	twd;
    long	fip;
    long	fcs;
    long	foo;
    long	fos;
    struct _fpreg fpregs[8];
    long	status;		/* software status information */
};

struct tss {
    uint16_t	back_link,__blh;
    uint32_t	esp0;
    uint16_t	ss0,__ss0h;
    uint32_t	esp1;
    uint16_t	ss1,__ss1h;
    uint32_t	esp2;
    uint16_t	ss2,__ss2h;
    uint32_t	__cr3;
    uint32_t	eip;
    uint32_t	eflags;
    uint32_t	eax,ecx,edx,ebx;
    uint32_t	esp;
    uint32_t	ebp;
    uint32_t	esi;
    uint32_t	edi;
    uint16_t	es, __esh;
    uint16_t	cs, __csh;
    uint16_t	ss, __ssh;
    uint16_t	ds, __dsh;
    uint16_t	fs, __fsh;
    uint16_t	gs, __gsh;
    uint16_t	ldt, __ldth;
    uint16_t	trace, bitmap;
};

struct  __attribute__((packed)) tss64 {
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

struct i387_fsave_struct fpu_state;

#ifdef __x86_64__
void dump_cpu_state(struct kqemu_cpu_state *env)
{
    uint32_t eflags = env->eflags;
    static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
    int i;

    printf("RAX=%016lx RBX=%016lx RCX=%016lx RDX=%016lx\n"
           "RSI=%016lx RDI=%016lx RBP=%016lx RSP=%016lx\n"
           "R8 =%016lx R9 =%016lx R10=%016lx R11=%016lx\n"
           "R12=%016lx R13=%016lx R14=%016lx R15=%016lx\n"
           "RIP=%016lx RFL=%08x [%c%c%c%c%c%c%c]    CPL=%d A20=%d\n",
           env->regs[R_EAX], 
           env->regs[R_EBX], 
           env->regs[R_ECX], 
           env->regs[R_EDX], 
           env->regs[R_ESI], 
           env->regs[R_EDI], 
           env->regs[R_EBP], 
           env->regs[R_ESP], 
           env->regs[8], 
           env->regs[9], 
           env->regs[10], 
           env->regs[11], 
           env->regs[12], 
           env->regs[13], 
           env->regs[14], 
           env->regs[15], 
           env->eip, eflags,
           eflags & DF_MASK ? 'D' : '-',
           eflags & CC_O ? 'O' : '-',
           eflags & CC_S ? 'S' : '-',
           eflags & CC_Z ? 'Z' : '-',
           eflags & CC_A ? 'A' : '-',
           eflags & CC_P ? 'P' : '-',
           eflags & CC_C ? 'C' : '-',
           env->cpl, 
           (env->a20_mask >> 20) & 1);

        for(i = 0; i < 6; i++) {
            struct kqemu_segment_cache *sc = &env->segs[i];
            printf("%s =%04x %016lx %08x %08x\n",
                        seg_name[i],
                        sc->selector,
                        sc->base,
                        sc->limit,
                        sc->flags);
        }
        printf("LDT=%04x %016lx %08x %08x\n",
                    env->ldt.selector,
                    env->ldt.base,
                    env->ldt.limit,
                    env->ldt.flags);
        printf("TR =%04x %016lx %08x %08x\n",
                    env->tr.selector,
                    env->tr.base,
                    env->tr.limit,
                    env->tr.flags);
        printf("GDT=     %016lx %08x\n",
                    env->gdt.base, env->gdt.limit);
        printf("IDT=     %016lx %08x\n",
                    env->idt.base, env->idt.limit);
        printf("CR0=%08lx CR2=%016lx CR3=%016lx CR4=%08lx\n",
               env->cr0, 
               env->cr2, 
               env->cr3, 
               env->cr4);
}
#else
void dump_cpu_state(struct kqemu_cpu_state *env)
{
    uint32_t eflags = env->eflags;
    static const char *seg_name[6] = { "ES", "CS", "SS", "DS", "FS", "GS" };
    int i;

    printf("EAX=%08x EBX=%08x ECX=%08x EDX=%08x\n"
           "ESI=%08x EDI=%08x EBP=%08x ESP=%08x\n"
           "EIP=%08x EFL=%08x [%c%c%c%c%c%c%c]    CPL=%d A20=%d\n",
           (uint32_t)env->regs[R_EAX], 
           (uint32_t)env->regs[R_EBX], 
           (uint32_t)env->regs[R_ECX], 
           (uint32_t)env->regs[R_EDX], 
           (uint32_t)env->regs[R_ESI], 
           (uint32_t)env->regs[R_EDI], 
           (uint32_t)env->regs[R_EBP], 
           (uint32_t)env->regs[R_ESP], 
           (uint32_t)env->eip, eflags,
           eflags & DF_MASK ? 'D' : '-',
           eflags & CC_O ? 'O' : '-',
           eflags & CC_S ? 'S' : '-',
           eflags & CC_Z ? 'Z' : '-',
           eflags & CC_A ? 'A' : '-',
           eflags & CC_P ? 'P' : '-',
           eflags & CC_C ? 'C' : '-',
           env->cpl, 
           (env->a20_mask >> 20) & 1);
    for(i = 0; i < 6; i++) {
        struct kqemu_segment_cache *sc = &env->segs[i];
        printf("%s =%04x %08x %08x %08x\n",
                    seg_name[i],
                    sc->selector,
                    (uint32_t)sc->base,
                    sc->limit,
                    sc->flags);
    }
    printf("LDT=%04x %08x %08x %08x\n",
                env->ldt.selector,
                (uint32_t)env->ldt.base,
                env->ldt.limit,
                env->ldt.flags);
    printf("TR =%04x %08x %08x %08x\n",
                env->tr.selector,
                (uint32_t)env->tr.base,
                env->tr.limit,
                env->tr.flags);
    printf("GDT=     %08x %08x\n",
                (uint32_t)env->gdt.base, env->gdt.limit);
    printf("IDT=     %08x %08x\n",
                (uint32_t)env->idt.base, env->idt.limit);
    printf("CR0=%08x CR2=%08x CR3=%08x CR4=%08x\n",
                (uint32_t)env->cr0, 
                (uint32_t)env->cr2, 
                (uint32_t)env->cr3, 
                (uint32_t)env->cr4);
    printf("DR0=%08lx DR1=%08lx DR2=%08lx DR3=%08lx\n"
           "DR6=%08lx DR7=%08lx\n",
           env->dr0,
           env->dr1,
           env->dr2,
           env->dr3,
           env->dr6,
           env->dr7);

    asm volatile ("fsave %0" : "=m" (fpu_state));
    printf("CWD=%04lx SWD=%04lx TWD=%04lx\n",
           fpu_state.cwd, fpu_state.swd, fpu_state.twd);
    for(i = 0; i < 8; i++) {
        printf("ST%d=%016llx %04x\n",
               i, 
               fpu_state.fpregs[i].mant, 
               fpu_state.fpregs[i].exponent);
    }
}
#endif

unsigned long alloc_page_addr;
unsigned long valloc_addr;
unsigned long valloc_user_addr;
unsigned long cr3_val;
uint8_t *ram_base;
int use_pae, long_mode;

static void set_gate(uint32_t *p, unsigned int type, unsigned int dpl, 
                     unsigned long addr, unsigned int sel)
{
    unsigned int e1, e2;
    e1 = (addr & 0xffff) | (sel << 16);
    e2 = (addr & 0xffff0000) | 0x8000 | (dpl << 13) | (type << 8);
    p[0] = e1;
    p[1] = e2;
#ifdef __x86_64__
    if (long_mode) {
        p[2] = addr >> 32;
        p[3] = 0;
    }
#endif
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

unsigned long alloc_phys(int size)
{
    unsigned long addr;
    addr = alloc_page_addr;
    alloc_page_addr += (size + 4095) & ~0xfff;
    return addr;
}

uint32_t *get_ptep_l2(unsigned long vaddr)
{
    int pgd_index = vaddr >> 22;
    uint32_t *pdep, *ptep;

    pdep = (uint32_t *)(ram_base + (cr3_val & ~0xfff));
    pdep += pgd_index;
    if (!(*pdep & PG_PRESENT_MASK)) {
        *pdep = alloc_phys(4096) | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK;
    }
    ptep = (uint32_t *)(ram_base + (*pdep & ~0xfff));
    ptep += (vaddr >> 12) & 0x3ff;
    return ptep;
}

uint64_t *get_ptep_l3(unsigned long vaddr)
{
    int pdpe_index, pde_index, pte_index;
    uint64_t pdpe, pde; 
    uint64_t *pdp_page, *pde_page, *pte_page;

    pdp_page = (void *)(ram_base + (cr3_val & ~0x1f));
    pdpe_index = (vaddr >> 30) & 3;
    pdpe = pdp_page[pdpe_index];
    if (!(pdpe & PG_PRESENT_MASK))  {
        pdpe = alloc_phys(4096) | PG_PRESENT_MASK;
        pdp_page[pdpe_index] = pdpe;
    }

    pde_page = (void *)(ram_base + (pdpe & ~0xfff));
    pde_index = (vaddr >> 21) & 0x1ff;
    pde = pde_page[pde_index];
    if (!(pde & PG_PRESENT_MASK))  {
        pde = alloc_phys(4096) | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK;
        pde_page[pde_index] = pde;
    }

    pte_page = (void *)(ram_base + (pde & ~0xfff));
    pte_index = (vaddr >> 12) & 0x1ff;
    return pte_page + pte_index;
}
#ifdef __x86_64__
uint64_t *get_ptep_l4(unsigned long vaddr)
{
    int pml4e_index, pdpe_index, pde_index, pte_index;
    uint64_t pml4e, pdpe, pde; 
    uint64_t *pml4_page, *pdp_page, *pde_page, *pte_page;

    pml4_page = (void *)(ram_base + (cr3_val & ~0xfff));
    pml4e_index = (vaddr >> 39) & 0x1ff;
    pml4e = pml4_page[pml4e_index];
    if (!(pml4e & PG_PRESENT_MASK))  {
        pml4e = alloc_phys(4096) | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK;
        pml4_page[pml4e_index] = pml4e;
    }
    
    pdp_page = (void *)(ram_base + (pml4e & ~0xfff));
    pdpe_index = (vaddr >> 30) & 0x1ff;
    pdpe = pdp_page[pdpe_index];
    if (!(pdpe & PG_PRESENT_MASK))  {
        pdpe = alloc_phys(4096) | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK;
        pdp_page[pdpe_index] = pdpe;
    }

    pde_page = (void *)(ram_base + (pdpe & ~0xfff));
    pde_index = (vaddr >> 21) & 0x1ff;
    pde = pde_page[pde_index];
    if (!(pde & PG_PRESENT_MASK))  {
        pde = alloc_phys(4096) | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK;
        pde_page[pde_index] = pde;
    }

    pte_page = (void *)(ram_base + (pde & ~0xfff));
    pte_index = (vaddr >> 12) & 0x1ff;
    return pte_page + pte_index;
}
#else
uint64_t *get_ptep_l4(unsigned long vaddr)
{
    return NULL;
}
#endif

void set_pte(unsigned long vaddr, unsigned long pte)
{
    //    printf("set_pte: %p %p\n", (void *)vaddr, (void *)pte);
    if (use_pae) {
        uint64_t *ptep;
        if (long_mode) {
            ptep = get_ptep_l4(vaddr);
            *ptep = pte;
        } else {
            ptep = get_ptep_l3(vaddr);
            *ptep = pte;
        }
    } else {
        uint32_t *ptep;
        ptep = get_ptep_l2(vaddr);
        *ptep = pte;
    }
}

unsigned long get_pte(unsigned long vaddr)
{
    if (use_pae) {
        uint64_t *ptep;
        if (long_mode) {
            ptep = get_ptep_l4(vaddr);
            return *ptep;
        } else {
            ptep = get_ptep_l3(vaddr);
            return *ptep;
        }
    } else {
        uint32_t *ptep;
        ptep = get_ptep_l2(vaddr);
        return *ptep;
    }
}

static unsigned long virt_to_phys(unsigned long vaddr)
{
    unsigned long pte;
    pte = get_pte(vaddr);
    if (!(pte & PG_PRESENT_MASK))
        return -1;
    return (pte & ~0xfff) + (vaddr & 0xfff);
}

int ldub(unsigned long vaddr)
{
    unsigned long paddr;
    paddr = virt_to_phys(vaddr);
    if (paddr == -1)
        return 0;
    return ram_base[paddr];
}

unsigned long vmalloc(int size, unsigned long *ppaddr)
{
    unsigned long addr, paddr;
    int i;

    size = (size + 4095) & ~0xfff;
    addr = valloc_addr;
    paddr = alloc_phys(size);
    for(i = 0; i < size; i += 4096) {
        set_pte(addr + i, (paddr + i) | PG_PRESENT_MASK | PG_RW_MASK);
    }
    valloc_addr += size + 4096;
    if (ppaddr)
        *ppaddr = paddr;
    return addr;
}

unsigned long vmalloc_user(int size)
{
    unsigned long addr, paddr;
    int i;

    size = (size + 4095) & ~0xfff;
    addr = valloc_user_addr;
    paddr = alloc_phys(size);
    for(i = 0; i < size; i += 4096) {
        set_pte(addr + i, (paddr + i) | PG_PRESENT_MASK | PG_RW_MASK | PG_USER_MASK);
    }
    valloc_user_addr += size + 4096;
    return addr;
}

unsigned long load_elf32(const char *filename, int is_user)
{
    Elf32_Ehdr ehdr;
    Elf32_Phdr *phdr;
    int fd, i;
    unsigned long pte;
    unsigned long size, paddr, vaddr;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror(filename);
        exit(1);
    }
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
        goto fail;
    if (ehdr.e_ident[0] != ELFMAG0 ||
        ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 ||
        ehdr.e_ident[3] != ELFMAG3)
        goto fail;

    size = ehdr.e_phnum * sizeof(phdr[0]);
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    phdr = malloc(size);
    if (!phdr)
        goto fail;
    if (read(fd, phdr, size) != size)
        goto fail;

    for(i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            lseek(fd, phdr[i].p_offset, SEEK_SET);
            size = phdr[i].p_memsz;
            paddr = alloc_phys(size);
            if (read(fd, ram_base + paddr, phdr[i].p_filesz) != 
                phdr[i].p_filesz) {
                goto fail;
            }
            vaddr = phdr[i].p_vaddr;
            for(i = 0; i < size; i += 4096) {
                pte = (paddr + i) | PG_PRESENT_MASK | PG_RW_MASK;
                if (is_user)
                    pte |= PG_USER_MASK;
                set_pte(vaddr + i, pte);
            }
        }
    }
    close(fd);
    return ehdr.e_entry;
 fail:
    fprintf(stderr, "Could not load '%s'\n", filename);
    exit(1);
    return -1;
}

unsigned long load_elf64(const char *filename, int is_user)
{
    Elf64_Ehdr ehdr;
    Elf64_Phdr *phdr;
    int fd, i;
    unsigned long pte;
    unsigned long size, paddr, vaddr;

    fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror(filename);
        exit(1);
    }
    if (read(fd, &ehdr, sizeof(ehdr)) != sizeof(ehdr))
        goto fail;
    if (ehdr.e_ident[0] != ELFMAG0 ||
        ehdr.e_ident[1] != ELFMAG1 ||
        ehdr.e_ident[2] != ELFMAG2 ||
        ehdr.e_ident[3] != ELFMAG3)
        goto fail;

    size = ehdr.e_phnum * sizeof(phdr[0]);
    lseek(fd, ehdr.e_phoff, SEEK_SET);
    phdr = malloc(size);
    if (!phdr)
        goto fail;
    if (read(fd, phdr, size) != size)
        goto fail;

    for(i = 0; i < ehdr.e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            lseek(fd, phdr[i].p_offset, SEEK_SET);
            size = phdr[i].p_memsz;
            paddr = alloc_phys(size);
            if (read(fd, ram_base + paddr, phdr[i].p_filesz) != 
                phdr[i].p_filesz) {
                goto fail;
            }
            vaddr = phdr[i].p_vaddr;
            for(i = 0; i < size; i += 4096) {
                pte = (paddr + i) | PG_PRESENT_MASK | PG_RW_MASK;
                if (is_user)
                    pte |= PG_USER_MASK;
                set_pte(vaddr + i, pte);
            }
        }
    }
    close(fd);
    return ehdr.e_entry;
 fail:
    fprintf(stderr, "Could not load '%s'\n", filename);
    exit(1);
    return -1;
}

#if defined(__x86_64__)

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

#if defined(__x86_64__) && 0
long host_syscall(long sys_num)
{
    long ret;
    asm volatile ("syscall" 
                  : "=a" (ret)
                  : "a" (sys_num)
                  : "r11", "rcx", "memory");
    return ret;
}
#else
long host_syscall(long sys_num)
{
    long ret;
    asm volatile("int $0x80"
                 : "=a" (ret)
                 : "a" (sys_num));
    return ret;
}
#endif

void host_syscall_speed(void)
{
    uint64_t min, max, ti;
    int i, ret;

    min = (1ULL << 63) - 1;
    max = 0;
    for(i = 0; i < 10000; i++) {
        ti = getclock();
	/* getpid() syscall, to avoid glibc optimization */
        ret = host_syscall(20);
        ti = getclock() - ti;
        if (ti < min)
            min = ti;
        if (ti > max)
            max = ti;
    }
    printf("host_syscall cycles: min=%" PRId64 " max=%" PRId64 "\n", 
           min, max);
}

void monitor_switch_speed(int fd)
{
    struct kqemu_cpu_state cpu_state, *kenv = &cpu_state;
    int min, max, ti, i, ret;

    min = 0x7fffffff;
    max = 0;
    for(i = 0; i < 1000; i++) {
        ti = getclock();
        ret = ioctl(fd, KQEMU_EXEC, kenv);
        if (ret != 0) {
            fprintf(stderr, "KQEMU_EXEC: error 0x%x\n", ret);
            exit(1);
        }
        ti = getclock() - ti;
        if (ti < min)
            min = ti;
        if (ti > max)
            max = ti;
    }
    printf("user/kernel/monitor switch cycles: min=%d max=%d\n", min, max);
}

struct kqemu_init init;
unsigned long idt_base, idt_paddr;
unsigned long gdt_base, gdt_paddr;
unsigned long ldt_base, ldt_paddr;
unsigned long tss_base, tss_paddr;
unsigned long exception_handler[0x20];

void set_ram_dirty(unsigned long ram_addr)
{
    init.ram_dirty[ram_addr >> 12] = 0xff;
}

long do_syscall(struct kqemu_cpu_state *kenv,
                int n, long arg0, long arg1)
{
    long ret, mask;

    switch(n) {
    case SYS_putchar:
        printf("%c", (int)(arg0 & 0xff));
        ret = 0;
        break;
    case SYS_exit:
        ret = arg0;
        exit(ret);
    case SYS_malloc:
        ret = vmalloc_user(arg0);
        break;
    case SYS_nop:
        /* nop syscall */
        asm volatile("rdtsc" : "=a" (ret), "=d" (arg0));
        break;
    case 5:
        set_pte(arg0, arg1);
        ret = 0;
        break;
    case 6:
        ret = get_pte(arg0);
        break;
    case 7:
        init.pages_to_flush[0] = arg0;
        kenv->nb_pages_to_flush = 1;                
        ret = 0;
        break;
    case 8:
        kenv->nb_pages_to_flush = KQEMU_FLUSH_ALL;
        ret = 0;
        break;
    case SYS_iopl:
        kenv->eflags = (kenv->eflags & ~IOPL_MASK) | 
            ((arg0 & 3) << IOPL_SHIFT);
        ret = 0;
        break;
    case SYS_set_tls:
        if (!(arg0 >= 0 && arg0 < 2))
            goto fail;
#ifdef __x86_64__
        /* we do not need to change the GDT */
        kenv->segs[R_FS + arg0].base = arg1;
#else
        {
            unsigned long ram_addr;
            ram_addr = gdt_paddr + (USER_FS & ~7) + (arg0 * 8);
            set_seg((void *)(ram_base + ram_addr), arg1, 0xfffff, 0xc0f2);
            set_ram_dirty(ram_addr);
            if ((kenv->segs[R_FS + arg0].selector | 3) == (USER_FS + arg0 * 8)) {
                kenv->segs[R_FS + arg0].base = arg1;
            }
        }
#endif
        ret = 0;
        break;
    case SYS_set_reg:
        switch(arg0) {
        case REG_CR0:
            mask = CR0_AM_MASK;
            kenv->cr0 = (kenv->cr0 & ~mask) | (arg1 & mask);
            break;
        case REG_DR0:
            kenv->dr0 = arg1;
            break;
        case REG_DR7:
            kenv->dr7 = arg1;
            break;
        case REG_CR4:
            mask = CR4_TSD_MASK;
            kenv->cr4 = (kenv->cr4 & ~mask) | (arg1 & mask);
            break;
        case REG_ES:
        case REG_CS:
        case REG_SS:
        case REG_DS:
        case REG_FS:
        case REG_GS:
            kenv->segs[arg0 - REG_ES].selector = arg1;
            break;
        default:
            goto fail;
        }
        ret = 0;
        break;
    case SYS_get_reg:
        switch(arg0) {
        case REG_CR0:
            ret = kenv->cr0;
            break;
        case REG_CR4:
            ret = kenv->cr4;
            break;
        case REG_USERONLY:
            ret = 1;
            break;
        default:
            goto fail;
        }
        break;
    case SYS_signal:
        if ((unsigned long)arg0 >= 0x20) {
        fail:
            printf("Invalid arg for pseudo syscall %d\n", n);
            ret = -1;
        } else {
            exception_handler[arg0] = arg1;
            ret = 0;
        }
        break;
    case SYS_kerneltest:
        /* nothing to do, only meaningful if using real kernel code */
        ret = 0;
        break;
    default:
        printf("Invalid pseudo syscall %d\n", n);
        ret = -1;
        break;
    }
    return ret;
}


int main(int argc, char **argv)
{
    int fd, i, code64, mode, idt_entry_size, user_only, dpl;
    struct kqemu_cpu_state cpu_state, *kenv = &cpu_state;
    uint32_t ldt_limit, tss_limit;
    long ret;
    unsigned long paddr;
    unsigned long stack_end, start_addr, kernel_entry, kernel_stack_end;
    struct kernel_header *kh;
    struct kqemu_phys_mem kphys_mem;
    
    mode = 4;
    if (argc >= 2) {
        if (!strcmp(argv[1], "-h")) {
            fprintf(stderr, "kqemu regression test utility, Copyright (c) 2005-2008 Fabrice Bellard\n"
                    "usage: kqemutest index\n"
                    "\n"
                    "index  test name\n"
                    "    0  LMA=0 CS64=0 PAE=0 U=1 (legacy 32 bit)\n"
                    "    1  LMA=0 CS64=0 PAE=1 U=1 (legacy 32 bit + PAE)\n"
                    "    2  LMA=1 CS64=0 PAE=1 U=1 (long mode, compatibility 32 bit)\n"
                    "    3  LMA=1 CS64=1 PAE=1 U=1 (long mode, 64 bit)\n"
                    "    4  LMA=0 CS64=0 PAE=0 U=0 (legacy 32 bit, kernel mode)\n"
                    "    5  LMA=1 CS64=1 PAE=1 U=0 (long mode, kernel mode)\n"
                    "\n"
                    "U=1 means user only virtualization\n");
            exit(1);
        }
        mode = atoi(argv[1]);
    }

    switch(mode) {
    case 0: /* legacy 32 bit */
        long_mode = 0;
        code64 = 0;
        use_pae = 0;
        user_only = 1;
        break;
    case 1: /* legacy 32 bit + PAE */
        long_mode = 0;
        code64 = 0;
        use_pae = 1;
        user_only = 1;
        break;
    case 2: /* long mode, compatibility 32 bit */
        long_mode = 1;
        code64 = 0;
        use_pae = 1;
        user_only = 1;
        break;
    case 3: /* long mode, 64 bit */
        long_mode = 1;
        code64 = 1;
        use_pae = 1;
        user_only = 1;
        break;
    case 4: /* legacy 32 bit, kernel mode */
        long_mode = 0;
        code64 = 0;
        use_pae = 0;
        user_only = 0;
        break;
    case 5: /* long mode, kernel mode */
        long_mode = 1;
        code64 = 1;
        use_pae = 1;
        user_only = 0;
        break;
    default:
        fprintf(stderr, "unsupported mode\n");
        exit(1);
    }

    printf("LMA=%d CS64=%d PAE=%d U=%d\n", 
           long_mode, code64, use_pae, user_only);

    host_syscall_speed();

    /* allocate the RAM */
    ram_base = alloc_pages(RAM_SIZE);
    memset(&init, 0, sizeof(init));
    init.ram_base = ram_base;
    init.ram_size = RAM_SIZE;
    init.ram_dirty = alloc_pages(RAM_SIZE / 4096);
    init.pages_to_flush = alloc_pages(4096);
    init.ram_pages_to_update = alloc_pages(4096);
    init.modified_ram_pages = alloc_pages(4096);
    memset(init.ram_dirty, 0xff, RAM_SIZE / 4096);

    cr3_val = alloc_phys(4096);
    
    if (long_mode) {
#ifdef __x86_64__
        kernel_entry = load_elf64("kerneltest-x86_64.out", 0);
        valloc_addr =      0xffffffffc0088000;
#else
        printf("long mode not supported on i386 host\n");
        exit(1);
#endif
    } else
    {
        kernel_entry = load_elf32("kerneltest-i386.out", 0);
        valloc_addr = 0xc0088000;
    }

#ifdef __x86_64__
    if (code64) {
        start_addr = load_elf64("usertest-x86_64.out", 1);
        stack_end =        0x0000007fc0000000;
        valloc_user_addr = 0x0000003000000000;
    } else
#endif
    {
        start_addr = load_elf32("usertest-i386.out", 1);
        stack_end = 0xc0000000;
        valloc_user_addr = 0x40000000;
    }

    kh = (void *)(ram_base + virt_to_phys(kernel_entry));

    fd = open("/dev/kqemu", O_RDWR);
    if (fd < 0) {
        perror("/dev/kqemu");
        exit(1);
    }
    //    asm volatile (".byte 0xf1");

    if (ioctl(fd, KQEMU_INIT, &init) < 0) {
        perror("KQEMU_INIT");
        exit(1);
    }

    /* init the phys to ram mapping */
    kphys_mem.phys_addr = 0;
    kphys_mem.size = RAM_SIZE;
    kphys_mem.ram_addr = 0;
    kphys_mem.io_index = KQEMU_IO_MEM_RAM;
    if (ioctl(fd, KQEMU_SET_PHYS_MEM, &kphys_mem) < 0) {
        perror("KQEMU_SET_PHYS_MEM");
        exit(1);
    }

    memset(kenv, 0, sizeof(*kenv));
    kenv->a20_mask = -1;
    kenv->cr0 = (uint32_t)(CR0_PG_MASK | CR0_PE_MASK | CR0_MP_MASK);
    kenv->cr3 = cr3_val;
    kenv->cr4 = 0;
    if (use_pae)
        kenv->cr4 |= CR4_PAE_MASK;
#ifdef __x86_64__
    kenv->efer = 0;
    if (long_mode)
        kenv->efer |= MSR_EFER_SCE | MSR_EFER_LME | MSR_EFER_LMA;
#endif
    /* IDT/GDT/LDT setup */
    idt_base = kh->kernel_idt;
    idt_paddr = virt_to_phys(idt_base);

    gdt_base = kh->kernel_gdt;
    gdt_paddr = virt_to_phys(gdt_base);

    ldt_base = kh->kernel_ldt;
    ldt_paddr = virt_to_phys(ldt_base);
    ldt_limit = 0x37;

    tss_base = vmalloc(4096, &tss_paddr);
    kernel_stack_end = kh->kernel_stack + KERNEL_STACK_SIZE;

    /* IDT init */
    if (long_mode)
        idt_entry_size = 16;
    else
        idt_entry_size = 8;

    for(i = 0; i < 0x14; i++) {
        if (i >= 3 && i <= 5)
            dpl = 3;
        else
            dpl = 0;
        set_gate((void *)(ram_base + idt_paddr + i * idt_entry_size),
                 14, dpl, kh->kernel_exceptions + i * 32, KERNEL_CS);
    }

    set_gate((void *)(ram_base + idt_paddr + 0x80 * idt_entry_size),
             15, 3, kh->kernel_syscall, KERNEL_CS);
    
    /* TSS init */
#ifdef __x86_64__
    if (long_mode) {
        struct tss64 *tss_ptr;
        tss_ptr = (void *)(ram_base + tss_paddr);
        tss_ptr->rsp0 = kernel_stack_end;
        tss_ptr->bitmap = 0x8000; /* no I/O permitted */
        tss_limit = sizeof(struct tss64) - 1;
        set_seg64((void *)(ram_base + gdt_paddr + (KERNEL_TS & ~7)),
                tss_base, tss_limit, 0x89);

        kenv->star = ((unsigned long)KERNEL_CS << 32) | 
            ((unsigned long)USER_CS << 48);
        kenv->lstar = kh->kernel_lstar;
        kenv->cstar = 0;
        kenv->fmask = 0;
        kenv->kernelgsbase = 0;

        set_seg64((void *)(ram_base + gdt_paddr + (KERNEL_LDT & ~7)),
                  ldt_base, ldt_limit, 0x82);
    } else
#endif
    {
        struct tss *tss_ptr;
        tss_ptr = (void *)(ram_base + tss_paddr);
        tss_ptr->esp0 = kernel_stack_end;
        tss_ptr->ss0 = KERNEL_DS;
        tss_ptr->bitmap = 0x8000; /* no I/O permitted */
        tss_limit = sizeof(struct tss) - 1;
        set_seg((void *)(ram_base + gdt_paddr + (KERNEL_TS & ~7)),
                tss_base, tss_limit, 0x89);

        set_seg((void *)(ram_base + gdt_paddr + (KERNEL_LDT & ~7)),
                ldt_base, ldt_limit, 0x82);
    }

    /* GDT init */
    set_seg((void *)(ram_base + gdt_paddr + (USER_CS & ~7)),
            0, 0xfffff, 0xc0fa);
    set_seg((void *)(ram_base + gdt_paddr + (USER_DS & ~7)),
            0, 0xfffff, 0xc0f2);
    set_seg((void *)(ram_base + gdt_paddr + (USER_CS64 & ~7)),
            0, 0xfffff, 0xa0fa); /* CS for long mode */
    if (long_mode) {
        set_seg((void *)(ram_base + gdt_paddr + (KERNEL_CS & ~7)),
                0, 0xfffff, 0xa09a);
    } else {
        set_seg((void *)(ram_base + gdt_paddr + (KERNEL_CS & ~7)),
                0, 0xfffff, 0xc09a);
    }
    set_seg((void *)(ram_base + gdt_paddr + (KERNEL_DS & ~7)),
            0, 0xfffff, 0xc092);

    set_seg((void *)(ram_base + gdt_paddr + (USER_SS16 & ~7)),
            stack_end - 0x10000, 0xffff, 0x00f2);
    set_seg((void *)(ram_base + gdt_paddr + (USER_FS & ~7)),
            0, 0xfffff, 0xc0f2);
    set_seg((void *)(ram_base + gdt_paddr + (USER_GS & ~7)),
            0, 0xfffff, 0xc0f2);

    /* LDT init */
    set_seg((void *)(ram_base + ldt_paddr + 0x30),
            0x4000, 0xfffff, 0xc0f2);

    if (code64) {
        kenv->segs[R_CS].selector = USER_CS64;
    } else {
        kenv->segs[R_CS].selector = USER_CS;
    }
    kenv->segs[R_SS].selector = USER_DS;
    kenv->segs[R_DS].selector = USER_DS;
    kenv->segs[R_ES].selector = USER_DS;
    kenv->segs[R_FS].selector = USER_FS;
    kenv->segs[R_GS].selector = USER_GS;

    kenv->user_only = user_only;
    kenv->eflags = IF_MASK | 2;
    kenv->eip = start_addr;
    kenv->cpl = 3;
    kenv->idt.base = idt_base;
    kenv->idt.limit = 256 * idt_entry_size - 1;
    kenv->gdt.base = gdt_base;
    kenv->gdt.limit = 0x0fff;
    kenv->ldt.selector = KERNEL_LDT;
    kenv->ldt.base = ldt_base;
    kenv->ldt.limit = ldt_limit;
    kenv->tr.selector = KERNEL_TS;
    kenv->tr.base = tss_base;
    kenv->tr.limit = tss_limit;
    kenv->tr.flags = 0x8900;

    paddr = alloc_phys(STACK_SIZE);
    for(i = 0; i < STACK_SIZE; i += 4096) {
        set_pte(stack_end - STACK_SIZE + i, 
                (paddr + i)  | PG_PRESENT_MASK | PG_USER_MASK | PG_RW_MASK);
    }
    kenv->regs[R_ESP] = stack_end;
    kenv->tsc_offset = 0;
    kenv->nb_pages_to_flush = 0;
    kenv->nb_ram_pages_to_update = 0;
    kenv->nb_modified_ram_pages = 0;
    //    asm volatile (".byte 0xf1");

    /* fpu registers */
    //    asm volatile ("fldpi\n");
    //    asm volatile ("fld1\n");

    for(;;) {
        ret = ioctl(fd, KQEMU_EXEC, kenv);
        if (ret < 0) {
            perror("KQEMU_EXEC");
            exit(1);
        }
        ret = kenv->retval;
        if (ret == (KQEMU_RET_INT | 0x80)) {
            kenv->regs[R_EAX] = 
                do_syscall(kenv, 
                           kenv->regs[R_EAX],
                           kenv->regs[R_EBX],
                           kenv->regs[R_ECX]);
            kenv->eip = kenv->next_eip;
        } else if (ret == KQEMU_RET_SYSCALL) {
            kenv->regs[R_EAX] = 
                do_syscall(kenv, 
                           kenv->regs[R_EAX],
                           kenv->regs[R_EDI],
                           kenv->regs[R_ESI]);
            kenv->eip = kenv->next_eip;
        } else if (ret == KQEMU_RET_SOFTMMU) {
            unsigned long pc;
            int opcode;
            pc = kenv->eip + kenv->segs[R_CS].base;
            opcode = ldub(pc);
            switch(opcode) {
            case 0xee:
                switch(kenv->regs[R_EDX] & 0xffff) {
                case 0x80:
                    putchar((int)(kenv->regs[R_EAX] & 0xff));
                    //                    fflush(stdout);
                    break;
                case 0x81:
                    ret = kenv->regs[R_EAX] & 0xff;
                    exit(ret);
                default:
                    goto unsupported_return_code;
                }
                kenv->eip++;
                break;
            default:
                goto unsupported_return_code;
            }
        } else if ((ret & ~0xff) == KQEMU_RET_EXCEPTION) {
            int intno = ret & 0xff;
            if (!exception_handler[intno]) 
                goto unsupported_return_code;
            /* we reset the selectors because in some tests we set
               incorrect values in them */
            if (code64) {
                kenv->segs[R_CS].selector = USER_CS64;
            } else {
                kenv->segs[R_CS].selector = USER_CS;
            }
            kenv->segs[R_SS].selector = USER_DS;
            kenv->segs[R_DS].selector = USER_DS;
            kenv->segs[R_ES].selector = USER_DS;
            kenv->segs[R_FS].selector = USER_FS;
            kenv->segs[R_GS].selector = USER_GS;
            kenv->eip = exception_handler[intno];
        } else {
        unsupported_return_code:
            printf("ret=%04lx error_code=%04x\n", ret, kenv->error_code);
            dump_cpu_state(kenv);
            break;
        }
    }
    close(fd);
    return ret;
}
