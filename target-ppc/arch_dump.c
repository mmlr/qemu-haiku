/*
 * writing ELF notes for ppc64 arch
 *
 *
 * Copyright IBM, Corp. 2013
 *
 * Authors:
 * Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#include "cpu.h"
#include "elf.h"
#include "exec/cpu-all.h"
#include "sysemu/dump.h"
#include "sysemu/kvm.h"

struct PPC64UserRegStruct {
    uint64_t gpr[32];
    uint64_t nip;
    uint64_t msr;
    uint64_t orig_gpr3;
    uint64_t ctr;
    uint64_t link;
    uint64_t xer;
    uint64_t ccr;
    uint64_t softe;
    uint64_t trap;
    uint64_t dar;
    uint64_t dsisr;
    uint64_t result;
} QEMU_PACKED;

struct PPC64ElfPrstatus {
    char pad1[112];
    struct PPC64UserRegStruct pr_reg;
    uint64_t pad2[4];
} QEMU_PACKED;


struct PPC64ElfFpregset {
    uint64_t fpr[32];
    uint64_t fpscr;
}  QEMU_PACKED;


struct PPC64ElfVmxregset {
    ppc_avr_t avr[32];
    ppc_avr_t vscr;
    union {
        ppc_avr_t unused;
        uint32_t value;
    } vrsave;
}  QEMU_PACKED;

struct PPC64ElfVsxregset {
    uint64_t vsr[32];
}  QEMU_PACKED;

struct PPC64ElfSperegset {
    uint32_t evr[32];
    uint64_t spe_acc;
    uint32_t spe_fscr;
}  QEMU_PACKED;

typedef struct noteStruct {
    Elf64_Nhdr hdr;
    char name[5];
    char pad3[3];
    union {
        struct PPC64ElfPrstatus  prstatus;
        struct PPC64ElfFpregset  fpregset;
        struct PPC64ElfVmxregset vmxregset;
        struct PPC64ElfVsxregset vsxregset;
        struct PPC64ElfSperegset speregset;
    } contents;
} QEMU_PACKED Note;


static void ppc64_write_elf64_prstatus(Note *note, PowerPCCPU *cpu)
{
    int i;
    uint64_t cr;
    struct PPC64ElfPrstatus *prstatus;
    struct PPC64UserRegStruct *reg;

    note->hdr.n_type = cpu_to_be32(NT_PRSTATUS);

    prstatus = &note->contents.prstatus;
    memset(prstatus, 0, sizeof(*prstatus));
    reg = &prstatus->pr_reg;

    for (i = 0; i < 32; i++) {
        reg->gpr[i] = cpu_to_be64(cpu->env.gpr[i]);
    }
    reg->nip = cpu_to_be64(cpu->env.nip);
    reg->msr = cpu_to_be64(cpu->env.msr);
    reg->ctr = cpu_to_be64(cpu->env.ctr);
    reg->link = cpu_to_be64(cpu->env.lr);
    reg->xer = cpu_to_be64(cpu_read_xer(&cpu->env));

    cr = 0;
    for (i = 0; i < 8; i++) {
        cr |= (cpu->env.crf[i] & 15) << (4 * (7 - i));
    }
    reg->ccr = cpu_to_be64(cr);
}

static void ppc64_write_elf64_fpregset(Note *note, PowerPCCPU *cpu)
{
    int i;
    struct PPC64ElfFpregset  *fpregset;

    note->hdr.n_type = cpu_to_be32(NT_PRFPREG);

    fpregset = &note->contents.fpregset;
    memset(fpregset, 0, sizeof(*fpregset));

    for (i = 0; i < 32; i++) {
        fpregset->fpr[i] = cpu_to_be64(cpu->env.fpr[i]);
    }
    fpregset->fpscr = cpu_to_be64(cpu->env.fpscr);
}

static void ppc64_write_elf64_vmxregset(Note *note, PowerPCCPU *cpu)
{
    int i;
    struct PPC64ElfVmxregset *vmxregset;

    note->hdr.n_type = cpu_to_be32(NT_PPC_VMX);
    vmxregset = &note->contents.vmxregset;
    memset(vmxregset, 0, sizeof(*vmxregset));

    for (i = 0; i < 32; i++) {
        vmxregset->avr[i].u64[0] = cpu_to_be64(cpu->env.avr[i].u64[0]);
        vmxregset->avr[i].u64[1] = cpu_to_be64(cpu->env.avr[i].u64[1]);
    }
    vmxregset->vscr.u32[3] = cpu_to_be32(cpu->env.vscr);
}
static void ppc64_write_elf64_vsxregset(Note *note, PowerPCCPU *cpu)
{
    int i;
    struct PPC64ElfVsxregset *vsxregset;

    note->hdr.n_type = cpu_to_be32(NT_PPC_VSX);
    vsxregset = &note->contents.vsxregset;
    memset(vsxregset, 0, sizeof(*vsxregset));

    for (i = 0; i < 32; i++) {
        vsxregset->vsr[i] = cpu_to_be64(cpu->env.vsr[i]);
    }
}
static void ppc64_write_elf64_speregset(Note *note, PowerPCCPU *cpu)
{
    struct PPC64ElfSperegset *speregset;
    note->hdr.n_type = cpu_to_be32(NT_PPC_SPE);
    speregset = &note->contents.speregset;
    memset(speregset, 0, sizeof(*speregset));

    speregset->spe_acc = cpu_to_be64(cpu->env.spe_acc);
    speregset->spe_fscr = cpu_to_be32(cpu->env.spe_fscr);
}

static const struct NoteFuncDescStruct {
    int contents_size;
    void (*note_contents_func)(Note *note, PowerPCCPU *cpu);
} note_func[] = {
    {sizeof(((Note *)0)->contents.prstatus),  ppc64_write_elf64_prstatus},
    {sizeof(((Note *)0)->contents.fpregset),  ppc64_write_elf64_fpregset},
    {sizeof(((Note *)0)->contents.vmxregset), ppc64_write_elf64_vmxregset},
    {sizeof(((Note *)0)->contents.vsxregset), ppc64_write_elf64_vsxregset},
    {sizeof(((Note *)0)->contents.speregset), ppc64_write_elf64_speregset},
    { 0, NULL}
};

typedef struct NoteFuncDescStruct NoteFuncDesc;

int cpu_get_dump_info(ArchDumpInfo *info,
                      const struct GuestPhysBlockList *guest_phys_blocks)
{
    /*
     * Currently only handling PPC64 big endian.
     */
    info->d_machine = EM_PPC64;
    info->d_endian = ELFDATA2MSB;
    info->d_class = ELFCLASS64;

    return 0;
}

ssize_t cpu_get_note_size(int class, int machine, int nr_cpus)
{
    int name_size = 8; /* "CORE" or "QEMU" rounded */
    size_t elf_note_size = 0;
    int note_head_size;
    const NoteFuncDesc *nf;

    if (class != ELFCLASS64) {
        return -1;
    }
    assert(machine == EM_PPC64);

    note_head_size = sizeof(Elf64_Nhdr);

    for (nf = note_func; nf->note_contents_func; nf++) {
        elf_note_size = elf_note_size + note_head_size + name_size +
                        nf->contents_size;
    }

    return (elf_note_size) * nr_cpus;
}

static int ppc64_write_all_elf64_notes(const char *note_name,
                                       WriteCoreDumpFunction f,
                                       PowerPCCPU *cpu, int id,
                                       void *opaque)
{
    Note note;
    int ret = -1;
    int note_size;
    const NoteFuncDesc *nf;

    for (nf = note_func; nf->note_contents_func; nf++) {
        note.hdr.n_namesz = cpu_to_be32(sizeof(note.name));
        note.hdr.n_descsz = cpu_to_be32(nf->contents_size);
        strncpy(note.name, note_name, sizeof(note.name));

        (*nf->note_contents_func)(&note, cpu);

        note_size = sizeof(note) - sizeof(note.contents) + nf->contents_size;
        ret = f(&note, note_size, opaque);
        if (ret < 0) {
            return -1;
        }
    }
    return 0;
}

int ppc64_cpu_write_elf64_note(WriteCoreDumpFunction f, CPUState *cs,
                               int cpuid, void *opaque)
{
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    return ppc64_write_all_elf64_notes("CORE", f, cpu, cpuid, opaque);
}

int ppc64_cpu_write_elf64_qemunote(WriteCoreDumpFunction f,
                                   CPUState *cpu, void *opaque)
{
    return 0;
}
