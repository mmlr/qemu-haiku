/*
 * Windows NT kernel wrapper for KQEMU
 *
 * Copyright (C) 2005 Filip Navara
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <stddef.h>
#include <ddk/ntddk.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#undef CDECL
#include "kqemu-kernel.h"

/* XXX: make it dynamic according to available RAM */
#define MAX_LOCKED_PAGES (16386 / 4)

struct kqemu_instance {
    struct kqemu_state *state;
    PIRP current_irp;
};

FAST_MUTEX instance_lock;
struct kqemu_instance *active_instance;
struct kqemu_global_state *kqemu_gs;

/* lock the page at virtual address 'user_addr' and return its
   page index. Return -1 if error */
struct kqemu_user_page *CDECL kqemu_lock_user_page(unsigned long *ppage_index,
                                                   unsigned long user_addr)
{
    PMDL mdl;
    PPFN_NUMBER mdl_pages;

    if (user_addr & 0xfff) {
        DbgPrint("kqemu: unaligned user memory\n");
        return NULL;
    }

    mdl = ExAllocatePool(NonPagedPool, sizeof(MDL) + sizeof(PFN_NUMBER));
    if (mdl == NULL) {
        DbgPrint("kqemu: Not enough memory for MDL structure\n");
        return NULL;
    }
    mdl_pages = (PPFN_NUMBER)(mdl + 1);

    MmInitializeMdl(mdl, user_addr, PAGE_SIZE);
    /* XXX: Protect with SEH. */
    MmProbeAndLockPages(mdl, KernelMode, IoModifyAccess);
    *ppage_index = mdl_pages[0];
    return (struct kqemu_user_page *)mdl;
}

void CDECL kqemu_unlock_user_page(struct kqemu_user_page *page)
{
    PMDL mdl = (PMDL)page;

    MmUnlockPages(mdl);
    ExFreePool(mdl);
}

struct kqemu_page *CDECL kqemu_alloc_zeroed_page(unsigned long *ppage_index)
{
    void *ptr;
    LARGE_INTEGER pa;

    ptr = MmAllocateNonCachedMemory(PAGE_SIZE);
    if (!ptr)
        return NULL;
    RtlZeroMemory(ptr, PAGE_SIZE);
    pa = MmGetPhysicalAddress(ptr);
    *ppage_index = (unsigned long)(pa.QuadPart >> PAGE_SHIFT);
    return (struct kqemu_page *)ptr;
}

void CDECL kqemu_free_page(struct kqemu_page *page)
{
    void *ptr = page;

    if (!ptr)
        return;
    MmFreeNonCachedMemory(ptr, PAGE_SIZE);
}

void * CDECL kqemu_page_kaddr(struct kqemu_page *page)
{
    void *ptr = page;
    return ptr;
}

void * CDECL kqemu_vmalloc(unsigned int size)
{
    void * ptr;

    ptr = ExAllocatePoolWithTag(NonPagedPool, size, TAG('K','Q','M','U'));
    if (!ptr)
        return NULL;
    RtlZeroMemory(ptr, size);
    return ptr;
}

void CDECL kqemu_vfree(void *ptr)
{
    if (!ptr)
        return;
    ExFreePool(ptr);
}

unsigned long CDECL kqemu_vmalloc_to_phys(const void *vaddr)
{
    LARGE_INTEGER pa;

    pa = MmGetPhysicalAddress((void *)vaddr);
    return (unsigned long)(pa.QuadPart >> PAGE_SHIFT);
}

/* Map a IO area in the kernel address space and return its
   address. Return NULL if error or not implemented.  */
void * CDECL kqemu_io_map(unsigned long page_index, unsigned int size)
{
#if 1
    PHYSICAL_ADDRESS pa;
    
    pa.QuadPart = page_index << PAGE_SHIFT;
    return MmMapIoSpace(pa, size, MmNonCached);
#else
    /* XXX: mingw32 tools too old */
    return NULL;
#endif
}

/* Unmap the IO area */
void CDECL kqemu_io_unmap(void *ptr, unsigned int size)
{
    return MmUnmapIoSpace(ptr, size);
}

/* return TRUE if a signal is pending (i.e. the guest must stop
   execution) */
int CDECL kqemu_schedule(void)
{
#if 0
    return active_instance->current_irp->Cancel;
#else
    /* XXX: temporary "fix" to correct the CancelIO() problem. A
       proper solution may be to add a new KQEMU_INTERRUPT ioctl. */
    return TRUE;
#endif
}

void CDECL kqemu_log(const char *fmt, ...)
{
    char log_buf[1024];
    va_list ap;

    va_start(ap, fmt);
    _vsnprintf(log_buf, sizeof(log_buf), fmt, ap);
    DbgPrint("kqemu: %s", log_buf);
    va_end(ap);
}

NTSTATUS STDCALL
KQemuCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    struct kqemu_instance *State;

    State = kqemu_vmalloc(sizeof(struct kqemu_instance));
    if (State == NULL)
    {
        Irp->IoStatus.Status = STATUS_INSUFFICIENT_RESOURCES;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    IrpStack->FileObject->FsContext = State;
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS STDCALL
KQemuClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    struct kqemu_instance *State = IrpStack->FileObject->FsContext;

    if (State->state) {
        kqemu_delete(State->state);
        State->state = NULL;
    }
    kqemu_vfree(State);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

NTSTATUS STDCALL
KQemuDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpStack = IoGetCurrentIrpStackLocation(Irp);
    struct kqemu_instance *State = IrpStack->FileObject->FsContext;
    NTSTATUS Status;
    int ret;

    Irp->IoStatus.Information = 0;

    switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
    {
        case KQEMU_INIT:
            if (State->state) {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            if (IrpStack->Parameters.DeviceIoControl.InputBufferLength <
                sizeof(struct kqemu_init)) 
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }
            State->state = kqemu_init((struct kqemu_init *)Irp->AssociatedIrp.SystemBuffer,
                                      kqemu_gs);
            if (!State->state) {
                Status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            } 
            Status = STATUS_SUCCESS;
            break;

        case KQEMU_EXEC:
            {
                struct kqemu_cpu_state *ctx;

                if (!State->state) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (IrpStack->Parameters.DeviceIoControl.InputBufferLength <
                    sizeof(*ctx) ||
                    IrpStack->Parameters.DeviceIoControl.OutputBufferLength <
                    sizeof(*ctx))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                
                ExAcquireFastMutex(&instance_lock);
                active_instance = State;
                State->current_irp = Irp;

                ctx = kqemu_get_cpu_state(State->state);
                
                RtlCopyMemory(ctx, Irp->AssociatedIrp.SystemBuffer, 
                              sizeof(*ctx));
                ret = kqemu_exec(State->state);
                RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, ctx, sizeof(*ctx));

                ExReleaseFastMutex(&instance_lock);
                
                Irp->IoStatus.Information = sizeof(*ctx);
                Status = STATUS_SUCCESS;
            }
            break;
    
        case KQEMU_SET_PHYS_MEM:
            {
                struct kqemu_phys_mem *kphys_mem;

                if (!State->state) {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                if (IrpStack->Parameters.DeviceIoControl.InputBufferLength <
                    sizeof(struct kqemu_phys_mem))
                {
                    Status = STATUS_INVALID_PARAMETER;
                    break;
                }
                
                ExAcquireFastMutex(&instance_lock);

                kphys_mem = (struct kqemu_phys_mem *)Irp->AssociatedIrp.SystemBuffer;
                ret = kqemu_set_phys_mem(State->state, kphys_mem);

                ExReleaseFastMutex(&instance_lock);
                
                if (ret == 0)
                    Status = STATUS_SUCCESS;
                else
                    Status = STATUS_INVALID_PARAMETER;
            }
            break;

        case KQEMU_GET_VERSION:
            if (IrpStack->Parameters.DeviceIoControl.OutputBufferLength <
                sizeof(int)) 
            {
                Status = STATUS_INVALID_PARAMETER;
                break;
            }

            *((int *)Irp->AssociatedIrp.SystemBuffer) = KQEMU_VERSION;
            Irp->IoStatus.Information = sizeof(int);
            Status = STATUS_SUCCESS;
            break;

        default:
            Status = STATUS_INVALID_PARAMETER;
            break;
    }

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}

VOID STDCALL
KQemuUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymlinkName;

    RtlInitUnicodeString(&SymlinkName, L"\\??\\kqemu");
    IoDeleteSymbolicLink(&SymlinkName);
    IoDeleteDevice(DriverObject->DeviceObject);
    if (kqemu_gs) {
        kqemu_global_delete(kqemu_gs);
        kqemu_gs = NULL;
    }
}

NTSTATUS STDCALL 
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymlinkName;
    NTSTATUS Status;

    DbgPrint("QEMU Accelerator Module version %d.%d.%d\n",
             (KQEMU_VERSION >> 16),
             (KQEMU_VERSION >> 8) & 0xff,
             (KQEMU_VERSION) & 0xff);

    MmLockPagableCodeSection(DriverEntry);

    ExInitializeFastMutex(&instance_lock);

    kqemu_gs = kqemu_global_init(MAX_LOCKED_PAGES);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KQemuCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KQemuClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KQemuDeviceControl;
    DriverObject->DriverUnload = KQemuUnload;

    RtlInitUnicodeString(&DeviceName, L"\\Device\\kqemu");
    RtlInitUnicodeString(&SymlinkName, L"\\??\\kqemu");

    Status = IoCreateDevice(DriverObject, 0,
                            &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE,
                            &DeviceObject);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    /* Create the dos device link */
    Status = IoCreateSymbolicLink(&SymlinkName, &DeviceName);
    if (!NT_SUCCESS(Status))
    {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    return STATUS_SUCCESS;
}
