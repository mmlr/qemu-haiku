/* $Id: kqemu-freebsd.c,v 1.6 2006/04/25 22:16:42 bellard Exp $ */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/ctype.h>
#include <sys/fcntl.h>
#include <sys/ioccom.h>
#include <sys/malloc.h>
#include <sys/module.h>
#if __FreeBSD_version >= 500000
#include <sys/mutex.h>
#endif
#include <sys/proc.h>
#include <sys/resourcevar.h>
#if __FreeBSD_version >= 500000
#include <sys/sched.h>
#endif
#include <sys/signalvar.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#if __FreeBSD_version < 500000
#include <sys/buf.h>
#endif

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_page.h>

#include <machine/vmparam.h>
#include <machine/stdarg.h>

#include "kqemu-kernel.h"

#ifndef KQEMU_MAJOR
#define KQEMU_MAJOR 250
#endif

MALLOC_DECLARE(M_KQEMU);
MALLOC_DEFINE(M_KQEMU, "kqemu", "kqemu buffers");

int kqemu_debug;
SYSCTL_INT(_debug, OID_AUTO, kqemu_debug, CTLFLAG_RW, &kqemu_debug, 0,
        "kqemu debug flag");

#define	USER_BASE	0x1000

/* lock the page at virtual address 'user_addr' and return its
   physical page index. Return NULL if error */
struct kqemu_user_page *CDECL kqemu_lock_user_page(unsigned long *ppage_index,
                                                   unsigned long user_addr)
{
    struct vmspace *vm = curproc->p_vmspace;
    vm_offset_t va = user_addr;
    vm_paddr_t pa = 0;
    int ret;
    pmap_t pmap;
#if __FreeBSD_version >= 500000
    ret = vm_map_wire(&vm->vm_map, va, va+PAGE_SIZE, VM_MAP_WIRE_USER);
#else
    ret = vm_map_user_pageable(&vm->vm_map, va, va+PAGE_SIZE, FALSE);
#endif
    if (ret != KERN_SUCCESS) {
	kqemu_log("kqemu_lock_user_page(%08lx) failed, ret=%d\n", user_addr, ret);
	return NULL;
    }
    pmap = vm_map_pmap(&vm->vm_map);
    pa = pmap_extract(pmap, va);
    /* kqemu_log("kqemu_lock_user_page(%08lx) va=%08x pa=%08x\n", user_addr, va, pa); */
    *ppage_index = pa >> PAGE_SHIFT;
    return (struct kqemu_user_page *)va;
}

void CDECL kqemu_unlock_user_page(struct kqemu_user_page *page)
{
    struct vmspace *vm = curproc->p_vmspace;
    vm_offset_t va;
    int ret;
    /* kqemu_log("kqemu_unlock_user_page(%08lx)\n", page_index); */
    va = (vm_offset_t)page;
#if __FreeBSD_version >= 500000
    ret = vm_map_unwire(&vm->vm_map, va, va+PAGE_SIZE, VM_MAP_WIRE_USER);
#else
    ret = vm_map_user_pageable(&vm->vm_map, va, va+PAGE_SIZE, TRUE);
#endif
#if 0
    if (ret != KERN_SUCCESS) {
	kqemu_log("kqemu_unlock_user_page(%08lx) failed, ret=%d\n", page_index, ret);
    }
#endif
}

/*
 * Allocate a new page. The page must be mapped in the kernel space.
 * Return the page_index or -1 if error.
 */
struct kqemu_page *CDECL kqemu_alloc_zeroed_page(unsigned long *ppage_index)
{
    pmap_t pmap;
    vm_offset_t va;
    vm_paddr_t pa;

    va = kmem_alloc(kernel_map, PAGE_SIZE);
    if (va == 0) {
	kqemu_log("kqemu_alloc_zeroed_page: NULL\n");
	return NULL;
    }
    pmap = vm_map_pmap(kernel_map);
    pa = pmap_extract(pmap, va);
    /* kqemu_log("kqemu_alloc_zeroed_page: %08x\n", pa); */
    *ppage_index = pa >> PAGE_SHIFT;
    return (struct kqemu_page *)va;
}

void CDECL kqemu_free_page(struct kqemu_page *page)
{
    if (kqemu_debug > 0)
    	kqemu_log("kqemu_free_page(%p)\n", page);
    kmem_free(kernel_map, (vm_offset_t) page, PAGE_SIZE);
}

/* return kernel address of the physical page page_index */
void * CDECL kqemu_page_kaddr(struct kqemu_page *page)
{
    vm_offset_t va = (vm_offset_t)page;
    return (void *)va;
}

/* contraint: each page of the vmalloced area must be in the first 4
   GB of physical memory */
void * CDECL kqemu_vmalloc(unsigned int size)
{
    void *ptr = malloc(size, M_KQEMU, M_WAITOK);
    if (kqemu_debug > 0)
	kqemu_log("kqemu_vmalloc(%d): %p\n", size, ptr);
    return ptr;
}

void CDECL kqemu_vfree(void *ptr)
{
    if (kqemu_debug > 0)
	kqemu_log("kqemu_vfree(%p)\n", ptr);
    free(ptr, M_KQEMU);
}

/* return the physical page index for a given virtual page */
unsigned long CDECL kqemu_vmalloc_to_phys(const void *vaddr)
{
    vm_paddr_t pa = vtophys(vaddr);
    if (pa == 0) {
	kqemu_log("kqemu_vmalloc_to_phys(%p)->error\n", vaddr);
	return -1;
    }
    if (kqemu_debug > 0)
	kqemu_log("kqemu_vmalloc_to_phys(%p)->%08x\n", vaddr, pa);
    return pa >> PAGE_SHIFT;
}

/* Map a IO area in the kernel address space and return its
   address. Return NULL if error or not implemented.  */
void * CDECL kqemu_io_map(unsigned long page_index, unsigned int size)
{
    return NULL;
}

/* Unmap the IO area */
void CDECL kqemu_io_unmap(void *ptr, unsigned int size)
{
}

#if __FreeBSD_version < 500000
static int
curpriority_cmp(struct proc *p)
{
    int c_class, p_class;

    c_class = RTP_PRIO_BASE(curproc->p_rtprio.type);
    p_class = RTP_PRIO_BASE(p->p_rtprio.type);
    if (p_class != c_class)
	return (p_class - c_class);
    if (p_class == RTP_PRIO_NORMAL)
	return (((int)p->p_priority - (int)curpriority) / PPQ);
    return ((int)p->p_rtprio.prio - (int)curproc->p_rtprio.prio);
}

/* return TRUE if a signal is pending (i.e. the guest must stop
   execution) */
int CDECL kqemu_schedule(void)
{
    struct proc *p = curproc;
    if (curpriority_cmp(p) > 0) {
	int s = splhigh();
	p->p_priority = MAXPRI;
	setrunqueue(p);
	p->p_stats->p_ru.ru_nvcsw++;
	mi_switch();
	splx(s);
    }
    return issignal(curproc) != 0;
}
#else
/* return TRUE if a signal is pending (i.e. the guest must stop
   execution) */
int CDECL kqemu_schedule(void)
{
    /* kqemu_log("kqemu_schedule\n"); */
    mtx_lock_spin(&sched_lock);
    mi_switch(SW_VOL, NULL);
    mtx_unlock_spin(&sched_lock);
    return SIGPENDING(curthread);
}
#endif

static char log_buf[4096];

void CDECL kqemu_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_buf, sizeof(log_buf), fmt, ap);
    printf("kqemu: %s", log_buf);
    va_end(ap);
}

struct kqemu_instance { 
#if __FreeBSD_version >= 500000
    TAILQ_ENTRY(kqemu_instance) kqemu_ent;
    struct cdev *kqemu_dev;
#endif
    /*    struct semaphore sem;  */
    struct kqemu_state *state;
};

static int kqemu_ref_count = 0;
static struct kqemu_global_state *kqemu_gs = NULL;

#if __FreeBSD_version < 500000
static dev_t kqemu_dev;
#else
static struct clonedevs *kqemuclones;
static TAILQ_HEAD(,kqemu_instance) kqemuhead = TAILQ_HEAD_INITIALIZER(kqemuhead);
static eventhandler_tag clonetag;
#endif

static d_close_t kqemu_close;
static d_open_t kqemu_open;
static d_ioctl_t kqemu_ioctl;

static struct cdevsw kqemu_cdevsw = {
#if __FreeBSD_version < 500000
	/* open */	kqemu_open,
	/* close */	kqemu_close,
	/* read */	noread,
	/* write */	nowrite,
	/* ioctl */	kqemu_ioctl,
	/* poll */	nopoll,
	/* mmap */	nommap,
	/* strategy */	nostrategy,
	/* name */	"kqemu",
	/* maj */	KQEMU_MAJOR,
	/* dump */	nodump,
	/* psize */	nopsize,
	/* flags */	0,
	/* bmaj */	-1
#else
	.d_version =	D_VERSION,
	.d_flags =	D_NEEDGIANT,
	.d_open =	kqemu_open,
	.d_ioctl =	kqemu_ioctl,
	.d_close =	kqemu_close,
	.d_name =	"kqemu"
#endif
};

#if __FreeBSD_version >= 500000
static void
#if __FreeBSD_version >= 600034
kqemu_clone(void *arg, struct ucred *cred, char *name, int namelen,
struct cdev **dev)
#else
kqemu_clone(void *arg, char *name, int namelen, struct cdev **dev)
#endif
{
    int unit, r;
    if (*dev != NULL)
	return;

    if (strcmp(name, "kqemu") == 0)
	unit = -1;
    else if (dev_stdclone(name, NULL, "kqemu", &unit) != 1)
	return;         /* Bad name */

    r = clone_create(&kqemuclones, &kqemu_cdevsw, &unit, dev, 0);
    if (r) {
	*dev = make_dev(&kqemu_cdevsw, unit2minor(unit),
	    UID_ROOT, GID_WHEEL, 0660, "kqemu%d", unit);
	if (*dev != NULL) {
	    dev_ref(*dev);
	    (*dev)->si_flags |= SI_CHEAPCLONE;
	}
    }
}
#endif

static void kqemu_destroy(struct kqemu_instance *ks)
{
#if __FreeBSD_version >= 500000
    struct cdev *dev = ks->kqemu_dev;
#endif

    if (ks->state) {
        kqemu_delete(ks->state);
        ks->state = NULL;
    }

#if __FreeBSD_version >= 500000
    dev->si_drv1 = NULL;
    TAILQ_REMOVE(&kqemuhead, ks, kqemu_ent);
    destroy_dev(dev);
#endif
    free(ks, M_KQEMU);
    --kqemu_ref_count;
}

/* ARGSUSED */
static int
#if __FreeBSD_version < 500000
kqemu_open(dev_t dev, int flags, int fmt __unused, struct proc *p)
{
#else
kqemu_open(struct cdev *dev, int flags, int fmt __unused,
    struct thread *td)
{
    struct proc	*p = td->td_proc;
#endif
    struct kqemu_instance *ks;

#if __FreeBSD_version < 500000
    if (dev->si_drv1)
	return(EBUSY);
#endif

    if ((flags & (FREAD|FWRITE)) == FREAD)
	return(EPERM);

    ks = malloc(sizeof(struct kqemu_instance), M_KQEMU, M_WAITOK);
    if (ks == NULL) {
	kqemu_log("malloc failed\n");
	return ENOMEM;
    }
    memset(ks, 0, sizeof *ks);
#if __FreeBSD_version >= 500000
    ks->kqemu_dev = dev;
    TAILQ_INSERT_TAIL(&kqemuhead, ks, kqemu_ent);
#endif
    kqemu_ref_count++;

    dev->si_drv1 = ks;
    if (kqemu_debug > 0)
	kqemu_log("opened by pid=%d\n", p->p_pid);
    return 0;
}

/* ARGSUSED */
static int
#if __FreeBSD_version < 500000
kqemu_ioctl(dev_t dev, u_long cmd, caddr_t addr,
    int flags __unused, struct proc *p)
#else
kqemu_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, 
    int flags __unused, struct thread *td)
#endif
{
    int error = 0;
    int ret;
    struct kqemu_instance *ks = dev->si_drv1;
    struct kqemu_state *s = ks->state;

    switch(cmd) {
    case KQEMU_INIT: {
	struct kqemu_init d1, *d = &d1;
	if (s != NULL) {
	    error = EIO;
	    break;
	}
	d1 = *(struct kqemu_init *)addr;
	if (kqemu_debug > 0)
	    kqemu_log("ram_base=%p ram_size=%ld\n", d1.ram_base, d1.ram_size);
	s = kqemu_init(d, kqemu_gs);
	if (s == NULL) {
	    error = ENOMEM;
	    break;
	}
	ks->state = s;
	break;
    }
    case KQEMU_EXEC: {
	struct kqemu_cpu_state *ctx;
	if (s == NULL) {
	    error = EIO;
	    break;
	}
	ctx = kqemu_get_cpu_state(s);
	*ctx = *(struct kqemu_cpu_state *)addr;
#if __FreeBSD_version >= 500000
	DROP_GIANT();
#endif
	ret = kqemu_exec(s);
#if __FreeBSD_version >= 500000
	PICKUP_GIANT();
	td->td_retval[0] = ret;
#else
	p->p_retval[0] = ret;
#endif
	*(struct kqemu_cpu_state *)addr = *ctx;
	break;
    }
    case KQEMU_GET_VERSION:
	*(int *)addr = KQEMU_VERSION;
	break;
    default:
	error = EINVAL;
    }
    return error;
}

/* ARGSUSED */
static int
#if __FreeBSD_version < 500000
kqemu_close(dev_t dev, int flags, int fmt __unused, struct proc *p)
{
#else
kqemu_close(struct cdev *dev __unused, int flags, int fmt __unused,
    struct thread *td)
{
    struct proc     *p = td->td_proc;
#endif
    struct kqemu_instance *ks = (struct kqemu_instance *) dev->si_drv1;

    kqemu_destroy(ks);

    if (kqemu_debug > 0)
	kqemu_log("closed by pid=%d\n", p->p_pid);
    return 0;
}

/* ARGSUSED */
static int
kqemu_modevent(module_t mod __unused, int type, void *data __unused)
{
    int error = 0;
    int max_locked_pages;
#if __FreeBSD_version < 500000
    int rc;
#else
    struct kqemu_instance *ks;
#endif

    switch (type) {
    case MOD_LOAD:
	printf("kqemu version 0x%08x\n", KQEMU_VERSION);
	max_locked_pages = physmem / 2;
        kqemu_gs = kqemu_global_init(max_locked_pages);
#if __FreeBSD_version < 500000
	if ((rc = cdevsw_add(&kqemu_cdevsw))) {
	    kqemu_log("error registering cdevsw, rc=%d\n", rc);
            error = ENOENT;
            break;
	}
	kqemu_dev = make_dev(&kqemu_cdevsw, 0,
			     UID_ROOT, GID_WHEEL, 0660, "kqemu");
#else
	clone_setup(&kqemuclones);
	clonetag = EVENTHANDLER_REGISTER(dev_clone, kqemu_clone, 0, 1000);
	if (!clonetag) {
            error = ENOMEM;
	    break;
	}
#endif
	kqemu_log("KQEMU installed, max_locked_mem=%dkB.\n",
		  max_locked_pages * 4);

	kqemu_ref_count = 0;
	break;
    case MOD_UNLOAD:
	if (kqemu_ref_count > 0) {
            error = EBUSY;
            break;
        }
#if __FreeBSD_version < 500000
	destroy_dev(kqemu_dev);
	if ((rc = cdevsw_remove(&kqemu_cdevsw)))
	    kqemu_log("error unregistering, rc=%d\n", rc);
#else
	EVENTHANDLER_DEREGISTER(dev_clone, clonetag);
	while ((ks = TAILQ_FIRST(&kqemuhead)) != NULL) {
	    kqemu_destroy(ks);
	}
	clone_cleanup(&kqemuclones);
#endif
        kqemu_global_delete(kqemu_gs);
        kqemu_gs = NULL;
	break;
    case MOD_SHUTDOWN:
	break;
    default:
	error = EOPNOTSUPP;
	break;
    }
    return (error);
}

DEV_MODULE(kqemu, kqemu_modevent, NULL);
MODULE_VERSION(kqemu, 1);
