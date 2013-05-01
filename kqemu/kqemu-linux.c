/*
 * Linux kernel wrapper for KQEMU
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
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/version.h>
#include <linux/ioctl.h>
#include <linux/smp_lock.h>
#include <linux/miscdevice.h>
#include <asm/atomic.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include "kqemu-kernel.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,19)
#error "Linux 2.4.19 or above needed"
#endif

/* The pfn_to_page() API appeared in 2.5.14 and changed to function during 2.6.x */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0) && !defined(pfn_to_page)
#define page_to_pfn(page) ((page) - mem_map)
#define pfn_to_page(pfn) (mem_map + (pfn))
#endif

#ifdef PAGE_KERNEL_EXEC
#if defined(__i386__)
/* problem : i386 kernels usually don't export __PAGE_KERNEL_EXEC */
#undef PAGE_KERNEL_EXEC
#define PAGE_KERNEL_EXEC __pgprot(__PAGE_KERNEL & ~_PAGE_NX)
#endif
#else
#define PAGE_KERNEL_EXEC PAGE_KERNEL
#endif

//#define DEBUG

#ifdef DEBUG
int lock_count;
int page_alloc_count;
#endif

/* if 0 is used, then devfs/udev is used to automatically create the
   device */
int major = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
module_param(major, int, 0);
#else
MODULE_PARM(major,"i");
#endif

/* Lock the page at virtual address 'user_addr' and return its
   physical address (page index). Return a host OS private user page
   identifier or NULL if error */
struct kqemu_user_page *CDECL kqemu_lock_user_page(unsigned long *ppage_index,
                                                   unsigned long user_addr)
{
    int ret;
    struct page *page;

    ret = get_user_pages(current, current->mm,
                         user_addr,
                         1, /* 1 page. */
                         1, /* 'write': intent to write. */
                         0, /* 'force': ? */
                         &page,
                         NULL);
    if (ret != 1)
        return NULL;
    /* we ensure here that the page cannot be swapped out by the
       kernel. */
    /* XXX: This test may be incorrect for 2.6 kernels */
    if (!page->mapping) {
        put_page(page);
        return NULL;
    }
#ifdef DEBUG
    lock_count++;
#endif
    *ppage_index = page_to_pfn(page);
    return (struct kqemu_user_page *)page;
}

void CDECL kqemu_unlock_user_page(struct kqemu_user_page *page1)
{
    struct page *page = (struct page *)page1;
    set_page_dirty(page);
    put_page(page);
#ifdef DEBUG
    lock_count--;
#endif
}

/* Allocate a new page and return its physical address (page
   index). Return a host OS private page identifier or NULL if
   error */
struct kqemu_page *CDECL kqemu_alloc_zeroed_page(unsigned long *ppage_index)
{
    unsigned long vaddr;
    struct page *page;

    vaddr = get_zeroed_page(GFP_KERNEL);
    if (!vaddr)
        return NULL;
#ifdef DEBUG
    page_alloc_count++;
#endif
    page = virt_to_page(vaddr);
    *ppage_index = page_to_pfn(page);
    return (struct kqemu_page *)page;
}

void CDECL kqemu_free_page(struct kqemu_page *page1)
{
    struct page *page = (struct page *)page1;
    __free_page(page);
#ifdef DEBUG
    page_alloc_count--;
#endif
}

/* Return a host kernel address of the physical page whose private
   identifier is 'page1' */
void * CDECL kqemu_page_kaddr(struct kqemu_page *page1)
{
    struct page *page = (struct page *)page1;
    return page_address(page);
}

/* Allocate 'size' bytes of memory in host kernel address space (size
   is a multiple of 4 KB) and return the address or NULL if error. The
   allocated memory must be marked as executable by the host kernel
   and must be page aligned. On i386 with PAE (but not on x86_64), it
   must be allocated in the first 4 GB of physical memory. */
void * CDECL kqemu_vmalloc(unsigned int size)
{
    return __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC);
}

void CDECL kqemu_vfree(void *ptr)
{
    return vfree(ptr);
}

/* Convert a page aligned address inside a memory area allocated by
   kqemu_vmalloc() to a physical address (page index) */
unsigned long CDECL kqemu_vmalloc_to_phys(const void *vaddr)
{
    struct page *page;
    page = vmalloc_to_page((void *)vaddr);
    if (!page)
        return -1;
    return page_to_pfn(page);
}

/* Map a IO area in the kernel address space and return its
   address. Return NULL if error or not implemented. This function is
   only used if an APIC is detected on the host CPU. */
void * CDECL kqemu_io_map(unsigned long page_index, unsigned int size)
{
    return ioremap(page_index << PAGE_SHIFT, size);
}

/* Unmap the IO area */
void CDECL kqemu_io_unmap(void *ptr, unsigned int size)
{
    return iounmap(ptr);
}

/* return TRUE if a signal is pending (i.e. the guest must stop
   execution) */
int CDECL kqemu_schedule(void)
{
    if (need_resched()) {
        schedule();
    }
    return signal_pending(current);
}

char log_buf[4096];

void CDECL kqemu_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_buf, sizeof(log_buf), fmt, ap);
    printk("kqemu: %s", log_buf);
    va_end(ap);
}

/*********************************************************/

static struct kqemu_global_state *kqemu_gs;

struct kqemu_instance {
    struct semaphore sem; 
    struct kqemu_state *state;
};

static int kqemu_open(struct inode *inode, struct file *filp)
{
    struct kqemu_instance *ks;
    
    ks = kmalloc(sizeof(struct kqemu_instance), GFP_KERNEL);
    if (!ks)
        return -ENOMEM;
    init_MUTEX(&ks->sem);
    ks->state = NULL;
    filp->private_data = ks;
    return 0;
}

static int kqemu_release(struct inode *inode, struct file *filp)
{
    struct kqemu_instance *ks = filp->private_data;

    down(&ks->sem);
    if (ks->state) {
        kqemu_delete(ks->state);
        ks->state = NULL;
    }
    up(&ks->sem);

    kfree(ks);

#ifdef DEBUG
    printk("lock_count=%d page_alloc_count=%d\n",
           lock_count, page_alloc_count);
#endif
    return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
static long kqemu_ioctl(struct file *filp,
                        unsigned int cmd, unsigned long arg)
#else
static int kqemu_ioctl(struct inode *inode, struct file *filp,
                       unsigned int cmd, unsigned long arg)
#endif
{
    struct kqemu_instance *ks = filp->private_data;
    struct kqemu_state *s = ks->state;
    long ret;

    down(&ks->sem);
    switch(cmd) {
    case KQEMU_INIT:
        {
            struct kqemu_init d1, *d = &d1;
            if (s) {
                ret = -EIO;
                break;
            }
            if (copy_from_user(d, (void *)arg, sizeof(*d))) {
                ret = -EFAULT;
                break;
            }
            s = kqemu_init(d, kqemu_gs);
            if (!s) {
                ret = -ENOMEM;
                break;
            }
            ks->state = s;
            ret = 0;
        }
        break;
    case KQEMU_SET_PHYS_MEM:
        {
            struct kqemu_phys_mem kphys_mem;
            if (!s) {
                ret = -EIO;
                break;
            }
            
            if (copy_from_user(&kphys_mem, (void *)arg, sizeof(kphys_mem))) {
                ret = -EFAULT;
                break;
            }
            ret = kqemu_set_phys_mem(s, &kphys_mem);
            if (ret != 0) {
                ret = -EINVAL;
            }
        }
        break;
    case KQEMU_EXEC:
        {
            struct kqemu_cpu_state *ctx;
            if (!s) {
                ret = -EIO;
                break;
            }
            
            ctx = kqemu_get_cpu_state(s);
            if (copy_from_user(ctx, (void *)arg, sizeof(*ctx))) {
                ret = -EFAULT;
                break;
            }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
            unlock_kernel();
#endif
            ret = kqemu_exec(s);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
            lock_kernel();
#endif
            if (copy_to_user((void *)arg, ctx, sizeof(*ctx))) {
                ret = -EFAULT;
                break;
            }
        }
        break;
    case KQEMU_GET_VERSION:
        {
            if (put_user(KQEMU_VERSION, (int *)arg) < 0) {
                ret = -EFAULT;
            } else {
                ret = 0;
            }
        }
        break;
    default:
        ret = -ENOIOCTLCMD;
        break;
    }
    up(&ks->sem);
    return ret;
}

static struct file_operations kqemu_fops = {
    owner:    THIS_MODULE,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    compat_ioctl: kqemu_ioctl,
    unlocked_ioctl: kqemu_ioctl,
#else
    ioctl: kqemu_ioctl,
#endif
    open:     kqemu_open,
    release:  kqemu_release,
};

static struct miscdevice kqemu_dev =
{
    .minor      = MISC_DYNAMIC_MINOR,
    .name       = "kqemu",
    .fops       = &kqemu_fops,
};

int init_module(void)
{
    int ret, max_locked_pages;
    struct sysinfo si;

    printk("QEMU Accelerator Module version %d.%d.%d, Copyright (c) 2005-2008 Fabrice Bellard\n",
           (KQEMU_VERSION >> 16),
           (KQEMU_VERSION >> 8) & 0xff,
           (KQEMU_VERSION) & 0xff);
    si_meminfo(&si);
    max_locked_pages = si.totalram / 2;
    kqemu_gs = kqemu_global_init(max_locked_pages);
    if (!kqemu_gs)
        return -ENOMEM;

    if (major > 0) {
        ret = register_chrdev(major, "kqemu", &kqemu_fops);
        if (ret < 0) {
            kqemu_global_delete(kqemu_gs);
            printk("kqemu: could not get major %d\n", major);
            return ret;
        }
    } else {
        ret = misc_register (&kqemu_dev);
        if (ret < 0) {
            kqemu_global_delete(kqemu_gs);
            printk("kqemu: could not create device\n");
            return ret;
        }
    }
    printk("KQEMU installed, max_locked_mem=%dkB.\n",
           max_locked_pages * 4);
    return 0;
}

void cleanup_module(void)
{
    if (major > 0) 
        unregister_chrdev(major, "kqemu");
    else
        misc_deregister (&kqemu_dev);
    if (kqemu_gs) {
        kqemu_global_delete(kqemu_gs);
        kqemu_gs = NULL;
    }
}

MODULE_LICENSE("GPL");
