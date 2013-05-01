/*
 * Haiku kernel wrapper for KQEMU
 *
 * Copyright (C) 2007-2009 Michael Lotz
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

#include <SupportDefs.h>
#include <drivers/Drivers.h>
#include <drivers/KernelExport.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#define IS_USER_ADDRESS(x)	true

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef signed int int32_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

#include "kqemu-kernel.h"

#define DEVICE_NAME "misc/kqemu"
#define MAX_LOCKED_PAGES (524288 / 4)
#define PAGE_SHIFT 12


struct kqemu_user_page {
	team_id	team;
	void *	address;
};


team_id
find_current_team()
{
	thread_info info;
	get_thread_info(find_thread(NULL), &info);
	return info.team;
}


/* Lock the page at virtual address 'userAddress' and return its
   physical address (page index). Return a host OS private user page
   identifier or NULL if error */
struct kqemu_user_page *
kqemu_lock_user_page(unsigned long *pageIndex, unsigned long userAddress)
{
	physical_entry entries[2];
	struct kqemu_user_page *userPage
		= (struct kqemu_user_page *)malloc(sizeof(struct kqemu_user_page));
	if (userPage == NULL) {
		kqemu_log("kqemu: failed to allocate user page when trying to lock\n");
		return NULL;
	}

	if (lock_memory((void *)userAddress, B_PAGE_SIZE, 0) != B_OK) {
		kqemu_log("kqemu: failed to lock memory for address 0x%08lx\n",
			userAddress);
		free(userPage);
		return NULL;
	}

	if (get_memory_map((void *)userAddress, B_PAGE_SIZE, entries, 2) != B_OK) {
		kqemu_log("kqemu: failed to get memory map for 0x%08lx\n", userAddress);
		unlock_memory((void *)userAddress, B_PAGE_SIZE, 0);
		free(userPage);
		return NULL;
	}

	userPage->team = find_current_team();
	userPage->address = (void *)userAddress;
	*pageIndex = (unsigned long)entries[0].address >> PAGE_SHIFT;
	return userPage;
}


void
kqemu_unlock_user_page(struct kqemu_user_page *page)
{
	if (unlock_memory_etc(page->team, page->address, B_PAGE_SIZE, 0) != B_OK) {
		kqemu_log("kqemu: failed to unlock memory for address 0x%08lx\n", page);
		dprintf("unlocking user page from team: %ld\n", find_current_team());
		panic("fail");
	}

	free(page);
}


/* Allocate a new page and return its physical address (page
   index). Return a host OS private page identifier or NULL if
   error */
struct kqemu_page *
kqemu_alloc_zeroed_page(unsigned long *pageIndex)
{
	void *page = NULL;
	physical_entry entries[2];

	if (create_area("kqemu alloc area", &page, B_ANY_KERNEL_ADDRESS,
		B_PAGE_SIZE, B_FULL_LOCK, B_KERNEL_READ_AREA
		| B_KERNEL_WRITE_AREA) < B_OK || page == NULL) {
		kqemu_log("kqemu: failed to create area for zeroed page\n");
		return NULL;
	}

	memset(page, 0, B_PAGE_SIZE);
	get_memory_map(page, B_PAGE_SIZE, entries, 2);
	*pageIndex = (unsigned long)entries[0].address >> PAGE_SHIFT;
	return (struct kqemu_page *)page;
}


void
kqemu_free_page(struct kqemu_page *page)
{
	delete_area(area_for(page));
}


/* Return a host kernel address of the physical page whose private
   identifier is 'page' */
void *
kqemu_page_kaddr(struct kqemu_page *page)
{
	return (void *)page;
}


/* Allocate 'size' bytes of memory in host kernel address space (size
   is a multiple of 4 KB) and return the address or NULL if error. The
   allocated memory must be marked as executable by the host kernel
   and must be page aligned. On i386 with PAE (but not on x86_64), it
   must be allocated in the first 4 GB of physical memory. */
void *
kqemu_vmalloc(unsigned int size)
{
	void *memory = NULL;
	if (create_area("kqemu alloc area", &memory, B_ANY_KERNEL_ADDRESS,
		size, B_FULL_LOCK, B_KERNEL_READ_AREA | B_KERNEL_WRITE_AREA) < B_OK
		|| memory == NULL) {
		kqemu_log("kqemu: failed to create area for kernel memory\n");
		return NULL;
	}

	return memory;
}


void
kqemu_vfree(void *pointer)
{
	delete_area(area_for(pointer));
}


/* Convert a page aligned address inside a memory area allocated by
   kqemu_vmalloc() to a physical address (page index) */
unsigned long
kqemu_vmalloc_to_phys(const void *address)
{
	physical_entry entries[2];
	get_memory_map(address, B_PAGE_SIZE, entries, 2);
	return (unsigned long)entries[0].address >> PAGE_SHIFT;
}


/* Map a IO area in the kernel address space and return its
   address. Return NULL if error or not implemented. This function is
   only used if an APIC is detected on the host CPU. */
void *
kqemu_io_map(unsigned long pageIndex, unsigned int size)
{
	return NULL;
}


/* Unmap the IO area */
void
kqemu_io_unmap(void *pointer, unsigned int size)
{
}


/* return TRUE if a signal is pending (i.e. the guest must stop
   execution) */
int
kqemu_schedule(void)
{
	return (has_signals_pending(NULL) != 0);
}


char log_buf[B_PAGE_SIZE];

void
kqemu_log(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vsprintf(log_buf, fmt, ap);
    dprintf(log_buf);
    va_end(ap);
}


/* Driver Interface */

static struct kqemu_global_state *sKQEMUGlobalState;

struct kqemu_instance {
	sem_id				lock;
	struct kqemu_state *state;
};


static status_t
kqemu_open(const char *name, uint32 mode, void **cookie)
{
	unsigned long dummy;
	struct kqemu_instance *instance;
	instance = (struct kqemu_instance *)kqemu_vmalloc(B_PAGE_SIZE);
	if (!instance)
		return B_NO_MEMORY;

	instance->lock = create_sem(1, "kqemu lock");
	instance->state = NULL;
	*cookie = (void *)instance;
	return 0;
}


static status_t
kqemu_close(void *cookie)
{
	(void)cookie;
	return B_OK;
}


static status_t
kqemu_free(void *cookie)
{
	struct kqemu_instance *instance = (struct kqemu_instance *)cookie;

	acquire_sem(instance->lock);
	if (instance->state) {
		kqemu_delete(instance->state);
		instance->state = NULL;
	}

	delete_sem(instance->lock);
	kqemu_vfree(instance);
	return B_OK;
}


static status_t
kqemu_control(void *cookie, uint32 op, void *data, size_t length)
{
	struct kqemu_instance *instance = (struct kqemu_instance *)cookie;
	struct kqemu_state *state = instance->state;
	status_t result = B_ERROR;

	if (acquire_sem(instance->lock) != B_OK)
		return B_ERROR;

	switch (op) {
		case KQEMU_INIT:
		{
			struct kqemu_init initData;
			if (state != NULL) {
				result = B_BUSY;
				break;
			}

			if (!IS_USER_ADDRESS(data) || user_memcpy(&initData, data,
				sizeof(struct kqemu_init)) != B_OK) {
				result = B_BAD_ADDRESS;
				break;
			}

			state = kqemu_init(&initData, sKQEMUGlobalState);
			if (state == NULL) {
				result = B_NO_MEMORY;
				break;
			}

			instance->state = state;
			result = B_OK;
			break;
		}

		case KQEMU_SET_PHYS_MEM:
		{
			struct kqemu_phys_mem physicalMemory;
			if (state == NULL) {
				result = B_NO_INIT;
				break;
			}

			if (!IS_USER_ADDRESS(data) || user_memcpy(&physicalMemory, data,
				sizeof(struct kqemu_phys_mem)) != B_OK) {
				result = B_BAD_ADDRESS;
				break;
			}

			result = kqemu_set_phys_mem(state, &physicalMemory);
			break;
		}

		case KQEMU_EXEC:
		{
			struct kqemu_cpu_state *cpuState;
			if (state == NULL) {
				result = B_NO_INIT;
				break;
			}

			if (!IS_USER_ADDRESS(data)) {
				result = B_BAD_ADDRESS;
				break;
			}

			cpuState = kqemu_get_cpu_state(state);
			if (user_memcpy(cpuState, data,
				sizeof(struct kqemu_cpu_state)) != B_OK) {
				result = B_BAD_ADDRESS;
				break;
			}

			result = kqemu_exec(state);

			if (user_memcpy(data, cpuState,
				sizeof(struct kqemu_cpu_state)) != B_OK) {
				result = B_BAD_ADDRESS;
				break;
			}

			break;
		}

		case KQEMU_GET_VERSION:
		{
			int version = KQEMU_VERSION;
			if (!IS_USER_ADDRESS(data) || user_memcpy(data, &version,
				sizeof(int)) != B_OK)
				result = B_BAD_ADDRESS;
			else
				result = B_OK;

			break;
		}
	}

	release_sem_etc(instance->lock, 1, B_DO_NOT_RESCHEDULE);
	return result;
}


static status_t
kqemu_read(void *cookie, off_t pos, void *buffer, size_t *len)
{
	(void)cookie;
	(void)pos;
	(void)buffer;
	(void)len;
	return B_OK;
}


static status_t
kqemu_write(void *cookie, off_t pos, const void *buffer, size_t *len)
{
	(void)cookie;
	(void)pos;
	(void)buffer;
	(void)len;
	return B_OK;
}


/* Haiku driver API */
int32 api_version = B_CUR_DRIVER_API_VERSION;


status_t
init_hardware(void)
{
	return B_OK;
}


const char **
publish_devices(void)
{
	static const char *devices[] = {
		DEVICE_NAME,
		NULL
	};

	return devices;
}


device_hooks *
find_device(const char *name)
{
	static device_hooks hooks = {
		&kqemu_open,
		&kqemu_close,
		&kqemu_free,
		&kqemu_control,
		&kqemu_read,
		&kqemu_write,
		NULL,
		NULL,
		NULL,
		NULL
	};

	if (strcmp(name, DEVICE_NAME) == 0)
		return &hooks;

	return NULL;
}


status_t
init_driver(void)
{
	dprintf("QEMU Accelerator Module version %d.%d.%d\n",
		(KQEMU_VERSION >> 16), (KQEMU_VERSION >> 8) & 0xff,
		(KQEMU_VERSION) & 0xff);

	sKQEMUGlobalState = kqemu_global_init(MAX_LOCKED_PAGES);
	if (!sKQEMUGlobalState)
		return B_NO_MEMORY;

	return B_OK;
}


void
uninit_driver(void)
{
	if (sKQEMUGlobalState) {
		kqemu_global_delete(sKQEMUGlobalState);
		sKQEMUGlobalState = NULL;
	}
}
