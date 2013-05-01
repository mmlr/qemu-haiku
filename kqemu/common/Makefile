#
# KQEMU
#
# Copyright (C) 2004-2008 Fabrice Bellard
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# version 2 as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
include ../config-host.mak
#CONFIG_WIN32=y
#ARCH=i386
#ARCH=x86_64

# From the Linux kernel
# cc-option
# Usage: cflags-y += $(call cc-option,$(CC),-march=winchip-c6,-march=i586)
cc-option = $(shell if test -z "`$(1) $(2) -S -o /dev/null -xc \
              /dev/null 2>&1`"; then echo "$(2)"; else echo "$(3)"; fi  ;) 

HOST_CC=gcc
MON_CC=gcc
MON_LD=ld
ifdef CONFIG_WIN32
TARGET=../kqemu-mod-$(ARCH)-win32.o
CC=i386-mingw32-gcc
LD=i386-mingw32-ld
else
TARGET=../kqemu-mod-$(ARCH).o
CC=gcc
LD=ld
endif

DEFINES=-D__KERNEL__
INCLUDES=-nostdinc -iwithprefix include -I. -I..
TOOLS_CFLAGS=-Wall -O2 $(WERROR) -g
COMMON_CFLAGS=-Wall -O2 -fomit-frame-pointer -fno-strict-aliasing $(WERROR)
ifeq ($(ARCH), x86_64)
COMMON_CFLAGS+=-mno-red-zone
endif

ifdef CONFIG_HAIKU
COMMON_CFLAGS+=-fno-pic
endif

CFLAGS=$(COMMON_CFLAGS)
MON_CFLAGS=$(COMMON_CFLAGS)
KERNEL_CFLAGS=$(COMMON_CFLAGS)

# Disable SSP if GCC supports it
MON_CFLAGS+=$(call cc-option,$(MON_CC),-fno-stack-protector,)
MON_CFLAGS+=$(call cc-option,$(MON_CC),-fno-stack-protector-all,)

ifeq ($(ARCH), x86_64)
KERNEL_CFLAGS+=-mcmodel=kernel
MON_CFLAGS+= -fpic # needed for correct computed goto relocations
endif
ifdef CONFIG_WIN32
# for win32, we need the same alignment for int64_t when using the
# Linux compiler
TOOLS_CFLAGS+=-malign-double
MON_CFLAGS+=-malign-double
endif
VISIBLE_SYMS=kqemu_init kqemu_exec kqemu_log kqemu_delete kqemu_get_cpu_state \
kqemu_debug \
kqemu_lock_user_page kqemu_vmalloc_to_phys kqemu_vfree kqemu_page_kaddr \
kqemu_vmalloc kqemu_unlock_user_page kqemu_schedule kqemu_alloc_zeroed_page \
kqemu_free_page kqemu_io_map kqemu_io_unmap \
kqemu_global_init kqemu_global_delete

all: $(TARGET)

$(TARGET): kernel.o $(ARCH)/kernel_asm.o
	$(LD) -r -o $@ kernel.o $(ARCH)/kernel_asm.o

monitor-image.h: monitor-image.bin genmon
	./genmon < $< > $@

monitor-image.bin: monitor-image.out
	objcopy -O binary $< $@

monitor-image.out: $(ARCH)/nexus_asm.o $(ARCH)/monitor_asm.o monitor.o monitor-utils.o interp.o
	$(MON_LD) -T $(ARCH)/monitor.ld -o $@ $^

$(ARCH)/nexus_asm.o: $(ARCH)/nexus_asm.S monitor_def.h

kernel.o: kernel.c common.c monitor-image.h kqemu_int.h

kernel.o: CFLAGS:=$(KERNEL_CFLAGS)

monitor.o: monitor.c common.c kqemu_int.h
monitor.o: CFLAGS:=$(MON_CFLAGS)
monitor.o: CC:=$(MON_CC)

monitor-utils.o: CFLAGS:=$(MON_CFLAGS)
monitor-utils.o:  CC:=$(MON_CC)

interp.o: CFLAGS:=$(MON_CFLAGS)
interp.o:  CC:=$(MON_CC)

$(ARCH)/nexus_asm.o: CC:=$(MON_CC)
$(ARCH)/monitor_asm.o: CC:=$(MON_CC)

monitor_def.h: genoffsets
	./genoffsets > $@

# XXX: incorrect if cross compiling
genoffsets: genoffsets.c kqemu_int.h 
	$(HOST_CC) $(TOOLS_CFLAGS) $(DEFINES) -I.. -o $@ $<

genmon: genmon.c
	$(HOST_CC) $(TOOLS_CFLAGS) -o $@ $<

%.o: %.c
	$(CC) $(CFLAGS) $(DEFINES) $(INCLUDES) -c -o $@ $<

%.o: %.S
	$(CC) $(DEFINES) $(INCLUDES) -D__ASSEMBLY__ -c -o $@ $<

clean:
	rm -f *.o *~ monitor-image.h genoffsets genmon monitor_def.h \
           monitor-image.bin monitor-image.out \
           i386/*.o x86_64/*.o
