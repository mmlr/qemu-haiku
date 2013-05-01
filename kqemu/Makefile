ifeq ($(PATCHLEVEL),)
# compile in kqemu directory 

-include config-host.mak

ifdef CONFIG_WIN32
all:
	$(MAKE) -f Makefile.winnt

install:
	@echo Read the kqemu-doc.html documentation to install

else
ifdef CONFIG_KBUILD26
# 2.6 build

all: kqemu.ko

kqemu.ko:
	make -C common all
	make -C $(KERNEL_PATH) M=`pwd` modules

else
# 2.4 build

all: kqemu.o

kqemu.o:
	make -C common all
	make -C $(KERNEL_PATH) SUBDIRS=`pwd` modules

endif # !CONFIG_KBUILD26

install:
	./install.sh

endif # !CONFIG_WIN32

clean:
	$(MAKE) -C common clean
	rm -f kqemu.ko *.o *~

FILES=configure Makefile README Changelog LICENSE COPYING \
      install.sh kqemu-linux.c kqemu.h \
      kqemu-kernel.h \
      kqemu-freebsd.c Makefile.freebsd \
      kqemu-haiku.c Makefile.haiku \
      kqemu-win32.c kqemu.sys kqemu.inf Makefile.winnt \
      kqemu-doc.texi kqemu-doc.html kqemu-tech.texi kqemu-tech.html
FILES+=common/Makefile common/insn_table.h  common/kqemu_int.h \
common/monitor-utils.c common/common.c  common/genmon.c common/interp.c \
common/genoffsets.c  common/monitor.c common/kernel.c \
common/i386/kernel_asm.S  common/i386/monitor_asm.S \
common/i386/monitor.ld common/i386/nexus_asm.S \
common/x86_64/kernel_asm.S  common/x86_64/monitor_asm.S \
common/x86_64/monitor.ld common/x86_64/nexus_asm.S
FILES+=tests/Makefile tests/kqemutest.c tests/kqemutest.h \
tests/kerneltest.c tests/lib.c tests/usertest.c \
tests/entry-i386.S tests/entry-x86_64.S tests/head.S \
tests/README

VERSION=1.4.0pre1
FILE=kqemu-$(VERSION)

tar:
	rm -rf /tmp/$(FILE)
	cp -r . /tmp/$(FILE)
	( cd /tmp ; tar zcvf /tmp/$(FILE).tar.gz $(addprefix $(FILE)/, $(FILES)) )
	rm -rf /tmp/$(FILE)

# documentation
doc: kqemu-doc.html kqemu-tech.html

%.html: %.texi
	texi2html -monolithic -number $<

else

ifeq ($(PATCHLEVEL),4)
# called from 2.4 kernel kbuild

obj-m:= kqemu.o
kqemu-objs:= kqemu-linux.o kqemu-mod-$(ARCH).o

include $(TOPDIR)/Rules.make

kqemu.o: $(kqemu-objs)
	$(LD) -r -o $@ $(kqemu-objs)

else
# called from 2.6 kernel kbuild

obj-m:= kqemu.o
kqemu-objs:= kqemu-linux.o kqemu-mod.o

$(obj)/kqemu-mod.o: $(src)/kqemu-mod-$(ARCH).o
	cp $< $@
endif
endif # PATCHLEVEL
