include ../config-host.mak

#CC=gcc34
LD=ld
CC_32=$(CC) -m32
LD_32=$(LD) -m elf_i386
CFLAGS=-O2 -Wall -Werror -fno-optimize-sibling-calls -fno-common \
       -fno-strict-aliasing -fno-builtin -g -I..
KERNEL_CFLAGS_32=$(CFLAGS)
KERNEL_CFLAGS_64=$(CFLAGS) -mno-red-zone -mcmodel=kernel

TARGETS=usertest-i386.out kerneltest-i386.out
ifeq ($(ARCH), x86_64)
TARGETS+=usertest-x86_64.out kerneltest-x86_64.out 
endif

all: $(TARGETS) kqemutest

# 32 bit user code
usertest-i386.out: head-i386.o usertest-i386.o
	$(LD_32) -o $@ -N -Ttext 0x20010000 $^

usertest-i386.o: usertest.c lib.c
	$(CC_32) $(CFLAGS) -o $@ -c $<

head-i386.o: head.S
	$(CC_32) -D__ASSEMBLY__ -c -o $@ $<

# 64 bit user code
usertest-x86_64.out: head-x86_64.o usertest-x86_64.o
	ld -o $@ -N -Ttext 0x20010000 $^

usertest-x86_64.o: usertest.c lib.c
	$(CC) $(CFLAGS) -o $@ -c $<

head-x86_64.o: head.S
	$(CC) -D__ASSEMBLY__ -c -o $@ $<

# 32 bit kernel code
kerneltest-i386.out: entry-i386.o kerneltest-i386.o
	$(LD_32) -o $@ -N -Ttext 0xc0000000 $^

kerneltest-i386.o: kerneltest.c
	$(CC_32) $(KERNEL_CFLAGS_32) -o $@ -c $<

entry-i386.o: entry-i386.S
	$(CC_32) -D__ASSEMBLY__ -c -o $@ $<

# 64 bit kernel code
kerneltest-x86_64.out: entry-x86_64.o kerneltest-x86_64.o
	ld -o $@ -N -Ttext 0xffffffffc0000000 $^

kerneltest-x86_64.o: kerneltest.c
	$(CC) $(KERNEL_CFLAGS_64) -o $@ -c $<

entry-x86_64.o: entry-x86_64.S
	$(CC) -D__ASSEMBLY__ -c -o $@ $<

# test main
kqemutest: kqemutest.c ../kqemu.h
	$(CC) $(CFLAGS) -o $@ kqemutest.c

clean:
	rm -f *.o *~ kqemutest *.out
