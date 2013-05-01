#!/bin/sh
# Installer for the kqemu module
set +e

# Find module name
if [ -f kqemu.ko ] ; then
   module=kqemu.ko
else
   module=kqemu.o
fi

# Find kernel install path
kernel_path="/lib/modules/`uname -r`"

mkdir -p "$kernel_path/misc"
cp "$module" "$kernel_path/misc"

/sbin/depmod -a
