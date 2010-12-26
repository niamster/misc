obj-m         := faulty.o
faulty-objs   := mod_main.o br_through_zero.o null_dereference.o div_by_zero.o printk.o

ARCH          := x86
CROSS_COMPILE :=

M  := $(shell pwd)
K  := $(shell uname -r)
KS := /lib/modules/$(K)/build

all:
	make -C $(KS) M=$(M) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules
