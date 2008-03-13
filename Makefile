
ifneq ($(KERNELRELEASE),)
	obj-m := nf_conntrack_skinny.o
else
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)

default:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean

help:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) help

modules_install:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules_install

endif
