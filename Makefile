#!/usr/bin/make -f
#
# Makefile -- build nf_skinny.
#
# $Id$
#
# Requires Linux kernel headers and build system to be installed.
#
# Copyright © Glen David Turner of Semaphore, South Australia, 2008.
#
# This file is part of nf_skinny.
#
# nf_skinny is free software: you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# nf_skinny is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with nf_skinny.  If not, see <http://www.gnu.org/licenses/>.

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
