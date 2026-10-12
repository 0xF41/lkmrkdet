ifneq ($(KERNELRELEASE),)
obj-m := lkmrkdet.o
ccflags-y += -I$(src) -Wall
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PYTHON ?= python3
HOSTCC ?= cc
ROOT := $(CURDIR)

.PHONY: all module test clean
all: module

module:
	$(PYTHON) scripts/configure.py --kdir "$(KDIR)" --output compat_autoconf.h
	$(MAKE) -C "$(KDIR)" M="$(ROOT)" modules

test:
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -pedantic -I. tests/test_entry_decode.c -o test_entry_decode
	./test_entry_decode
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

clean:
	$(RM) test_entry_decode compat_autoconf.h
	@if test -d "$(KDIR)"; then $(MAKE) -C "$(KDIR)" M="$(ROOT)" clean; fi
endif
