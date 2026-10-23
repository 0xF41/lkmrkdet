ifneq ($(KERNELRELEASE),)
obj-m := lkmrkdet.o
lkmrkdet-y := src/main.o src/symbols.o src/report.o src/evidence.o \
	src/interface.o src/modules.o src/filesystem.o src/network.o \
	src/syscalls.o src/processes.o src/ftrace.o
ccflags-y += -I$(src) -I$(src)/include -Wall
else
KDIR ?= /lib/modules/$(shell uname -r)/build
PYTHON ?= python3
HOSTCC ?= cc
ROOT := $(CURDIR)

.PHONY: all module test-lab clean
all: module

# Public workflow: build the module for the running kernel.
module:
	$(PYTHON) scripts/configure.py --kdir "$(KDIR)" --output compat_autoconf.h
	$(MAKE) -C "$(KDIR)" M="$(ROOT)" modules

# Local lab only: tests/ and lab scripts are intentionally not published.
test-lab:
	$(HOSTCC) -std=c11 -Wall -Wextra -Werror -pedantic -I. -Iinclude tests/test_entry_decode.c -o test_entry_decode
	./test_entry_decode
	$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

clean:
	$(RM) test_entry_decode compat_autoconf.h
	@if test -d "$(KDIR)"; then $(MAKE) -C "$(KDIR)" M="$(ROOT)" clean; fi
endif
