// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include "lkmrkdet.h"

typedef unsigned long (*rk_lookup_t)(const char *);
static rk_lookup_t rk_lookup;
static unsigned long rk_text_start, rk_text_end;
static int resolver_error = -EOPNOTSUPP;

int rk_read(void *dst, const void *src, size_t length)
{
	if (!src)
		return -EFAULT;
	return copy_from_kernel_nofault(dst, src, length);
}

unsigned long rk_symbol(const char *name)
{
	return rk_lookup ? rk_lookup(name) : 0;
}

bool rk_core_text(unsigned long address)
{
	return rk_text_start && address >= rk_text_start && address < rk_text_end;
}

bool rk_text_ready(void)
{
	return rk_text_start && rk_text_end > rk_text_start;
}

void rk_resolve_symbols(bool enabled)
{
#if IS_ENABLED(CONFIG_KPROBES) && IS_ENABLED(CONFIG_KALLSYMS)
	struct kprobe probe = {
		.symbol_name = "kallsyms_lookup_name",
		.flags = KPROBE_FLAG_DISABLED,
	};
	if (enabled) {
		resolver_error = register_kprobe(&probe);
		if (!resolver_error) {
			rk_lookup = (rk_lookup_t)probe.addr;
			unregister_kprobe(&probe);
			if (!rk_lookup)
				resolver_error = -ENOENT;
		}
	}
#endif
	rk_text_start = rk_symbol("_stext");
	rk_text_end = rk_symbol("_etext");
	rk_modules_resolve_symbols();
	if (rk_text_end <= rk_text_start)
		rk_text_start = rk_text_end = 0;
}

int rk_resolver_error(void)
{
	return resolver_error;
}

bool rk_symbols_available(void)
{
	return rk_lookup != NULL;
}
