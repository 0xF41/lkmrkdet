// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"
#include <asm/unistd.h>
#include <linux/kallsyms.h>
#include "compat_autoconf.h"

struct rk_syscall_target { unsigned int nr; const char *name; };
void rk_scan_syscalls(struct rk_session *s)
{
	static const struct rk_syscall_target targets[] = {
		{ __NR_read, "read" }, { __NR_getdents64, "getdents64" },
		{ __NR_kill, "kill" }, { __NR_openat, "openat" },
		{ __NR_init_module, "init_module" }, { __NR_finit_module, "finit_module" },
		{ __NR_delete_module, "delete_module" }, { __NR_bpf, "bpf" },
#ifdef __NR_getdents
		{ __NR_getdents, "getdents" },
#endif
	};
	unsigned long *table = (unsigned long *)rk_symbol("sys_call_table");
	unsigned int i;
	char name[64], target[96];
	if (!rk_symbols_available()) {
		rk_record(s, "syscalls", "selected native handlers", RK_UNSUPPORTED,
			"symbols_unavailable", "Kernel symbol resolution unavailable.");
		return;
	}
	rk_record(s, "syscalls", "coverage", RK_INFO,
#if RK_SYSCALL_TABLE_METADATA_ONLY
		"table_is_tracing_metadata",
		"Matching x86 headers identify sys_call_table as tracing metadata. Table anomalies do not establish live dispatch interception. Selected handler entries are also sampled."
#else
		"dispatch_not_attested",
		"Selected native handler entries and table pointers only. The dispatch implementation is not inferred from kernel version; compat ABIs and deeper callsites are not covered."
#endif
	);
	if (!table)
		rk_record(s, "syscalls", "sys_call_table", RK_UNSUPPORTED, "table_unavailable",
			"No table symbol; handler-entry inspection remains available.");
	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		unsigned long expected, address;
#ifdef CONFIG_X86_64
		snprintf(name, sizeof(name), "__x64_sys_%s", targets[i].name);
#else
		snprintf(name, sizeof(name), "__arm64_sys_%s", targets[i].name);
#endif
		expected = rk_symbol(name);
		snprintf(target, sizeof(target), "handler:%s", targets[i].name);
		if (expected)
			rk_inspect_pointer(s, "syscalls", target, expected, expected, true);
		else
			rk_record(s, "syscalls", target, RK_UNSUPPORTED, "handler_unavailable",
				"Named handler symbol was not resolved.");
		if (!table)
			continue;
		snprintf(target, sizeof(target), "table:%s[%u]", targets[i].name, targets[i].nr);
		if (rk_read(&address, &table[targets[i].nr], sizeof(address)))
			rk_record(s, "syscalls", target, RK_ERROR, "table_entry_unreadable",
				"Failed bounded read at a compile-time syscall number.");
		else
			rk_inspect_pointer(s, "syscalls", target, address, expected, true);
	}
}
