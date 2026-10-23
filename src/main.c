// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"

static struct proc_dir_entry *rk_proc;
static bool resolve_symbols = true;
module_param(resolve_symbols, bool, 0400);
MODULE_PARM_DESC(resolve_symbols, "Use a temporary disabled kprobe to resolve kernel symbols (default Y)");

static int __init rk_init(void)
{
	rk_resolve_symbols(resolve_symbols);
	/* Publish only after initialization; no automatic scan or baseline. */
	rk_proc = proc_create("lkmrkdet", 0600, NULL, &rk_ops);
	if (!rk_proc)
		return -ENOMEM;
	pr_info("lkmrkdet %s: inspection interface ready; resolver error=%d\n",
		RK_VERSION, rk_resolver_error());
	return 0;
}

static void __exit rk_exit(void)
{
	proc_remove(rk_proc);
	pr_info("lkmrkdet: unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Felix Kwan");
MODULE_DESCRIPTION("STANDCON kernel callback and cross-view inspection PoC");
MODULE_VERSION(RK_VERSION);
