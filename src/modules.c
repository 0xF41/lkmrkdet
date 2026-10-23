// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"
#include <linux/kallsyms.h>
#include <linux/slab.h>
#include "compat_autoconf.h"

static struct list_head *rk_module_list;
static struct mutex *rk_module_mutex;
static struct kset **rk_module_kset;
static const struct kobj_type *rk_module_ktype;

void rk_modules_resolve_symbols(void)
{
	rk_module_list = (void *)rk_symbol("modules");
	rk_module_mutex = (void *)rk_symbol("module_mutex");
	rk_module_kset = (void *)rk_symbol("module_kset");
	rk_module_ktype = (void *)rk_symbol("module_ktype");
}

/* Called with module_mutex held and a live module or referenced kobject. */
static int rk_add_module(struct rk_session *s, struct module *mod, bool listed,
		bool sysfs)
{
	struct rk_module_view view = { .object = (unsigned long)mod };
	enum module_state state;
	unsigned int i;
#if RK_HAVE_MODULE_MEM
	struct module_memory memory;
#else
	struct module_layout memory;
#endif
	if (rk_read(&state, &mod->state, sizeof(state)) ||
	    rk_read(view.name, mod->name, sizeof(view.name)))
		return -EFAULT;
	if (state != MODULE_STATE_LIVE)
		return 0; /* loading/unloading objects are not declared hidden */
	view.name[sizeof(view.name) - 1] = '\0';
#if RK_HAVE_MODULE_MEM
	if (rk_read(&memory, &mod->mem[MOD_TEXT], sizeof(memory)))
		return -EFAULT;
	view.text_size = memory.size;
#else
	if (rk_read(&memory, &mod->core_layout, sizeof(memory)))
		return -EFAULT;
	view.text_size = memory.text_size;
#endif
	view.text = (unsigned long)memory.base;
	for (i = 0; i < s->nr_modules; i++) {
		if (s->modules[i].object == view.object) {
			s->modules[i].listed |= listed;
			s->modules[i].sysfs |= sysfs;
			return 0;
		}
	}
	if (s->nr_modules == RK_MAX_MODULES)
		return -E2BIG;
	view.listed = listed;
	view.sysfs = sysfs;
	s->modules[s->nr_modules++] = view;
	return 0;
}

int rk_registry(struct rk_session *s)
{
	struct kobject **refs, *obj;
	struct list_head *node, *next;
	struct kset *kset = NULL;
	unsigned int count = 0, steps = 0, i;
	int ret = 0;
	unsigned long flags;

	if (!rk_module_mutex || !rk_module_list || !rk_module_kset || !rk_module_ktype)
		return -EOPNOTSUPP;
	refs = kcalloc(RK_MAX_MODULES, sizeof(*refs), GFP_KERNEL);
	if (!refs)
		return -ENOMEM;
	ret = mutex_lock_interruptible(rk_module_mutex);
	if (ret)
		goto free_refs;
	if (rk_read(&node, &rk_module_list->next, sizeof(node))) {
		ret = -EFAULT;
		goto unlock;
	}
	while (node != rk_module_list) {
		struct module *mod;
		if (++steps > RK_MAX_MODULES || rk_read(&next, &node->next, sizeof(next))) {
			ret = -EOVERFLOW;
			goto unlock;
		}
		mod = container_of(node, struct module, list);
		ret = rk_add_module(s, mod, true, false);
		if (ret)
			goto unlock;
		node = next;
	}
	if (rk_read(&kset, rk_module_kset, sizeof(kset)) || !kset) {
		ret = -EFAULT;
		goto unlock;
	}
	/* References prevent ordinary sysfs teardown from freeing these objects.
	 * Do not call kobject_put while holding module_mutex: teardown can wait. */
	spin_lock_irqsave(&kset->list_lock, flags);
	steps = 0;
	list_for_each_entry(obj, &kset->list, entry) {
		if (++steps > RK_MAX_MODULES || count == RK_MAX_MODULES) {
			ret = -E2BIG;
			break;
		}
		if (obj->ktype == rk_module_ktype)
			refs[count++] = kobject_get(obj);
	}
	spin_unlock_irqrestore(&kset->list_lock, flags);
	for (i = 0; i < count && !ret; i++) {
		struct module *mod;
		struct module_kobject *mk = container_of(refs[i], struct module_kobject, kobj);
		if (rk_read(&mod, &mk->mod, sizeof(mod))) {
			ret = -EFAULT;
			break;
		}
		if (mod) /* built-in module kobjects have mod == NULL */
			ret = rk_add_module(s, mod, false, true);
	}
unlock:
	mutex_unlock(rk_module_mutex);
	for (i = 0; i < count; i++)
		kobject_put(refs[i]);
free_refs:
	kfree(refs);
	s->registry_ready = !ret;
	return ret;
}

void rk_scan_modules(struct rk_session *s, int registry_ret)
{
	unsigned int i, findings = 0;
	if (registry_ret) {
		rk_record(s, "modules", "registries", registry_ret == -EOPNOTSUPP ?
			RK_UNSUPPORTED : RK_ERROR, "registry_unavailable",
			"Could not complete a module-list/kobject snapshot; no clean result is implied.");
		return;
	}
	for (i = 0; i < s->nr_modules; i++) {
		struct rk_module_view *m = &s->modules[i];
		if (m->listed == m->sysfs)
			continue;
		findings++;
		rk_describe(s, rk_record(s, "modules", m->name, RK_SUSPICIOUS,
			m->listed ? "live_module_missing_kobject" : "live_kobject_missing_module",
			"A LIVE module is present in only one registry. Recheck lifecycle and corroborate."), m->text);
	}
	if (!findings)
		rk_record(s, "modules", "registries", RK_OK, "registries_consistent",
			"LIVE module registrations agree; built-ins and transitional objects excluded. Both-view removal is not covered.");
}
