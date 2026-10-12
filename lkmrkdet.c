// SPDX-License-Identifier: GPL-2.0-only
/* STANDCON inspection PoC. An OK observation is not an integrity attestation. */
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/utsname.h>
#include <linux/timekeeping.h>
#include <linux/capability.h>
#include <linux/user_namespace.h>
#include <linux/seq_file.h>
#include <linux/sched/signal.h>
#include <linux/pid_namespace.h>
#include <linux/nsproxy.h>
#include <net/net_namespace.h>
#include <asm/unistd.h>
#include "compat_autoconf.h"
#include "entry_decode.h"

#if !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error "lkmrkdet currently supports x86-64 and AArch64 only"
#endif

#define RK_VERSION "0.2.1"
#define RK_MAX_COMMAND 128
#define RK_MAX_MODULES 1024
#define RK_MAX_TASKS 8192
#define RK_MAX_RECORDS 256
#define RK_JSON_SIZE (2 * 1024 * 1024)
#define RK_MODULES BIT(0)
#define RK_FILESYSTEM BIT(1)
#define RK_NETWORK BIT(2)
#define RK_SYSCALLS BIT(3)
#define RK_PROCESSES BIT(4)
#define RK_FTRACE BIT(5)
#define RK_ALL (RK_MODULES | RK_FILESYSTEM | RK_NETWORK | RK_SYSCALLS | RK_PROCESSES | RK_FTRACE)

enum rk_status { RK_OK, RK_SUSPICIOUS, RK_UNSUPPORTED, RK_ERROR, RK_INFO };
static const char * const rk_status_names[] = {
	"OK", "SUSPICIOUS", "UNSUPPORTED", "ERROR", "INFO"
};

struct rk_record {
	char check[24], target[96], code[48], owner[80], symbol[128], detail[256];
	enum rk_status status;
	unsigned long address, expected;
};

struct rk_module_view {
	unsigned long object, text;
	unsigned int text_size;
	char name[MODULE_NAME_LEN];
	bool listed, sysfs;
};

struct rk_task_view {
	int pid;
	u64 start_ns;
	char comm[TASK_COMM_LEN];
};

struct rk_session {
	struct mutex lock;
	struct rk_record *records;
	struct rk_module_view *modules;
	struct rk_task_view *tasks;
	char *json;
	size_t json_len;
	unsigned int nr_records, nr_modules, nr_tasks, checks;
	unsigned long sampled_entries[64];
	unsigned int nr_sampled_entries;
	unsigned int net_ns, pid_ns;
	int render_error;
	bool scanned, truncated, registry_ready, tasks_complete;
	u64 started_ns, finished_ns;
};

typedef unsigned long (*rk_lookup_t)(const char *);
static rk_lookup_t rk_lookup;
static struct list_head *rk_module_list;
static struct mutex *rk_module_mutex;
static struct kset **rk_module_kset;
static const struct kobj_type *rk_module_ktype;
static unsigned long rk_text_start, rk_text_end;
static int resolver_error = -EOPNOTSUPP;
static struct proc_dir_entry *rk_proc;
static bool resolve_symbols = true;
module_param(resolve_symbols, bool, 0400);
MODULE_PARM_DESC(resolve_symbols, "Use a temporary disabled kprobe to resolve kernel symbols (default Y)");

static int rk_read(void *dst, const void *src, size_t length)
{
	if (!src)
		return -EFAULT;
	return copy_from_kernel_nofault(dst, src, length);
}

static unsigned long rk_symbol(const char *name)
{
	return rk_lookup ? rk_lookup(name) : 0;
}

static struct rk_record *rk_record(struct rk_session *s, const char *check,
		const char *target, enum rk_status status, const char *code,
		const char *detail)
{
	struct rk_record *r;
	if (s->nr_records == RK_MAX_RECORDS) {
		s->truncated = true;
		return NULL;
	}
	r = &s->records[s->nr_records++];
	memset(r, 0, sizeof(*r));
	strscpy(r->check, check, sizeof(r->check));
	strscpy(r->target, target, sizeof(r->target));
	strscpy(r->code, code, sizeof(r->code));
	strscpy(r->detail, detail, sizeof(r->detail));
	r->status = status;
	return r;
}

static bool rk_core_text(unsigned long address)
{
	return rk_text_start && address >= rk_text_start && address < rk_text_end;
}

static int rk_owner(struct rk_session *s, unsigned long address)
{
	unsigned int i;
	for (i = 0; i < s->nr_modules; i++) {
		struct rk_module_view *m = &s->modules[i];
		if (m->text_size && address - m->text < m->text_size)
			return i;
	}
	return -1;
}

static void rk_describe(struct rk_session *s, struct rk_record *r,
		unsigned long address)
{
	int owner;
	if (!r)
		return;
	r->address = address;
	snprintf(r->symbol, sizeof(r->symbol), "%ps", (void *)address);
	owner = rk_owner(s, address);
	if (rk_core_text(address))
		strscpy(r->owner, "vmlinux", sizeof(r->owner));
	else if (owner >= 0)
		snprintf(r->owner, sizeof(r->owner), "%s%s", s->modules[owner].name,
			 s->modules[owner].listed ? "" : " (unlisted)");
	else
		strscpy(r->owner, "unresolved", sizeof(r->owner));
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

static int rk_registry(struct rk_session *s)
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

static void rk_scan_modules(struct rk_session *s, int registry_ret)
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

static void rk_code_evidence(struct rk_session *s, const char *check,
		const char *target, unsigned long address)
{
	rk_u8 bytes[32];
	struct rk_entry e;
	struct rk_record *r;
	unsigned long destination;
	int origin, dest;
	unsigned int i;
	enum rk_status status = RK_INFO;

	/* A table entry and a resolved symbol often refer to the same code. One
	 * observation per code address; pointer comparisons remain separate. */
	for (i = 0; i < s->nr_sampled_entries; i++)
		if (s->sampled_entries[i] == address)
			return;
	if (s->nr_sampled_entries == ARRAY_SIZE(s->sampled_entries)) {
		rk_record(s, check, target, RK_ERROR, "entry_sample_limit",
			"Code-sampling capacity exhausted; no clean result is implied.");
		return;
	}
	s->sampled_entries[s->nr_sampled_entries++] = address;

	if (rk_read(bytes, (void *)address, sizeof(bytes))) {
		rk_record(s, check, target, RK_ERROR, "entry_unreadable",
			"Could not safely sample function-entry bytes.");
		return;
	}
#ifdef CONFIG_X86_64
	e = rk_decode_entry(RK_X86_64, bytes, sizeof(bytes), address);
#else
	e = rk_decode_entry(RK_ARM64, bytes, sizeof(bytes), address);
#endif
	if (e.kind == RK_NONE)
		return; /* absence of a recognised pattern does not attest code integrity */
	destination = (unsigned long)e.target;
	if (e.kind == RK_INDIRECT) {
		if (rk_read(&destination, (void *)(unsigned long)e.literal, sizeof(destination))) {
			rk_record(s, check, target, RK_ERROR, "branch_literal_unreadable",
				"Recognised an indirect-entry branch but could not read its destination.");
			return;
		}
	}
	if (e.kind != RK_BREAKPOINT && s->registry_ready && rk_text_start) {
		origin = rk_owner(s, address);
		dest = rk_owner(s, destination);
		if (rk_core_text(address)) {
			if (!rk_core_text(destination))
				status = RK_SUSPICIOUS;
		} else if (origin >= 0 && dest != origin) {
			status = RK_SUSPICIOUS;
		}
	}
	r = rk_record(s, check, target, status, e.name,
		"Entry-pattern observation only. Tracing, probes, livepatch and compiler thunks can be legitimate; unrecognised patches are not covered.");
	rk_describe(s, r, destination ?: address);
	if (r)
		r->expected = address;
}

static void rk_inspect_pointer(struct rk_session *s, const char *check,
		const char *target, unsigned long address, unsigned long expected,
		bool require_core)
{
	struct rk_record *r;
	enum rk_status status = RK_OK;
	const char *code = "owner_observed", *detail;
	int owner = rk_owner(s, address);

	if (!address) {
		rk_record(s, check, target, RK_ERROR, "null_callback", "Expected callback is NULL.");
		return;
	}
	detail = "Target belongs to observed executable memory; this is not a complete hook or code-integrity check.";
	if (expected && address != expected) {
		status = RK_SUSPICIOUS;
		code = "unexpected_handler";
		detail = "Observed pointer differs from the named expected handler. Authorised redirection must be considered.";
	} else if (!rk_text_start || !s->registry_ready) {
		status = RK_UNSUPPORTED;
		code = "ownership_incomplete";
		detail = "Pointer was collected, but executable ownership could not be validated completely.";
	} else if ((!rk_core_text(address) && owner < 0) ||
		   (require_core && !rk_core_text(address)) ||
		   (owner >= 0 && !s->modules[owner].listed)) {
		status = RK_SUSPICIOUS;
		code = "unexpected_code_owner";
		detail = "Callback targets unknown, unlisted, or context-inappropriate executable memory.";
	}
	r = rk_record(s, check, target, status, code, detail);
	rk_describe(s, r, address);
	if (r)
		r->expected = expected;
	rk_code_evidence(s, check, target, address);
}

static const char *rk_directory_handler(const char *path, const char *fstype)
{
	if (!strcmp(path, "/proc"))
		return "proc_root_readdir";
	if (!strcmp(path, "/sys"))
		return "kernfs_fop_readdir";
	if (!strcmp(fstype, "ext4"))
		return "ext4_readdir";
	if (!strcmp(fstype, "tmpfs"))
		return "dcache_readdir";
	if (!strcmp(fstype, "overlay"))
		return "ovl_iterate";
	return NULL;
}

static void rk_scan_filesystem(struct rk_session *s)
{
	static const char * const paths[] = { "/", "/proc", "/sys" };
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(paths); i++) {
		struct file *file;
		unsigned long address;
		unsigned long expected;
		const char *handler;
		file = filp_open(paths[i], O_RDONLY | O_DIRECTORY, 0);
		if (IS_ERR(file)) {
			rk_record(s, "filesystem", paths[i], RK_ERROR, "open_failed",
				"Could not open directory in the caller's mount namespace.");
			continue;
		}
		address = (unsigned long)READ_ONCE(file->f_op->iterate_shared);
#if RK_HAVE_FOPS_ITERATE
		if (!address)
			address = (unsigned long)READ_ONCE(file->f_op->iterate);
#endif
		handler = rk_directory_handler(paths[i], file->f_inode->i_sb->s_type->name);
		expected = handler ? rk_symbol(handler) : 0;
		if (handler && !expected)
			rk_record(s, "filesystem", paths[i], RK_UNSUPPORTED, "expected_handler_unavailable",
				"Named-handler comparison unavailable; ownership evidence is still collected.");
		rk_inspect_pointer(s, "filesystem", paths[i], address,
			expected,
			!strcmp(paths[i], "/proc") || !strcmp(paths[i], "/sys"));
		filp_close(file, NULL);
	}
}

static void rk_scan_network(struct rk_session *s)
{
	static const struct { const char *path, *handler; } targets[] = {
		{ "/proc/net/tcp", "tcp4_seq_show" },
		{ "/proc/net/tcp6", "tcp6_seq_show" },
		{ "/proc/net/udp", "udp4_seq_show" },
		{ "/proc/net/udp6", "udp6_seq_show" },
	};
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(targets); i++) {
		struct file *file;
		struct seq_file seq;
		struct seq_operations ops;
		file = filp_open(targets[i].path, O_RDONLY, 0);
		if (IS_ERR(file)) {
			rk_record(s, "network", targets[i].path,
				PTR_ERR(file) == -ENOENT ? RK_UNSUPPORTED : RK_ERROR,
				"proc_net_unavailable", "Reporting endpoint absent or inaccessible; no socket-hiding result is implied.");
			continue;
		}
		/* These documented proc endpoints use seq_file. Never invoke the
		 * inspected show callback ourselves. Private-data reads are nofault. */
		if (rk_read(&seq, file->private_data, sizeof(seq)) ||
		    rk_read(&ops, seq.op, sizeof(ops))) {
			rk_record(s, "network", targets[i].path, RK_ERROR, "seq_ops_unreadable",
				"Could not read the opened endpoint's seq_operations.");
		} else {
			unsigned long expected = rk_symbol(targets[i].handler);
			if (!expected)
				rk_record(s, "network", targets[i].path, RK_UNSUPPORTED,
					"expected_handler_unavailable",
					"Named show-handler comparison unavailable; ownership evidence is still collected.");
			rk_inspect_pointer(s, "network", targets[i].path,
				(unsigned long)ops.show, expected, false);
		}
		filp_close(file, NULL);
	}
	rk_record(s, "network", "coverage", RK_INFO, "proc_reporting_only",
		"Inspects opened proc reporting callbacks, not socket inventory or netlink/sock_diag handlers.");
}

struct rk_syscall_target { unsigned int nr; const char *name; };
static void rk_scan_syscalls(struct rk_session *s)
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
	if (!rk_lookup) {
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

static void rk_scan_processes(struct rk_session *s)
{
	struct task_struct *task;
	unsigned int steps = 0;
	s->tasks_complete = true;
	if (task_active_pid_ns(current) != &init_pid_ns) {
		s->tasks_complete = false;
		rk_record(s, "processes", "task snapshot", RK_UNSUPPORTED, "noninitial_pid_namespace",
			"Initial PID namespace required to compare the process list with proc enumeration.");
		return;
	}
	rcu_read_lock();
	for_each_process(task) {
		struct rk_task_view *view;
		int pid = task_pid_nr(task);
		if (++steps > RK_MAX_TASKS || s->nr_tasks == RK_MAX_TASKS) {
			s->tasks_complete = false;
			break;
		}
		if (!pid)
			continue;
		view = &s->tasks[s->nr_tasks++];
		view->pid = pid;
		view->start_ns = READ_ONCE(task->start_boottime);
		/* Lock-free name is descriptive only; never used for identity. */
		memcpy(view->comm, task->comm, sizeof(view->comm));
		view->comm[sizeof(view->comm) - 1] = '\0';
	}
	rcu_read_unlock();
	rk_record(s, "processes", "task snapshot", s->tasks_complete ? RK_INFO : RK_ERROR,
		s->tasks_complete ? "snapshot_for_user_comparison" : "task_limit_reached",
		"Thread-group leaders from for_each_process; client compares proc enumeration and start time. Task-list DKOM and threads are not covered.");
}

static __printf(2, 3) int rk_append(struct rk_session *s, const char *fmt, ...)
{
	va_list args;
	int needed;
	size_t available = RK_JSON_SIZE - s->json_len;
	if (s->render_error)
		return s->render_error;
	if (!available) {
		s->render_error = -ENOSPC;
		return s->render_error;
	}
	va_start(args, fmt);
	needed = vsnprintf(s->json + s->json_len, available, fmt, args);
	va_end(args);
	if (needed < 0 || needed >= available) {
		s->render_error = -ENOSPC;
		return s->render_error;
	}
	s->json_len += needed;
	return 0;
}

/* All strings, including attacker-controlled names, must be JSON escaped. */
static void rk_json_string(struct rk_session *s, const char *str)
{
	const unsigned char *p = (const unsigned char *)str;
	rk_append(s, "\"");
	while (*p) {
		if (*p == '"' || *p == '\\')
			rk_append(s, "\\%c", *p);
		else if (*p < 0x20 || *p >= 0x7f)
			rk_append(s, "\\u%04x", *p);
		else
			rk_append(s, "%c", *p);
		p++;
	}
	rk_append(s, "\"");
}

static int rk_render(struct rk_session *s)
{
	unsigned int i;
	s->json_len = 0;
	s->render_error = 0;
	rk_append(s, "{\"schema\":1,\"version\":\"%s\",\"kernel\":", RK_VERSION);
	rk_json_string(s, init_uts_ns.name.release);
	rk_append(s, ",\"arch\":");
#ifdef CONFIG_X86_64
	rk_json_string(s, "x86_64");
#else
	rk_json_string(s, "aarch64");
#endif
	rk_append(s, ",\"resolver_error\":%d,\"scanned\":%s,\"checks\":%u,"
		  "\"truncated\":%s,\"tasks_complete\":%s,\"module_count\":%u,"
		  "\"started_ns\":%llu,\"finished_ns\":%llu,\"pid_ns\":%u,\"net_ns\":%u,\"records\":[",
		  resolver_error, s->scanned ? "true" : "false", s->checks,
		  s->truncated ? "true" : "false", s->tasks_complete ? "true" : "false",
		  s->nr_modules, s->started_ns, s->finished_ns, s->pid_ns, s->net_ns);
	for (i = 0; i < s->nr_records; i++) {
		struct rk_record *r = &s->records[i];
		if (i)
			rk_append(s, ",");
		rk_append(s, "{\"check\":"); rk_json_string(s, r->check);
		rk_append(s, ",\"target\":"); rk_json_string(s, r->target);
		rk_append(s, ",\"status\":"); rk_json_string(s, rk_status_names[r->status]);
		rk_append(s, ",\"code\":"); rk_json_string(s, r->code);
		rk_append(s, ",\"owner\":"); rk_json_string(s, r->owner);
		rk_append(s, ",\"symbol\":"); rk_json_string(s, r->symbol);
		rk_append(s, ",\"address\":\"0x%lx\",\"expected\":\"0x%lx\",\"detail\":", r->address, r->expected);
		rk_json_string(s, r->detail);
		rk_append(s, "}");
	}
	rk_append(s, "],\"tasks\":[");
	for (i = 0; i < s->nr_tasks; i++) {
		if (i)
			rk_append(s, ",");
		rk_append(s, "{\"pid\":%d,\"start_ns\":%llu,\"comm\":", s->tasks[i].pid, s->tasks[i].start_ns);
		rk_json_string(s, s->tasks[i].comm);
		rk_append(s, "}");
	}
	if (rk_append(s, "]}\n")) {
		s->json_len = 0;
		return -ENOSPC;
	}
	return 0;
}

static int rk_parse_command(char *command, unsigned int *checks)
{
	char *token, *list;
	unsigned int mask = 0, flag;
	command = strim(command);
	if (!strcmp(command, "status")) {
		*checks = 0;
		return 0;
	}
	if (strncmp(command, "scan ", 5))
		return -EINVAL;
	list = command + 5;
	if (!strcmp(list, "all")) {
		*checks = RK_ALL;
		return 0;
	}
	while ((token = strsep(&list, ","))) {
		if (!strcmp(token, "modules")) flag = RK_MODULES;
		else if (!strcmp(token, "filesystem")) flag = RK_FILESYSTEM;
		else if (!strcmp(token, "network")) flag = RK_NETWORK;
		else if (!strcmp(token, "syscalls")) flag = RK_SYSCALLS;
		else if (!strcmp(token, "processes")) flag = RK_PROCESSES;
		else if (!strcmp(token, "ftrace")) flag = RK_FTRACE;
		else return -EINVAL;
		if (mask & flag)
			return -EINVAL;
		mask |= flag;
	}
	*checks = mask;
	return mask ? 0 : -EINVAL;
}

static bool rk_authorized(void)
{
	return ns_capable(&init_user_ns, CAP_SYS_ADMIN);
}

static ssize_t rk_write(struct file *file, const char __user *buf,
		size_t count, loff_t *offset)
{
	struct rk_session *s = file->private_data;
	char *command;
	unsigned int checks;
	int ret, registry_ret;
	if (!rk_authorized())
		return -EPERM;
	if (!count || count >= RK_MAX_COMMAND)
		return -EINVAL;
	command = memdup_user_nul(buf, count);
	if (IS_ERR(command))
		return PTR_ERR(command);
	if (memchr(command, '\0', count)) {
		kfree(command);
		return -EINVAL;
	}
	ret = rk_parse_command(command, &checks);
	kfree(command);
	if (ret)
		return ret;
	if (mutex_lock_interruptible(&s->lock))
		return -EINTR;
	if (s->scanned) {
		ret = -EALREADY;
		goto out;
	}
	s->checks = checks;
	s->nr_records = 0;
	s->started_ns = ktime_get_boottime_ns();
	if (checks) {
		registry_ret = rk_registry(s);
		if (checks & RK_MODULES) rk_scan_modules(s, registry_ret);
		if (checks & RK_FILESYSTEM) rk_scan_filesystem(s);
		if (checks & RK_NETWORK) rk_scan_network(s);
		if (checks & RK_SYSCALLS) rk_scan_syscalls(s);
		if (checks & RK_PROCESSES) rk_scan_processes(s);
		if (checks & RK_FTRACE)
			rk_record(s, "ftrace", "tracefs comparison", RK_INFO, "client_collection_required",
				"Client reads existing tracefs enabled_functions around the scan and correlates entry branches. This module does not enumerate internal ftrace lists.");
	} else {
		rk_record(s, "status", "resolver", rk_lookup ? RK_INFO : RK_UNSUPPORTED,
			rk_lookup ? "disabled_kprobe_resolver" : "resolver_unavailable",
			"Kernel symbol lookup uses a temporary disabled probe, removed during init. It shares the kernel trust boundary.");
	}
	s->finished_ns = ktime_get_boottime_ns();
	s->scanned = !!checks;
	ret = rk_render(s);
	if (!ret) {
		*offset = 0;
		ret = count;
	}
out:
	mutex_unlock(&s->lock);
	return ret;
}

static ssize_t rk_proc_read(struct file *file, char __user *buf,
		size_t count, loff_t *offset)
{
	struct rk_session *s = file->private_data;
	ssize_t ret;
	if (!rk_authorized())
		return -EPERM;
	if (mutex_lock_interruptible(&s->lock))
		return -EINTR;
	ret = simple_read_from_buffer(buf, count, offset, s->json, s->json_len);
	mutex_unlock(&s->lock);
	return ret;
}

static void rk_free_session(struct rk_session *s)
{
	if (!s)
		return;
	kvfree(s->records);
	kvfree(s->modules);
	kvfree(s->tasks);
	kvfree(s->json);
	kfree(s);
}

static int rk_open(struct inode *inode, struct file *file)
{
	struct rk_session *s;
	if (!rk_authorized())
		return -EPERM;
	if (!try_module_get(THIS_MODULE))
		return -ENODEV;
	s = kzalloc(sizeof(*s), GFP_KERNEL);
	if (!s)
		goto nomem;
	s->records = kvcalloc(RK_MAX_RECORDS, sizeof(*s->records), GFP_KERNEL);
	s->modules = kvcalloc(RK_MAX_MODULES, sizeof(*s->modules), GFP_KERNEL);
	s->tasks = kvcalloc(RK_MAX_TASKS, sizeof(*s->tasks), GFP_KERNEL);
	s->json = kvzalloc(RK_JSON_SIZE, GFP_KERNEL);
	if (!s->records || !s->modules || !s->tasks || !s->json) {
		rk_free_session(s);
		goto nomem;
	}
	mutex_init(&s->lock);
	s->pid_ns = task_active_pid_ns(current)->ns.inum;
	s->net_ns = current->nsproxy->net_ns->ns.inum;
	rk_record(s, "status", "interface", RK_INFO, "request_required",
		"Write status or scan all, then read this same descriptor. Each scan is private to its open file.");
	rk_render(s);
	file->private_data = s;
	return 0;
nomem:
	module_put(THIS_MODULE);
	return -ENOMEM;
}

static int rk_release(struct inode *inode, struct file *file)
{
	rk_free_session(file->private_data);
	module_put(THIS_MODULE);
	return 0;
}

static const struct proc_ops rk_ops = {
	.proc_open = rk_open,
	.proc_read = rk_proc_read,
	.proc_write = rk_write,
	.proc_lseek = default_llseek,
	.proc_release = rk_release,
};

static int __init rk_init(void)
{
#if IS_ENABLED(CONFIG_KPROBES) && IS_ENABLED(CONFIG_KALLSYMS)
	struct kprobe probe = {
		.symbol_name = "kallsyms_lookup_name",
		.flags = KPROBE_FLAG_DISABLED,
	};
	if (resolve_symbols) {
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
	rk_module_list = (void *)rk_symbol("modules");
	rk_module_mutex = (void *)rk_symbol("module_mutex");
	rk_module_kset = (void *)rk_symbol("module_kset");
	rk_module_ktype = (void *)rk_symbol("module_ktype");
	if (rk_text_end <= rk_text_start)
		rk_text_start = rk_text_end = 0;
	/* Publish only after all initialization; no automatic scan or baseline. */
	rk_proc = proc_create("lkmrkdet", 0600, NULL, &rk_ops);
	if (!rk_proc)
		return -ENOMEM;
	pr_info("lkmrkdet %s: inspection interface ready; resolver error=%d\n", RK_VERSION, resolver_error);
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
