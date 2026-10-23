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
#include "lkmrkdet.h"

#if !defined(CONFIG_X86_64) && !defined(CONFIG_ARM64)
#error "lkmrkdet currently supports x86-64 and AArch64 only"
#endif

static const char * const rk_status_names[] = {
	"OK", "SUSPICIOUS", "UNSUPPORTED", "ERROR", "INFO"
};

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

struct rk_record *rk_record(struct rk_session *s, const char *check,
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

void rk_describe(struct rk_session *s, struct rk_record *r,
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

void rk_inspect_pointer(struct rk_session *s, const char *check,
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
		if (checks & RK_FTRACE) rk_scan_ftrace(s);
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

const struct proc_ops rk_ops = {
	.proc_open = rk_open,
	.proc_read = rk_proc_read,
	.proc_write = rk_write,
	.proc_lseek = default_llseek,
	.proc_release = rk_release,
};

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
