// SPDX-License-Identifier: GPL-2.0-only
#include <linux/capability.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/proc_fs.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/timekeeping.h>
#include <linux/uaccess.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include <net/net_namespace.h>
#include "lkmrkdet.h"

struct rk_check {
	const char *name;
	unsigned int bit;
	void (*scan)(struct rk_session *);
};

static const struct rk_check rk_checks[] = {
	{ "modules", RK_MODULES, rk_scan_modules },
	{ "filesystem", RK_FILESYSTEM, rk_scan_filesystem },
	{ "network", RK_NETWORK, rk_scan_network },
	{ "syscalls", RK_SYSCALLS, rk_scan_syscalls },
	{ "processes", RK_PROCESSES, rk_scan_processes },
	{ "ftrace", RK_FTRACE, rk_scan_ftrace },
};

static int rk_parse_command(char *command, unsigned int *checks)
{
	char *token, *list;
	unsigned int mask = 0, flag, i;
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
		for (i = 0; i < ARRAY_SIZE(rk_checks); i++)
			if (!strcmp(token, rk_checks[i].name))
				break;
		if (i == ARRAY_SIZE(rk_checks))
			return -EINVAL;
		flag = rk_checks[i].bit;
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
	int ret;
	unsigned int i;
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
		s->registry_ret = rk_registry(s);
		for (i = 0; i < ARRAY_SIZE(rk_checks); i++)
			if (checks & rk_checks[i].bit)
				rk_checks[i].scan(s);
	} else {
		rk_record(s, "status", "resolver",
			rk_symbols_available() ? RK_INFO : RK_UNSUPPORTED,
			rk_symbols_available() ? "disabled_kprobe_resolver" : "resolver_unavailable",
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
