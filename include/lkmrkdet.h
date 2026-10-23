/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef LKMRKDET_INTERNAL_H
#define LKMRKDET_INTERNAL_H

#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/kobject.h>
#include <linux/mutex.h>
#include <linux/sched.h>

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

/* Internal interfaces only; none are exported to other modules. */
extern const struct proc_ops rk_ops;
void rk_resolve_symbols(bool enabled);
int rk_resolver_error(void);
bool rk_symbols_available(void);
unsigned long rk_symbol(const char *name);
int rk_read(void *dst, const void *src, size_t length);
struct rk_record *rk_record(struct rk_session *s, const char *check,
	const char *target, enum rk_status status, const char *code, const char *detail);
void rk_describe(struct rk_session *s, struct rk_record *r, unsigned long address);
void rk_inspect_pointer(struct rk_session *s, const char *check,
	const char *target, unsigned long address, unsigned long expected, bool require_core);
void rk_modules_resolve_symbols(void);
int rk_registry(struct rk_session *s);
void rk_scan_modules(struct rk_session *s, int registry_ret);
void rk_scan_filesystem(struct rk_session *s);
void rk_scan_network(struct rk_session *s);
void rk_scan_syscalls(struct rk_session *s);
void rk_scan_processes(struct rk_session *s);
void rk_scan_ftrace(struct rk_session *s);
#endif
