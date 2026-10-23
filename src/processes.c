// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"
#include <linux/sched/signal.h>
#include <linux/pid_namespace.h>

void rk_scan_processes(struct rk_session *s)
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
