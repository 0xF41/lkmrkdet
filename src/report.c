// SPDX-License-Identifier: GPL-2.0-only
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/utsname.h>
#include "lkmrkdet.h"

static const char * const rk_status_names[] = {
	"OK", "SUSPICIOUS", "UNSUPPORTED", "ERROR", "INFO"
};

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

int rk_render(struct rk_session *s)
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
		  rk_resolver_error(), s->scanned ? "true" : "false", s->checks,
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
