// SPDX-License-Identifier: GPL-2.0-only
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include "entry_decode.h"
#include "lkmrkdet.h"

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

static void rk_note_length(struct rk_session *s, long written, size_t size)
{
	if (written < 0 || (unsigned long)written >= size)
		s->truncated = true;
}

void rk_describe(struct rk_session *s, struct rk_record *r,
		unsigned long address)
{
	int owner;
	if (!r)
		return;
	r->address = address;
	rk_note_length(s, snprintf(r->symbol, sizeof(r->symbol), "%ps", (void *)address),
		       sizeof(r->symbol));
	owner = rk_owner(s, address);
	if (rk_core_text(address))
		rk_note_length(s, strscpy(r->owner, "vmlinux", sizeof(r->owner)),
			       sizeof(r->owner));
	else if (owner >= 0)
		rk_note_length(s, snprintf(r->owner, sizeof(r->owner), "%s%s",
					   s->modules[owner].name,
					   s->modules[owner].listed ? "" : " (unlisted)"),
			       sizeof(r->owner));
	else
		rk_note_length(s, strscpy(r->owner, "unresolved", sizeof(r->owner)),
			       sizeof(r->owner));
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
	if (e.kind != RK_BREAKPOINT && s->registry_ready && rk_text_ready()) {
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
	} else if (!rk_text_ready() || !s->registry_ready) {
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
