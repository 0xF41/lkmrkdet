// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"

/* Actual tracefs collection/correlation remains in client.py/trace_evidence.py. */
void rk_scan_ftrace(struct rk_session *s)
{
	rk_record(s, "ftrace", "tracefs comparison", RK_INFO, "client_collection_required",
		"Client reads existing tracefs enabled_functions around the scan and correlates entry branches. This module does not enumerate internal ftrace lists.");
}
