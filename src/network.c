// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"
#include <linux/fs.h>
#include <linux/seq_file.h>

void rk_scan_network(struct rk_session *s)
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
