// SPDX-License-Identifier: GPL-2.0-only
#include "lkmrkdet.h"
#include <linux/fs.h>
#include "compat_autoconf.h"

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

void rk_scan_filesystem(struct rk_session *s)
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
