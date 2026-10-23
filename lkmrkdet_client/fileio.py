# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, non-following reads for untrusted report paths."""
import os
import stat


def read_regular_file(path, limit):
    """Read a regular file without following symlinks and with a byte ceiling."""
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('Report must be a regular file')
        if info.st_size > limit:
            raise ValueError('Report exceeds bounded size')
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, min(65536, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError('Report exceeds bounded size')
            chunks.append(chunk)
        return b''.join(chunks)
    finally:
        os.close(fd)
