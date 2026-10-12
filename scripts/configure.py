#!/usr/bin/env python3
"""Discover header features, including distro backports; no version-only guess."""
import argparse
from pathlib import Path


def configure(kdir: Path) -> str:
    roots = [kdir.resolve()]
    makefile = roots[0] / 'Makefile'
    if makefile.exists():
        for line in makefile.read_text().splitlines():
            if line.startswith('include ') and line.endswith('/Makefile'):
                candidate = Path(line.split(' ', 1)[1]).parent
                if candidate.is_dir():
                    roots.append(candidate)
    # Ubuntu split headers use a wrapper Makefile referring to common headers.
    def header(relative: str) -> str:
        for root in roots:
            path = root / relative
            if path.is_file():
                return path.read_text()
        raise SystemExit(f'Missing matching kernel header: {relative} (KDIR={kdir})')

    fs = header('include/linux/fs.h')
    module = header('include/linux/module.h')
    if 'struct proc_ops {' not in header('include/linux/proc_fs.h'):
        raise SystemExit('This implementation requires the proc_ops API (Linux 5.6+).')
    metadata_only = False
    config = roots[0] / '.config'
    config_text = config.read_text() if config.is_file() else ''
    if 'CONFIG_X86_64=y' in config_text.splitlines():
        try:
            syscall = header('arch/x86/include/asm/syscall.h')
            metadata_only = 'purely for kernel/trace/trace_syscalls.c' in syscall
        except SystemExit:
            pass
    # Split common-header packages can include OTHER architectures' headers.
    # Never infer the target architecture from the presence of an x86 file.
    features = {
        'RK_HAVE_FOPS_ITERATE': '(*iterate)' in fs,
        'RK_HAVE_MODULE_MEM': 'struct module_memory {' in module,
        'RK_SYSCALL_TABLE_METADATA_ONLY': metadata_only,
    }
    return ('/* Generated from matching headers; do not edit. */\n' +
            ''.join(f'#define {name} {int(value)}\n' for name, value in features.items()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kdir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    text = configure(args.kdir)
    if not args.output.exists() or args.output.read_text() != text:
        args.output.write_text(text)
    print(text, end='')
