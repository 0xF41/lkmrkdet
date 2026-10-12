import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('configure', Path(__file__).parents[1] / 'scripts/configure.py')
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)


class HeaderFeatureTests(unittest.TestCase):
    def create_headers(self, root, x86=True, old=False):
        root.mkdir(parents=True, exist_ok=True)
        (root / '.config').write_text('CONFIG_X86_64=y\n' if x86 else 'CONFIG_ARM64=y\n')
        files = {
            'include/linux/fs.h': 'int (*iterate_shared)(void);' + ('int (*iterate)(void);' if old else ''),
            'include/linux/module.h': 'struct module_layout {' if old else 'struct module_memory {',
            'include/linux/proc_fs.h': 'struct proc_ops {',
        }
        if x86:
            files['arch/x86/include/asm/syscall.h'] = '/* This is used purely for kernel/trace/trace_syscalls.c */'
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)

    def test_ubuntu_split_headers_and_dispatch_backport(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            common, flavor = root / 'common', root / 'flavor'
            self.create_headers(common)
            flavor.mkdir()
            (flavor / 'Makefile').write_text(f'include {common}/Makefile\n')
            (flavor / '.config').write_text('CONFIG_X86_64=y\n')
            result = configure.configure(flavor)
            self.assertIn('RK_SYSCALL_TABLE_METADATA_ONLY 1', result)
            self.assertIn('RK_HAVE_MODULE_MEM 1', result)
            self.assertIn('RK_HAVE_FOPS_ITERATE 0', result)

    def test_arm_headers_do_not_inherit_x86_dispatch_claim(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            # Common headers may contain x86 files even for an ARM target.
            self.create_headers(root, x86=True)
            (root / '.config').write_text('CONFIG_ARM64=y\n')
            self.assertIn('RK_SYSCALL_TABLE_METADATA_ONLY 0', configure.configure(root))

    def test_old_layout_features_are_detected_without_release_guess(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.create_headers(root, old=True)
            text = configure.configure(root)
            self.assertIn('RK_HAVE_MODULE_MEM 0', text)
            self.assertIn('RK_HAVE_FOPS_ITERATE 1', text)


if __name__ == '__main__':
    unittest.main()
