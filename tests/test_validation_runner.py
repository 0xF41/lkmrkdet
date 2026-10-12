"""Exercise cleanup and report ownership without executing privileged commands."""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('validate_vm', Path(__file__).parents[1] / 'scripts/validate_vm.py')
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ValidationRunnerTests(unittest.TestCase):
    def run_validation(self, already_loaded=False, failure=None):
        commands = []

        def run(argv, **kwargs):
            commands.append(argv)
            fail = (failure == 'load' and argv[0] == 'insmod') or (
                failure == 'smoke' and argv[-1] == 'tests/runtime_smoke.py')
            return SimpleNamespace(returncode=int(fail), stdout='', stderr='test failure' if fail else '')

        def fake_path(name):
            if str(name) == '/proc/lkmrkdet':
                return SimpleNamespace(exists=lambda: already_loaded)
            if str(name) == '/sys/module/lkmrkdet/srcversion':
                return SimpleNamespace(is_file=lambda: True, read_text=lambda: 'ABCD\n')
            return Path(name)

        def modinfo(argv, **kwargs):
            return 'ABCD\n' if 'srcversion' in argv else '6.8-test SMP\n'

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'lkmrkdet.ko').write_bytes(b'NOT AN EXECUTABLE MODULE')
            with patch.object(runner, 'ROOT', root), patch.object(runner, 'Path', fake_path), \
                    patch.object(runner.os, 'geteuid', return_value=0), \
                    patch.object(runner.os, 'uname', return_value=SimpleNamespace(release='6.8-test', machine='x86_64')), \
                    patch.object(runner.os, 'chown'), \
                    patch.object(runner.subprocess, 'check_output', side_effect=modinfo), \
                    patch.object(runner.subprocess, 'run', side_effect=run), \
                    patch('sys.argv', ['validate_vm.py']), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = runner.main()
            folders = list((root / 'reports').iterdir())
            self.assertEqual(len(folders), 1)
            recorded = json.loads((folders[0] / 'result.json').read_text())
            self.assertEqual(recorded['exit_status'], code)
            self.assertEqual((folders[0] / 'result.json').stat().st_mode & 0o777, 0o600)
            return code, commands, recorded

    def test_failed_smoke_still_unloads_its_own_module(self):
        code, commands, recorded = self.run_validation(failure='smoke')
        self.assertEqual(code, 2)
        self.assertIn(['rmmod', 'lkmrkdet'], commands)
        self.assertTrue(recorded['loaded_here'])

    def test_reused_module_is_not_unloaded(self):
        code, commands, recorded = self.run_validation(already_loaded=True)
        self.assertEqual(code, 0)
        self.assertFalse(any(argv[0] in {'insmod', 'rmmod'} for argv in commands))
        self.assertFalse(recorded['loaded_here'])

    def test_failed_load_is_recorded_and_no_unload_attempted(self):
        code, commands, recorded = self.run_validation(failure='load')
        self.assertEqual(code, 2)
        self.assertFalse(any(argv[0] == 'rmmod' for argv in commands))
        self.assertFalse(recorded['loaded_here'])


if __name__ == '__main__':
    unittest.main()
