"""Import-path regression: launch tools as independent processes outside ROOT."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class StandaloneEntrypoints(unittest.TestCase):
    def test_help_from_outside_project_without_pythonpath(self):
        env = dict(os.environ)
        env.pop('PYTHONPATH', None)
        env['PYTHONSAFEPATH'] = '1'
        # --help exits before privilege checks or any module operation.
        with tempfile.TemporaryDirectory() as directory:
            for path in ['client.py', 'tests/runtime_smoke.py', 'scripts/validate_vm.py',
                         'scripts/validate_caraxes.py', 'scripts/validate_samples.py',
                         'scripts/canary_worker.py']:
                with self.subTest(path=path):
                    completed = subprocess.run([sys.executable, str(ROOT / path), '--help'],
                                               cwd=directory, env=env, capture_output=True,
                                               text=True, timeout=20)
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn('usage:', completed.stdout)
