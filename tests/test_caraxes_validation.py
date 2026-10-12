"""Controlled-case evidence and cleanup tests; never load modules in unit tests."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_caraxes as case
from scripts.report_context import boot_context, capture_tracefs, TRACEFS_LIMIT


def observation(visible=True, identity=True, alive=True):
    return {'file': {'visible': visible, 'identity_match': identity, 'content_match': True},
            'process': {'visible': visible, 'identity_match': identity, 'alive': alive}}


def report(hidden_pid=None):
    records = [case.client.result(name, 'collection', 'OK', 'complete', 'test') for name in case.client.CHECKS]
    if hidden_pid:
        records.append(case.client.result('processes', hidden_pid, 'SUSPICIOUS',
                                          'missing_from_proc_enumeration', 'test'))
    return {'scanned': True, 'checks': sum(case.client.CHECKS.values()), 'truncated': False, 'tasks_complete': True,
            'pid_comparison_complete': True, 'ftrace_complete': True, 'records': records}


class ComparisonTests(unittest.TestCase):
    def compare(self, active=None, first=None, second=None, restored=None, recovery=None):
        return case.comparison(observation(), first or observation(False), active or report(123),
                               second or observation(False), restored or observation(), recovery or report(), 123)

    def test_ground_truth_plus_targeted_finding_is_a_detection(self):
        result = self.compare()
        self.assertEqual(result['process_detection'], 'DETECTED')
        self.assertEqual(result['file_hiding'], 'CONFIRMED')
        self.assertEqual(result['active_detector_exit_status'], 1)
        self.assertEqual(result['exit_status'], 0)
        self.assertEqual(result['ftrace_registration_inspection'], 'TRACEFS_OBSERVED')

    def test_unrelated_alert_does_not_count_as_target_detection(self):
        result = self.compare(active=report(999))
        self.assertEqual(result['process_detection'], 'MISSED')
        self.assertEqual(result['exit_status'], 1)

    def test_not_actually_hidden_is_not_a_detector_miss(self):
        result = self.compare(active=report(), first=observation(), second=observation())
        self.assertEqual(result['process_detection'], 'NOT_EXERCISED')
        self.assertEqual(result['exit_status'], 2)

    def test_process_exit_or_pid_reuse_makes_evidence_inconclusive(self):
        for changed in [observation(False, identity=False), observation(False, alive=False)]:
            result = self.compare(second=changed)
            self.assertEqual(result['process_detection'], 'INCONCLUSIVE')
            self.assertEqual(result['exit_status'], 2)

    def test_incomplete_detector_is_not_a_confirmed_miss(self):
        active = report()
        active['truncated'] = True
        self.assertEqual(self.compare(active=active)['process_detection'], 'INCONCLUSIVE')

    def test_visibility_must_return_after_unload(self):
        result = self.compare(restored=observation(False))
        self.assertFalse(result['canaries_visible_after_unload'])
        self.assertEqual(result['exit_status'], 2)

    def test_failed_probe_is_not_hiding(self):
        failed = {'file': {'error': 'permission denied'}, 'process': {'error': 'gone'}}
        self.assertEqual(case.hiding_state(failed, failed, 'file'), 'INCONCLUSIVE')
        self.assertFalse(case.present(failed, 'process'))

    def test_file_filters_are_scored_independently(self):
        before = observation()
        before['owner_file'] = dict(before['file'])
        first, second, restored = observation(False), observation(False), observation()
        # Name filter stays visible while ownership filter hides a distinct file.
        first['owner_file'], second['owner_file'] = dict(first['file']), dict(second['file'])
        first['file'], second['file'] = dict(before['file']), dict(before['file'])
        restored['owner_file'] = dict(before['file'])
        result = case.comparison(before, first, report(123), second, restored, report(), 123)
        self.assertEqual(result['file_hiding_by_fixture'], {'file': 'NOT_OBSERVED', 'owner_file': 'CONFIRMED'})
        self.assertEqual(result['exit_status'], 0)


class FakeLab:
    def __init__(self, fail=None):
        self.child = SimpleNamespace(pid=123)
        self.loaded = set()
        self.events = []
        self.fail = fail

    def setup(self):
        self.events.append('setup')

    def observe(self, label):
        return observation(visible=not label.startswith('active'))

    def scan(self, label):
        self.events.append('scan-' + label)
        if self.fail == label:
            raise RuntimeError('simulated collection failure')
        return report(123 if label == 'active' else None)

    def load(self, key):
        self.events.append('load-' + key)
        self.loaded.add(key)

    def unload(self, key):
        if key in self.loaded:
            self.events.append('unload-' + key)
            self.loaded.remove(key)

    def save(self, name, text):
        self.events.append('saved-' + name)

    def cleanup(self):
        self.events.append('cleanup')
        self.unload('sample')
        self.unload('detector')
        return []


class LifecycleTests(unittest.TestCase):
    def test_after_order_reloads_detector_only_after_sample(self):
        lab = FakeLab()
        self.assertEqual(case.execute_case(lab, 'after')['exit_status'], 0)
        load = [e for e in lab.events if e.startswith(('load-', 'unload-'))]
        self.assertEqual(load, ['load-detector', 'unload-detector', 'load-sample',
                                'load-detector', 'unload-sample', 'unload-detector'])
        self.assertFalse(lab.loaded)

    def test_before_order_retains_detector(self):
        lab = FakeLab()
        self.assertEqual(case.execute_case(lab, 'before')['exit_status'], 0)
        self.assertEqual(lab.events.count('load-detector'), 1)
        self.assertFalse(lab.loaded)

    def test_active_scan_failure_cleans_up_sample_then_detector(self):
        lab = FakeLab(fail='active')
        result = case.execute_case(lab, 'after')
        self.assertEqual(result['exit_status'], 2)
        self.assertEqual(lab.events[-3:], ['cleanup', 'unload-sample', 'unload-detector'])
        self.assertFalse(lab.loaded)

    def test_bad_baseline_never_loads_sample(self):
        lab = FakeLab(fail='before')
        self.assertEqual(case.execute_case(lab, 'after')['exit_status'], 2)
        self.assertNotIn('load-sample', lab.events)
        self.assertFalse(lab.loaded)


class ProvenanceTests(unittest.TestCase):
    def test_raw_capture_keeps_unparseable_evidence_and_marks_truncation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / 'enabled_functions'
            raw = b'kernel output a future parser may reject\n'
            path.write_bytes(raw)
            meta, captured = capture_tracefs((root,))
            self.assertEqual(meta['status'], 'OBSERVED')
            self.assertEqual(captured, raw)
            path.write_bytes(b'x' * (TRACEFS_LIMIT + 100))
            meta, captured = capture_tracefs((root,))
            self.assertEqual(meta['status'], 'TRUNCATED')
            self.assertEqual(len(captured), TRACEFS_LIMIT)

    def test_pinned_configuration_excludes_module_unlinking(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'rootkit.h').write_text('char* MAGIC_WORD = "caraxes"; int USER_HIDE = 1001; int GROUP_HIDE = 21;')
            (root / 'hooks.h').write_text('#include "hooks_getdents64.h"\nHOOK("sys_getdents64", hook, &orig)')
            (root / 'caraxes.c').write_text('//hide_module();\n')
            with patch.object(case.os, 'getuid', return_value=1000), patch.dict(case.os.environ, {'SUDO_UID': '1000'}):
                self.assertEqual(case.sample_configuration(root)['hidden_uid'], 1001)
                (root / 'caraxes.c').write_text('hide_module();\n')
                with self.assertRaises(ValueError):
                    case.sample_configuration(root)

    def test_boot_identity_is_explicit_and_missing_fields_are_recorded(self):
        with tempfile.TemporaryDirectory() as temp:
            proc = Path(temp)
            (proc / 'sys/kernel/random').mkdir(parents=True)
            (proc / 'sys/kernel/random/boot_id').write_text('test-boot\n')
            (proc / 'sys/kernel/tainted').write_text('0\n')
            (proc / 'uptime').write_text('39.5 70.2\n')
            (proc / 'stat').write_text('cpu 0\nbtime 100\n')
            context = boot_context(proc)
            self.assertEqual(context['boot_id'], 'test-boot')
            self.assertEqual(context['uptime_seconds'], 39.5)
            self.assertFalse(context['errors'])
            (proc / 'uptime').unlink()
            self.assertIn('uptime_seconds', boot_context(proc)['errors'])


if __name__ == '__main__':
    unittest.main()
