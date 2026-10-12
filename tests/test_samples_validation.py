"""Per-sample scoring, isolation and recovery semantics; no rootkit is loaded."""
from pathlib import Path
import os
import select
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_samples as cases
from scripts.report_context import require_reboot_after_sample


def report(sample='diamorphine', pid=100, detect=True):
    records = [cases.client.result(name, 'collection', 'OK', 'observed', 'test') for name in cases.client.CHECKS]
    if detect:
        records += [cases.client.result('processes', pid, 'SUSPICIOUS', 'missing_from_proc_enumeration', 'test'),
                    cases.client.result('modules', sample, 'SUSPICIOUS', 'live_kobject_missing_module', 'test'),
                    cases.client.result('network', '/proc/net/tcp', 'SUSPICIOUS', 'x86_call_rel32', 'test')]
    return {'records': records, 'scanned': True, 'checks': sum(cases.client.CHECKS.values()),
            'truncated': False, 'tasks_complete': True, 'pid_comparison_complete': True, 'ftrace_complete': True}


def observation(hidden=True):
    return {'file': {'visible': not hidden, 'held_identity_match': True, 'held_content_match': True},
            'control_file': {'visible': True, 'held_identity_match': True, 'held_content_match': True,
                             'direct_identity_match': True, 'direct_content_match': True},
            'process': {'visible': not hidden, 'ipc_identity_match': True, 'alive': True,
                        'direct_identity_match': True},
            'module': {'listed': not hidden, 'sysfs_present': True},
            'tcp': {'target': {'held_identity_match': True, 'roundtrip_ok': True, 'visible_in_proc_tcp': not hidden},
                    'control': {'held_identity_match': True, 'roundtrip_ok': True, 'visible_in_proc_tcp': True}}}


class FeatureScoring(unittest.TestCase):
    def test_failed_module_observation_is_not_unexercised(self):
        first, second = observation(), observation()
        second['module'] = {'error': 'permission denied'}
        value = cases.evaluate({'sample': 'diamorphine'}, first, second, report(detect=False), 100)
        self.assertIsNone(value['module_reporting']['unlisted_after_known_load'])
        self.assertEqual(value['module_detection'], 'INCONCLUSIVE')

    def test_hidden_untargeted_file_makes_file_result_inconclusive(self):
        first, second = observation(), observation()
        first['control_file']['visible'] = False
        value = cases.evaluate({'sample': 'diamorphine'}, first, second, report(), 100)
        self.assertFalse(value['untargeted_control_intact'])
        self.assertEqual(value['file_hiding'], 'INCONCLUSIVE')

    def test_diamorphine_module_and_process_scored_individually(self):
        value = cases.evaluate({'sample': 'diamorphine'}, observation(), observation(), report(), 100)
        self.assertEqual(value['module_detection'], 'DETECTED')
        self.assertEqual(value['process_detection'], 'DETECTED')
        self.assertEqual(value['tcp_ipv4_hiding'], 'NOT_TESTED')

    def test_inactive_process_hiding_is_not_a_miss(self):
        first, second = observation(), observation()
        first['process']['visible'] = second['process']['visible'] = True
        value = cases.evaluate({'sample': 'diamorphine'}, first, second, report(detect=False), 100)
        self.assertEqual(value['process_detection'], 'NOT_EXERCISED')
        self.assertEqual(value['module_detection'], 'NO_MATCHING_FINDING')

    def test_singularity_blocked_identity_is_incomplete_not_clean(self):
        r = report(sample='singularity', detect=False)
        r['records'].append(cases.client.result('processes', 100, 'INFO', 'lifecycle_inconclusive', 'lookup blocked'))
        value = cases.evaluate({'sample': 'singularity'}, observation(), observation(), r, 100)
        self.assertEqual(value['process_hiding'], 'CONFIRMED')
        self.assertEqual(value['process_detection'], 'INCOMPLETE')
        self.assertEqual(value['tcp_ipv4_hiding'], 'CONFIRMED')

    def test_missing_or_unparseable_report_cannot_be_clean(self):
        value = cases.evaluate({'sample': 'singularity'}, observation(), observation(), None, 100)
        self.assertEqual(value['module_detection'], 'INCOMPLETE')
        self.assertIsNone(value['scan_exit_status'])

    def test_lost_ipc_identity_is_not_confirmed_hiding(self):
        first, second = observation(), observation()
        second['process']['ipc_identity_match'] = False
        self.assertEqual(cases.hiding_state(first, second, 'process'), 'INCONCLUSIVE')

    def test_network_control_must_remain_visible(self):
        first, second = observation(), observation()
        first['tcp']['control']['visible_in_proc_tcp'] = False
        value = cases.evaluate({'sample': 'singularity'}, first, second, report(sample='singularity'), 100)
        self.assertEqual(value['tcp_ipv4_hiding'], 'INCONCLUSIVE')
        self.assertEqual(value['network_callback_detection'], 'INCONCLUSIVE')

    def test_unrelated_module_alert_is_not_target_detection(self):
        r = report(sample='other')
        value = cases.evaluate({'sample': 'diamorphine'}, observation(), observation(), r, 100)
        self.assertEqual(value['module_detection'], 'NO_MATCHING_FINDING')


class FakeLab:
    def __init__(self, failure=None):
        self.metadata = {'sample': 'diamorphine'}
        self.loaded = set()
        self.sample_attempted = False
        self.detector_errors = []
        self.events = []
        self.worker = SimpleNamespace(pid=100, activate=lambda: {'event': 'activated'})
        self.failure = failure

    def setup(self): pass
    def observe(self, label):
        value = observation(hidden=label != 'before')
        value['file'].update(direct_identity_match=True, direct_content_match=True)
        if self.failure == 'control' and label != 'before':
            value['control_file']['visible'] = False
        if self.failure == 'baseline-tcp' and label == 'before':
            value['tcp']['target']['visible_in_proc_tcp'] = False
        return value
    def load(self, key):
        self.loaded.add(key)
        self.events.append('load-' + key)
    def unload(self, key):
        self.loaded.remove(key)
        self.events.append('unload-' + key)
    def load_sample(self):
        self.sample_attempted = True
        self.events.append('load-sample')
        if self.failure == 'load': raise RuntimeError('partial init failure')
        self.loaded.add('sample')
    def collect_scan(self, label):
        if self.failure == label: return None
        return report(detect=label == 'active')
    def save(self, name, text): pass
    def save_json(self, name, value): pass
    def cleanup(self):
        if 'detector' in self.loaded: self.unload('detector')
        return []


class LifecycleScoring(unittest.TestCase):
    def test_hidden_baseline_socket_prevents_sample_load(self):
        lab = FakeLab(failure='baseline-tcp')
        result = cases.execute(lab, 'after')
        self.assertFalse(result['reboot_required'])
        self.assertNotIn('load-sample', lab.events)

    def test_failed_active_control_sets_incomplete_bit(self):
        lab = FakeLab(failure='control')
        result = cases.execute(lab, 'after')
        self.assertEqual(result['exit_status'], 2)
        self.assertFalse(result['untargeted_control_intact'])

    def test_after_case_leaves_explicit_reboot_requirement(self):
        lab = FakeLab()
        result = cases.execute(lab, 'after')
        self.assertTrue(result['reboot_required'])
        self.assertFalse(result['sample_removed'])
        self.assertEqual(lab.loaded, {'sample'})
        self.assertEqual(lab.events, ['load-detector', 'unload-detector', 'load-sample', 'load-detector', 'unload-detector'])

    def test_bad_baseline_never_attempts_sample(self):
        lab = FakeLab(failure='before')
        result = cases.execute(lab, 'after')
        self.assertFalse(result['reboot_required'])
        self.assertNotIn('load-sample', lab.events)

    def test_failed_initialization_still_requires_reboot(self):
        lab = FakeLab(failure='load')
        result = cases.execute(lab, 'after')
        self.assertTrue(result['reboot_required'])
        self.assertEqual(result['exit_status'], 2)

    def test_failed_collection_does_not_lose_cleanup_or_recovery_state(self):
        lab = FakeLab(failure='active')
        result = cases.execute(lab, 'before')
        self.assertTrue(result['reboot_required'])
        self.assertEqual(result['exit_status'], 2)
        self.assertNotIn('detector', lab.loaded)

    def test_pending_recovery_blocks_same_boot_but_not_new_boot(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'reports').mkdir()
            (root / 'reports/pending-sample-reboot.json').write_text('{"boot_id":"old"}')
            with self.assertRaises(ValueError):
                require_reboot_after_sample(root, {'boot_id': 'old'})
            require_reboot_after_sample(root, {'boot_id': 'new'})

    def test_invalid_recovery_identity_cannot_bypass_guard(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'reports').mkdir()
            path = root / 'reports/pending-sample-reboot.json'
            for invalid in ['{}', '{"boot_id":null}', '[]', '{"boot_id":""}', 'x' * 65537]:
                with self.subTest(invalid=invalid[:40]):
                    path.write_text(invalid)
                    with self.assertRaises(ValueError):
                        require_reboot_after_sample(root, {'boot_id': 'new'})


class CanaryFailureCleanup(unittest.TestCase):
    def test_signal_failure_still_closes_control_and_event_fds(self):
        worker = cases.Canary.__new__(cases.Canary)
        worker.control, worker.events = os.pipe()
        worker.pidfd = os.open(os.devnull, os.O_RDONLY)
        fds = [worker.control, worker.events, worker.pidfd]
        with patch.object(cases.signal, 'pidfd_send_signal', create=True, side_effect=PermissionError('blocked')):
            with self.assertRaises(PermissionError):
                worker.close()
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        worker.close()  # repeated cleanup is harmless


@unittest.skipUnless(hasattr(os, 'pidfd_open'), 'Linux pidfd integration test')
class CanaryIPC(unittest.TestCase):
    def test_owned_detached_canary_heartbeat_and_cleanup_without_activation(self):
        # Benign canary only: no trigger signal, rootkit or privileged action.
        actor = cases.Canary(31)
        pidfd = os.dup(actor.pidfd)
        try:
            event = actor.heartbeat()
            self.assertEqual(event['ppid'], 1)
            self.assertEqual(event['pid'], actor.pid)
            self.assertFalse(select.select([pidfd], [], [], 0)[0])
            actor.close()
            self.assertTrue(select.select([pidfd], [], [], 3)[0])
        finally:
            actor.close()
            os.close(pidfd)
