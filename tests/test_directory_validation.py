"""Owned-directory evidence, lifecycle and cleanup; unit tests load no modules."""
import errno
import json
import os
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import validate_directories as dirs


def fixture(hidden=False, accessible=True):
    return {'visible': not hidden, 'fd_visible': not hidden, 'held_identity_match': True,
            'held_marker_identity_match': True, 'held_content_match': True,
            'direct_open_accessible': accessible, 'direct_identity_match': accessible,
            'chdir_accessible': accessible, 'chdir_identity_match': accessible,
            'held_marker_listed': True,
            'relative_marker_identity_match': True, 'relative_marker_content_match': True}


def observation(hidden=False, accessible=True):
    return {'directories': {'name_directory': fixture(hidden, accessible),
                            'control_directory': fixture()}}


def report(candidates=True):
    records = [dirs.client.result(name, 'scope', 'OK', 'observed', 'test') for name in dirs.client.CHECKS]
    if candidates:
        records.append(dirs.client.result('ftrace', '__x64_sys_getdents64', 'SUSPICIOUS',
                                          'ipmodify_on_selected_function', 'test'))
    return {'records': records, 'scanned': True, 'checks': 63, 'truncated': False,
            'tasks_complete': True, 'pid_comparison_complete': True, 'ftrace_complete': True}


class EvidenceTests(unittest.TestCase):
    def test_two_omissions_and_retained_identity_confirm_hiding(self):
        value = dirs.compare(observation(True), observation(True), report())
        self.assertEqual(value['directory_hiding'], 'CONFIRMED')
        self.assertEqual(value['enumeration_hook_evidence'], 'DETECTED')
        self.assertEqual(value['exit_status'], 0)
        self.assertTrue(value['object_level_directory_detection'].startswith('NOT_IMPLEMENTED'))

    def test_blocked_direct_open_and_chdir_do_not_mean_directory_destroyed(self):
        value = dirs.compare(observation(True, False), observation(True, False), report())
        self.assertEqual(value['directory_hiding'], 'CONFIRMED')
        self.assertEqual(value['exit_status'], 0)

    def test_parent_path_and_fd_must_agree(self):
        first, second = observation(True), observation(True)
        second['directories']['name_directory']['fd_visible'] = True
        self.assertEqual(dirs.compare(first, second, report())['directory_hiding'], 'INCONCLUSIVE')

    def test_lost_directory_or_marker_identity_is_not_confirmed_hiding(self):
        for field in ['held_identity_match', 'held_marker_identity_match', 'held_content_match']:
            with self.subTest(field=field):
                first, second = observation(True), observation(True)
                second['directories']['name_directory'][field] = False
                self.assertEqual(dirs.compare(first, second, report())['exit_status'], 2)

    def test_failed_control_does_not_score_target_hiding(self):
        for field in ['visible', 'held_marker_listed']:
            with self.subTest(field=field):
                first, second = observation(True), observation(True)
                first['directories']['control_directory'][field] = False
                value = dirs.compare(first, second, report())
                self.assertFalse(value['directory_control_intact'])
                self.assertEqual(value['directory_hiding'], 'INCONCLUSIVE')
                self.assertEqual(value['exit_status'], 2)

    def test_table_mutation_without_hiding_is_unexercised(self):
        value = dirs.compare(observation(), observation(), report())
        self.assertEqual(value['directory_hiding'], 'NOT_OBSERVED')
        self.assertEqual(value['enumeration_hook_evidence'], 'NOT_EXERCISED')
        self.assertEqual(value['exit_status'], 2)

    def test_unrelated_network_alert_is_not_directory_hook_detection(self):
        active = report(False)
        active['records'].append(dirs.client.result('network', '/proc/net/tcp', 'SUSPICIOUS', 'x86_call_rel32', 'test'))
        value = dirs.compare(observation(True), observation(True), active)
        self.assertEqual(value['enumeration_hook_evidence'], 'NO_MATCHING_FINDING')
        self.assertEqual(value['exit_status'], 1)

    def test_failed_or_incomplete_scan_cannot_be_clean(self):
        for active in [None, {**report(False), 'truncated': True}, {**report(False), 'ftrace_complete': False}]:
            with self.subTest(active=active):
                value = dirs.compare(observation(True), observation(True), active)
                self.assertEqual(value['enumeration_hook_evidence'], 'INCOMPLETE')
                self.assertEqual(value['exit_status'], 2)

    def test_name_uid_and_gid_are_scored_independently(self):
        first, second = observation(True), observation(True)
        for observed in [first, second]:
            observed['directories']['uid_directory'] = fixture(False)
            observed['directories']['gid_directory'] = fixture(True)
        value = dirs.compare(first, second, report())
        self.assertEqual(value['directory_hiding_by_fixture'],
                         {'name_directory': 'CONFIRMED', 'uid_directory': 'NOT_OBSERVED', 'gid_directory': 'CONFIRMED'})


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.canaries = dirs.DirectoryCanaries()

    def tearDown(self):
        self.canaries.cleanup()

    def test_real_canaries_are_repeatably_visible_and_identity_stable(self):
        self.canaries.setup(dirs.specs({'sample': 'diamorphine'}))
        for _ in range(2):
            current = self.canaries.observe()
            self.assertTrue(all(dirs.present(r) for r in current['directories'].values()))
            self.assertTrue(all(r['held_marker_listed'] for r in current['directories'].values()))
        root = self.canaries.parent
        descriptors = [self.canaries.parent_fd] + [f[k] for f in self.canaries.fixtures.values()
                                                  for k in ['dir_fd', 'marker_fd']]
        self.assertEqual(self.canaries.cleanup(), [])
        self.assertFalse(root.exists())
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_direct_lookup_denial_preserves_held_and_relative_evidence(self):
        self.canaries.setup(dirs.specs({'sample': 'singularity'}))
        target = self.canaries.fixtures['name_directory']['path']
        original = dirs.os.open
        def denied(path, *args, **kwargs):
            if path == target:
                raise FileNotFoundError(errno.ENOENT, 'hidden')
            return original(path, *args, **kwargs)
        with patch.object(dirs.os, 'open', side_effect=denied), \
                patch.object(dirs, 'probe_chdir', return_value={'accessible': False, 'errno': errno.ENOENT}):
            current = self.canaries.observe()['directories']['name_directory']
        self.assertFalse(current['direct_open_accessible'])
        self.assertTrue(dirs.retained_identity(current))
        self.assertTrue(current['relative_marker_content_match'])

    def test_unexpected_contents_are_never_recursively_deleted(self):
        self.canaries.setup([('control_directory', 'ordinary', None, None)])
        fixture = self.canaries.fixtures['control_directory']
        unexpected = fixture['path'] / 'unexpected.txt'
        unexpected.write_text('do not delete')
        parent, path = self.canaries.parent, fixture['path']
        errors = self.canaries.cleanup()
        self.assertTrue(errors)
        self.assertTrue(unexpected.exists())
        # Test owns this file; remove it explicitly after verifying retention.
        unexpected.unlink()
        path.rmdir()
        parent.rmdir()
        self.canaries.parent = None
        fixture['directory_created'] = False

    def test_cleanup_retry_without_owned_descriptors_never_uses_cwd(self):
        self.canaries.setup([('control_directory', 'ordinary', None, None)])
        fixture = self.canaries.fixtures['control_directory']
        parent, path = self.canaries.parent, fixture['path']
        with patch.object(dirs.os, 'unlink', side_effect=PermissionError('temporarily blocked')):
            self.assertTrue(self.canaries.cleanup())
        with patch.object(dirs.os, 'unlink') as unlink:
            self.assertTrue(self.canaries.cleanup())
            unlink.assert_not_called()
        # All remaining names are inside the exact test-owned directory.
        (path / dirs.MARKER).unlink()
        path.rmdir()
        parent.rmdir()
        self.canaries.parent = None
        fixture['directory_created'] = fixture['marker_created'] = False

    def test_partial_creation_failure_closes_already_owned_resources(self):
        with patch.object(dirs.os, 'write', return_value=0):
            with self.assertRaises(OSError):
                self.canaries.setup([('name_directory', 'target', None, None)])
        parent = self.canaries.parent
        self.assertEqual(self.canaries.cleanup(), [])
        self.assertFalse(parent.exists())

    def test_successful_chown_return_without_matching_ownership_is_rejected(self):
        with patch.object(dirs.os, 'fchown', return_value=None):
            with self.assertRaises(ValueError):
                self.canaries.setup([('uid_directory', 'owned', os.getuid() + 1, None)])
        parent = self.canaries.parent
        self.assertEqual(self.canaries.cleanup(), [])
        self.assertFalse(parent.exists())

    def test_caraxes_specs_isolate_uid_and_gid_selection(self):
        definitions = dirs.specs({'sample': 'caraxes', 'config': {'magic_word': 'caraxes',
                                                                'hidden_uid': 1001, 'hidden_gid': 21}})
        self.assertIn(('uid_directory', 'uid_selected_directory', 1001, None), definitions)
        self.assertIn(('gid_directory', 'gid_selected_directory', None, 21), definitions)


class FakeLab:
    def __init__(self, sample='caraxes', failure=None):
        self.metadata = {'sample': sample}
        self.failure = failure
        self.loaded = set()
        self.events = []
        self.sample_attempted = False
        self.sample_removed = False

    def setup(self): pass
    def observe(self, label):
        current = observation(label.startswith('active'))
        if self.failure == 'baseline':
            current['directories']['control_directory']['visible'] = False
        if self.failure == 'recovery' and label == 'restored':
            current['directories']['name_directory']['visible'] = False
        return current
    def collect_scan(self, label):
        if self.failure == label: return None
        return report(label == 'active')
    def load(self, key):
        self.loaded.add(key)
        self.events.append('load-' + key)
    def unload(self, key):
        if key in self.loaded:
            self.loaded.remove(key)
            self.events.append('unload-' + key)
            if key == 'sample': self.sample_removed = True
    def load_sample(self):
        self.sample_attempted = True
        if self.failure == 'load': raise RuntimeError('partial init')
        self.load('sample')
    def save(self, *args): pass
    def cleanup(self):
        if self.metadata['sample'] == 'caraxes': self.unload('sample')
        self.unload('detector')
        return []


class LifecycleTests(unittest.TestCase):
    def test_failed_detector_baseline_never_attempts_sample(self):
        lab = FakeLab(failure='before')
        value = dirs.execute(lab, 'after')
        self.assertEqual(value['exit_status'], 2)
        self.assertFalse(value['reboot_required'])
        self.assertNotIn('load-sample', lab.events)

    def test_active_collection_failure_still_cleans_up_owned_caraxes(self):
        lab = FakeLab(failure='active')
        value = dirs.execute(lab, 'after')
        self.assertEqual(value['exit_status'], 2)
        self.assertTrue(value['sample_removed'])
        self.assertFalse(lab.loaded)

    def test_caraxes_restores_directories_and_still_requires_fresh_boot(self):
        lab = FakeLab()
        value = dirs.execute(lab, 'after')
        self.assertEqual(value['exit_status'], 0)
        self.assertTrue(value['sample_removed'])
        self.assertTrue(value['directories_restored_after_unload'])
        self.assertTrue(value['reboot_required'])
        self.assertEqual(lab.events, ['load-detector', 'unload-detector', 'load-sample',
                                     'load-detector', 'unload-sample', 'unload-detector'])

    def test_self_hidden_sample_is_left_for_reboot(self):
        lab = FakeLab('singularity')
        value = dirs.execute(lab, 'before')
        self.assertEqual(value['exit_status'], 0)
        self.assertFalse(value['sample_removed'])
        self.assertEqual(lab.loaded, {'sample'})
        self.assertNotIn('unload-sample', lab.events)

    def test_bad_directory_baseline_never_loads_sample(self):
        lab = FakeLab(failure='baseline')
        value = dirs.execute(lab, 'after')
        self.assertEqual(value['exit_status'], 2)
        self.assertFalse(value['reboot_required'])
        self.assertNotIn('load-sample', lab.events)

    def test_failed_initialization_requires_reboot_without_claiming_removal(self):
        lab = FakeLab('diamorphine', 'load')
        value = dirs.execute(lab, 'after')
        self.assertTrue(value['reboot_required'])
        self.assertFalse(value['sample_removed'])
        self.assertEqual(value['exit_status'], 2)

    def test_bad_recovery_is_incomplete(self):
        value = dirs.execute(FakeLab(failure='recovery'), 'after')
        self.assertEqual(value['exit_status'], 2)
        self.assertFalse(value['directories_restored_after_unload'])

    def test_reboot_marker_precedes_failed_insmod_and_blocks_same_boot_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'reports').mkdir()
            lab = dirs.DirectoryLab.__new__(dirs.DirectoryLab)
            lab.metadata = {'sample': 'singularity', 'boot': {'boot_id': 'directory-boot'},
                            'modules': {'sample': {'path': '/owned/sample.ko'}}}
            lab.owner = SimpleNamespace(st_uid=os.getuid(), st_gid=os.getgid())
            lab.output = root / 'reports/case'
            lab.sample_attempted = False
            lab.loaded = set()
            calls = []
            def run(label, argv):
                marker = root / 'reports/pending-sample-reboot.json'
                self.assertEqual(json.loads(marker.read_text())['boot_id'], 'directory-boot')
                self.assertTrue(lab.sample_attempted)
                calls.append(label)
                return subprocess.CompletedProcess(argv, 1, '', 'partial init')
            lab.run = run
            with patch.object(dirs, 'ROOT', root), \
                    patch.object(dirs, 'boot_context', return_value={'boot_id': 'directory-boot'}):
                with self.assertRaises(RuntimeError):
                    lab.load_sample()
                with self.assertRaises(ValueError):
                    lab.load_sample()
            self.assertEqual(calls, ['load-sample'])
