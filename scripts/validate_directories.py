#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Dedicated owned-directory hiding tests. Run one reviewed sample per boot."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import client
from scripts import validate_caraxes as common
from scripts import validate_samples as samples
from scripts.report_context import boot_context, require_reboot_after_sample

MARKER = 'marker.txt'
CHDIR_PROBE = '''import json,os,sys
try:
    os.chdir(sys.argv[1])
    s=os.stat(".")
    print(json.dumps({"accessible":True,"dev_ino":[s.st_dev,s.st_ino]}))
except OSError as e:
    print(json.dumps({"accessible":False,"errno":e.errno}))
'''


def specs(metadata):
    sample = metadata['sample']
    if sample == 'caraxes':
        config = metadata['config']
        targets = [('name_directory', 'probe_' + config['magic_word'] + '_directory', None, None),
                   ('uid_directory', 'uid_selected_directory', config['hidden_uid'], None),
                   ('gid_directory', 'gid_selected_directory', None, config['hidden_gid'])]
    else:
        name = 'diamorphine_secret_directory' if sample == 'diamorphine' else 'singularity_probe_directory'
        targets = [('name_directory', name, None, None)]
    return targets + [('control_directory', 'ordinary_control_directory', None, None)]


def error(exc):
    return {'errno': getattr(exc, 'errno', None), 'message': str(exc)}


def listing(path):
    names = []
    with os.scandir(path) as entries:
        for entry in entries:
            if len(names) == 128:
                raise ValueError('Owned-directory listing exceeds its bound')
            names.append(entry.name)
    return names


def probe_chdir(path):
    # This child never changes the manager's cwd or emits a sensitive pathname.
    completed = subprocess.run([sys.executable, '-I', '-c', CHDIR_PROBE, str(path)],
                               cwd='/', capture_output=True, text=True, timeout=5)
    if completed.returncode:
        raise ValueError('Directory access probe failed: ' + str(completed.returncode))
    result = json.loads(completed.stdout)
    if not isinstance(result, dict) or type(result.get('accessible')) is not bool:
        raise ValueError('Invalid directory access probe result')
    return result


class DirectoryCanaries:
    def __init__(self):
        self.parent = None
        self.parent_fd = None
        self.fixtures = {}
        self.payload = ('STANDCON directory canary ' + uuid.uuid4().hex).encode('ascii')

    def setup(self, definitions):
        self.parent = Path(tempfile.mkdtemp(prefix='lkmrkdet-directories-'))
        self.parent_fd = os.open(self.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for key, name, uid, gid in definitions:
            if '/' in name or name in {'', '.', '..'}:
                raise ValueError('Canary name must be a simple basename')
            fixture = {'name': name, 'path': self.parent / name, 'dir_fd': None,
                       'marker_fd': None, 'directory_created': False, 'marker_created': False}
            self.fixtures[key] = fixture
            os.mkdir(name, mode=0o700, dir_fd=self.parent_fd)
            fixture['directory_created'] = True
            fixture['dir_fd'] = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                        dir_fd=self.parent_fd)
            if uid is not None or gid is not None:
                os.fchown(fixture['dir_fd'], -1 if uid is None else uid, -1 if gid is None else gid)
            held = os.fstat(fixture['dir_fd'])
            if (uid is not None and held.st_uid != uid) or (gid is not None and held.st_gid != gid):
                raise ValueError('Directory ownership does not match the selected canary identity')
            fixture.update(identity=(held.st_dev, held.st_ino), uid=held.st_uid, gid=held.st_gid)
            fixture['marker_fd'] = os.open(MARKER, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
                                          0o600, dir_fd=fixture['dir_fd'])
            fixture['marker_created'] = True
            if os.write(fixture['marker_fd'], self.payload) != len(self.payload):
                raise OSError('Short directory-marker write')
            marker = os.fstat(fixture['marker_fd'])
            fixture['marker_identity'] = (marker.st_dev, marker.st_ino)

    def identities(self):
        return {'parent': str(self.parent), 'marker_sha256': hashlib.sha256(self.payload).hexdigest(),
                'directories': {key: {'path': str(f['path']), 'dev_ino': f['identity'],
                                      'uid': f['uid'], 'gid': f['gid'], 'marker_dev_ino': f['marker_identity']}
                                for key, f in self.fixtures.items()}}

    def observe(self):
        result = {'directories': {}, 'parent_listing': None, 'parent_fd_listing': None}
        for field, location in [('parent_listing', self.parent), ('parent_fd_listing', self.parent_fd)]:
            try:
                result[field] = listing(location)
            except (OSError, ValueError) as exc:
                result[field + '_error'] = error(exc)
        for key, fixture in self.fixtures.items():
            record = {'visible': None, 'fd_visible': None}
            result['directories'][key] = record
            for field, source in [('visible', 'parent_listing'), ('fd_visible', 'parent_fd_listing')]:
                if result[source] is not None:
                    record[field] = fixture['name'] in result[source]
            try:
                held, marker = os.fstat(fixture['dir_fd']), os.fstat(fixture['marker_fd'])
                record.update(held_identity_match=stat.S_ISDIR(held.st_mode) and
                              (held.st_dev, held.st_ino) == fixture['identity'],
                              held_marker_identity_match=stat.S_ISREG(marker.st_mode) and
                              (marker.st_dev, marker.st_ino) == fixture['marker_identity'],
                              held_content_match=os.pread(fixture['marker_fd'], len(self.payload) + 1, 0) == self.payload)
            except OSError as exc:
                record['held_error'] = error(exc)
            try:
                record['held_marker_listed'] = MARKER in listing(fixture['dir_fd'])
                fd = os.open(MARKER, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fixture['dir_fd'])
                try:
                    current = os.fstat(fd)
                    record['relative_marker_identity_match'] = (current.st_dev, current.st_ino) == fixture['marker_identity']
                    record['relative_marker_content_match'] = os.read(fd, len(self.payload) + 1) == self.payload
                finally:
                    os.close(fd)
            except (OSError, ValueError) as exc:
                record['relative_access_error'] = error(exc)
            try:
                fd = os.open(fixture['path'], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                record['direct_open_accessible'] = True
                try:
                    current = os.fstat(fd)
                    record['direct_identity_match'] = (current.st_dev, current.st_ino) == fixture['identity']
                finally:
                    os.close(fd)
            except OSError as exc:
                record['direct_open_accessible'] = False
                record['direct_open_error'] = error(exc)
            try:
                entered = probe_chdir(fixture['path'])
                record['chdir_accessible'] = entered['accessible']
                if entered['accessible']:
                    record['chdir_identity_match'] = entered.get('dev_ino') == list(fixture['identity'])
                else:
                    record['chdir_errno'] = entered.get('errno')
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                record['chdir_probe_error'] = error(exc)
        return result

    def cleanup(self):
        errors = []
        for fixture in self.fixtures.values():
            if fixture['marker_created']:
                if fixture['dir_fd'] is None:
                    errors.append('marker cleanup deferred: owned directory descriptor unavailable')
                else:
                    try:
                        os.unlink(MARKER, dir_fd=fixture['dir_fd'])
                        fixture['marker_created'] = False
                    except OSError as exc:
                        errors.append('marker cleanup: ' + str(exc))
            for field in ['marker_fd', 'dir_fd']:
                if fixture[field] is not None:
                    try:
                        os.close(fixture[field])
                    except OSError as exc:
                        errors.append('descriptor cleanup: ' + str(exc))
                    fixture[field] = None
            if fixture['directory_created']:
                if self.parent_fd is None:
                    errors.append('directory cleanup deferred: owned parent descriptor unavailable')
                else:
                    try:
                        os.rmdir(fixture['name'], dir_fd=self.parent_fd)
                        fixture['directory_created'] = False
                    except OSError as exc:
                        errors.append('directory cleanup: ' + str(exc))
        if self.parent_fd is not None:
            try:
                os.close(self.parent_fd)
            except OSError as exc:
                errors.append('parent descriptor cleanup: ' + str(exc))
            self.parent_fd = None
        if self.parent is not None:
            try:
                self.parent.rmdir()  # Exact owned path only, never recursive.
                self.parent = None
            except OSError as exc:
                errors.append('parent cleanup: ' + str(exc))
        return errors


def retained_identity(record):
    return all(record.get(field) is True for field in
               ['held_identity_match', 'held_marker_identity_match', 'held_content_match'])


def present(record):
    return retained_identity(record) and all(record.get(field) is True for field in
        ['visible', 'fd_visible', 'direct_open_accessible', 'direct_identity_match',
          'chdir_accessible', 'chdir_identity_match', 'held_marker_listed',
          'relative_marker_identity_match', 'relative_marker_content_match'])


def directory_state(first, second):
    if not all(retained_identity(r) for r in [first, second]):
        return 'INCONCLUSIVE'
    if all(r.get('visible') is False and r.get('fd_visible') is False for r in [first, second]):
        return 'CONFIRMED'
    if all(r.get('visible') is True and r.get('fd_visible') is True for r in [first, second]):
        return 'NOT_OBSERVED'
    return 'INCONCLUSIVE'


def enumeration_candidate(record):
    if record['status'] != 'SUSPICIOUS':
        return False
    target = record['target']
    return ((record['check'] == 'syscalls' and
             (target in {'handler:getdents', 'handler:getdents64'} or
              target.startswith(('table:getdents[', 'table:getdents64[')))) or
            (record['check'] == 'ftrace' and target in {'__x64_sys_getdents', '__x64_sys_getdents64'}))


def compare(first, second, report):
    controls = all(present(r['directories'].get('control_directory', {})) for r in [first, second])
    keys = set(first['directories']) | set(second['directories'])
    states = {key: directory_state(first['directories'].get(key, {}), second['directories'].get(key, {}))
              if controls else 'INCONCLUSIVE' for key in sorted(keys) if key != 'control_directory'}
    combined = ('CONFIRMED' if 'CONFIRMED' in states.values() else
                'INCONCLUSIVE' if not states or 'INCONCLUSIVE' in states.values() else 'NOT_OBSERVED')
    candidates = [] if report is None else [r for r in report['records'] if enumeration_candidate(r)]
    if combined != 'CONFIRMED':
        evidence = 'NOT_EXERCISED' if combined == 'NOT_OBSERVED' else 'INCONCLUSIVE'
    elif candidates:
        evidence = 'DETECTED'
    elif (report is None or report['truncated'] or not report.get('ftrace_complete', False) or
          not {'syscalls', 'ftrace'}.issubset({r['check'] for r in report['records']}) or any(
            r['check'] in {'syscalls', 'ftrace'} and r['status'] in {'ERROR', 'UNSUPPORTED'} for r in report['records'])):
        evidence = 'INCOMPLETE'
    else:
        evidence = 'NO_MATCHING_FINDING'
    outcome = 1 if evidence == 'NO_MATCHING_FINDING' else 0
    if (combined != 'CONFIRMED' or not controls or 'INCONCLUSIVE' in states.values() or
            report is None or client.exit_status(report) & 2 or evidence in {'INCOMPLETE', 'INCONCLUSIVE'}):
        outcome |= 2
    return {'exit_status': outcome, 'directory_hiding': combined, 'directory_hiding_by_fixture': states,
            'directory_control_intact': controls, 'enumeration_hook_evidence': evidence,
            'enumeration_hook_candidates': candidates,
            'object_level_directory_detection': 'NOT_IMPLEMENTED: hook evidence is not a directory-object finding',
            'scan_exit_status': None if report is None else client.exit_status(report),
            'trust_caveat': 'Held descriptors corroborate owned objects; all observations still share guest-kernel trust.'}


def execute(lab, order):
    result = {'sample': lab.metadata['sample'], 'detector_order': order, 'exit_status': 2}
    try:
        lab.setup()
        before = lab.observe('before')
        if not before['directories'] or not all(present(r) for r in before['directories'].values()):
            raise RuntimeError('Directory baseline visibility/identity/access failed; sample not loaded.')
        lab.load('detector')
        baseline = lab.collect_scan('before')
        if baseline is None or client.exit_status(baseline):
            raise RuntimeError('Detector baseline anomalous/incomplete; sample not loaded.')
        if order == 'after':
            lab.unload('detector')
        lab.load_sample()
        if order == 'after':
            lab.load('detector')
        first = lab.observe('active-before-scan')
        active = lab.collect_scan('active')
        second = lab.observe('active-after-scan')
        result.update(compare(first, second, active))
        if lab.metadata['sample'] == 'caraxes':
            lab.unload('sample')
            restored = lab.observe('restored')
            recovery = lab.collect_scan('restored')
            result['directories_restored_after_unload'] = (
                set(restored['directories']) == set(before['directories']) and
                all(present(r) for r in restored['directories'].values()))
            result['recovery_scan_exit_status'] = None if recovery is None else client.exit_status(recovery)
            if not result['directories_restored_after_unload'] or recovery is None or client.exit_status(recovery):
                result['exit_status'] |= 2
    except (Exception, KeyboardInterrupt) as exc:
        result['exit_status'] |= 2
        result['error'] = str(exc) or type(exc).__name__
        lab.save('failure.txt', traceback.format_exc())
    finally:
        result['cleanup_errors'] = lab.cleanup()
        result['sample_removed'] = lab.sample_removed if lab.sample_attempted else None
        result['reboot_required'] = lab.sample_attempted
        if result['cleanup_errors']:
            result['exit_status'] |= 2
    return result


class DirectoryLab(common.Lab):
    def __init__(self, metadata):
        super().__init__(metadata)
        self.canaries = DirectoryCanaries()
        self.sample_attempted = False
        self.sample_removed = False

    def setup(self):
        self.canaries.setup(specs(self.metadata))
        self.save_json('directory-identities', self.canaries.identities())

    def observe(self, label):
        boot = boot_context()
        if boot['boot_id'] != self.metadata['boot']['boot_id']:
            raise RuntimeError('Boot changed during directory experiment.')
        observation = {'boot': boot, **self.canaries.observe()}
        self.save_json(label + '-directories', observation)
        self.capture_tracing(label)
        return observation

    def load_sample(self):
        boot = boot_context()
        if boot['boot_id'] != self.metadata['boot']['boot_id']:
            raise RuntimeError('Boot changed before sample load.')
        require_reboot_after_sample(ROOT, boot)
        # Mark every directory case before insmod, even unloadable Caraxes, so
        # subsequent samples use separate boots rather than shared exposure.
        state = ROOT / 'reports/pending-sample-reboot.json'
        temporary = state.with_name(state.name + '.tmp-' + uuid.uuid4().hex)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as file:
            os.fchown(file.fileno(), self.owner.st_uid, self.owner.st_gid)
            json.dump({'boot_id': boot['boot_id'], 'sample': self.metadata['sample'],
                       'report_directory': str(self.output), 'case': 'directories', 'recovery': 'reboot'}, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, state)
        self.sample_attempted = True
        if self.metadata['sample'] == 'caraxes':
            self.load('sample')
        else:
            if self.run('load-sample', ['insmod', self.metadata['modules']['sample']['path']]).returncode:
                raise RuntimeError('Sample initialization failed; preserve evidence and reboot.')
            self.loaded.add('sample')
            time.sleep(samples.SAMPLES[self.metadata['sample']]['settle_seconds'])

    def collect_scan(self, label):
        return samples.SampleLab.collect_scan(self, label)

    def unload(self, key):
        loaded = key in self.loaded
        super().unload(key)
        if key == 'sample' and loaded and key not in self.loaded:
            self.sample_removed = True

    def cleanup(self):
        errors = []
        keys = ['sample', 'detector'] if self.metadata['sample'] == 'caraxes' else ['detector']
        for key in keys:
            try:
                self.unload(key)
            except Exception as exc:
                errors.append('module cleanup: ' + str(exc))
        return errors + self.canaries.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', choices=['caraxes', 'diamorphine', 'singularity'])
    parser.add_argument('--sample-dir', type=Path)
    parser.add_argument('--detector-order', choices=['before', 'after'], default='after')
    parser.add_argument('--preflight', action='store_true')
    args = parser.parse_args()
    if not args.preflight and os.geteuid() != 0:
        parser.error('Use sudo for the directory experiment, or --preflight for read-only checks.')
    try:
        if args.sample == 'caraxes':
            metadata = common.preflight(args.sample_dir or ROOT.parent / 'rootkits/caraxes')
            metadata['sample'] = 'caraxes'
        else:
            metadata = samples.preflight(args.sample, args.sample_dir)
        if not metadata['boot']['boot_id']:
            raise ValueError('Directory case requires an available boot identity.')
        metadata.update(case='directories', directory_specs=specs(metadata), recovery='REBOOT_REQUIRED')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Preflight failed: ' + str(exc), file=sys.stderr)
        return 2
    if args.preflight:
        print(json.dumps(metadata, indent=2))
        return 0
    lab = DirectoryLab(metadata)
    lab.save_json('environment', metadata)
    print('Reports: ' + str(lab.output), flush=True)
    before_log = lab.run('kernel-log-before', ['dmesg', '--color=never'])
    result = execute(lab, args.detector_order)
    after_log = lab.run('kernel-log-after', ['dmesg', '--color=never'])
    if before_log.returncode or after_log.returncode:
        result['exit_status'] |= 2
    result['events'] = lab.events
    lab.save_json('boot-after', boot_context())
    lab.save_json('result', result)
    print(json.dumps({k: v for k, v in result.items() if k not in {'events', 'enumeration_hook_candidates'}}, indent=2))
    print('Reports saved to: ' + str(lab.output), flush=True)
    if result['reboot_required']:
        print('REBOOT REQUIRED before the next sample, including after Caraxes unload.', flush=True)
    print('0=directory behaviour and hook evidence observed; 1=no matching hook finding; 2=incomplete/unexercised; 3=both.', flush=True)
    return result['exit_status']


if __name__ == '__main__':
    sys.exit(main())
