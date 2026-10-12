#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Controlled lab test of an existing, unmodified Caraxes checkout and lkmrkdet.

Loads the pinned sample only when this script is explicitly run as root. Verifies
hiding of owned canaries, captures detector evidence, then unloads both modules.
No kernel patching or sample implementation is performed by this runner.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tempfile
import traceback
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import client
from scripts.report_context import boot_context, capture_tracefs, require_reboot_after_sample

REVIEWED_COMMIT = '899e8be6b5f6c7236bd23b52aa65051de757e0b3'


def no_comments(text):
    # Only used on the pinned sample's simple configuration/initialization files.
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)


def sample_configuration(directory):
    rootkit = no_comments((directory / 'rootkit.h').read_text())
    init = no_comments((directory / 'caraxes.c').read_text())
    hooks = no_comments((directory / 'hooks.h').read_text())
    magic = re.search(r'\bMAGIC_WORD\s*=\s*"([A-Za-z0-9_-]+)"\s*;', rootkit)
    uid = re.search(r'\bUSER_HIDE\s*=\s*(\d+)\s*;', rootkit)
    gid = re.search(r'\bGROUP_HIDE\s*=\s*(\d+)\s*;', rootkit)
    if not magic or not uid or not gid:
        raise ValueError('Unrecognised sample configuration; inspect the source before updating this test.')
    if re.search(r'\bhide_module\s*\(', init):
        raise ValueError('This test requires the sample to keep its module registration for ordinary cleanup.')
    if 'HOOK("sys_getdents64"' not in hooks or 'hooks_filldir.h' in hooks:
        raise ValueError('This case covers the reviewed getdents64 configuration only.')
    config = {'magic_word': magic[1], 'hidden_uid': int(uid[1]), 'hidden_gid': int(gid[1])}
    if config['hidden_uid'] in {0, os.getuid(), int(os.environ.get('SUDO_UID', '-1'))}:
        raise ValueError('The canary UID must differ from root and the managing user.')
    if config['hidden_gid'] == 0 or len(config['magic_word']) > 32:
        raise ValueError('Unsupported test configuration.')
    return config


def command_text(argv):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=30).strip()


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as file:
        for block in iter(lambda: file.read(65536), b''):
            digest.update(block)
    return digest.hexdigest()


def preflight(directory):
    require_reboot_after_sample(ROOT)
    directory = directory.resolve(strict=True)
    git = ['git', '-c', f'safe.directory={directory}', '-C', str(directory)]
    revision = command_text(git + ['rev-parse', 'HEAD'])
    if revision != REVIEWED_COMMIT:
        raise ValueError(f'Sample revision differs from reviewed {REVIEWED_COMMIT}: {revision}')
    if command_text(git + ['status', '--porcelain', '--untracked-files=no']):
        raise ValueError('Sample tracked files are modified; this case requires the reviewed source.')
    config = sample_configuration(directory)
    release = os.uname().release
    info = {'kernel': release, 'arch': os.uname().machine, 'sample_directory': str(directory),
            'sample_commit': revision, 'config': config, 'boot': boot_context(), 'modules': {}}
    for key, path in [('detector', ROOT / 'lkmrkdet.ko'), ('sample', directory / 'caraxes.ko')]:
        name = command_text(['modinfo', '-F', 'name', str(path)])
        expected = 'lkmrkdet' if key == 'detector' else 'caraxes'
        if name != expected:
            raise ValueError(f'{path} is not the expected module {expected}')
        vermagic = command_text(['modinfo', '-F', 'vermagic', str(path)])
        if not vermagic.startswith(release + ' '):
            raise ValueError(f'{path}: vermagic mismatch: {vermagic}')
        info['modules'][key] = {'path': str(path), 'name': name, 'vermagic': vermagic,
                                'srcversion': command_text(['modinfo', '-F', 'srcversion', str(path)]),
                                'sha256': sha256(path)}
    # Tracked-source identity and binary identity are both recorded. A source
    # commit alone does not prove how an existing .ko was built.
    info['source_sha256'] = {p.name: sha256(p) for p in sorted(directory.iterdir())
                             if p.is_file() and (p.suffix in {'.c', '.h'} or p.name == 'Makefile')
                             and not p.name.endswith('.mod.c')}
    rows = Path('/proc/modules').read_text().splitlines()
    visible = {line.split()[0] for line in rows if line.split()}
    for name in ['caraxes', 'lkmrkdet', 'diamorphine', 'singularity']:
        if name in visible or (Path('/sys/module') / name).exists():
            raise ValueError(f'{name} is already present; use a fresh lab baseline for this case.')
    if Path('/proc/lkmrkdet').exists():
        raise ValueError('Detector interface already present.')
    info['preflight_observation'] = 'No listed sample/detector seen; this is not an attestation.'
    return info


def present(observation, kind):
    record = observation[kind]
    return (record.get('visible') is True and record.get('identity_match') is True
            and record.get('alive' if kind == 'process' else 'content_match') is True)


def hiding_state(first, second, kind):
    records = [first[kind], second[kind]]
    if not all(r.get('identity_match') is True and
               r.get('alive' if kind == 'process' else 'content_match') is True for r in records):
        return 'INCONCLUSIVE'
    if all(r.get('visible') is False for r in records):
        return 'CONFIRMED'
    if all(r.get('visible') is True for r in records):
        return 'NOT_OBSERVED'
    return 'INCONCLUSIVE'


def comparison(before, first, active, second, restored, recovery, pid):
    file_kinds = ['file'] + (['owner_file'] if 'owner_file' in before else [])
    file_states = {kind: hiding_state(first, second, kind) for kind in file_kinds}
    file_state = ('CONFIRMED' if 'CONFIRMED' in file_states.values() else
                  'INCONCLUSIVE' if 'INCONCLUSIVE' in file_states.values() else 'NOT_OBSERVED')
    process_state = hiding_state(first, second, 'process')
    records = active['records']
    matching = [r for r in records if r['check'] == 'processes' and
                r['target'] == str(pid) and r['status'] == 'SUSPICIOUS' and
                r['code'] == 'missing_from_proc_enumeration']
    if process_state != 'CONFIRMED':
        detection = 'NOT_EXERCISED' if process_state == 'NOT_OBSERVED' else 'INCONCLUSIVE'
    elif matching:
        detection = 'DETECTED'
    elif client.exit_status(active) & 2:
        detection = 'INCONCLUSIVE'
    else:
        detection = 'MISSED'
    canaries = file_kinds + ['process'] + (['control_file'] if 'control_file' in before else [])
    baseline_visible = all(present(before, kind) for kind in canaries)
    visibility_restored = all(present(restored, kind) for kind in canaries)
    control_intact = ('control_file' not in before or
                      (present(first, 'control_file') and present(second, 'control_file')))
    outcome = 1 if detection == 'MISSED' else 0
    if (not baseline_visible or not visibility_restored or not control_intact or file_state != 'CONFIRMED' or
            detection in {'INCONCLUSIVE', 'NOT_EXERCISED'} or
            client.exit_status(active) & 2 or client.exit_status(recovery) != 0):
        outcome |= 2
    return {
        'exit_status': outcome,
        'file_hiding': file_state,
        'file_hiding_by_fixture': file_states,
        'process_hiding': process_state,
        'process_detection': detection,
        'canaries_visible_before': baseline_visible,
        'canaries_visible_after_unload': visibility_restored,
        'untargeted_control_intact': control_intact,
        'file_content_detector': 'NOT_TESTED: inodeyou-cpp is separate',
        'ftrace_registration_inspection': ('TRACEFS_OBSERVED' if active.get('ftrace_complete') else
                                         'UNAVAILABLE_OR_NOT_REQUESTED'),
        'ftrace_candidates': [r for r in records if r['check'] == 'ftrace' and r['status'] == 'SUSPICIOUS'],
        'active_detector_exit_status': client.exit_status(active),
        'recovery_detector_exit_status': client.exit_status(recovery),
        'process_findings': matching,
        'kernel_candidates': [r for r in records if r['check'] != 'processes' and r['status'] == 'SUSPICIOUS'],
        'interpretation': ('Module registration consistency is not a benign-module classifier. '
                           'Process discrepancy and hook attribution are separate results. '
                           'Tracefs attribution still relies on the guest kernel.'),
    }


def execute_case(lab, order):
    """Orchestrated separately so failure and cleanup paths can be tested."""
    result = {'exit_status': 2, 'detector_order': order}
    try:
        lab.setup()
        before = lab.observe('before')
        baseline_kinds = ['file', 'process'] + [kind for kind in ['owner_file', 'control_file'] if kind in before]
        if not all(present(before, kind) for kind in baseline_kinds):
            raise RuntimeError('Canaries are not consistently visible in the baseline.')
        lab.load('detector')
        baseline = lab.scan('before')
        if client.exit_status(baseline) != 0:
            raise RuntimeError('Baseline detector scan is anomalous or incomplete; sample was not loaded.')
        if order == 'after':
            lab.unload('detector')
        lab.load('sample')
        if order == 'after':
            lab.load('detector')
        first = lab.observe('active-before-scan')
        active = lab.scan('active')
        second = lab.observe('active-after-scan')
        lab.unload('sample')
        restored = lab.observe('restored')
        recovery = lab.scan('restored')
        result.update(comparison(before, first, active, second, restored, recovery, lab.child.pid))
    except (Exception, KeyboardInterrupt) as exc:
        result['error'] = str(exc) or type(exc).__name__
        lab.save('failure.txt', traceback.format_exc())
    finally:
        errors = lab.cleanup()
        result['cleanup_errors'] = errors
        if errors:
            result['exit_status'] |= 2
    return result


class Lab:
    def __init__(self, metadata):
        self.metadata = metadata
        self.loaded = set()
        self.child = None
        self.fixture_dir = None
        self.files = {}
        self.events = []
        self.owner = ROOT.stat()
        reports = ROOT / 'reports'
        if not reports.exists():
            reports.mkdir(mode=0o700)
            os.chown(reports, self.owner.st_uid, self.owner.st_gid)
        self.output = reports / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') +
                                 '-controlled-' + uuid.uuid4().hex[:8])
        self.output.mkdir(mode=0o700)
        os.chown(self.output, self.owner.st_uid, self.owner.st_gid)
        self.sequence = 0

    def save(self, name, text):
        fd = os.open(self.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as file:
            os.fchown(file.fileno(), self.owner.st_uid, self.owner.st_gid)
            file.write(text if isinstance(text, bytes) else text.encode('utf-8'))

    def save_json(self, name, value):
        self.save(name + '.json', json.dumps(value, indent=2, ensure_ascii=True) + '\n')

    def run(self, label, argv, timeout=60):
        self.sequence += 1
        stem = f'{self.sequence:02d}-{label}'
        event = {'label': label, 'argv': argv, 'utc': datetime.now(timezone.utc).isoformat()}
        try:
            completed = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                                       errors='replace', timeout=timeout)
            stdout, stderr, code = completed.stdout, completed.stderr, completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b''
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors='replace')
            stderr, code = 'Timed out; inspect VM console.\n', 124
        except OSError as exc:
            stdout, stderr, code = '', str(exc), 127
        event.update(returncode=code, stdout=stem + '.stdout', stderr=stem + '.stderr')
        self.events.append(event)
        self.save(event['stdout'], stdout)
        self.save(event['stderr'], stderr)
        print(f'{label}: exit {code}', flush=True)
        return subprocess.CompletedProcess(argv, code, stdout, stderr)

    def load(self, key):
        info = self.metadata['modules'][key]
        # No rebuilding, patching, parameters or auto-persistence installation.
        if self.run('load-' + key, ['insmod', info['path']]).returncode:
            raise RuntimeError(f'Could not load {key}; see command logs.')
        self.loaded.add(key)
        path = Path('/sys/module') / info['name'] / 'srcversion'
        if path.read_text().strip() != info['srcversion']:
            raise RuntimeError(f'{key} loaded identity does not match the recorded build.')

    def unload(self, key):
        if key not in self.loaded:
            return
        name = self.metadata['modules'][key]['name']
        if self.run('unload-' + key, ['rmmod', name], timeout=30).returncode:
            raise RuntimeError(f'Could not unload {name}; inspect VM console and restore the snapshot if needed.')
        self.loaded.remove(key)

    def setup(self):
        self.fixture_dir = Path(tempfile.mkdtemp(prefix='lkmrkdet-canaries-'))
        self.payload = ('STANDCON validation canary ' + uuid.uuid4().hex + '\n').encode('ascii')
        uid = self.metadata['config']['hidden_uid']
        # Separate name hiding from ownership hiding, plus an untargeted control.
        for kind, name, owner in [('file', 'probe_' + self.metadata['config']['magic_word'] + '.txt', 0),
                                  ('owner_file', 'ownership_probe.txt', uid),
                                  ('control_file', 'ordinary_control.txt', 0)]:
            path = self.fixture_dir / name
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self.files[kind] = {'path': path, 'fd': fd}
            if os.write(fd, self.payload) != len(self.payload):
                raise RuntimeError('Could not create complete file canary.')
            if owner:
                os.fchown(fd, owner, owner)
            stat = os.fstat(fd)
            self.files[kind]['identity'] = (stat.st_dev, stat.st_ino)
            self.files[kind]['uid'] = stat.st_uid
            self.files[kind]['gid'] = stat.st_gid
        # Only this disposable child changes identity; no accounts or system
        # ownership are modified, and the SSH management user is not targeted.
        self.child = subprocess.Popen(
            [sys.executable, '-I', '-u', '-c',
             'import os,json,time; print(json.dumps({"pid":os.getpid(),"uid":os.getuid(),"gid":os.getgid()}),flush=True); time.sleep(300)'],
            cwd='/', user=uid, group=uid, extra_groups=(), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True)
        if not select.select([self.child.stdout], [], [], 10)[0]:
            raise RuntimeError('Timed out waiting for canary readiness.')
        ready = json.loads(self.child.stdout.readline(512))
        if ready['pid'] != self.child.pid or ready['uid'] != uid or ready['gid'] != uid:
            raise RuntimeError('Canary identity does not match.')
        self.start_ticks = client.parse_stat_start(Path(f'/proc/{self.child.pid}/stat').read_text())
        self.save_json('canaries', {'files': {kind: {'path': str(f['path']), 'dev_ino': f['identity'],
                                                   'uid': f['uid'], 'gid': f['gid']}
                                            for kind, f in self.files.items()},
                                   'file_sha256': hashlib.sha256(self.payload).hexdigest(),
                                   'process': ready, 'process_start_ticks': self.start_ticks})

    def observe(self, label):
        observation = {'boot': boot_context(), 'file': {}, 'process': {}}
        if observation['boot']['boot_id'] != self.metadata['boot']['boot_id']:
            raise RuntimeError('Boot identity changed during the experiment.')
        for kind, fixture in self.files.items():
            path = fixture['path']
            observation[kind] = {}
            try:
                names = os.listdir(self.fixture_dir)
                directory_fd = os.open(self.fixture_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    fd_names = os.listdir(directory_fd)
                finally:
                    os.close(directory_fd)
                direct_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    stat = os.fstat(direct_fd)
                    direct = os.read(direct_fd, len(self.payload) + 1)
                finally:
                    os.close(direct_fd)
                held = os.pread(fixture['fd'], len(self.payload) + 1, 0)
                observation[kind] = {'visible': path.name in names, 'fd_visible': path.name in fd_names,
                                     'listing': names, 'fd_listing': fd_names,
                                     'identity_match': (stat.st_dev, stat.st_ino) == fixture['identity'],
                                     'content_match': direct == held == self.payload,
                                     'dev_ino': [stat.st_dev, stat.st_ino], 'uid': stat.st_uid, 'gid': stat.st_gid}
            except (OSError, ValueError) as exc:
                observation[kind]['error'] = str(exc)
        try:
            visible = self.child.pid in client.enumerate_pids()
            ticks = client.parse_stat_start(Path(f'/proc/{self.child.pid}/stat').read_text())
            observation['process'] = {'pid': self.child.pid, 'visible': visible,
                                      'identity_match': ticks == self.start_ticks,
                                      'alive': self.child.poll() is None, 'start_ticks': ticks}
        except (OSError, ValueError) as exc:
            observation['process']['error'] = str(exc)
        self.save_json(label + '-canaries', observation)
        self.capture_tracing(label)
        return observation

    def capture_tracing(self, label):
        # Read existing tracefs only: no mount, enabling probes or trace changes.
        evidence, raw = capture_tracefs()
        evidence['matching_lines'] = [line for line in raw.decode(errors='replace').splitlines()
                                      if 'getdents64' in line or 'caraxes' in line]
        self.save(label + '-tracefs.txt', raw)
        self.save_json(label + '-tracing', evidence)

    def scan(self, label):
        completed = self.run(label + '-scan', [sys.executable, str(ROOT / 'client.py'),
                                               'scan', '--format', 'json'], timeout=90)
        if completed.returncode not in {0, 1, 2, 3}:
            raise RuntimeError(f'{label} scan could not complete.')
        report = client.validate_report(json.loads(completed.stdout))
        if report['checks'] != sum(client.CHECKS.values()) or not report['scanned']:
            raise RuntimeError('Full scan was not acknowledged.')
        if client.exit_status(report) != completed.returncode:
            raise RuntimeError('Scan JSON and client exit code disagree.')
        self.save_json(label + '-scan', report)
        return report

    def cleanup(self):
        errors = []
        # Restore reporting first, then unload only modules this case loaded.
        for key in ['sample', 'detector']:
            try:
                self.unload(key)
            except Exception as exc:
                errors.append(str(exc))
        if self.child:
            try:
                if self.child.poll() is None:
                    self.child.terminate()
                    try:
                        self.child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.child.kill()
                        self.child.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                errors.append('child cleanup: ' + str(exc))
            finally:
                self.child.stdout.close()
        for fixture in self.files.values():
            try:
                os.close(fixture['fd'])
                fixture['path'].unlink(missing_ok=True)
            except OSError as exc:
                errors.append('file cleanup: ' + str(exc))
        if self.fixture_dir:
            try:
                # Exact owned paths only, never recursive deletion.
                self.fixture_dir.rmdir()
            except OSError as exc:
                errors.append('file cleanup: ' + str(exc))
        return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sample-dir', type=Path, default=ROOT.parent / 'rootkits/caraxes')
    parser.add_argument('--detector-order', choices=['before', 'after'], default='after',
                        help='Whether detector remains loaded before sample, or reloads afterward (default).')
    parser.add_argument('--preflight', action='store_true', help='Only inspect build/configuration; no root or module loading.')
    args = parser.parse_args()
    if not args.preflight and os.geteuid() != 0:
        parser.error('Run with sudo for the experiment, or use --preflight for read-only inspection.')
    try:
        metadata = preflight(args.sample_dir)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'Preflight failed: {exc}', file=sys.stderr)
        return 2
    metadata['detector_order'] = args.detector_order
    if args.preflight:
        print(json.dumps(metadata, indent=2))
        return 0
    if not metadata['boot']['boot_id']:
        print('Cannot establish boot identity.', file=sys.stderr)
        return 2
    lab = Lab(metadata)
    lab.save_json('environment', metadata)
    print(f'Reports: {lab.output}', flush=True)
    before_log = lab.run('kernel-log-before', ['dmesg', '--color=never'])
    result = execute_case(lab, args.detector_order)
    after_log = lab.run('kernel-log-after', ['dmesg', '--color=never'])
    if before_log.returncode or after_log.returncode:
        result['exit_status'] |= 2
    lab.save_json('boot-after', boot_context())
    result['events'] = lab.events
    lab.save_json('result', result)
    summary = {key: value for key, value in result.items() if key not in {'events', 'kernel_candidates', 'process_findings'}}
    print(json.dumps(summary, indent=2))
    print(f'Reports saved to: {lab.output}')
    print('0=case completed; 1=process hiding missed; 2=incomplete/unexercised case; 3=both. Review kernel logs separately.')
    return result['exit_status']


if __name__ == '__main__':
    sys.exit(main())
