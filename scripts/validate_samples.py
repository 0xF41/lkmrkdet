#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reboot-isolated detection tests of existing Diamorphine/Singularity modules.

No sample source modification, installation scripts, remote-shell triggers or
forced module removal. Run ONE sample, retain reports, reboot before the next.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import socket
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
from scripts.report_context import boot_context, require_reboot_after_sample

SAMPLES = {
    'diamorphine': {'directory': 'Diamorphine', 'revision': 'af494fad213654aae16cfdbbb50e7dc26383e4b2',
                    'filename': 'diamorphine_secret_probe.txt', 'signal': 31, 'settle_seconds': 1},
    'singularity': {'directory': 'Singularity', 'revision': '87875157c4dda767709eb2538708510b8bf7ef00',
                    'filename': 'singularity_probe.txt', 'signal': 59, 'settle_seconds': 7},
}
STATE = ROOT / 'reports' / 'pending-sample-reboot.json'


def preflight(sample, sample_dir=None):
    spec = SAMPLES[sample]
    directory = (sample_dir or ROOT.parent / 'rootkits' / spec['directory']).resolve(strict=True)
    git = ['git', '-c', f'safe.directory={directory}', '-C', str(directory)]
    revision = common.command_text(git + ['rev-parse', 'HEAD'])
    if revision != spec['revision'] or common.command_text(git + ['status', '--porcelain', '--untracked-files=no']):
        raise ValueError('Sample source differs from the reviewed revision; a new review is required.')
    boot = boot_context()
    if not boot['boot_id']:
        raise ValueError('Boot identity unavailable.')
    require_reboot_after_sample(ROOT, boot)
    metadata = {'sample': sample, 'sample_directory': str(directory), 'sample_commit': revision,
                'kernel': os.uname().release, 'arch': os.uname().machine, 'boot': boot,
                'recovery': 'REBOOT_REQUIRED', 'modules': {}}
    for key, path, name in [('detector', ROOT / 'lkmrkdet.ko', 'lkmrkdet'),
                            ('sample', directory / (sample + '.ko'), sample)]:
        if common.command_text(['modinfo', '-F', 'name', str(path)]) != name:
            raise ValueError('Unexpected module name for ' + str(path))
        vermagic = common.command_text(['modinfo', '-F', 'vermagic', str(path)])
        if not vermagic.startswith(metadata['kernel'] + ' '):
            raise ValueError('Module kernel mismatch: ' + str(path))
        metadata['modules'][key] = {'path': str(path), 'name': name, 'vermagic': vermagic,
                                    'srcversion': common.command_text(['modinfo', '-F', 'srcversion', str(path)]),
                                    'sha256': common.sha256(path)}
    metadata['source_sha256'] = {
        str(path.relative_to(directory)): common.sha256(path)
        for path in sorted(directory.rglob('*'))
        if path.is_file() and '.git' not in path.parts and
        (path.suffix in {'.c', '.h'} or path.name == 'Makefile') and not path.name.endswith('.mod.c')
    }
    rows = Path('/proc/modules').read_text().splitlines()
    listed = {line.split()[0] for line in rows if line.split()}
    for name in ['diamorphine', 'singularity', 'caraxes', 'lkmrkdet']:
        if name in listed or (Path('/sys/module') / name).exists():
            raise ValueError(name + ' already visible; establish a reboot-isolated baseline.')
    if Path('/proc/lkmrkdet').exists():
        raise ValueError('Detector already loaded.')
    if sample == 'diamorphine':
        header = (directory / 'diamorphine.h').read_text()
        if '#define MAGIC_PREFIX "diamorphine_secret"' not in header or 'SIGINVIS = 31' not in header:
            raise ValueError('Unexpected Diamorphine controls/configuration.')
        metadata['dispatch_caveat'] = 'On this Ubuntu build, table changes may not intercept live syscalls; score actual behaviour separately.'
    else:
        configuration = (directory / 'include/hiding_directory_def.h').read_text()
        if '"singularity"' not in configuration or '#define PORT 8081' not in (directory / 'modules/hiding_tcp.c').read_text():
            raise ValueError('Unexpected Singularity file/port configuration.')
        metadata['process_control_caveat'] = 'Signal 59 hides caller/parents; only an init-adopted disposable root child may activate it.'
        metadata['observation_caveat'] = 'Sample can filter memory reads, proc/tracefs output and logs. On-host results can be manipulated.'
    return metadata


class Canary:
    """Init-adopted bounded worker, with a pidfd retained BEFORE sample loading."""
    def __init__(self, trigger):
        self.token = uuid.uuid4().hex
        self.control = self.events = self.pidfd = None
        control_read, control_write = os.pipe()
        event_read, event_write = os.pipe()
        self.control, self.events = control_write, event_read
        starter = None
        try:
            try:
                starter = subprocess.Popen([sys.executable, str(ROOT / 'scripts/canary_worker.py'),
                                            '--control-fd', str(control_read), '--event-fd', str(event_write),
                                            '--signal', str(trigger), '--token', self.token],
                                           pass_fds=(control_read, event_write), start_new_session=True,
                                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           cwd='/')
            finally:
                # Do not retain our own writer: worker exit must produce EOF.
                os.close(control_read)
                os.close(event_write)
            starter.wait(timeout=10)
            if starter.returncode:
                raise RuntimeError('Canary starter failed before detachment.')
            ready = self.receive('ready')
            if ready['ppid'] != 1:
                raise ValueError('Canary still has a managing parent; activation refused.')
            self.pid = ready['pid']
            self.pidfd = os.pidfd_open(self.pid)
            self.start_ticks = client.parse_stat_start(Path(f'/proc/{self.pid}/stat').read_text())
            self.heartbeat()
        except BaseException:
            if starter is not None and starter.poll() is None:
                starter.kill()
                starter.wait(timeout=5)
            try:
                self.close()
            except OSError:
                pass
            raise

    def receive(self, expected):
        deadline = time.monotonic() + 5
        raw = b''
        while b'\n' not in raw and len(raw) < 512:
            remaining = max(0, deadline - time.monotonic())
            if not select.select([self.events], [], [], remaining)[0]:
                raise TimeoutError('Canary event missing; independent IPC corroboration unavailable.')
            block = os.read(self.events, 1)
            if not block:
                raise OSError('Canary pipe closed')
            raw += block
        if not raw.endswith(b'\n'):
            raise ValueError('Oversized or unterminated canary event')
        event = json.loads(raw)
        if event['token'] != self.token or event['event'] != expected:
            raise ValueError('Canary event/identity mismatch: ' + repr(event))
        if hasattr(self, 'pid') and event['pid'] != self.pid:
            raise ValueError('Canary PID changed')
        return event

    def heartbeat(self):
        os.write(self.control, b'p')
        return self.receive('heartbeat')

    def activate(self):
        os.write(self.control, b'a')
        return self.receive('activated')

    def close(self):
        try:
            if self.pidfd is not None:
                try:
                    signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)
                    if not select.select([self.pidfd], [], [], 3)[0]:
                        signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                        if not select.select([self.pidfd], [], [], 3)[0]:
                            raise OSError('Owned canary did not exit after pidfd signals')
                except ProcessLookupError:
                    pass
                finally:
                    os.close(self.pidfd)
                    self.pidfd = None
        finally:
            # Closing control also lets a worker without a ready pidfd exit.
            for name in ['control', 'events']:
                fd = getattr(self, name, None)
                if fd is not None:
                    os.close(fd)
                    setattr(self, name, None)


def feature_score(report, check, predicate):
    if report is None:
        return 'INCOMPLETE'
    records = [r for r in report['records'] if r['check'] == check]
    if any(r['status'] == 'SUSPICIOUS' and predicate(r) for r in records):
        return 'DETECTED'
    if (report['truncated'] or not records or
            any(r['status'] in {'ERROR', 'UNSUPPORTED'} or r['code'] in
                {'lifecycle_inconclusive', 'identity_changed'} for r in records)):
        return 'INCOMPLETE'
    if check == 'processes' and (not report.get('tasks_complete') or
                                 not report.get('pid_comparison_complete')):
        return 'INCOMPLETE'
    return 'NO_MATCHING_FINDING'


def hiding_state(first, second, key):
    records = [first[key], second[key]]
    identity_key = 'ipc_identity_match' if key == 'process' else 'held_identity_match'
    if not all(r.get(identity_key) is True and r.get('alive' if key == 'process' else 'held_content_match') is True for r in records):
        return 'INCONCLUSIVE'
    if all(r.get('visible') is False for r in records):
        return 'CONFIRMED'
    if all(r.get('visible') is True for r in records):
        return 'NOT_OBSERVED'
    return 'INCONCLUSIVE'


def present_file(record):
    return all(record.get(key) is True for key in
               ['visible', 'held_identity_match', 'held_content_match',
                'direct_identity_match', 'direct_content_match'])


def canaries_present(observation):
    if not all(present_file(observation[key]) for key in ['file', 'control_file']):
        return False
    if not all(observation['process'].get(key) is True for key in
               ['visible', 'alive', 'ipc_identity_match', 'direct_identity_match']):
        return False
    if 'tcp' in observation:
        return all(all(observation['tcp'].get(name, {}).get(key) is True for key in
                       ['visible_in_proc_tcp', 'held_identity_match', 'roundtrip_ok'])
                   for name in ['target', 'control'])
    return True


def consistent_boolean(records, key, expected):
    if all(record.get(key) is expected for record in records):
        return True
    if all(record.get(key) is (not expected) for record in records):
        return False
    return None


def evaluate(metadata, first, second, report, pid):
    sample = metadata['sample']
    process_hidden = hiding_state(first, second, 'process')
    file_hidden = hiding_state(first, second, 'file')
    control_intact = all(present_file(r['control_file']) for r in [first, second])
    if not control_intact:
        file_hidden = 'INCONCLUSIVE'
    module_unlisted = consistent_boolean([r['module'] for r in [first, second]], 'listed', False)
    sysfs_absent = consistent_boolean([r['module'] for r in [first, second]], 'sysfs_present', False)
    process_detection = feature_score(report, 'processes', lambda r: r['target'] == str(pid) and r['code'] == 'missing_from_proc_enumeration')
    if process_hidden != 'CONFIRMED':
        process_detection = 'NOT_EXERCISED' if process_hidden == 'NOT_OBSERVED' else 'INCONCLUSIVE'
    module_detection = feature_score(report, 'modules', lambda r: r['target'] == sample)
    if module_unlisted is not True:
        module_detection = 'NOT_EXERCISED' if module_unlisted is False else 'INCONCLUSIVE'
    networking = ('NOT_TESTED' if sample != 'singularity' else
                  feature_score(report, 'network', lambda r: r['target'] == '/proc/net/tcp'))
    tcp_hiding = 'NOT_TESTED'
    if sample == 'singularity':
        targets = [r.get('tcp', {}).get('target', {}) for r in [first, second]]
        controls = [r.get('tcp', {}).get('control', {}) for r in [first, second]]
        if all(r.get('held_identity_match') and r.get('roundtrip_ok') for r in targets):
            tcp_hiding = ('CONFIRMED' if all(r.get('visible_in_proc_tcp') is False for r in targets) else
                          'NOT_OBSERVED' if all(r.get('visible_in_proc_tcp') is True for r in targets) else 'INCONCLUSIVE')
        else:
            tcp_hiding = 'INCONCLUSIVE'
        control_ok = all(r.get('visible_in_proc_tcp') is True and r.get('roundtrip_ok') is True and
                         r.get('held_identity_match') is True for r in controls)
        if not control_ok:
            tcp_hiding = 'INCONCLUSIVE'
        if tcp_hiding != 'CONFIRMED':
            networking = 'NOT_EXERCISED' if tcp_hiding == 'NOT_OBSERVED' else 'INCONCLUSIVE'
    ftrace_candidates = [] if report is None else [r for r in report['records'] if r['check'] == 'ftrace' and r['status'] == 'SUSPICIOUS']
    return {'sample': sample, 'file_hiding': file_hidden, 'process_hiding': process_hidden,
            'untargeted_control_intact': control_intact,
            'process_detection': process_detection, 'module_reporting': {'unlisted_after_known_load': module_unlisted,
                                                                        'sysfs_path_absent': sysfs_absent},
            'module_detection': module_detection, 'network_callback_detection': networking,
            'tcp_ipv4_hiding': tcp_hiding,
            'ftrace_candidates': ftrace_candidates,
            'scan_exit_status': None if report is None else client.exit_status(report),
            'any_detector_candidate': report is not None and any(r['status'] == 'SUSPICIOUS' for r in report['records']),
            'file_content_detector': 'NOT_TESTED: inodeyou-cpp separate',
            'trust_caveat': 'Sample may manipulate these on-host observations; IPC/held descriptors corroborate canaries, not whole-kernel integrity.'}


class SampleLab(common.Lab):
    def __init__(self, metadata):
        super().__init__(metadata)
        self.worker = None
        self.sockets = {}
        self.sample_attempted = False
        self.detector_errors = []

    def setup(self):
        self.fixture_dir = Path(tempfile.mkdtemp(prefix='lkmrkdet-fixtures-'))
        self.payload = ('STANDCON canary ' + uuid.uuid4().hex).encode('ascii')
        for key, name in [('file', SAMPLES[self.metadata['sample']]['filename']), ('control_file', 'ordinary_control.txt')]:
            path = self.fixture_dir / name
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            self.files[key] = {'path': path, 'fd': fd}
            if os.write(fd, self.payload) != len(self.payload):
                raise OSError('Short canary-file write')
            stat = os.fstat(fd)
            self.files[key]['identity'] = (stat.st_dev, stat.st_ino)
        self.worker = Canary(SAMPLES[self.metadata['sample']]['signal'])
        if self.metadata['sample'] == 'singularity':
            for key, port in [('target', 8081), ('control', 0)]:
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sockets[key] = listener
                listener.settimeout(2)
                listener.bind(('127.0.0.2', port))
                listener.listen(2)
            self.socket_identity = {key: {'port': sock.getsockname()[1], 'inode': os.fstat(sock.fileno()).st_ino}
                                    for key, sock in self.sockets.items()}
        self.save_json('canaries', {'pid': self.worker.pid, 'start_ticks': self.worker.start_ticks,
                                   'file_sha256': hashlib.sha256(self.payload).hexdigest(),
                                   'files': {k: {'path': str(f['path']), 'dev_ino': f['identity']} for k, f in self.files.items()},
                                   'sockets': getattr(self, 'socket_identity', {})})

    def observe(self, label):
        observation = {'boot': boot_context(), 'file': {}, 'control_file': {}, 'process': {}, 'module': {}}
        if observation['boot']['boot_id'] != self.metadata['boot']['boot_id']:
            raise RuntimeError('Boot identity changed during the experiment.')
        for key, fixture in self.files.items():
            held = os.fstat(fixture['fd'])
            observation[key] = {'held_identity_match': (held.st_dev, held.st_ino) == fixture['identity'],
                                'held_content_match': os.pread(fixture['fd'], len(self.payload) + 1, 0) == self.payload}
            try:
                observation[key]['visible'] = fixture['path'].name in os.listdir(self.fixture_dir)
                direct = os.open(fixture['path'], os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    stat = os.fstat(direct)
                    observation[key]['direct_identity_match'] = (stat.st_dev, stat.st_ino) == fixture['identity']
                    observation[key]['direct_content_match'] = os.read(direct, len(self.payload) + 1) == self.payload
                finally:
                    os.close(direct)
            except OSError as exc:
                observation[key]['direct_or_enumeration_error'] = {'errno': exc.errno, 'message': str(exc)}
        try:
            event = self.worker.heartbeat()
            observation['process'].update(alive=not bool(select.select([self.worker.pidfd], [], [], 0)[0]),
                                          ipc_identity_match=event['pid'] == self.worker.pid and event['ppid'] == 1,
                                          pid=event['pid'], ppid=event['ppid'])
        except (OSError, ValueError, TimeoutError) as exc:
            observation['process']['ipc_error'] = str(exc)
        try:
            observation['process']['visible'] = self.worker.pid in client.enumerate_pids()
            start = client.parse_stat_start(Path(f'/proc/{self.worker.pid}/stat').read_text())
            observation['process']['direct_identity_match'] = start == self.worker.start_ticks
        except (OSError, ValueError) as exc:
            observation['process']['direct_or_enumeration_error'] = str(exc)
        try:
            name = self.metadata['sample']
            rows = Path('/proc/modules').read_text().splitlines()
            observation['module'] = {'listed': any(r.split()[0] == name for r in rows if r.split()),
                                     'sysfs_present': (Path('/sys/module') / name).exists()}
        except OSError as exc:
            observation['module']['error'] = str(exc)
        if self.sockets:
            observation['tcp'] = self.observe_tcp()
        self.save_json(label + '-canaries', observation)
        self.capture_tracing(label)
        return observation

    def observe_tcp(self):
        observation = {}
        try:
            with Path('/proc/net/tcp').open('rb') as file:
                text = file.read(2 * 1024 * 1024 + 1)
            if len(text) > 2 * 1024 * 1024:
                raise ValueError('TCP reporting size limit')
            inodes = {int(row.split()[9]) for row in text.decode('ascii').splitlines()[1:] if len(row.split()) >= 10}
        except (OSError, ValueError) as exc:
            inodes = None
            observation['report_error'] = str(exc)
        for key, listener in self.sockets.items():
            identity = self.socket_identity[key]
            result = {'port': identity['port'], 'inode': identity['inode'],
                      'visible_in_proc_tcp': None if inodes is None else identity['inode'] in inodes,
                      'held_identity_match': os.fstat(listener.fileno()).st_ino == identity['inode']}
            try:
                # Owned loopback sockets only; this is not a shell or remote probe.
                with socket.create_connection(('127.0.0.2', identity['port']), timeout=2) as connection:
                    connection.sendall(self.payload)
                    accepted, _ = listener.accept()
                    with accepted:
                        accepted.settimeout(2)
                        received = b''
                        while len(received) < len(self.payload):
                            part = accepted.recv(len(self.payload) - len(received))
                            if not part:
                                break
                            received += part
                        accepted.sendall(received)
                    returned = b''
                    while len(returned) < len(self.payload):
                        part = connection.recv(len(self.payload) - len(returned))
                        if not part:
                            break
                        returned += part
                    result['roundtrip_ok'] = returned == self.payload
            except OSError as exc:
                result['roundtrip_ok'] = False
                result['error'] = str(exc)
            observation[key] = result
        return observation

    def load_sample(self):
        # Mark the boot dirty BEFORE calling insmod: even failed init may leave
        # partial hooks. Only a different boot ID permits a subsequent sample.
        boot = boot_context()
        if boot['boot_id'] != self.metadata['boot']['boot_id']:
            raise RuntimeError('Boot identity changed before sample load.')
        require_reboot_after_sample(ROOT, boot)
        state = {'boot_id': self.metadata['boot']['boot_id'], 'sample': self.metadata['sample'],
                 'report_directory': str(self.output), 'recovery': 'reboot'}
        tmp = STATE.with_name(STATE.name + '.tmp-' + uuid.uuid4().hex)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as file:
            os.fchown(file.fileno(), self.owner.st_uid, self.owner.st_gid)
            json.dump(state, file)
            file.flush()
            os.fsync(file.fileno())
        os.replace(tmp, STATE)
        self.sample_attempted = True
        completed = self.run('load-sample', ['insmod', self.metadata['modules']['sample']['path']])
        if completed.returncode:
            raise RuntimeError('Sample load failed; possible partial initialization. Preserve logs and reboot.')
        self.loaded.add('sample')
        time.sleep(SAMPLES[self.metadata['sample']]['settle_seconds'])

    def collect_scan(self, label):
        completed = self.run(label + '-scan', [sys.executable, str(ROOT / 'client.py'), 'scan', '--format', 'json'], timeout=30)
        try:
            report = client.validate_report(json.loads(completed.stdout))
            if report['checks'] != sum(client.CHECKS.values()) or not report['scanned']:
                raise ValueError('Full scan not acknowledged')
            if completed.returncode != client.exit_status(report):
                raise ValueError('Exit status and report disagree')
        except (ValueError, TypeError, KeyError) as exc:
            self.save_json(label + '-collection-error', {'error': str(exc), 'returncode': completed.returncode,
                                                       'raw_stdout_preserved': True})
            return None
        self.save_json(label + '-scan', report)
        return report

    def cleanup(self):
        errors = []
        try:
            if self.worker:
                self.worker.close()
        except OSError as exc:
            errors.append('canary cleanup: ' + str(exc))
        for sock in self.sockets.values():
            sock.close()
        # Sample removal is intentionally not attempted: self-hiding is the
        # feature under test, and these checkouts require reboot-isolated recovery.
        if 'detector' in self.loaded:
            try:
                self.unload('detector')
            except Exception as exc:
                errors.append('detector cleanup: ' + str(exc))
        for fixture in self.files.values():
            try:
                os.close(fixture['fd'])
                fixture['path'].unlink(missing_ok=True)
            except OSError as exc:
                errors.append('file cleanup: ' + str(exc))
        if self.fixture_dir:
            try:
                self.fixture_dir.rmdir()
            except OSError as exc:
                errors.append('fixture cleanup: ' + str(exc))
        return errors


def execute(lab, order):
    result = {'sample': lab.metadata['sample'], 'detector_order': order, 'exit_status': 2}
    try:
        lab.setup()
        before = lab.observe('before')
        if not canaries_present(before):
            raise RuntimeError('Baseline canary visibility, identity or activity failed; sample not loaded.')
        lab.load('detector')
        baseline = lab.collect_scan('before')
        if baseline is None or client.exit_status(baseline) != 0:
            raise RuntimeError('Baseline anomalous/incomplete; sample not loaded.')
        if order == 'after':
            lab.unload('detector')
        lab.load_sample()
        if order == 'after':
            try:
                lab.load('detector')
            except Exception as exc:
                lab.detector_errors.append(str(exc))
        lab.save_json('activation', lab.worker.activate())
        first = lab.observe('active-before-scan')
        report = lab.collect_scan('active') if 'detector' in lab.loaded else None
        second = lab.observe('active-after-scan')
        result.update(evaluate(lab.metadata, first, second, report, lab.worker.pid))
        result['exit_status'] = 0 if report is not None and not client.exit_status(report) & 2 else 2
        if any(result[key] == 'NO_MATCHING_FINDING' for key in
                ['process_detection', 'module_detection', 'network_callback_detection']):
            result['exit_status'] |= 1  # explicit feature-level coverage miss
        if (not result['untargeted_control_intact'] or lab.detector_errors or
                any(result[key] in {'INCOMPLETE', 'INCONCLUSIVE'} for key in
                    ['file_hiding', 'process_hiding', 'process_detection', 'module_detection',
                     'network_callback_detection', 'tcp_ipv4_hiding'])):
            result['exit_status'] |= 2
        result['detector_load_errors'] = lab.detector_errors
    except (Exception, KeyboardInterrupt) as exc:
        result['exit_status'] |= 2
        result['error'] = str(exc) or type(exc).__name__
        lab.save('failure.txt', traceback.format_exc())
    finally:
        result['cleanup_errors'] = lab.cleanup()
        result['reboot_required'] = lab.sample_attempted
        result['sample_removed'] = False if lab.sample_attempted else None
        if result['cleanup_errors']:
            result['exit_status'] |= 2
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('sample', choices=SAMPLES)
    parser.add_argument('--sample-dir', type=Path)
    parser.add_argument('--detector-order', choices=['before', 'after'], default='after')
    parser.add_argument('--preflight', action='store_true', help='Read-only inspection; no module loading.')
    args = parser.parse_args()
    if not args.preflight and os.geteuid() != 0:
        parser.error('Use sudo to run the lab test, or --preflight for read-only inspection.')
    try:
        metadata = preflight(args.sample, args.sample_dir)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('Preflight failed: ' + str(exc), file=sys.stderr)
        return 2
    if args.preflight:
        print(json.dumps(metadata, indent=2))
        return 0
    lab = SampleLab(metadata)
    lab.save_json('environment', metadata)
    print('Reports: ' + str(lab.output), flush=True)
    before_log = lab.run('kernel-log-before', ['dmesg', '--color=never'])
    result = execute(lab, args.detector_order)
    after_log = lab.run('kernel-log-after', ['dmesg', '--color=never'])
    if before_log.returncode or after_log.returncode:
        result['exit_status'] |= 2
    lab.save_json('boot-after', boot_context())
    result['events'] = lab.events
    lab.save_json('result', result)
    print(json.dumps({k: v for k, v in result.items() if k not in {'events', 'ftrace_candidates'}}, indent=2))
    print('Reports saved to: ' + str(lab.output), flush=True)
    if result['reboot_required']:
        print('REBOOT REQUIRED before another sample or recovery validation. This script did not remove the rootkit.', flush=True)
    print('0=observations completed; 1=feature-level miss; 2=incomplete case; 3=both. '
          'NOT_EXERCISED/NOT_TESTED features are not coverage passes.', flush=True)
    return result['exit_status']


if __name__ == '__main__':
    sys.exit(main())
