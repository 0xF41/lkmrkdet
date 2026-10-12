#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Explicit privileged validation; load only this detector, record and clean up."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.report_context import boot_context, capture_tracefs, require_reboot_after_sample


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-clean', action='store_true',
                        help='Require non-suspicious, supported kernel checks on a clean snapshot')
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error('Run with sudo; this explicitly loads the compiled detector.')
    if args.expect_clean:
        try:
            require_reboot_after_sample(ROOT)
        except (OSError, ValueError, KeyError) as exc:
            parser.error(str(exc))
    release = os.uname().release
    module = ROOT / 'lkmrkdet.ko'
    if not module.is_file():
        parser.error(f'Build first: make -C {ROOT} module W=1 KCFLAGS=-Werror')
    vermagic = subprocess.check_output(['modinfo', '-F', 'vermagic', str(module)], text=True)
    if not vermagic.startswith(release + ' '):
        parser.error(f'Module kernel mismatch: {vermagic.strip()} versus {release}')

    # Reports contain addresses and kernel logs. Restrict to the project owner.
    owner = ROOT.stat()
    reports = ROOT / 'reports'
    if not reports.exists():
        reports.mkdir(mode=0o700)
        os.chown(reports, owner.st_uid, owner.st_gid)
    name = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex[:8]
    output = reports / name
    output.mkdir(mode=0o700)
    os.chown(output, owner.st_uid, owner.st_gid)
    events = []
    loaded_here = False
    outcome = 0

    def save(filename, text):
        path = output / filename
        with path.open('xb') as file:
            file.write(text if isinstance(text, bytes) else text.encode('utf-8'))
        path.chmod(0o600)
        os.chown(path, owner.st_uid, owner.st_gid)

    def save_tracefs(label):
        evidence, raw = capture_tracefs()
        save('tracefs-' + label + '.json', json.dumps(evidence, indent=2) + '\n')
        save('tracefs-' + label + '.txt', raw)

    def run(label, argv, timeout=120):
        print(f'Running {label}...', flush=True)
        event = {'label': label, 'argv': argv}
        try:
            result = subprocess.run(argv, cwd=ROOT, capture_output=True,
                                    text=True, errors='replace', timeout=timeout)
            event['returncode'] = result.returncode
            save(label + '.stdout', result.stdout)
            save(label + '.stderr', result.stderr)
        except subprocess.TimeoutExpired as exc:
            event['returncode'] = 124
            save(label + '.stdout', (exc.stdout or b'').decode(errors='replace')
                 if isinstance(exc.stdout, bytes) else (exc.stdout or ''))
            save(label + '.stderr', 'Command timed out. Check VM console and kernel logs.\n')
        except OSError as exc:
            event['returncode'] = 127
            save(label + '.stderr', str(exc) + '\n')
        events.append(event)
        print(f'{label}: exit {event["returncode"]}', flush=True)
        return event['returncode']

    save('environment.json', json.dumps({'kernel': release, 'machine': os.uname().machine,
                                        'vermagic': vermagic.strip(),
                                        'expect_clean': args.expect_clean,
                                        'boot': boot_context()}, indent=2) + '\n')
    if run('kernel-log-before', ['dmesg', '--color=never']):
        outcome |= 2
    save_tracefs('before')
    try:
        if Path('/proc/lkmrkdet').exists():
            loaded_version = Path('/sys/module/lkmrkdet/srcversion')
            disk_version = subprocess.check_output(['modinfo', '-F', 'srcversion', str(module)], text=True).strip()
            if (not loaded_version.is_file() or
                    loaded_version.read_text().strip() != disk_version):
                raise RuntimeError('An older/different detector is already loaded. Unload it yourself before validating this build.')
            print('Using an already-loaded detector; it will remain loaded.', flush=True)
        else:
            code = run('load', ['insmod', str(module)])
            if code:
                raise RuntimeError('Detector load failed; inspect load.stderr and kernel logs.')
            loaded_here = True
        save_tracefs('after-load')
        if run('status', [sys.executable, 'client.py', 'status', '--format', 'json']):
            raise RuntimeError('Status collection failed.')
        code = run('scan', [sys.executable, 'client.py', 'scan', '--format', 'json'])
        save_tracefs('after-scan')
        outcome |= code if code in {0, 1, 2, 3} else 2
        smoke = [sys.executable, 'tests/runtime_smoke.py']
        if args.expect_clean:
            smoke.append('--expect-clean')
        if run('runtime-smoke', smoke):
            outcome |= 2
    except (Exception, KeyboardInterrupt) as exc:
        save('validation-error.txt', str(exc) + '\n')
        print(str(exc), file=sys.stderr)
        outcome |= 2
    finally:
        if loaded_here:
            if run('unload', ['rmmod', 'lkmrkdet'], timeout=30):
                outcome |= 2
        if run('kernel-log-after', ['dmesg', '--color=never']):
            outcome |= 2
        save_tracefs('after')
        save('boot-after.json', json.dumps(boot_context(), indent=2) + '\n')
        save('result.json', json.dumps({'exit_status': outcome, 'loaded_here': loaded_here,
                                      'events': events}, indent=2) + '\n')

    print(f'Reports saved to: {output}', flush=True)
    print('Review kernel-log-before/after for new warnings. A smoke pass is not proof of rootkit coverage.')
    return outcome


if __name__ == '__main__':
    sys.exit(main())
