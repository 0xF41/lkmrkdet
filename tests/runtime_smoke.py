#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Privileged interface tests; run after explicitly loading lkmrkdet.ko."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import errno
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('client', ROOT / 'client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)
ENDPOINT = '/proc/lkmrkdet'


def rejection(payload, expected=errno.EINVAL):
    fd = os.open(ENDPOINT, os.O_RDWR | os.O_CLOEXEC)
    try:
        try:
            os.write(fd, payload)
        except OSError as exc:
            assert exc.errno == expected, (payload, exc)
        else:
            raise AssertionError(f'Request accepted unexpectedly: {payload!r}')
    finally:
        os.close(fd)


def partial_reads():
    fd = os.open(ENDPOINT, os.O_RDWR | os.O_CLOEXEC)
    try:
        os.write(fd, b'status\n')
        os.lseek(fd, 0, os.SEEK_SET)
        prefix = os.read(fd, 7)
        pieces = [prefix]
        while chunk := os.read(fd, 113):
            pieces.append(chunk)
        client.validate_report(json.loads(b''.join(pieces)))
        assert os.read(fd, 1) == b''
    finally:
        os.close(fd)


def one_scan_per_open():
    fd = os.open(ENDPOINT, os.O_RDWR | os.O_CLOEXEC)
    try:
        os.write(fd, b'scan processes\n')
        os.lseek(fd, 0, os.SEEK_SET)
        assert client.read_report(fd)['checks'] == client.CHECKS['processes']
        try:
            os.write(fd, b'scan modules\n')
        except OSError as exc:
            assert exc.errno == errno.EALREADY, exc
        else:
            raise AssertionError('A second scan was accepted on the same descriptor')
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-clean', action='store_true',
                        help='Additionally require complete, non-suspicious kernel checks')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo after loading the detector.')
    for payload in [b'x' * 128, b'scan', b'scan nope', b'scan modules,modules',
                    b'scan modules,', b'status\x00scan all', b'scan all,modules',
                    b'scan /etc/passwd', b'scan processes\nscan modules']:
        rejection(payload)
    partial_reads()
    one_scan_per_open()
    with ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(lambda _: client.request('status'), range(24)))
    assert all(not report['scanned'] for report in statuses)

    child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'])
    try:
        report = client.request('scan all', compare_processes=True)
        if args.expect_clean:
            assert client.exit_status(report) == 0, report['records']
        assert any(task['pid'] == child.pid for task in report['tasks']), 'Known child absent from kernel task snapshot'
        assert not any(record['check'] == 'processes' and record['target'] == str(child.pid)
                       and record['status'] == 'SUSPICIOUS' for record in report['records'])
        for _ in range(5):
            repeated = client.request('scan filesystem,network,modules,syscalls')
            client.validate_report(repeated)
        if args.expect_clean:
            assert client.exit_status(repeated) == 0, repeated['records']
        client.display(report, verbose=True)
    finally:
        child.terminate()
        child.wait(timeout=10)
    print('Runtime interface tests passed: malformed requests, partial reads/EOF, transaction isolation, concurrency, known process and repeated scans.')
    print('Review kernel logs separately for warnings; this is not a rootkit-coverage test.')


if __name__ == '__main__':
    main()
