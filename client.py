#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read per-open lkmrkdet reports; add a namespace/identity-aware PID comparison."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import sys
import time
sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace_evidence

CLIENT_VERSION = '0.3.0'

CHECKS = {'modules': 1, 'filesystem': 2, 'network': 4, 'syscalls': 8, 'processes': 16, 'ftrace': 32}
STATUSES = {'OK', 'SUSPICIOUS', 'UNSUPPORTED', 'ERROR', 'INFO'}
REPORT_LIMIT = 2 * 1024 * 1024
SAVED_REPORT_LIMIT = 8 * 1024 * 1024  # client indentation and PID evidence add size
MAX_RECORDS = 512


def checks_argument(value):
    if value == 'all':
        return value
    names = value.split(',')
    if not names or len(set(names)) != len(names) or any(n not in CHECKS for n in names):
        raise argparse.ArgumentTypeError('Use all or distinct names: ' + ','.join(CHECKS))
    return value


def validate_report(report):
    if not isinstance(report, dict) or report.get('schema') != 1:
        raise ValueError('Unsupported or missing report schema')
    for name in ['scanned', 'truncated', 'tasks_complete']:
        if type(report.get(name)) is not bool:
            raise ValueError(f'Missing boolean field {name}')
    for name in ['pid_comparison_complete', 'ftrace_complete']:
        if name in report and type(report[name]) is not bool:
            raise ValueError(f'Invalid boolean field {name}')
    for name in ['checks', 'pid_ns', 'net_ns', 'resolver_error', 'module_count',
                 'started_ns', 'finished_ns']:
        if type(report.get(name)) is not int:
            raise ValueError(f'Missing integer field {name}')
    for name in ['kernel', 'arch', 'version']:
        if not isinstance(report.get(name), str):
            raise ValueError(f'Missing string field {name}')
    records = report.get('records')
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError('Invalid record list')
    for record in records:
        if not isinstance(record, dict) or record.get('status') not in STATUSES:
            raise ValueError('Invalid record status')
        for name in ['check', 'target', 'code', 'detail']:
            if not isinstance(record.get(name), str):
                raise ValueError(f'Invalid record field {name}')
    tasks = report.get('tasks')
    if not isinstance(tasks, list) or len(tasks) > 8192:
        raise ValueError('Invalid task snapshot')
    seen = set()
    for task in tasks:
        if not isinstance(task, dict) or type(task.get('pid')) is not int or task['pid'] <= 0:
            raise ValueError('Invalid task PID')
        if task['pid'] in seen:
            raise ValueError('Duplicate task PID; snapshot is inconsistent')
        seen.add(task['pid'])
        if type(task.get('start_ns')) is not int or task['start_ns'] < 0:
            raise ValueError('Invalid task start time')
        if not isinstance(task.get('comm'), str):
            raise ValueError('Invalid task name')
    if report['checks'] & ~sum(CHECKS.values()):
        raise ValueError('Unknown check-mask bits')
    return report


def read_report(fd):
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > REPORT_LIMIT:
            raise ValueError('Report exceeds bounded size')
        chunks.append(chunk)
    return validate_report(json.loads(b''.join(chunks)))


def enumerate_pids(proc=Path('/proc')):
    # Numeric top-level proc directories correspond to thread-group leaders.
    with os.scandir(proc) as entries:
        return {int(entry.name) for entry in entries if entry.name.isascii() and entry.name.isdigit()}


def namespace_id(proc=Path('/proc')):
    link = os.readlink(proc / 'self/ns/pid')
    match = re.fullmatch(r'pid:\[(\d+)\]', link)
    if not match:
        raise ValueError('Cannot interpret PID namespace identity')
    return int(match[1])


def parse_stat_start(text):
    # comm may contain spaces, newlines and parentheses; fields follow LAST ).
    _, separator, rest = text.rpartition(')')
    if not separator:
        raise ValueError('Malformed proc stat record')
    fields = rest.split()
    if len(fields) < 20:
        raise ValueError('Truncated proc stat record')
    return int(fields[19])  # field 22, with rest beginning at field 3


def result(check, target, status, code, detail):
    return {'check': check, 'target': str(target), 'status': status,
            'code': code, 'detail': detail}


def process_findings(report, before, after, read_start, hz, revalidate=None):
    """Require direct identity or later matching kernel birth identity, not kill(0).

    Revalidation is a fresh process-only transaction AFTER failed direct lookups.
    It distinguishes persistent task/proc discrepancies from exit/reuse; neither
    kernel snapshot is an independent trust source.
    """
    if not report['tasks_complete']:
        return [result('processes', 'cross-view', 'UNSUPPORTED', 'snapshot_incomplete',
                       'No complete kernel task snapshot; proc comparison not performed.')]
    findings = []
    pending = []
    compared = 0
    for task in report['tasks']:
        pid = task['pid']
        if pid in before or pid in after:
            continue
        compared += 1
        try:
            ticks = read_start(pid)
        except (FileNotFoundError, ProcessLookupError):
            pending.append((task, len(findings)))
            findings.append(result('processes', pid, 'INFO', 'lifecycle_inconclusive',
                                   'Absent from both enumerations; direct lookup no longer exists. Exit or lookup hiding cannot be distinguished.'))
            continue
        except (OSError, ValueError) as exc:
            findings.append(result('processes', pid, 'ERROR', 'identity_unavailable', str(exc)))
            continue
        expected = task['start_ns'] * hz // 1_000_000_000
        if ticks != expected:
            findings.append(result('processes', pid, 'INFO', 'identity_changed',
                                   'Direct lookup has a different start time; PID reuse or timing prevents attribution.'))
            continue
        finding = result('processes', pid, 'SUSPICIOUS', 'missing_from_proc_enumeration',
                         f'Kernel snapshot contains {task["comm"]!r}; direct proc lookup matches its start time, but both numeric enumerations omit it.')
        finding['identity_source'] = 'direct_proc_stat'
        findings.append(finding)
    if pending and revalidate is not None:
        try:
            confirmation = validate_report(revalidate())
            if (not confirmation['scanned'] or confirmation['checks'] != CHECKS['processes'] or
                    any(confirmation[key] != report[key] for key in ['kernel', 'arch', 'version']) or
                    confirmation['pid_ns'] != report['pid_ns'] or not confirmation['tasks_complete'] or
                    confirmation['truncated'] or confirmation['started_ns'] <= report['finished_ns'] or
                    confirmation['finished_ns'] < confirmation['started_ns'] or
                    not any(r['check'] == 'processes' for r in confirmation['records']) or
                    any(r['check'] == 'processes' and r['status'] in {'ERROR', 'UNSUPPORTED'}
                        for r in confirmation['records'])):
                raise ValueError('Process revalidation is incomplete, stale or namespace-mismatched')
            confirmed_tasks = {task['pid']: task for task in confirmation['tasks']}
        except (OSError, ValueError, KeyError, TypeError) as exc:
            for task, index in pending:
                findings[index] = result('processes', task['pid'], 'ERROR', 'revalidation_unavailable', str(exc))
        else:
            for task, index in pending:
                confirmed = confirmed_tasks.get(task['pid'])
                if confirmed is None:
                    findings[index]['detail'] += ' The later kernel snapshot also lacks this task; exit remains inconclusive.'
                elif confirmed['start_ns'] != task['start_ns']:
                    findings[index] = result('processes', task['pid'], 'INFO', 'identity_changed',
                                             'Later kernel snapshot has a different birth time; PID reuse prevents attribution.')
                else:
                    finding = result('processes', task['pid'], 'SUSPICIOUS', 'missing_from_proc_enumeration',
                                     'Both proc enumerations omit this PID and direct lookup is unavailable, but a later kernel '
                                     'snapshot retains the same PID, namespace and nanosecond birth identity. '
                                     'This is corroborated same-kernel evidence, not independent attestation.')
                    finding.update(identity_source='kernel_task_revalidation',
                                   revalidation={'started_ns': confirmation['started_ns'],
                                                 'finished_ns': confirmation['finished_ns'],
                                                 'pid_ns': confirmation['pid_ns'], 'start_ns': confirmed['start_ns']})
                    findings[index] = finding
    if not compared:
        findings.append(result('processes', 'cross-view', 'OK', 'enumeration_consistent',
                                'Every kernel-snapshot leader appeared in at least one bracketing proc enumeration. Task-list DKOM is not covered.'))
    return findings


def add_records(report, records):
    room = MAX_RECORDS - len(report['records'])
    if len(records) > room:
        report['truncated'] = True
    report['records'].extend(records[:room])


def request(command, endpoint=Path('/proc/lkmrkdet'), compare_processes=False):
    expected_mask = 0
    if command.startswith('scan '):
        names = checks_argument(command[5:])
        expected_mask = sum(CHECKS.values()) if names == 'all' else sum(CHECKS[n] for n in names.split(','))
    tracing = trace_evidence.snapshot() if expected_mask & CHECKS['ftrace'] else None
    before = enumerate_pids() if compare_processes else None
    ns_before = namespace_id() if compare_processes else None
    fd = os.open(endpoint, os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        payload = (command + '\n').encode('ascii')
        if os.write(fd, payload) != len(payload):
            raise OSError('Short write to detector interface')
        os.lseek(fd, 0, os.SEEK_SET)
        report = read_report(fd)
    finally:
        os.close(fd)
    if report['checks'] != expected_mask or report['scanned'] != bool(expected_mask):
        raise ValueError('Detector did not acknowledge the requested checks')
    report['collected_utc'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())
    report['client_version'] = CLIENT_VERSION
    if compare_processes:
        after = enumerate_pids()
        ns_after = namespace_id()
        if report['pid_ns'] != ns_before or ns_after != ns_before:
            report['pid_comparison_complete'] = False
            add_records(report, [result('processes', 'cross-view', 'ERROR', 'namespace_mismatch',
                                       'Kernel snapshot and proc namespace identity do not agree.')])
        else:
            def read_start(pid):
                return parse_stat_start(Path(f'/proc/{pid}/stat').read_text())
            findings = process_findings(report, before, after, read_start,
                                        os.sysconf('SC_CLK_TCK'),
                                        revalidate=lambda: request('scan processes', endpoint))
            add_records(report, findings)
            report['pid_comparison_complete'] = report['tasks_complete']
    if tracing is not None:
        after_trace = trace_evidence.snapshot()
        findings, complete = trace_evidence.assess(tracing, after_trace)
        report['ftrace'] = {'before': tracing, 'after': after_trace}
        report['ftrace_complete'] = complete
        trace_evidence.correlate_entry_calls(report['records'], tracing, after_trace)
        add_records(report, findings)
    return report


def exit_status(report):
    if not report['scanned']:
        return 0
    suspicious = any(r['status'] == 'SUSPICIOUS' for r in report['records'])
    incomplete = report['truncated'] or any(r['status'] in {'ERROR', 'UNSUPPORTED'} for r in report['records'])
    # Process candidates that could not be attributed are explicitly incomplete.
    incomplete |= any(r['code'] in {'lifecycle_inconclusive', 'identity_changed'} for r in report['records'])
    requested = {name for name, bit in CHECKS.items() if report['checks'] & bit}
    covered = {r['check'] for r in report['records']}
    incomplete |= not requested.issubset(covered)
    if 'processes' in requested and (not report['tasks_complete'] or
                                    not report.get('pid_comparison_complete', False)):
        incomplete = True
    if 'ftrace' in requested and not report.get('ftrace_complete', False):
        incomplete = True
    return int(suspicious) | (2 if incomplete else 0)


def display(report, verbose=False):
    print(f'lkmrkdet {report["version"]} | client {report.get("client_version", "not recorded")} | '
          f'{report["kernel"]} | {report["arch"]}')
    print(f'Resolved symbols: {"yes" if report["resolver_error"] == 0 else "unavailable"}; '
          f'observed LIVE modules: {report["module_count"]}')
    if report['scanned']:
        elapsed = (report['finished_ns'] - report['started_ns']) / 1_000_000
        print(f'Scan: {elapsed:.2f} ms | PID namespace {report["pid_ns"]} | network namespace {report["net_ns"]}')
    for record in report['records']:
        if record['status'] == 'OK' and not verbose:
            continue
        print(safe_text(f'[{record["status"]}] {record["check"]}: {record["target"]} — {record["code"]}'))
        if record.get('address') not in {None, '0x0'}:
            print(safe_text(f'  {record["address"]} {record.get("symbol", "")} | owner: {record.get("owner", "")}'))
        print('  ' + safe_text(record['detail']))
        if record.get('tracefs_callback'):
            print('  Tracefs callback: ' + safe_text(record['tracefs_callback']) +
                  ' | flags: ' + safe_text(record['tracefs_flags']))
    counts = Counter(r['status'] for r in report['records'])
    print('Records: ' + ', '.join(f'{name}={counts[name]}' for name in ['OK', 'SUSPICIOUS', 'UNSUPPORTED', 'ERROR', 'INFO']))
    if report['scanned']:
        code = exit_status(report)
        if code & 1:
            print('Suspicious evidence observed; investigate and corroborate.')
        elif code & 2:
            print('Inspection incomplete; absence of findings is not a clean result.')
        else:
            print('No anomaly observed within the selected checks; kernel integrity is NOT established.')
        if code & 2:
            print('Some requested observations were unsupported, failed, truncated or inconclusive.')


def safe_text(text):
    """Do not let names read from an untrusted kernel inject terminal controls."""
    return ''.join(f'\\x{ord(c):02x}' if ord(c) < 32 or 0x7f <= ord(c) <= 0x9f else c for c in text)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ['status', 'scan', 'show']:
        p = commands.add_parser(name)
        p.add_argument('--format', choices=['text', 'json'], default='text')
        p.add_argument('--verbose', action='store_true')
        if name == 'scan':
            p.add_argument('--checks', type=checks_argument, default='all')
        if name == 'show':
            p.add_argument('report', type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'show':
            if args.report.stat().st_size > SAVED_REPORT_LIMIT:
                raise ValueError('Report exceeds bounded size')
            report = validate_report(json.loads(args.report.read_text()))
        else:
            if os.geteuid() != 0:
                raise PermissionError('Use sudo to access the root-restricted detector interface.')
            checks = args.checks if args.command == 'scan' else ''
            report = request('scan ' + checks if checks else 'status',
                             compare_processes=checks == 'all' or 'processes' in checks.split(','))
        if args.format == 'json':
            print(json.dumps(report, indent=2, ensure_ascii=True))
        else:
            display(report, args.verbose)
        return exit_status(report)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f'lkmrkdet: inspection failed: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
