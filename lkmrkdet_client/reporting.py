# SPDX-License-Identifier: GPL-2.0-only
"""Report schema, record helpers, and exit-status semantics."""
import argparse

CLIENT_VERSION = '0.3.1'

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


def result(check, target, status, code, detail):
    return {'check': check, 'target': str(target), 'status': status,
            'code': code, 'detail': detail}


def add_records(report, records):
    room = MAX_RECORDS - len(report['records'])
    if len(records) > room:
        report['truncated'] = True
    report['records'].extend(records[:room])


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
