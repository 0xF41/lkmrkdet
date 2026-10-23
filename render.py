# SPDX-License-Identifier: GPL-2.0-only
"""Human-readable rendering for live and saved reports."""
from collections import Counter
import json
import os
import sys
import textwrap

from reporting import CHECKS, exit_status

COLORS = {'heading': '\x1b[1;36m', 'good': '\x1b[32m', 'suspicious': '\x1b[1;91m',
          'warning': '\x1b[33m', 'info': '\x1b[34m', 'dim': '\x1b[2m', 'bold': '\x1b[1m'}
STATUS_STYLES = {'OK': 'good', 'SUSPICIOUS': 'suspicious', 'ERROR': 'warning',
                 'UNSUPPORTED': 'warning', 'INFO': 'info'}
CHECK_TITLES = {'processes': 'PROCESSES', 'modules': 'MODULES', 'network': 'NETWORK',
                'filesystem': 'FILESYSTEM', 'syscalls': 'SYSTEM CALLS', 'ftrace': 'TRACING',
                'status': 'INVENTORY'}
CODE_LABELS = {
    'missing_from_proc_enumeration': 'Missing from proc enumeration',
    'live_kobject_missing_module': 'Module kobject missing from the module list',
    'live_module_missing_kobject': 'Module missing its kobject registration',
    'unexpected_handler': 'Unexpected handler pointer',
    'unexpected_code_owner': 'Unexpected code owner',
    'x86_call_rel32': 'Function-entry CALL', 'arm64_bl_imm26': 'Function-entry CALL',
    'ipmodify_on_selected_function': 'IPMODIFY tracing registration',
    'lifecycle_inconclusive': 'Process lifetime or lookup is inconclusive',
    'identity_changed': 'Process identity changed',
    'snapshot_for_user_comparison': 'Kernel task snapshot collected',
    'client_collection_required': 'Client tracefs comparison requested',
    'proc_reporting_only': 'Proc network reporting callbacks only',
    'table_is_tracing_metadata': 'Syscall table is tracing metadata',
}


def color_enabled(mode='auto', stream=None, environ=None):
    """Explicit CLI choice wins; automatic colour respects terminal conventions."""
    if mode == 'always':
        return True
    if mode == 'never':
        return False
    stream = sys.stdout if stream is None else stream
    environ = os.environ if environ is None else environ
    return ('NO_COLOR' not in environ and environ.get('TERM') != 'dumb' and
            stream.isatty())


def safe_text(text):
    """Do not let names read from an untrusted kernel inject terminal controls."""
    return ''.join(f'\\x{ord(c):02x}' if ord(c) < 32 or 0x7f <= ord(c) <= 0x9f else c for c in text)


def styled(text, style, enabled):
    # Escape report-controlled terminal sequences BEFORE adding our own codes.
    text = safe_text(str(text))
    return COLORS[style] + text + '\x1b[0m' if enabled else text


def display(report, verbose=False, color='auto', saved=False):
    enabled = color_enabled(color)
    def paint(text, style='dim'):
        return styled(text, style, enabled)

    print(paint('lkmrkdet', 'heading'))
    print(paint(f'Kernel module {report["version"]} | Client {report.get("client_version", "not recorded")}', 'bold'))
    print(paint(f'{report["kernel"]} | {report["arch"]}'))
    if saved:
        print(paint('Saved report - not a live scan'))
    print()

    counts = Counter(r['status'] for r in report['records'])
    if report['scanned']:
        code = exit_status(report)
        heading, style = (('SUSPICIOUS EVIDENCE FOUND', 'suspicious') if code & 1 else
                          ('INSPECTION INCOMPLETE', 'warning') if code & 2 else
                          ('NO SUSPICIOUS FINDINGS', 'good'))
        print(paint(heading, style))
        print(' | '.join(paint(f'{counts[status]} {label}', STATUS_STYLES[status] if counts[status] else 'dim')
                         for status, label in [('SUSPICIOUS', 'suspicious'), ('OK', 'OK'),
                                               ('ERROR', 'errors'), ('UNSUPPORTED', 'unsupported'),
                                               ('INFO', 'info')]))
        print(paint('Inspection incomplete' if code & 2 else 'Inspection complete',
                    'warning' if code & 2 else 'good') + paint(f' | Exit code: {code}'))
        elapsed = (report['finished_ns'] - report['started_ns']) / 1_000_000
        print(paint(f'Kernel collection: {elapsed:.2f} ms | Observed LIVE modules: {report["module_count"]}'))
    else:
        print(paint('STATUS - NOT A SCAN', 'info'))
        print(paint(f'Observed LIVE modules: {report["module_count"]}'))
    if verbose or report['resolver_error']:
        print(paint('Symbol resolver: ' + ('available' if report['resolver_error'] == 0 else 'unavailable'),
                    'dim' if report['resolver_error'] == 0 else 'warning'))
    if verbose:
        print(paint(f'PID namespace: {report["pid_ns"]} | Network namespace: {report["net_ns"]}'))

    groups = {check: [] for check in CHECK_TITLES}
    for record in report['records']:
        groups.setdefault(record['check'], []).append(record)
    for check, records in groups.items():
        requested = report['scanned'] and bool(report['checks'] & CHECKS.get(check, 0))
        if not records and not requested:
            continue
        print()
        print(paint(CHECK_TITLES.get(check, check.upper()), 'heading'))
        visible = records if verbose else [r for r in records if r['status'] != 'OK']
        process_incomplete = requested and check == 'processes' and (
            not report['tasks_complete'] or not report.get('pid_comparison_complete', False))
        tracing_incomplete = requested and check == 'ftrace' and not report.get('ftrace_complete', False)
        alarms = any(r['status'] in {'SUSPICIOUS', 'ERROR', 'UNSUPPORTED'} or
                     r['code'] in {'lifecycle_inconclusive', 'identity_changed'} for r in records)
        ok_count = sum(r['status'] == 'OK' for r in records)
        if not verbose and ok_count and not alarms and not (process_incomplete or tracing_incomplete):
            noun = 'observation' if ok_count == 1 else 'observations'
            print('  ' + paint('[OK]', 'good') + f' {ok_count} {noun} without an anomaly')
        if not records:
            print('  ' + paint('[UNSUPPORTED]', 'warning') + ' No observations returned for this check')
        for record in visible:
            status, target, finding = record['status'], record['target'], record['code']
            style = 'warning' if finding in {'lifecycle_inconclusive', 'identity_changed'} else STATUS_STYLES[status]
            if check == 'processes' and target.isascii() and target.isdigit():
                target = 'PID ' + target
            label = CODE_LABELS.get(finding, finding.replace('_', ' ').capitalize())
            print('  ' + paint(f'[{status}]', style) + ' ' + paint(target, 'bold') + ' - ' + paint(label, style))
            detail = record['detail']
            if not verbose and record.get('identity_source') == 'kernel_task_revalidation':
                detail = 'A later kernel snapshot matches the PID and birth identity; direct proc lookup is unavailable.'
            elif not verbose and record.get('identity_source') == 'direct_proc_stat':
                detail = 'Direct proc lookup matches the process start time; both enumerations omit this PID.'
            elif not verbose and record.get('tracefs_callback'):
                detail = ('Entry CALL matches a stable IPMODIFY tracing trampoline.'
                          if 'I' in record.get('tracefs_flags', '') else
                          'Entry CALL matches a stable tracing trampoline.')
            elif not verbose and finding == 'ipmodify_on_selected_function':
                detail = 'This tracing registration can redirect execution; verify whether it is authorised.'
            if verbose or status != 'INFO':
                for line in textwrap.wrap(safe_text(detail), width=92):
                    print('    ' + paint(line))
            if record.get('address') not in {None, '0x0'}:
                print('    ' + paint(f'Address: {record["address"]} | Owner: {record.get("owner") or "unresolved"}'))
                if verbose and record.get('symbol'):
                    print('    ' + paint('Symbol: ' + record['symbol']))
            if record.get('tracefs_callback'):
                print('    ' + paint(f'Tracefs callback: {record["tracefs_callback"]} | Flags: {record.get("tracefs_flags", "")}'))
            elif check == 'ftrace' and record.get('symbol'):
                print('    ' + paint(f'Callback: {record["symbol"]} | Flags: {record.get("flags", "")}'))
            if verbose:
                print('    ' + paint('Code: ' + finding))
                if record.get('revalidation'):
                    print('    ' + paint('Revalidation: ' + json.dumps(record['revalidation'], sort_keys=True)))
        if process_incomplete:
            print('  ' + paint('[UNSUPPORTED]', 'warning') + ' Process comparison is incomplete')
        if tracing_incomplete:
            print('  ' + paint('[UNSUPPORTED]', 'warning') + ' Tracefs comparison is incomplete')

    print()
    if report['scanned']:
        print(paint('Counts are observations, not a count of rootkits. Kernel integrity is not established.'))
    else:
        print(paint('Inventory only. Run scan to inspect for anomalies.'))
