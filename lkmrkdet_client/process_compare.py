# SPDX-License-Identifier: GPL-2.0-only
"""Namespace-aware comparison of the kernel task snapshot with proc enumeration."""
import os
from pathlib import Path
import re

from .reporting import CHECKS, result, validate_report


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
