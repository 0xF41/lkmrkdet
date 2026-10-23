# SPDX-License-Identifier: GPL-2.0-only
"""Bounded /proc/lkmrkdet transactions and trace correlation."""
import json
import os
from pathlib import Path
import time

from . import trace_evidence
from .process_compare import enumerate_pids, namespace_id, parse_stat_start, process_findings
from .reporting import (CHECKS, CLIENT_VERSION, REPORT_LIMIT, add_records,
                        checks_argument, result, validate_report)


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
