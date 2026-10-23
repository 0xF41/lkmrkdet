#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read per-open lkmrkdet reports; add a namespace/identity-aware PID comparison."""
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

import endpoint
import process_compare
import render
import reporting
import trace_evidence  # re-exported for compatibility
from endpoint import read_report, request
from process_compare import (enumerate_pids, namespace_id, parse_stat_start,
                             process_findings)
from render import (CHECK_TITLES, CODE_LABELS, COLORS, STATUS_STYLES, color_enabled,
                    display, safe_text, styled)
from reporting import (CHECKS, CLIENT_VERSION, MAX_RECORDS, REPORT_LIMIT,
                       SAVED_REPORT_LIMIT, STATUSES, add_records, checks_argument,
                       exit_status, result, validate_report)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ['status', 'scan', 'show']:
        p = commands.add_parser(name)
        p.add_argument('--format', choices=['text', 'json'], default='text')
        p.add_argument('--verbose', action='store_true')
        p.add_argument('--color', choices=['auto', 'always', 'never'], default='auto',
                       help='Text colour: auto for terminals (respects NO_COLOR/TERM=dumb), always, or never. JSON stays plain.')
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
            display(report, args.verbose, color=args.color, saved=args.command == 'show')
        return exit_status(report)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        enabled = args.format != 'json' and color_enabled(args.color, stream=sys.stderr)
        print(styled(f'lkmrkdet: inspection failed: {exc}', 'warning', enabled), file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
