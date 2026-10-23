# SPDX-License-Identifier: GPL-2.0-only
"""Command-line entry point for per-open lkmrkdet reports."""
import argparse
import json
import os
from pathlib import Path
import sys

from .endpoint import request
from .render import color_enabled, display, styled
from .reporting import (CLIENT_VERSION, SAVED_REPORT_LIMIT, exit_status,
                        parse_checks, validate_report)


def checks_argument(value):
    try:
        return parse_checks(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version',
                        version=f'lkmrkdet client {CLIENT_VERSION}')
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
