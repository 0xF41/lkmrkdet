#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read per-open lkmrkdet reports; add a namespace/identity-aware PID comparison."""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

from lkmrkdet_client import (cli, endpoint, process_compare, render, reporting,
                             trace_evidence)  # noqa: F401
from lkmrkdet_client.cli import main
from lkmrkdet_client.endpoint import read_report, request
from lkmrkdet_client.process_compare import (enumerate_pids, namespace_id,
                                             parse_stat_start, process_findings)
from lkmrkdet_client.render import (CHECK_TITLES, CODE_LABELS, COLORS, STATUS_STYLES,
                                    color_enabled, display, safe_text, styled)
from lkmrkdet_client.reporting import (CHECKS, CLIENT_VERSION, MAX_RECORDS, REPORT_LIMIT,
                                       SAVED_REPORT_LIMIT, STATUSES, add_records,
                                       checks_argument, exit_status, result,
                                       validate_report)


if __name__ == '__main__':
    sys.exit(main())
