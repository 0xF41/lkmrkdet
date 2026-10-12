#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""On-host acquisition metadata; useful provenance, not independent attestation."""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import os
import json

TRACEFS_LIMIT = 2 * 1024 * 1024


def require_reboot_after_sample(project_root, boot=None):
    """Do not mix a known reboot-only sample with a claimed clean lab run."""
    state_path = Path(project_root) / 'reports/pending-sample-reboot.json'
    if not state_path.exists():
        return
    with state_path.open('rb') as file:
        raw = file.read(65537)
    if len(raw) > 65536:
        raise ValueError('Sample recovery state exceeds its size limit.')
    state = json.loads(raw)
    if not isinstance(state, dict) or not isinstance(state.get('boot_id'), str) or not state['boot_id']:
        raise ValueError('Invalid sample recovery boot identity: ' + str(state_path))
    current = boot_context() if boot is None else boot
    if not current.get('boot_id') or state['boot_id'] == current['boot_id']:
        raise ValueError('Sample recovery requires a reboot before this test. See ' + str(state_path))


def capture_tracefs(roots=(Path('/sys/kernel/tracing'), Path('/sys/kernel/debug/tracing'))):
    """Preserve bounded raw evidence even if a higher-level parser rejects it."""
    evidence = {'status': 'UNSUPPORTED', 'source': None, 'bytes_read': 0,
                'detail': 'No existing tracefs enabled_functions endpoint.'}
    for root in roots:
        path = root / 'enabled_functions'
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        except OSError as exc:
            evidence.update(status='ERROR', source=str(path), detail=str(exc))
            return evidence, b''
        evidence['source'] = str(path)
        try:
            blocks, length = [], 0
            while length <= TRACEFS_LIMIT:
                block = os.read(fd, min(65536, TRACEFS_LIMIT + 1 - length))
                if not block:
                    break
                blocks.append(block)
                length += len(block)
            raw = b''.join(blocks)
            evidence.update(status='TRUNCATED' if len(raw) > TRACEFS_LIMIT else 'OBSERVED',
                            bytes_read=len(raw), sha256=hashlib.sha256(raw[:TRACEFS_LIMIT]).hexdigest(),
                            detail='Bounded raw capture only; no mount or tracing changes.')
            return evidence, raw[:TRACEFS_LIMIT]
        except OSError as exc:
            evidence.update(status='ERROR', detail=str(exc))
            return evidence, b''
        finally:
            os.close(fd)
    return evidence, b''


def boot_context(proc=Path('/proc')):
    context = {'collected_utc': datetime.now(timezone.utc).isoformat(), 'errors': {}}
    readers = {
        'boot_id': lambda: (proc / 'sys/kernel/random/boot_id').read_text().strip(),
        'uptime_seconds': lambda: float((proc / 'uptime').read_text().split()[0]),
        'kernel_taint': lambda: int((proc / 'sys/kernel/tainted').read_text().strip()),
        'boot_time_unix': lambda: int(next(line.split()[1] for line in
                                         (proc / 'stat').read_text().splitlines()
                                         if line.startswith('btime '))),
    }
    for name, read in readers.items():
        try:
            context[name] = read()
        except (OSError, ValueError, IndexError, StopIteration) as exc:
            context[name] = None
            context['errors'][name] = str(exc) or type(exc).__name__
    if context['boot_time_unix'] is not None:
        try:
            context['boot_utc'] = datetime.fromtimestamp(context['boot_time_unix'], timezone.utc).isoformat()
        except (OverflowError, OSError, ValueError) as exc:
            context['errors']['boot_utc'] = str(exc)
    return context
