#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, detached lab process. IPC provides identity when proc lookup is hidden."""
import argparse
import json
import os
import select
import signal
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control-fd', type=int, required=True)
    parser.add_argument('--event-fd', type=int, required=True)
    parser.add_argument('--signal', type=int, choices=[31, 59], required=True)
    parser.add_argument('--token', required=True)
    parser.add_argument('--seconds', type=int, default=120)
    args = parser.parse_args()
    if not 10 <= args.seconds <= 180:
        parser.error('Canary lifetime must be 10–180 seconds.')
    # A failed/inactive sample must not kill the canary with its trigger signal.
    signal.pthread_sigmask(signal.SIG_BLOCK, {args.signal})
    if os.fork():
        os._exit(0)
    deadline = time.monotonic() + args.seconds
    # Do not let Singularity's self-hiding operation affect the managing lineage.
    adoption_deadline = min(deadline, time.monotonic() + 3)
    while os.getppid() != 1 and time.monotonic() < adoption_deadline:
        time.sleep(0.01)
    def event(kind, **extra):
        payload = {'event': kind, 'pid': os.getpid(), 'ppid': os.getppid(),
                   'token': args.token, **extra}
        raw = (json.dumps(payload) + '\n').encode('ascii')
        if os.write(args.event_fd, raw) != len(raw):
            raise OSError('Short canary event write')
    if os.getppid() != 1:
        event('error', detail='Canary not adopted by init; activation refused.')
        return 2
    event('ready')
    while time.monotonic() < deadline:
        remaining = max(0, deadline - time.monotonic())
        if not select.select([args.control_fd], [], [], remaining)[0]:
            break
        command = os.read(args.control_fd, 1)
        if command in {b'', b'q'}:
            break
        if command == b'p':
            event('heartbeat')
        elif command == b'a':
            try:
                os.kill(os.getpid(), args.signal)
                event('activated', signal=args.signal)
            except OSError as exc:
                event('activation_error', errno=exc.errno)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
