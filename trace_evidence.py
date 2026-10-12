# SPDX-License-Identifier: GPL-2.0-only
"""Read-only tracefs evidence. No mounts, probe registration or trace changes."""
import hashlib
import os
from pathlib import Path
import re
import time

BYTE_LIMIT = 2 * 1024 * 1024
ENTRY_LIMIT = 8192
ROOTS = (Path('/sys/kernel/tracing'), Path('/sys/kernel/debug/tracing'))
SYSCALLS = ('read', 'getdents', 'getdents64', 'kill', 'openat', 'init_module',
            'finit_module', 'delete_module', 'bpf')
NETWORK_HANDLERS = {'/proc/net/tcp': 'tcp4_seq_show', '/proc/net/tcp6': 'tcp6_seq_show',
                    '/proc/net/udp': 'udp4_seq_show', '/proc/net/udp6': 'udp6_seq_show'}
WATCHED = {prefix + name for prefix in ('__x64_sys_', '__arm64_sys_', '__ia32_sys_')
           for name in SYSCALLS} | {
    'proc_root_readdir', 'kernfs_fop_readdir', 'ext4_readdir', 'dcache_readdir',
    'ovl_iterate',
} | set(NETWORK_HANDLERS.values())

# t_show() uses %pS: either a numeric fallback or symbol+offset/size [module].
# Keep the printable identity; only a numeric address can correlate a CALL.
POINTER_RE = re.compile(
    r'(?P<display>\(null\)|(?:0x)?[0-9a-fA-F]{1,16}(?![\w.+/-])|'
    r'[A-Za-z_.$][\w.$:]*\+0x[0-9a-fA-F]{1,16}/0x[0-9a-fA-F]{1,16}'
    r'(?:\s+\[[\w.-]+\])?)', re.ASCII)


def parse_pointer(text):
    match = POINTER_RE.match(text)
    if not match:
        raise ValueError('Unrecognised tracefs pointer description: ' + repr(text[:160]))
    display = match['display']
    numeric = re.fullmatch(r'(?:0x)?[0-9a-fA-F]{1,16}', display)
    module = re.search(r'\[([\w.-]+)\]', display, re.ASCII)
    return {'display': display, 'address': int(display, 16) if numeric else None,
            'module': module[1] if module else None}, text[match.end():].lstrip()


def parse_references(tail):
    references = []
    while tail:
        kind = next((kind for prefix, kind in [('tramp:', 'trampoline'), ('ops:', 'ops'),
                                               ('->', 'callee')] if tail.startswith(prefix)), None)
        if kind is None:
            raise ValueError('Unrecognised tracefs reference: ' + repr(tail[:160]))
        prefix_length = {'trampoline': 6, 'ops': 4, 'callee': 2}[kind]
        pointer, tail = parse_pointer(tail[prefix_length:].lstrip())
        ref = {'kind': kind, **pointer}
        if kind != 'callee':
            if not tail.startswith('('):
                raise ValueError('Missing tracefs callback parentheses')
            callback, tail = parse_pointer(tail[1:].lstrip())
            if not tail.startswith(')'):
                raise ValueError('Unterminated tracefs callback parentheses')
            tail = tail[1:].lstrip()
            ref['callback'] = callback['display']
            ref['callback_module'] = callback['module']
        references.append(ref)
    return references


def parse_enabled_functions(text):
    entries = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if len(line) > 2048:
            raise ValueError('Tracefs entry/line limit exceeded')
        if line.lstrip().startswith('direct-->'):
            if not entries or 'D' not in entries[-1]['flags']:
                raise ValueError('Orphan tracefs direct-call continuation')
            direct, remaining = parse_pointer(line.strip()[9:].lstrip())
            if remaining:
                raise ValueError('Trailing data after tracefs direct-call continuation')
            if len(entries[-1]['references']) == 16:
                raise ValueError('Tracefs reference limit exceeded')
            entries[-1]['references'].append({'kind': 'direct', **direct})
            entries[-1]['raw'] += '\n' + line
            continue
        if len(entries) == ENTRY_LIMIT:
            raise ValueError('Tracefs entry/line limit exceeded')
        match = re.fullmatch(r'([\w.$:]+)(?:\s+\[([\w.-]+)\])?\s+\((\d+)\)(.*)', line, re.ASCII)
        if not match:
            raise ValueError('Unrecognised enabled_functions row: ' + repr(line[:160]))
        function, target_module, count, tail = match.groups()
        positions = [tail.index(marker) for marker in ('tramp:', 'ops:', '->') if marker in tail]
        split = min(positions) if positions else len(tail)
        flags_text, reference_text = tail[:split], tail[split:].strip()
        flags = ''.join(flags_text.split())
        if any(flag not in 'RIDOM' for flag in flags) or len(set(flags)) != len(flags):
            raise ValueError('Unrecognised enabled_functions flags: ' + repr(flags[:80]))
        try:
            references = parse_references(reference_text)
        except ValueError as exc:
            raise ValueError(str(exc) + '; row=' + repr(line[:400])) from exc
        if len(references) > 16:
            raise ValueError('Tracefs reference limit exceeded')
        tramps = [ref for ref in references if ref['kind'] == 'trampoline']
        callbacks = [ref for ref in references if ref['kind'] in {'trampoline', 'ops'}]
        # Multiple callbacks are preserved, never guessed to be one owner.
        chosen = callbacks[0] if len(callbacks) == 1 else None
        callee = next((ref for ref in references if ref['kind'] == 'callee'), None)
        callback = chosen['callback'] if chosen else callee['display'] if not callbacks and callee else None
        callback_module = chosen['callback_module'] if chosen else callee['module'] if not callbacks and callee else None
        trampoline = tramps[0]['address'] if len(tramps) == 1 else None
        entries.append({'function': function, 'target_module': target_module,
                        'count': int(count), 'flags': flags, 'trampoline': trampoline,
                        'callback': callback, 'callback_module': callback_module,
                        'references': references, 'raw': line})
    return entries


def snapshot(roots=ROOTS):
    acquired = {'status': 'UNSUPPORTED', 'source': None, 'entries': [],
                'started_ns': time.monotonic_ns(), 'detail': 'No existing tracefs enabled_functions endpoint.'}
    for root in roots:
        path = root / 'enabled_functions'
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        except FileNotFoundError:
            continue
        except OSError as exc:
            acquired.update(status='ERROR', source=str(path), detail=str(exc))
            break
        acquired['source'] = str(path)
        try:
            chunks, length = [], 0
            while True:
                chunk = os.read(fd, min(65536, BYTE_LIMIT + 1 - length))
                if not chunk:
                    break
                chunks.append(chunk)
                length += len(chunk)
                if length > BYTE_LIMIT:
                    raise ValueError('Tracefs byte limit exceeded')
            raw = b''.join(chunks)
            acquired.update(sha256=hashlib.sha256(raw).hexdigest(), bytes_read=len(raw))
            entries = parse_enabled_functions(raw.decode('ascii'))
            acquired.update(status='OBSERVED', detail='Read existing tracefs only; no configuration changes.',
                            total_entries=len(entries),
                            entries=sorted((e for e in entries if e['function'] in WATCHED),
                                           key=lambda e: e['function']))
        except (OSError, ValueError) as exc:
            acquired.update(status='ERROR', detail=str(exc))
        finally:
            os.close(fd)
        break
    acquired['finished_ns'] = time.monotonic_ns()
    return acquired


def record(target, status, code, detail, **evidence):
    return {'check': 'ftrace', 'target': target, 'status': status, 'code': code,
            'detail': detail, **evidence}


def assess(before, after):
    findings = []
    for label, snap in [('before', before), ('after', after)]:
        if snap['status'] != 'OBSERVED':
            findings.append(record(label, snap['status'], 'tracefs_collection_failed', snap['detail']))
    if findings:
        return findings, False
    if before['source'] != after['source'] or before['entries'] != after['entries']:
        return [record('selected functions', 'ERROR', 'tracefs_changed_during_scan',
                       'Selected registrations changed between reads; attribution is inconclusive.')], False
    for entry in after['entries']:
        active = entry['count'] > 0
        ipmodify = active and 'I' in entry['flags']
        direct = active and 'D' in entry['flags']
        findings.append(record(entry['function'], 'SUSPICIOUS' if ipmodify else 'INFO',
                               'ipmodify_on_selected_function' if ipmodify else
                               'direct_tracing_observed' if direct else 'tracing_observed',
                               ('IPMODIFY can redirect this selected function. Verify authorisation; livepatch can be legitimate.'
                                if ipmodify else 'Tracing observation alone is not malicious. M is historical, not proof of active redirection.'),
                               owner=entry['callback_module'] or 'not attributed by tracefs',
                               symbol=entry['callback'] or '',
                               address=hex(entry['trampoline'] or 0), flags=entry['flags'],
                               callback_count=entry['count'], source=after['source'], raw=entry['raw']))
    if not findings:
        findings.append(record('selected functions', 'OK', 'no_selected_registrations',
                               'No selected registration reported by enabled_functions. Other hooks and forged tracefs output are not covered.'))
    return findings, True


def correlate_entry_calls(records, before, after):
    """Attribute only stable single-callback entry CALLs to an exact trampoline.

    IPMODIFY remains suspicious. A known ordinary tracing CALL can be INFO.
    Do not suppress JMPs, ownership/pointer anomalies, mismatches or partial reads.
    """
    if (before['status'] != 'OBSERVED' or after['status'] != 'OBSERVED' or
            before['source'] != after['source'] or before['entries'] != after['entries']):
        return
    entries = after['entries']
    for observed in records:
        if observed['code'] not in {'x86_call_rel32', 'arm64_bl_imm26'}:
            continue
        check, target = observed['check'], observed['target']
        if check == 'syscalls' and target.startswith('handler:'):
            syscall = target.split(':', 1)[1]
            functions = {'__x64_sys_' + syscall, '__arm64_sys_' + syscall}
        elif check == 'network' and target in NETWORK_HANDLERS:
            # The opened seq callback must equal its named expected handler.
            # Sharing a trampoline alone never legitimises a substituted pointer.
            try:
                origin = int(observed.get('expected', ''), 16)
                known_origin = any(r['check'] == check and r['target'] == target and
                                   r['code'] == 'owner_observed' and r['status'] == 'OK' and
                                   int(r.get('address', '0x0'), 16) == origin and
                                   int(r.get('expected', '0x0'), 16) == origin
                                   for r in records)
            except (TypeError, ValueError):
                continue
            if not origin or not known_origin:
                continue
            functions = {NETWORK_HANDLERS[target]}
        else:
            # Do not correlate arbitrary callsites by sharing a trampoline alone.
            continue
        try:
            destination = int(observed.get('address', ''), 16)
        except (ValueError, TypeError):
            continue
        matching = [e for e in entries if e['function'] in functions and e['count'] == 1 and
                    e['trampoline'] == destination and destination != 0]
        if len(matching) != 1:
            continue
        e = matching[0]
        observed.update(tracefs_callback=e['callback'], tracefs_callback_owner=e['callback_module'],
                        tracefs_flags=e['flags'], tracefs_source=after['source'])
        # owner remains the kernel-collection result, not silently overwritten
        # with a module claim from a different observation source.
        if 'I' not in e['flags'] and 'D' not in e['flags']:
            observed['status'] = 'INFO'
        observed['detail'] += ' Destination matches a stable reported tracing trampoline; callback attribution is in tracefs_callback_owner.'
