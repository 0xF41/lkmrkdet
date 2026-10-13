"""Terminal presentation contracts, including machine-readable output integrity."""
from contextlib import redirect_stderr, redirect_stdout
import copy
import errno
import io
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import client


class Terminal(io.StringIO):
    def __init__(self, tty=False):
        super().__init__()
        self.tty = tty

    def isatty(self):
        return self.tty


def report(records=None, checks=63, scanned=True):
    return {'schema': 1, 'version': '0.2.1', 'client_version': client.CLIENT_VERSION,
            'kernel': '6.8.0-146-generic', 'arch': 'x86_64', 'resolver_error': 0,
            'scanned': scanned, 'checks': checks, 'truncated': False,
            'tasks_complete': True, 'pid_comparison_complete': True, 'ftrace_complete': True,
            'module_count': 2, 'started_ns': 0, 'finished_ns': 1_000_000,
            'pid_ns': 1, 'net_ns': 1, 'tasks': [],
            'records': records if records is not None else [
                client.result(name, 'scope', 'OK', 'observed', 'Recorded observation.') for name in client.CHECKS]}


def render(value, tty=False, color='auto', verbose=False, saved=False):
    stream = Terminal(tty)
    with patch.dict(os.environ, {'TERM': 'xterm-256color'}, clear=True), redirect_stdout(stream):
        client.display(value, color=color, verbose=verbose, saved=saved)
    return stream.getvalue()


class ColorPolicy(unittest.TestCase):
    def test_auto_requires_a_real_terminal(self):
        self.assertTrue(client.color_enabled('auto', Terminal(True), {}))
        self.assertFalse(client.color_enabled('auto', Terminal(False), {}))
        self.assertNotIn('\x1b', render(report()))
        self.assertIn('\x1b', render(report(), tty=True))

    def test_no_color_and_dumb_terminal_disable_automatic_color(self):
        for env in [{'NO_COLOR': '1'}, {'NO_COLOR': ''}, {'TERM': 'dumb'}]:
            with self.subTest(env=env):
                self.assertFalse(client.color_enabled('auto', Terminal(True), env))

    def test_explicit_choice_overrides_environment_and_redirect(self):
        self.assertTrue(client.color_enabled('always', Terminal(False), {'NO_COLOR': '1', 'TERM': 'dumb'}))
        self.assertFalse(client.color_enabled('never', Terminal(True), {}))
        self.assertIn('\x1b', render(report(), color='always'))
        self.assertNotIn('\x1b', render(report(), tty=True, color='never'))


class GroupedOutput(unittest.TestCase):
    def test_summary_precedes_groups_and_clean_check_is_not_attestation(self):
        text = render(report())
        self.assertLess(text.index('NO SUSPICIOUS FINDINGS'), text.index('\nPROCESSES\n'))
        for title in ['PROCESSES', 'MODULES', 'NETWORK', 'FILESYSTEM', 'SYSTEM CALLS', 'TRACING']:
            self.assertEqual(text.count('\n' + title + '\n'), 1)
        self.assertIn('Inspection complete | Exit code: 0', text)
        self.assertIn('Kernel integrity is not established.', text)

    def test_related_findings_are_grouped_and_counted_without_mutating_report(self):
        value = report()
        value['records'].extend([
            client.result('network', '/proc/net/tcp', 'SUSPICIOUS', 'x86_call_rel32', 'Network call.'),
            client.result('processes', 3388, 'SUSPICIOUS', 'missing_from_proc_enumeration', 'Full identity evidence.'),
            client.result('network', '/proc/net/udp', 'SUSPICIOUS', 'x86_call_rel32', 'Second network call.')])
        original = copy.deepcopy(value)
        text = render(value, color='always')
        self.assertIn('SUSPICIOUS EVIDENCE FOUND', text)
        self.assertIn('3 suspicious', text)
        self.assertIn('PID 3388', text)
        self.assertIn(client.COLORS['suspicious'], text)
        self.assertEqual(value, original)
        self.assertEqual(client.exit_status(value), 1)
        plain = render(value)
        network = plain.split('\nNETWORK\n', 1)[1].split('\nFILESYSTEM\n', 1)[0]
        self.assertIn('/proc/net/tcp', network)
        self.assertIn('/proc/net/udp', network)
        self.assertNotIn('PID 3388', network)

    def test_incomplete_and_mixed_results_remain_distinct(self):
        value = report()
        value['records'].append(client.result('processes', 123, 'INFO', 'lifecycle_inconclusive', 'Lookup gone.'))
        text = render(value)
        self.assertIn('INSPECTION INCOMPLETE', text)
        self.assertNotIn('NO SUSPICIOUS FINDINGS', text)
        self.assertIn('Exit code: 2', text)
        value['records'].append(client.result('modules', 'unknown', 'SUSPICIOUS', 'unexpected_handler', 'Different pointer.'))
        text = render(value)
        self.assertIn('SUSPICIOUS EVIDENCE FOUND', text)
        self.assertIn('Inspection incomplete', text)
        self.assertIn('Exit code: 3', text)

    def test_missing_requested_observation_is_visible(self):
        value = report([client.result('modules', 'list', 'OK', 'consistent', 'Observed.')], checks=5)
        text = render(value)
        self.assertIn('No observations returned for this check', text)
        self.assertIn('Inspection incomplete', text)

    def test_unperformed_process_or_trace_comparison_never_gets_healthy_group(self):
        for field, title in [('pid_comparison_complete', 'PROCESSES'), ('ftrace_complete', 'TRACING')]:
            with self.subTest(field=field):
                value = report()
                value[field] = False
                text = render(value)
                section = text.split('\n' + title + '\n', 1)[1].split('\n\n', 1)[0]
                self.assertNotIn('[OK]', section)
                self.assertIn('[UNSUPPORTED]', section)
                self.assertIn('Inspection incomplete', text)

    def test_verbose_keeps_original_detail_code_and_address(self):
        finding = client.result('processes', 3388, 'SUSPICIOUS', 'missing_from_proc_enumeration', 'Full original identity evidence.')
        finding.update(identity_source='kernel_task_revalidation', address='0x1234', owner='unresolved',
                       revalidation={'start_ns': 5})
        value = report([finding], checks=16)
        concise = render(value)
        verbose = render(value, verbose=True)
        self.assertIn('later kernel snapshot', concise)
        self.assertIn('Full original identity evidence.', verbose)
        self.assertIn('Code: missing_from_proc_enumeration', verbose)
        self.assertIn('Address: 0x1234', verbose)
        self.assertIn('Revalidation:', verbose)

    def test_correlated_entry_has_concise_context_and_full_verbose_evidence(self):
        finding = client.result('network', '/proc/net/tcp', 'SUSPICIOUS', 'x86_call_rel32', 'Full original branch evidence.')
        finding.update(tracefs_callback='0x1234', tracefs_flags='RIM', address='0x5678', owner='unresolved')
        value = report([finding], checks=4)
        concise = render(value)
        self.assertIn('Entry CALL matches a stable IPMODIFY tracing trampoline.', concise)
        self.assertIn('Tracefs callback: 0x1234 | Flags: RIM', concise)
        self.assertIn('Full original branch evidence.', render(value, verbose=True))

    def test_inventory_and_saved_replay_are_clearly_labelled(self):
        value = report([client.result('status', 'resolver', 'UNSUPPORTED', 'resolver_unavailable', 'Not available.')],
                       checks=0, scanned=False)
        text = render(value)
        self.assertIn('STATUS - NOT A SCAN', text)
        self.assertNotIn('Inspection complete', text)
        self.assertNotIn('NO SUSPICIOUS FINDINGS', text)
        self.assertIn('Saved report - not a live scan', render(report(), saved=True))

    def test_report_control_sequences_are_escaped_even_with_color(self):
        value = report([client.result('processes', '123\x1b[2J', 'ERROR', 'identity_unavailable', 'Bad\nlookup\x1b[2J')], checks=16)
        value['kernel'] = 'kernel\x1b[2J'
        text = render(value, color='always')
        self.assertNotIn('\x1b[2J', text)
        self.assertIn('\\x1b[2J', text)
        self.assertIn(client.COLORS['heading'], text)


class MachineReadableOutput(unittest.TestCase):
    def test_json_ignores_forced_color_and_preserves_exit_code(self):
        value = report()
        value['records'].append(client.result('processes', 3388, 'SUSPICIOUS', 'missing_from_proc_enumeration', 'Evidence.'))
        stream, errors = Terminal(True), Terminal(True)
        with patch.object(client, 'request', return_value=value), patch.object(client.os, 'geteuid', return_value=0), \
                redirect_stdout(stream), redirect_stderr(errors):
            code = client.main(['scan', '--format', 'json', '--color', 'always'])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(stream.getvalue()), value)
        self.assertNotIn('\x1b', stream.getvalue())
        self.assertEqual(errors.getvalue(), '')

    def test_failed_json_request_has_no_ansi_on_either_stream(self):
        stream, errors = Terminal(True), Terminal(True)
        with patch.object(client, 'request', side_effect=OSError('unavailable')), \
                patch.object(client.os, 'geteuid', return_value=0), redirect_stdout(stream), redirect_stderr(errors):
            code = client.main(['scan', '--format', 'json', '--color', 'always'])
        self.assertEqual(code, 2)
        self.assertEqual(stream.getvalue(), '')
        self.assertNotIn('\x1b', errors.getvalue())

    def test_text_failure_uses_amber_on_stderr_and_preserves_failure_code(self):
        stream, errors = Terminal(True), Terminal(True)
        with patch.object(client, 'request', side_effect=OSError('unavailable')), \
                patch.object(client.os, 'geteuid', return_value=0), redirect_stdout(stream), redirect_stderr(errors):
            code = client.main(['scan', '--color', 'always'])
        self.assertEqual(code, 2)
        self.assertIn(client.COLORS['warning'], errors.getvalue())
        self.assertEqual(stream.getvalue(), '')


@unittest.skipUnless(hasattr(os, 'openpty'), 'Requires a pseudo-terminal')
class TerminalEntrypoint(unittest.TestCase):
    def test_saved_report_cli_auto_color_in_a_real_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory) / 'report.json'
            fixture.write_text(json.dumps(report()))
            for mode, no_color, expected in [('auto', False, True), ('never', False, False), ('auto', True, False)]:
                with self.subTest(mode=mode, no_color=no_color):
                    env = dict(os.environ, TERM='xterm-256color')
                    env.pop('NO_COLOR', None)
                    if no_color:
                        env['NO_COLOR'] = '1'
                    master, slave = os.openpty()
                    process = None
                    try:
                        process = subprocess.Popen([sys.executable, str(Path(client.__file__).resolve()),
                                                    'show', str(fixture), '--color', mode],
                                                   stdout=slave, stderr=subprocess.PIPE, env=env, cwd=directory)
                        # Keep our slave open until capture: Darwin can discard
                        # unread PTY bytes when the final slave descriptor closes.
                        _, errors = process.communicate(timeout=10)
                        output = b''
                        while select.select([master], [], [], 0.2)[0]:
                            try:
                                block = os.read(master, 65536)
                            except OSError as exc:
                                if exc.errno == errno.EIO:  # Linux PTY EOF
                                    break
                                raise
                            if not block:
                                break
                            output += block
                        self.assertEqual(process.returncode, 0, errors)
                        self.assertIn(b'Saved report - not a live scan', output)
                        self.assertEqual(b'\x1b[' in output, expected)
                    finally:
                        if slave is not None:
                            os.close(slave)
                        if process is not None and process.poll() is None:
                            process.kill()
                            process.wait(timeout=5)
                        os.close(master)
