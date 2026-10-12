from pathlib import Path
import tempfile
import unittest

import client
import trace_evidence as trace

CARAXES = '__x64_sys_getdents64 (1) R I     M \ttramp: 0xffffffffc0b3d000 (fh_ftrace_thunk+0x0/0x170 [caraxes]) ->ftrace_ops_assist_func+0x0/0x180'


def snap(line=CARAXES):
    return {'status': 'OBSERVED', 'source': '/trace/enabled_functions',
            'entries': trace.parse_enabled_functions(line), 'detail': 'test'}


def entry(code='x86_call_rel32', address='0xffffffffc0b3d000'):
    return {'check': 'syscalls', 'target': 'handler:getdents64', 'code': code,
            'status': 'SUSPICIOUS', 'address': address, 'detail': 'Entry observation.',
            'owner': 'unresolved'}


class TraceEvidenceTests(unittest.TestCase):
    def test_actual_report_line_attributes_caraxes_and_ipmodify(self):
        e = trace.parse_enabled_functions(CARAXES)[0]
        self.assertEqual(e['flags'], 'RIM')
        self.assertEqual(e['callback_module'], 'caraxes')
        self.assertEqual(e['trampoline'], 0xffffffffc0b3d000)
        records, complete = trace.assess(snap(), snap())
        self.assertTrue(complete)
        self.assertEqual(records[0]['code'], 'ipmodify_on_selected_function')
        self.assertEqual(records[0]['status'], 'SUSPICIOUS')

    def test_history_and_direct_bpf_are_not_automatically_malicious(self):
        for line in ['__x64_sys_read (0) M', '__x64_sys_read (1) D M ->bpf_trampoline+0x0/0x100']:
            records, complete = trace.assess(snap(line), snap(line))
            self.assertTrue(complete)
            self.assertEqual(records[0]['status'], 'INFO')

    def test_normal_tracing_call_is_attributed_without_replacing_owner(self):
        s = snap(CARAXES.replace('R I     M', 'R'))
        r = entry()
        trace.correlate_entry_calls([r], s, s)
        self.assertEqual(r['status'], 'INFO')
        self.assertEqual(r['owner'], 'unresolved')
        self.assertEqual(r['tracefs_callback_owner'], 'caraxes')

    def test_ipmodify_attribution_remains_candidate(self):
        r = entry()
        trace.correlate_entry_calls([r], snap(), snap())
        self.assertEqual(r['status'], 'SUSPICIOUS')
        self.assertEqual(r['tracefs_flags'], 'RIM')

    def test_mismatched_multi_callback_and_jump_are_not_suppressed(self):
        for r, s in [(entry(address='0x1000'), snap()),
                     (entry(code='x86_jmp_rel32'), snap()),
                     (entry(), snap(CARAXES.replace('(1)', '(2)')))]:
            trace.correlate_entry_calls([r], s, s)
            self.assertEqual(r['status'], 'SUSPICIOUS')
            self.assertNotIn('tracefs_callback', r)

    def test_unknown_flags_and_invalid_rows_fail_explicitly(self):
        for line in ['malformed', '__x64_sys_read (1) X', CARAXES.replace('0xffffffffc0b3d000', 'bad_address')]:
            with self.assertRaises(ValueError):
                trace.parse_enabled_functions(line)

    def test_changed_registration_is_inconclusive(self):
        records, complete = trace.assess(snap(), snap(''))
        self.assertFalse(complete)
        self.assertEqual(records[0]['status'], 'ERROR')
        r = entry()
        trace.correlate_entry_calls([r], snap(), snap(''))
        self.assertNotIn('tracefs_callback', r)

    def test_snapshot_bounds_and_unavailable_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.assertEqual(trace.snapshot((root,))['status'], 'UNSUPPORTED')
            path = root / 'enabled_functions'
            path.write_text(CARAXES + '\n')
            self.assertEqual(trace.snapshot((root,))['entries'][0]['callback_module'], 'caraxes')
            path.write_bytes(b'x' * (trace.BYTE_LIMIT + 1))
            self.assertEqual(trace.snapshot((root,))['status'], 'ERROR')

    def test_missing_trace_collection_is_never_clean(self):
        r = {'scanned': True, 'checks': client.CHECKS['ftrace'], 'truncated': False,
             'records': [client.result('ftrace', 'collection', 'INFO', 'client_collection_required', 'x')]}
        self.assertEqual(client.exit_status(r), 2)
        r['ftrace_complete'] = True
        self.assertEqual(client.exit_status(r), 0)

    def test_arm_handler_attribution_uses_same_tracefs_evidence(self):
        s = snap(CARAXES.replace('__x64_sys_', '__arm64_sys_'))
        r = entry(code='arm64_bl_imm26')
        trace.correlate_entry_calls([r], s, s)
        self.assertEqual(r['tracefs_callback_owner'], 'caraxes')
        self.assertEqual(r['status'], 'SUSPICIOUS')

    def test_record_exhaustion_is_explicit(self):
        r = {'records': [client.result('x', 'x', 'INFO', 'x', 'x')] * client.MAX_RECORDS,
             'truncated': False}
        client.add_records(r, [client.result('ftrace', 'x', 'SUSPICIOUS', 'x', 'x')])
        self.assertEqual(len(r['records']), client.MAX_RECORDS)
        self.assertTrue(r['truncated'])

    def test_symbolic_trampoline_is_valid_but_not_an_address_guess(self):
        line = '__x64_sys_read (1) R tramp: ftrace_regs_caller+0x0/0x100 (kprobe_ftrace_handler+0x0/0x100) ->ftrace_ops_assist_func+0x0/0x180'
        parsed = trace.parse_enabled_functions(line)[0]
        self.assertIsNone(parsed['trampoline'])
        self.assertEqual(parsed['references'][0]['display'], 'ftrace_regs_caller+0x0/0x100')
        records, complete = trace.assess(snap(line), snap(line))
        self.assertTrue(complete)
        self.assertEqual(records[0]['status'], 'INFO')
        observed = entry()
        trace.correlate_entry_calls([observed], snap(line), snap(line))
        self.assertNotIn('tracefs_callback', observed)

    def test_observed_baseline_hid_bpf_row_is_parsed_without_candidate(self):
        # Actual raw tracefs from the passing 0.2.1 baseline. This format caused
        # the numeric-only 0.2 parser to fail before the raw data was captured.
        text = ('__hid_bpf_tail_call (1) R   D   M \ttramp: ftrace_regs_caller+0x0/0x78 '
                '(call_direct_funcs+0x0/0x20)\n'
                '\tdirect-->bpf_trampoline_6442510829+0x0/0xf1\n')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / 'enabled_functions').write_text(text)
            acquired = trace.snapshot((root,))
            self.assertEqual(acquired['status'], 'OBSERVED')
            self.assertEqual(acquired['total_entries'], 1)
            self.assertEqual(acquired['entries'], [])  # outside selected watchlist
            records, complete = trace.assess(acquired, acquired)
            self.assertTrue(complete)
            self.assertEqual(records[0]['status'], 'OK')

    def test_multiple_trampolines_preserve_all_callbacks(self):
        line = '__x64_sys_read (2) R tramp: 0xffffffffc0123000 (handler_a+0x0/0x10 [a]) tramp: ftrace_caller+0x0/0x80 (handler_b+0x0/0x10 [b])'
        parsed = trace.parse_enabled_functions(line)[0]
        self.assertEqual(len(parsed['references']), 2)
        self.assertIsNone(parsed['callback_module'])
        self.assertIsNone(parsed['trampoline'])

    def test_ops_and_direct_continuation_are_legitimate_formats(self):
        line = '__arm64_sys_read (1) D O M ops: bpf_ops+0x0/0x40 (bpf_handler+0x0/0x10)\n\tdirect-->bpf_trampoline_1+0x0/0x80'
        parsed = trace.parse_enabled_functions(line)[0]
        self.assertEqual([r['kind'] for r in parsed['references']], ['ops', 'direct'])
        with self.assertRaises(ValueError):
            trace.parse_enabled_functions('\tdirect-->bpf_trampoline_1+0x0/0x80')

    def test_kernel_reported_error_is_not_accepted_as_clean(self):
        for line in ['__x64_sys_read (1) R tramp: ERROR!', '__x64_sys_read (1) O ops: ERROR!']:
            with self.assertRaisesRegex(ValueError, 'row='):
                trace.parse_enabled_functions(line)

    def test_singularity_numeric_network_callback_is_correlated_without_owner_guess(self):
        line = 'tcp4_seq_show (1) R I M tramp: 0xffffffffc0d7c000 (0xffffffffc0ccb8b0)'
        s = snap(line)
        pointer = {'check': 'network', 'target': '/proc/net/tcp', 'code': 'owner_observed',
                   'address': '0xffffffff81001000', 'expected': '0xffffffff81001000', 'status': 'OK'}
        call = {**entry(address='0xffffffffc0d7c000'), 'check': 'network', 'target': '/proc/net/tcp',
                'expected': pointer['address']}
        trace.correlate_entry_calls([pointer, call], s, s)
        self.assertEqual(call['tracefs_callback'], '0xffffffffc0ccb8b0')
        self.assertIsNone(call['tracefs_callback_owner'])
        self.assertEqual(call['owner'], 'unresolved')
        self.assertEqual(call['status'], 'SUSPICIOUS')

    def test_substituted_network_pointer_is_never_legitimised(self):
        s = snap('tcp4_seq_show (1) R tramp: 0xffffffffc0d7c000 (handler+0x0/0x10)')
        pointer = {'check': 'network', 'target': '/proc/net/tcp', 'code': 'unexpected_handler',
                   'address': '0xffffffff81002000', 'expected': '0xffffffff81001000', 'status': 'SUSPICIOUS'}
        call = {**entry(address='0xffffffffc0d7c000'), 'check': 'network', 'target': '/proc/net/tcp',
                'expected': pointer['address']}
        trace.correlate_entry_calls([pointer, call], s, s)
        self.assertNotIn('tracefs_callback', call)
        self.assertEqual(call['status'], 'SUSPICIOUS')

    def test_network_trampoline_match_without_origin_evidence_is_insufficient(self):
        s = snap('tcp4_seq_show (1) R tramp: 0xffffffffc0d7c000 (handler+0x0/0x10)')
        call = {**entry(address='0xffffffffc0d7c000'), 'check': 'network', 'target': '/proc/net/tcp',
                'expected': '0xffffffff81001000'}
        trace.correlate_entry_calls([call], s, s)
        self.assertNotIn('tracefs_callback', call)
        self.assertEqual(call['status'], 'SUSPICIOUS')
        bad_origin = {'check': 'network', 'target': '/proc/net/tcp', 'code': 'owner_observed',
                      'status': 'ERROR', 'address': call['expected'], 'expected': call['expected']}
        trace.correlate_entry_calls([bad_origin, call], s, s)
        self.assertNotIn('tracefs_callback', call)


if __name__ == '__main__':
    unittest.main()
