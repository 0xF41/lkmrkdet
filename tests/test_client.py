import importlib.util
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

spec = importlib.util.spec_from_file_location('client', Path(__file__).parents[1] / 'client.py')
client = importlib.util.module_from_spec(spec)
spec.loader.exec_module(client)


def report(records=None, checks=16, tasks=None):
    return {'schema': 1, 'version': 'test', 'kernel': 'test', 'arch': 'test',
            'resolver_error': 0, 'scanned': True, 'truncated': False,
            'tasks_complete': True, 'pid_comparison_complete': True,
            'module_count': 1, 'started_ns': 0,
            'finished_ns': 1, 'pid_ns': 1, 'net_ns': 1, 'checks': checks,
            'records': records or [], 'tasks': tasks or []}


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.task = {'pid': 123, 'start_ns': 1_000_000_000, 'comm': 'demo'}
        self.report = report(tasks=[self.task])

    def test_missing_pid_requires_matching_identity(self):
        records = client.process_findings(self.report, set(), set(), lambda pid: 100, 100)
        self.assertEqual(records[0]['status'], 'SUSPICIOUS')

    def test_reused_pid_is_inconclusive_not_hidden(self):
        records = client.process_findings(self.report, set(), set(), lambda pid: 101, 100)
        self.assertEqual(records[0]['code'], 'identity_changed')
        self.report['records'] = records
        self.assertEqual(client.exit_status(self.report), 2)

    def test_exit_during_scan_is_not_clean(self):
        def gone(pid):
            raise FileNotFoundError()
        records = client.process_findings(self.report, set(), set(), gone, 100)
        self.assertEqual(records[0]['code'], 'lifecycle_inconclusive')
        self.report['records'] = records
        self.assertEqual(client.exit_status(self.report), 2)

    def test_permission_failure_is_error(self):
        def denied(pid):
            raise PermissionError('denied')
        records = client.process_findings(self.report, set(), set(), denied, 100)
        self.assertEqual(records[0]['status'], 'ERROR')

    def test_visible_on_either_side_is_not_flagged(self):
        records = client.process_findings(self.report, {123}, set(), lambda pid: 100, 100)
        self.assertEqual(records[0]['status'], 'OK')

    def test_incomplete_snapshot_is_not_compared(self):
        self.report['tasks_complete'] = False
        records = client.process_findings(self.report, set(), set(), lambda pid: 100, 100)
        self.assertEqual(records[0]['status'], 'UNSUPPORTED')

    def test_stat_name_with_parentheses_and_spaces(self):
        fields = ['S'] + ['0'] * 18 + ['321'] + ['0'] * 5
        self.assertEqual(client.parse_stat_start('123 (odd ) name ( here) ' + ' '.join(fields)), 321)

    def test_schema_rejects_unknown_status_and_duplicate_pid(self):
        r = report([client.result('processes', 'x', 'CLEAN', 'x', 'x')])
        with self.assertRaises(ValueError):
            client.validate_report(r)
        r = report(tasks=[self.task, self.task])
        with self.assertRaises(ValueError):
            client.validate_report(r)

    def test_suspicious_and_failed_checks_are_both_preserved(self):
        r = report([client.result('modules', 'x', 'SUSPICIOUS', 'x', 'x'),
                    client.result('network', 'x', 'ERROR', 'x', 'x')], checks=5)
        self.assertEqual(client.exit_status(r), 3)

    def test_missing_check_and_truncation_never_return_clean(self):
        self.assertEqual(client.exit_status(report(checks=1)), 2)
        r = report([client.result('modules', 'x', 'OK', 'x', 'x')], checks=1)
        r['truncated'] = True
        self.assertEqual(client.exit_status(r), 2)

    def test_kernel_task_snapshot_without_client_comparison_is_incomplete(self):
        r = report([client.result('processes', 'snapshot', 'INFO', 'snapshot_for_user_comparison', 'x')])
        del r['pid_comparison_complete']
        self.assertEqual(client.exit_status(r), 2)

    def test_terminal_controls_are_escaped(self):
        self.assertEqual(client.safe_text('module\x1b[2J\n\x9b'), 'module\\x1b[2J\\x0a\\x9b')


class RevalidationTests(unittest.TestCase):
    def setUp(self):
        # The Singularity case omitted a live canary from enumeration AND lookup.
        self.task = {'pid': 2415, 'start_ns': 10_000_000_000, 'comm': 'python3'}
        self.first = report(tasks=[self.task])
        self.later = report([client.result('processes', 'snapshot', 'INFO', 'snapshot_for_user_comparison', 'test')],
                            tasks=[dict(self.task)])
        self.later.update(started_ns=2, finished_ns=3)

    def gone(self, pid):
        raise FileNotFoundError()

    def compare(self, later=None):
        return client.process_findings(self.first, set(), set(), self.gone, 100,
                                       revalidate=lambda: self.later if later is None else later)

    def test_same_birth_identity_revalidates_lookup_hidden_task(self):
        records = self.compare()
        self.assertEqual(records[0]['status'], 'SUSPICIOUS')
        self.assertEqual(records[0]['code'], 'missing_from_proc_enumeration')
        self.assertEqual(records[0]['identity_source'], 'kernel_task_revalidation')
        self.first['records'] = records
        self.assertEqual(client.exit_status(self.first), 1)

    def test_real_exit_stays_inconclusive(self):
        self.later['tasks'] = []
        self.assertEqual(self.compare()[0]['code'], 'lifecycle_inconclusive')

    def test_pid_reuse_is_not_hiding(self):
        self.later['tasks'][0]['start_ns'] += 1
        self.assertEqual(self.compare()[0]['code'], 'identity_changed')

    def test_stale_namespace_or_incomplete_confirmation_is_error(self):
        for changed in [{'pid_ns': 2}, {'started_ns': 1}, {'finished_ns': 1},
                        {'tasks_complete': False}, {'truncated': True}, {'checks': 63},
                        {'kernel': 'other'}, {'arch': 'other'}, {'version': 'other'},
                        {'records': []}]:
            with self.subTest(changed=changed):
                self.assertEqual(self.compare({**self.later, **changed})[0]['code'], 'revalidation_unavailable')

    def test_malformed_or_failed_confirmation_cannot_be_clean(self):
        for malformed in [[], {'schema': 99}]:
            self.assertEqual(self.compare(malformed)[0]['status'], 'ERROR')
        records = client.process_findings(self.first, set(), set(), self.gone, 100,
                                          revalidate=Mock(side_effect=OSError('interface disappeared')))
        self.assertEqual(records[0]['status'], 'ERROR')

    def test_direct_identity_does_not_require_second_transaction(self):
        provider = Mock(side_effect=AssertionError('unexpected revalidation'))
        records = client.process_findings(self.first, set(), set(), lambda pid: 1000, 100, provider)
        self.assertEqual(records[0]['identity_source'], 'direct_proc_stat')
        provider.assert_not_called()

    def test_multiple_missing_tasks_use_one_confirmation(self):
        second = {**self.task, 'pid': 2416}
        self.first['tasks'].append(second)
        self.later['tasks'].append(dict(second))
        provider = Mock(return_value=self.later)
        records = client.process_findings(self.first, set(), set(), self.gone, 100, provider)
        self.assertEqual([r['status'] for r in records], ['SUSPICIOUS', 'SUSPICIOUS'])
        provider.assert_called_once_with()

    def test_live_request_uses_fresh_descriptor_without_recursive_comparison(self):
        with patch.object(client, 'enumerate_pids', side_effect=[set(), set()]), \
                patch.object(client, 'namespace_id', return_value=1), \
                patch.object(client.os, 'open', return_value=7), \
                patch.object(client.os, 'write', side_effect=lambda fd, data: len(data)) as write, \
                patch.object(client.os, 'lseek'), patch.object(client.os, 'close') as close, \
                patch.object(client, 'read_report', side_effect=[self.first, self.later]), \
                patch.object(client.Path, 'read_text', side_effect=FileNotFoundError()):
            acquired = client.request('scan processes', compare_processes=True)
        self.assertEqual(write.call_count, 2)
        self.assertEqual(close.call_count, 2)
        self.assertTrue(acquired['pid_comparison_complete'])
        self.assertEqual(acquired['records'][0]['identity_source'], 'kernel_task_revalidation')


if __name__ == '__main__':
    unittest.main()
