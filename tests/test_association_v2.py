import json
import unittest
from copy import deepcopy

from spine.ait_dataset import adapt_annotations, SCOPE
from spine.envelope import build_envelope
from spine.association_v2 import apply_records, empty_state, report, migrate_state
from spine import association_prototype as baseline


def fixture(identity, clock, account='alice', outcome='failure', session='A', location='mail.log'):
    body = 'Login: ' if outcome == 'success' else 'Disconnected (auth failed, 3 attempts in 14 secs): '
    payload = {'id': identity, '@timestamp': f'2022-01-24T{clock}Z',
        'predecoder': {'hostname': 'mail'}, 'decoder': {'name': 'dovecot'},
        'location': location,
        'full_log': f'Jan 24 {clock} mail dovecot: imap-login: ' + body +
            f'user=<{account}>, method=PLAIN, rip=172.19.130.4, lip=172.19.130.4, TLS, session=<{session}>'}
    record = build_envelope(raw_text=json.dumps(payload), source='wazuh', collector='wazuh_alerts',
        record_kind='alert', source_scope=SCOPE, source_record_id=identity, observed_time='2026-10-05T00:00:00Z')
    record['agent'] = {'id': '19'}
    return adapt_annotations(record)


class ReviewTests(unittest.TestCase):
    def test_same_context_is_candidate_not_confirmed_membership(self):
        s = empty_state()
        apply_records(s, [fixture('f', '09:00:00'), fixture('s', '09:30:00', outcome='success', session='B')])
        self.assertEqual({d['status'] for d in s['decisions'].values()}, {'candidate'})
        self.assertFalse(report(s)['cases'][0]['confirmed_incident'])
        self.assertNotIn('success_sessions', report(s)['cases'][0])

    def test_late_conflict_reassesses_previous_candidate(self):
        s = empty_state()
        apply_records(s, [fixture('f', '09:00:00')])
        old_history = deepcopy(s['history'])
        apply_records(s, [fixture('s', '09:00:00', outcome='success')])
        self.assertEqual({d['status'] for d in s['decisions'].values()}, {'pending_review'})
        self.assertEqual(len(s['session_conflicts']), 1)
        self.assertEqual(report(s)['cases'][0]['candidate_failure_session_messages'], 0)
        self.assertEqual(report(s)['cases'][0]['candidate_success_sessions'], 0)
        self.assertEqual(s['history'][:len(old_history)], old_history)
        self.assertEqual(report(s)['cases'][0]['status'], 'needs_reassessment')

    def test_changed_account_does_not_hide_same_session_conflict(self):
        s = empty_state()
        apply_records(s, [fixture('f', '09:00:00'), fixture('g', '09:00:00', account='bob')])
        self.assertEqual(len(s['session_conflicts']), 1)
        self.assertTrue(all(d['status'] == 'pending_review' for d in s['decisions'].values()))

    def test_two_eligible_cases_are_not_merged(self):
        s = empty_state()
        apply_records(s, [fixture('a', '09:00:00'), fixture('b', '11:00:00', session='B')])
        apply_records(s, [fixture('bridge', '10:00:00', session='C')])
        pending = [d for d in s['decisions'].values() if d['status'] == 'pending_review']
        self.assertEqual(len(pending), 1)
        self.assertEqual(len(pending[0]['candidate_case_ids']), 2)
        self.assertEqual(len(s['cases']), 2)

    def test_duplicate_evidence_and_replay(self):
        s = empty_state()
        rows = [fixture('a', '09:00:00'), fixture('b', '09:00:00', location='syslog')]
        apply_records(s, rows)
        c = report(s)['cases'][0]
        self.assertEqual(c['candidate_failure_session_messages'], 1)
        self.assertEqual(c['candidate_evidence_representations'], 2)
        self.assertEqual(c['candidate_source_reported_failed_attempts'], 3)
        before = deepcopy(s)
        self.assertEqual(apply_records(s, rows), {'inserted': 0, 'replay': 2})
        self.assertEqual(s, before)

    def test_other_account_is_unassigned(self):
        s = empty_state()
        apply_records(s, [fixture('a', '09:00:00'), fixture('b', '09:30:00', account='bob', session='B', outcome='success')])
        self.assertEqual(report(s)['decision_counts'], {'candidate': 1, 'unassigned': 1})

    def test_migration_preserves_original_evidence_history_and_case_ids(self):
        old = baseline.empty_state()
        baseline.apply_records(old, [fixture('a', '09:00:00'), fixture('b', '09:30:00', session='B', outcome='success')])
        original = deepcopy(old)
        new = migrate_state(old)
        self.assertEqual(old, original)
        self.assertEqual(new['evidence'], old['evidence'])
        self.assertEqual(new['history'][:len(old['history'])], old['history'])
        self.assertEqual(set(new['cases']), set(old['cases']))
        self.assertEqual(new['revision'], old['revision'] + 1)
        self.assertTrue(all(d['status'] == 'candidate' for d in new['decisions'].values()))
        restored = json.loads(json.dumps(new))
        self.assertEqual(report(new), report(restored))

    def test_conflicted_anchor_withholds_its_existing_success_candidates(self):
        s = empty_state()
        apply_records(s, [fixture('a', '09:00:00'), fixture('b', '09:30:00', session='B', outcome='success')])
        apply_records(s, [fixture('conflict', '09:00:00', outcome='success')])
        self.assertEqual(len(s['cases']), 1)
        self.assertTrue(all(d['status'] == 'pending_review' for d in s['decisions'].values()))
        self.assertEqual(report(s)['cases'][0]['candidate_success_sessions'], 0)


if __name__ == '__main__':
    unittest.main()
