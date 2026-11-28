"""Case reassessment must retain the same episode limits as association."""
from copy import deepcopy
import unittest

from spine.association import fingerprint
from spine.manager_reassessment import evaluate_case
from test_association_episodes import dns, execution, install, login


def assessment(alerts):
    case = {'case_id': 'review-case', 'revision': len(alerts), 'status': 'active', 'alerts': alerts}
    return evaluate_case(case, {'revision': 1, 'complete': True, 'cases': [case]},
                         {'stored_originals': [], 'payload_conflicts': []})


class ReassessmentEpisodeTests(unittest.TestCase):
    def test_valid_remote_login_episode_remains_supported(self):
        result = assessment([login(1, 0), login(2, 599, success=True)])
        self.assertTrue(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_remote_login_episode_span_is_rechecked(self):
        result = assessment([login(1, 0), login(2, 601)])
        pair = result['pair_checks'][0]
        self.assertTrue(pair['time_eligible'])  # The older generic window is wider.
        self.assertFalse(pair['pair_has_assignment_support'])
        self.assertIn('episode_span_exceeded', [r.get('withheld_reason') for r in pair['relationship_rules']])

    def test_terminal_success_prevents_later_failure_support(self):
        result = assessment([login(1, 0, success=True), login(2, 30)])
        self.assertFalse(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_two_distinct_successes_are_not_one_supported_episode(self):
        result = assessment([login(1, 0, success=True), login(2, 30, success=True)])
        self.assertFalse(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_conflicting_known_sids_constrain_unknown_sid_bridge(self):
        result = assessment([login(1, 0), login(2, 20, targetUserSid='S-1-5-21-1'),
                             login(3, 40, targetUserSid='S-1-5-21-2')])
        self.assertFalse(any(p['pair_has_assignment_support'] for p in result['pair_checks']))

    def test_repeated_native_event_id_has_no_episode_assignment_authority(self):
        first, second = login(1, 0), login(2, 30)
        second['event']['record_id'] = first['event']['record_id']
        result = assessment([first, second])
        self.assertFalse(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_dns_whole_episode_limit_prevents_pairwise_chaining(self):
        result = assessment([dns(20, 0, 100), dns(21, 40, 101), dns(22, 61, 102)])
        self.assertFalse(any(p['pair_has_assignment_support'] for p in result['pair_checks']))

    def test_valid_dns_context_is_retained(self):
        result = assessment([dns(20, 0, 100), dns(21, 60, 101)])
        self.assertTrue(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_service_command_time_limit_is_rechecked(self):
        result = assessment([install(10, 0), execution(11, 301)])
        self.assertFalse(result['pair_checks'][0]['pair_has_assignment_support'])

    def test_competing_service_names_remove_episode_authority(self):
        result = assessment([install(10, 0), install(12, 2, serviceName='OtherService'), execution(11, 10)])
        self.assertFalse(any(p['pair_has_assignment_support'] for p in result['pair_checks']))

    def test_observations_do_not_become_confirmed_activity_counts(self):
        result = assessment([login(1, 0), login(2, 20), login(3, 30, success=True)])
        self.assertEqual(result['counts']['evidence_representations'], 3)
        self.assertEqual(result['counts']['unsupported_occurrence_representations'], 3)
        self.assertIsNone(result['counts']['confirmed_underlying_activities'])
        self.assertIsNone(result['counts']['session_totals'])
        self.assertFalse(result['memberships_changed'])

    def test_inputs_are_unchanged(self):
        alerts = [login(1, 0), login(2, 601)]
        before = fingerprint(alerts)
        assessment(alerts)
        self.assertEqual(fingerprint(alerts), before)


if __name__ == '__main__':
    unittest.main()
