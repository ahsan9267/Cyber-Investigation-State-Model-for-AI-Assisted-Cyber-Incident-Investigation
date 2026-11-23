import unittest

from spine.association import associate_alert, has_assignment_support
from test_association import alert, case, snapshot


class ConservativePolicyTests(unittest.TestCase):
    def test_authentication_context_is_only_a_possible_relationship(self):
        incoming = alert("b", 5)

        decision = associate_alert(
            incoming,
            snapshot(case("c1", alert("a"))),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["reason"], "weak_context_only")
        self.assertEqual(decision["possible_case_ids"], ["c1"])
        self.assertEqual(decision["candidate_case_ids"], [])

        comparison = decision["comparisons"][0]["alert_comparisons"][0]
        self.assertTrue(comparison["possible_match"])
        self.assertFalse(comparison["supports_match"])

    def test_multiple_weak_matches_do_not_choose_a_case(self):
        decision = associate_alert(
            alert("c", 10),
            snapshot(
                case("c1", alert("a")),
                case("c2", alert("b", 5)),
            ),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["possible_case_ids"], ["c1", "c2"])
        self.assertIsNone(decision["case_id"])

    def test_strong_match_can_assign_despite_another_weak_match(self):
        incoming = alert("c", 10)
        strong = alert("a")
        weak = alert("b", 5)

        guid = "11111111-2222-3333-4444-555555555555"
        for record in (incoming, strong):
            record["attributes"]["process"] = {"guid": guid}

        decision = associate_alert(
            incoming,
            snapshot(case("c1", strong), case("c2", weak)),
        )

        self.assertEqual(
            (decision["decision"], decision["case_id"]),
            ("EXISTING_CASE", "c1"),
        )
        self.assertEqual(decision["possible_case_ids"], ["c2"])

    def test_unknown_rule_does_not_gain_assignment_authority(self):
        self.assertFalse(
            has_assignment_support([{"rule": "unvalidated_rule"}])
        )
        self.assertFalse(
            has_assignment_support([{"rule": "authentication_context"}])
        )
        self.assertTrue(
            has_assignment_support([{"rule": "same_process_guid"}])
        )


if __name__ == "__main__":
    unittest.main()