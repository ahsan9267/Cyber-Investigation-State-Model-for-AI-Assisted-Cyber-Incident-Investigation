import unittest

from spine.association import associate_alert
from test_association import alert, case, snapshot


P = "11111111-2222-3333-4444-555555555555"
C = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
S = "12345678-1234-1234-1234-123456789abc"


def process(identity, guid, parent=None, host="server-a"):
    record = alert(identity, 5)
    record["event"] = {"provider": "sysmon"}
    record["host"] = {"name": host}
    record["attributes"] = {"process": {"guid": guid}}

    if parent is not None:
        record["attributes"]["process"]["parent"] = {"guid": parent}

    return record


class ProcessLineageTests(unittest.TestCase):
    def test_direct_child_joins_parent_case(self):
        parent = process("p", P)
        child = process("c", C, P)

        decision = associate_alert(
            child,
            snapshot(case("c1", parent)),
        )

        self.assertEqual(
            (decision["decision"], decision["case_id"]),
            ("EXISTING_CASE", "c1"),
        )

        rules = decision["comparisons"][0]["alert_comparisons"][0][
            "relationship_rules"
        ]
        rule = next(
            item for item in rules
            if item["rule"] == "direct_parent_child_process"
        )

        self.assertEqual(rule["parent_alert_id"], parent["record_id"])
        self.assertEqual(rule["child_alert_id"], child["record_id"])

    def test_parent_alert_arriving_later_joins_child_case(self):
        decision = associate_alert(
            process("p", P),
            snapshot(case("c1", process("c", C, P))),
        )
        self.assertEqual(decision["case_id"], "c1")

    def test_siblings_alone_do_not_establish_a_direct_edge(self):
        decision = associate_alert(
            process("s", S, P),
            snapshot(case("c1", process("c", C, P))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_same_guids_on_different_hosts_do_not_match(self):
        decision = associate_alert(
            process("c", C, P, host="server-b"),
            snapshot(case("c1", process("p", P))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_self_parent_is_not_accepted(self):
        decision = associate_alert(
            process("c", C, C),
            snapshot(case("c1", process("p", C))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_two_node_parent_cycle_is_not_accepted(self):
        decision = associate_alert(
            process("c", C, P),
            snapshot(case("c1", process("p", P, C))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_conflicting_parents_of_same_process_are_not_accepted(self):
        decision = associate_alert(
            process("a", C, P),
            snapshot(case("c1", process("b", C, S))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_process_id_alone_does_not_match(self):
        a = process("a", None)
        b = process("b", None)

        for record in (a, b):
            record["attributes"]["process"]["id"] = 1234

        decision = associate_alert(a, snapshot(case("c1", b)))
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_lineage_does_not_bypass_time_policy(self):
        child = process("c", C, P)
        child["event_time"] = {"utc": "2026-10-06T15:00:00Z"}

        decision = associate_alert(
            child,
            snapshot(case("c1", process("p", P))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")


if __name__ == "__main__":
    unittest.main()