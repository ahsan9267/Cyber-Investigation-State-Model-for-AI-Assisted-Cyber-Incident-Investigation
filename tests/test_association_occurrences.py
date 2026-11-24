import json
import unittest
from copy import deepcopy

from spine.ait_dataset import adapt_annotations, SCOPE
from spine.envelope import build_envelope
from spine.association import associate_alert
from spine.occurrences import describe_occurrence


def sample(
    identity,
    session="A",
    location="mail.log",
    outcome="failure",
):
    body = (
        "Login: "
        if outcome == "success"
        else "Disconnected (auth failed, 3 attempts in 14 secs): "
    )

    payload = {
        "id": identity,
        "@timestamp": "2022-01-24T09:00:00Z",
        "predecoder": {"hostname": "mail"},
        "decoder": {"name": "dovecot"},
        "location": location,
        "full_log": (
            "Jan 24 09:00:00 mail dovecot: imap-login: "
            + body
            + "user=<alice>, method=PLAIN, rip=172.19.130.4, "
            + "lip=172.19.130.4, TLS, session=<"
            + session
            + ">"
        ),
    }

    record = build_envelope(
        raw_text=json.dumps(payload),
        source="wazuh",
        collector="wazuh_alerts",
        record_kind="alert",
        source_scope=SCOPE,
        source_record_id=identity,
        observed_time="2026-10-05T00:00:00Z",
    )

    record["agent"] = {"id": "19"}
    return adapt_annotations(record)


def context(*groups):
    return {
        "revision": 1,
        "complete": True,
        "cases": [
            {
                "case_id": cid,
                "revision": 1,
                "status": "active",
                "alerts": records,
            }
            for cid, records in groups
        ],
    }


class OccurrenceTests(unittest.TestCase):
    def test_three_representations_share_one_message_reference(self):
        rows = [
            sample("a"),
            sample("b", location="syslog"),
            sample("c", location="auth.log"),
        ]

        self.assertEqual(len({r["record_id"] for r in rows}), 3)
        self.assertEqual(
            len({describe_occurrence(r)["id"] for r in rows}),
            1,
        )

        occurrence = describe_occurrence(rows[0])
        self.assertEqual(
            occurrence["count_unit"], "source_session_message"
        )
        self.assertEqual(
            occurrence["source_reported_failed_attempts"], 3
        )

    def test_duplicate_reuses_case_and_retains_record_references(self):
        a = sample("a")
        b = sample("b", location="syslog")
        incoming = sample("c")

        snapshot = context(("c1", [a, b]))
        before = deepcopy((incoming, snapshot))

        decision = associate_alert(incoming, snapshot)

        self.assertEqual(
            (decision["case_id"], decision["delivery"]),
            ("c1", "duplicate_representation"),
        )
        self.assertEqual(
            decision["duplicate_of_alert_ids"],
            sorted([a["record_id"], b["record_id"]]),
        )
        self.assertEqual(
            decision["alert_id"], incoming["record_id"]
        )
        self.assertEqual((incoming, snapshot), before)

    def test_different_session_is_distinct(self):
        a = sample("a")
        b = sample("b", session="B")

        self.assertNotEqual(
            describe_occurrence(a)["id"],
            describe_occurrence(b)["id"],
        )
        self.assertEqual(
            associate_alert(b, context(("c1", [a])))["delivery"],
            "new",
        )

    def test_duplicate_owner_wins_over_another_context_match(self):
        a = sample("a")
        b = sample("b", session="B")
        incoming = sample("c")

        decision = associate_alert(
            incoming,
            context(("c1", [a]), ("c2", [b])),
        )

        self.assertEqual(
            (decision["decision"], decision["case_id"]),
            ("EXISTING_CASE", "c1"),
        )
        self.assertEqual(
            decision["delivery"], "duplicate_representation"
        )

    def test_same_occurrence_in_two_cases_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "multiple cases"):
            associate_alert(
                sample("c"),
                context(
                    ("c1", [sample("a")]),
                    ("c2", [sample("b")]),
                ),
            )

    def test_conflicting_terminal_report_is_not_a_duplicate(self):
        a = sample("a")
        b = sample("b", outcome="success")

        self.assertNotEqual(
            describe_occurrence(a)["id"],
            describe_occurrence(b)["id"],
        )

        decision = associate_alert(b, context(("c1", [a])))

        self.assertEqual(
            decision["reason"], "conflicting_session_context"
        )
        self.assertEqual(decision["delivery"], "new")

    def test_duplicate_does_not_hide_known_conflict(self):
        decision = associate_alert(
            sample("c"),
            context(
                ("c1", [sample("a")]),
                ("c2", [sample("b", outcome="success")]),
            ),
        )

        self.assertEqual(
            decision["delivery"], "duplicate_representation"
        )
        self.assertTrue(decision["occurrence_conflicted"])
        self.assertEqual(
            decision["conflicting_case_ids"], ["c2"]
        )

    def test_unsupported_profile_does_not_claim_an_occurrence_count(self):
        record = sample("a")
        record["provenance"]["dataset_adapter"] = "unknown"

        occurrence = describe_occurrence(record)

        self.assertFalse(
            occurrence["representation_matching_supported"]
        )
        self.assertEqual(
            occurrence["count_unit"],
            "record_not_confirmed_occurrence",
        )

    def test_same_record_is_replay_not_new_representation(self):
        record = sample("a")

        decision = associate_alert(
            record,
            context(("c1", [record])),
        )

        self.assertEqual(decision["delivery"], "replay")


if __name__ == "__main__":
    unittest.main()