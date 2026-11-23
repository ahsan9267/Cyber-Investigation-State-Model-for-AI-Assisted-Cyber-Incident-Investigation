import json
import unittest
from copy import deepcopy

from spine.envelope import build_envelope
from spine.association import associate_alert


def alert(identity, minute=0, account="alice", source="10.0.0.10"):
    record = build_envelope(
        raw_text=json.dumps({"test_event": identity}),
        source="wazuh",
        collector="wazuh_alerts",
        record_kind="alert",
        source_scope="test/lab-a",
        source_record_id=identity,
        observed_time="2026-10-06T00:00:00Z",
    )
    record["event_time"] = {
        "utc": f"2026-10-06T10:{minute:02d}:00Z"
    }
    record["host"] = {"name": "server-a"}
    record["event"] = {
        "provider": "security",
        "type": "authentication",
    }
    record["attributes"]["authentication"] = {
        "outcome": "failure",
        "target": {"name": account, "domain": "LAB"},
        "source_ip": source,
        "logon_type": 3,
    }
    return record


def case(cid, *records):
    return {
        "case_id": cid,
        "revision": 1,
        "status": "active",
        "alerts": list(records),
    }


def snapshot(*cases):
    return {
        "revision": 1,
        "complete": True,
        "cases": list(cases),
    }


class AssociationTests(unittest.TestCase):
    def test_first_alert_recommends_new_case(self):
        decision = associate_alert(alert("a"), snapshot())

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertIsNone(decision["case_id"])

    def test_later_success_keeps_context_link_without_assignment(self):
        incoming = alert("success", 20)
        incoming["attributes"]["authentication"]["outcome"] = "success"

        decision = associate_alert(
            incoming,
            snapshot(case("c1", alert("failure"))),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["reason"], "weak_context_only")
        self.assertEqual(decision["possible_case_ids"], ["c1"])
        self.assertIsNone(decision["case_id"])

        rule = decision["comparisons"][0]["alert_comparisons"][0][
            "relationship_rules"
        ][0]["rule"]
        self.assertEqual(rule, "authentication_context")

    def test_unrelated_account_remains_separate(self):
        decision = associate_alert(
            alert("b", 5, account="bob"),
            snapshot(case("c1", alert("a"))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_same_ip_and_time_alone_do_not_match(self):
        incoming = alert("b")
        incoming["attributes"]["authentication"].pop("target")

        decision = associate_alert(
            incoming,
            snapshot(case("c1", alert("a"))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_different_host_or_source_scope_does_not_match(self):
        for field in ("host", "scope"):
            incoming = alert("b", 10)

            if field == "host":
                incoming["host"]["name"] = "server-b"
            else:
                from hashlib import sha256

                incoming["provenance"]["source_scope"] = "test/lab-b"
                identity = [
                    incoming["collector"],
                    "test/lab-b",
                    incoming["provenance"]["source_record_id"],
                ]
                incoming["record_id"] = sha256(
                    json.dumps(
                        identity,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest()

            with self.subTest(field=field):
                decision = associate_alert(
                    incoming,
                    snapshot(case("c1", alert("a"))),
                )
                self.assertEqual(decision["decision"], "NEW_CASE")

    def test_two_plausible_cases_are_not_merged(self):
        first = alert("a")
        second = alert("b", 10)
        incoming = alert("c", 15)

        # Two existing cases independently contain alerts from the
        # same process. Step 3 must not arbitrarily choose or merge them.
        guid = "11111111-2222-3333-4444-555555555555"
        for record in (first, second, incoming):
            record["attributes"] = {"process": {"guid": guid}}

        decision = associate_alert(
            incoming,
            snapshot(case("c1", first), case("c2", second)),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["reason"], "multiple_plausible_cases")
        self.assertEqual(decision["candidate_case_ids"], ["c1", "c2"])

    def test_replay_reuses_existing_assignment(self):
        existing = alert("a")
        decision = associate_alert(
            existing,
            snapshot(case("c1", existing)),
        )

        self.assertEqual(
            (decision["delivery"], decision["case_id"]),
            ("replay", "c1"),
        )

    def test_distinct_repeated_attempt_is_not_replay(self):
        decision = associate_alert(
            alert("b"),
            snapshot(case("c1", alert("a"))),
        )

        self.assertEqual(decision["delivery"], "new")
        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["possible_case_ids"], ["c1"])

    def test_missing_or_distant_time_does_not_match(self):
        for event_time in (
            None,
            {"utc": "2026-10-06T15:00:00Z"},
        ):
            incoming = alert("b")
            incoming["event_time"] = event_time

            with self.subTest(event_time=event_time):
                decision = associate_alert(
                    incoming,
                    snapshot(case("c1", alert("a"))),
                )
                self.assertEqual(decision["decision"], "NEW_CASE")

    def test_telemetry_is_not_an_investigation_trigger(self):
        incoming = alert("b")
        incoming["record_kind"] = "telemetry"

        decision = associate_alert(incoming, snapshot())

        self.assertIsNone(decision["decision"])
        self.assertEqual(decision["delivery"], "excluded")

    def test_unsupported_alert_still_gets_new_case(self):
        incoming = alert("b")
        incoming["attributes"] = {}

        decision = associate_alert(
            incoming,
            snapshot(case("c1", alert("a"))),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_process_guid_rule(self):
        previous = alert("a")
        incoming = alert("b", 5, account="bob")
        guid = "{11111111-2222-3333-4444-555555555555}"

        for record in (previous, incoming):
            record["attributes"] = {"process": {"guid": guid}}

        decision = associate_alert(
            incoming,
            snapshot(case("c1", previous)),
        )
        self.assertEqual(decision["decision"], "EXISTING_CASE")

    def test_sensor_flow_rule_and_distinct_flow(self):
        previous = alert("a")
        incoming = alert("b", 5)

        for record in (previous, incoming):
            record["event"] = {"provider": "suricata"}
            record["attributes"] = {
                "network": {
                    "flow_id": "123",
                    "source_ip": "10.0.0.1",
                    "source_port": 50000,
                    "destination_ip": "10.0.0.2",
                    "destination_port": 443,
                    "protocol": "TCP",
                }
            }

        context = snapshot(case("c1", previous))

        self.assertEqual(
            associate_alert(incoming, context)["decision"],
            "EXISTING_CASE",
        )

        incoming["attributes"]["network"]["flow_id"] = "124"

        self.assertEqual(
            associate_alert(incoming, context)["decision"],
            "NEW_CASE",
        )

    def test_session_conflict_does_not_join_case(self):
        previous = alert("a")
        incoming = alert("b")

        for record in (previous, incoming):
            record["event"]["provider"] = "dovecot"
            record["attributes"]["authentication"].update(
                service="imap",
                session_id="S1",
            )

        incoming["attributes"]["authentication"]["outcome"] = "success"

        decision = associate_alert(
            incoming,
            snapshot(case("c1", previous)),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")
        self.assertEqual(decision["reason"], "conflicting_session_context")

    def test_incomplete_snapshot_is_rejected(self):
        context = snapshot()
        context["complete"] = False

        with self.assertRaises(ValueError):
            associate_alert(alert("a"), context)

    def test_deterministic_nonmutating_and_versioned(self):
        incoming = alert("incoming", 20)
        context = snapshot(
            case("c2", alert("b", 10)),
            case("c1", alert("a")),
        )
        original = deepcopy((incoming, context))

        first = associate_alert(incoming, context)

        self.assertEqual((incoming, context), original)

        context["cases"].reverse()
        self.assertEqual(associate_alert(incoming, context), first)

        context["revision"] += 1
        self.assertNotEqual(
            associate_alert(incoming, context)["decision_id"],
            first["decision_id"],
        )

    def test_case_span_prevents_indefinite_chaining(self):
        old = alert("a")
        recent = alert("b")
        incoming = alert("c")

        recent["event_time"] = {"utc": "2026-10-06T12:00:00Z"}
        incoming["event_time"] = {"utc": "2026-10-06T12:30:00Z"}

        decision = associate_alert(
            incoming,
            snapshot(case("c1", old, recent)),
        )

        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_conflicting_known_sids_do_not_match(self):
        previous = alert("a")
        incoming = alert("b", 5)

        previous["attributes"]["authentication"]["target"]["sid"] = (
            "S-1-5-21-1"
        )
        incoming["attributes"]["authentication"]["target"]["sid"] = (
            "S-1-5-21-2"
        )

        decision = associate_alert(
            incoming,
            snapshot(case("c1", previous)),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_zero_guid_is_not_a_relationship(self):
        previous = alert("a")
        incoming = alert("b", 5)

        for record in (previous, incoming):
            record["attributes"] = {
                "process": {
                    "guid": "00000000-0000-0000-0000-000000000000"
                }
            }

        decision = associate_alert(
            incoming,
            snapshot(case("c1", previous)),
        )
        self.assertEqual(decision["decision"], "NEW_CASE")

    def test_conflicting_payload_under_same_id_is_rejected(self):
        import hashlib

        previous = alert("a")
        changed = deepcopy(previous)
        changed["raw"]["text"] = '{"changed": true}'
        changed["raw"]["sha256"] = hashlib.sha256(
            changed["raw"]["text"].encode()
        ).hexdigest()

        with self.assertRaises(ValueError):
            associate_alert(
                changed,
                snapshot(case("c1", previous)),
            )


if __name__ == "__main__":
    unittest.main()