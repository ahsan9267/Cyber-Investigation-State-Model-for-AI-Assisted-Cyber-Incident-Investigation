"""Development evaluation of Step 3; all cases exist only in memory."""

from collections import Counter
from copy import deepcopy
import json

from spine.association import POLICY, associate_alert, fingerprint
from spine.envelope import build_envelope


G1 = "11111111-2222-3333-4444-555555555555"
G2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def auth(account="alice", outcome="failure"):
    return {
        "authentication": {
            "outcome": outcome,
            "target": {"name": account, "domain": "LAB"},
            "source_ip": "10.0.0.10",
            "logon_type": 3,
        }
    }


def flow(identifier):
    return {
        "network": {
            "flow_id": identifier,
            "source_ip": "10.0.0.10",
            "source_port": 50000,
            "destination_ip": "10.0.0.20",
            "destination_port": 443,
            "protocol": "TCP",
        }
    }


def event(
    identity,
    minute,
    attributes,
    provider="security",
    host="server-a",
):
    return {
        "id": identity,
        "time": f"2026-10-06T10:{minute:02d}:00Z",
        "host": host,
        "provider": provider,
        "attributes": attributes,
    }


def scenarios():
    # Expected groups describe the intended controlled scenario.
    # These labels are never passed to the association engine.
    return [
        {
            "name": "related_login_sequence_and_other_account",
            "description": (
                "One controlled login sequence; Bob is independent."
            ),
            "events": [
                event("a1", 0, auth()),
                event("a2", 2, auth()),
                event("a3", 5, auth(outcome="success")),
                event("b1", 6, auth("bob", "success")),
            ],
            "expected_groups": [
                "login-A", "login-A", "login-A", "independent-B"
            ],
        },
        {
            "name": "independent_actors_with_same_login_context",
            "description": (
                "Different controlled actors use the same account "
                "and client. Their independence is not observable "
                "in the supplied fields."
            ),
            "events": [
                event("a1", 0, auth()),
                event("b1", 2, auth(outcome="success")),
            ],
            "expected_groups": ["actor-A", "actor-B"],
        },
        {
            "name": "shared_ip_but_different_hosts",
            "description": (
                "Independent activity shares an account name "
                "and client IP."
            ),
            "events": [
                event("a1", 0, auth(), host="server-a"),
                event("b1", 2, auth(), host="server-b"),
            ],
            "expected_groups": [
                "host-A-activity", "host-B-activity"
            ],
        },
        {
            "name": "two_alerts_from_one_process_instance",
            "description": (
                "Two alerts in one controlled process investigation."
            ),
            "events": [
                event(
                    "p1", 0,
                    {"process": {"guid": G1}},
                    provider="sysmon",
                ),
                event(
                    "p2", 2,
                    {"process": {"guid": G1}},
                    provider="sysmon",
                ),
            ],
            "expected_groups": ["process-A", "process-A"],
        },
        {
            "name": "parent_child_process_chain",
            "description": (
                "A controlled parent-child execution chain "
                "belongs together."
            ),
            "events": [
                event(
                    "p1", 0,
                    {"process": {"guid": G1}},
                    provider="sysmon",
                ),
                event(
                    "p2", 2,
                    {
                        "process": {
                            "guid": G2,
                            "parent": {"guid": G1},
                        }
                    },
                    provider="sysmon",
                ),
            ],
            "expected_groups": ["execution-A", "execution-A"],
        },
        {
            "name": "same_flow_and_independent_flow",
            "description": (
                "Two alerts from one flow; a separate flow is independent."
            ),
            "events": [
                event("n1", 0, flow("100"), provider="suricata"),
                event("n2", 2, flow("100"), provider="suricata"),
                event("n3", 3, flow("200"), provider="suricata"),
            ],
            "expected_groups": ["flow-A", "flow-A", "flow-B"],
        },
    ]


def normalized(spec, scenario_name):
    # Synthetic normalized input, not an end-to-end normalizer test.
    record = build_envelope(
        raw_text=json.dumps(spec, sort_keys=True),
        source=spec["provider"],
        collector="synthetic_alerts",
        record_kind="alert",
        source_scope="evaluation/" + scenario_name,
        source_record_id=spec["id"],
        observed_time="2026-10-06T11:00:00Z",
    )

    record["event_time"] = {"utc": spec["time"]}
    record["host"] = {"name": spec["host"]}
    record["event"] = {"provider": spec["provider"]}
    record["attributes"] = deepcopy(spec["attributes"])
    record["priority"]["actionable"] = True
    record["normalization"].update(
        parser="synthetic_evaluation/1",
        status="partial",
    )
    return record


def pair_counts(expected, actual):
    counts = {
        "correctly_associated_pairs": 0,
        "incorrectly_merged_pairs": 0,
        "missed_association_pairs": 0,
        "correctly_separated_pairs": 0,
    }

    for i in range(len(expected)):
        for j in range(i):
            related = expected[i] == expected[j]
            grouped = actual[i] == actual[j]

            if related and grouped:
                key = "correctly_associated_pairs"
            elif grouped:
                key = "incorrectly_merged_pairs"
            elif related:
                key = "missed_association_pairs"
            else:
                key = "correctly_separated_pairs"

            counts[key] += 1

    return counts


def evaluate(scenario):
    records = [
        normalized(item, scenario["name"])
        for item in scenario["events"]
    ]
    before = fingerprint(records)

    snapshot = {
        "revision": 0,
        "complete": True,
        "cases": [],
    }
    actual = []
    decisions = []

    for spec, record in zip(scenario["events"], records):
        decision = associate_alert(record, snapshot)
        route = decision["decision"]

        if route == "NEW_CASE":
            cid = "test-case-" + str(len(snapshot["cases"]) + 1)
            target = {
                "case_id": cid,
                "revision": 0,
                "status": "active",
                "alerts": [],
            }
            snapshot["cases"].append(target)

        elif route == "EXISTING_CASE":
            cid = decision["case_id"]
            target = next(
                case for case in snapshot["cases"]
                if case["case_id"] == cid
            )

        else:
            raise RuntimeError(
                "Synthetic admitted alert was not routed"
            )

        target["alerts"].append(deepcopy(record))
        target["revision"] += 1
        snapshot["revision"] += 1
        actual.append(cid)

        decisions.append({
            "input": spec["id"],
            "route": route,
            "case_id": cid,
            "reason": decision["reason"],
            "decision_id": decision["decision_id"],
        })

    if fingerprint(records) != before:
        raise RuntimeError("Evaluation input was modified")

    counts = pair_counts(scenario["expected_groups"], actual)

    return {
        "scenario": scenario["name"],
        "description": scenario["description"],
        "expected_groups": scenario["expected_groups"],
        "actual_groups": actual,
        "expected_case_count": len(set(scenario["expected_groups"])),
        "actual_case_count": len(snapshot["cases"]),
        "pair_counts": counts,
        "matches_ground_truth": (
            counts["incorrectly_merged_pairs"] == 0
            and counts["missed_association_pairs"] == 0
        ),
        "decisions": decisions,
    }


def main():
    fixtures = scenarios()
    results = [evaluate(scenario) for scenario in fixtures]

    totals = Counter()
    for result in results:
        totals.update(result["pair_counts"])

    print(json.dumps({
        "evaluation": "synthetic_development_scenarios/1",
        "policy": POLICY,
        "fixture_sha256": fingerprint(fixtures),
        "scope": (
            "Routing evaluation with an in-memory "
            "case-manager substitute"
        ),
        "held_out_evaluation": False,
        "live_normalization_tested": False,
        "database_written": False,
        "scenarios_matching_ground_truth": sum(
            result["matches_ground_truth"]
            for result in results
        ),
        "scenario_count": len(results),
        "pair_totals": dict(totals),
        "results": results,
    }, indent=2))


if __name__ == "__main__":
    main()