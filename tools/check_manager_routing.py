"""Rollback-only database checks for record routing."""

from datetime import datetime, timezone
import getpass
import json
from unittest.mock import patch
import uuid

from spine.envelope import build_envelope
from spine.manager_database import connect_manager_database
from spine.manager_routing import process_record_work
from spine.manager_snapshot import (
    assert_snapshot_current,
    build_locked_snapshot,
)
from spine.manager_views import load_annotation_context
from spine.manager_work import discover_work
from spine.storage import store_record


def expect(actual, expected, label):
    if actual != expected:
        raise RuntimeError(
            f"{label}: expected {expected!r}, received {actual!r}"
        )
    print(f"PASS: {label}")


TABLES = (
    "ingestion.records",
    "ingestion.record_conflicts",
    "investigation.work_items",
    "investigation.evidence_views",
    "investigation.cases",
    "investigation.case_memberships",
    "investigation.routing_decisions",
    "investigation.case_history",
    "investigation.case_relationships",
    "investigation.pending_investigation_work",
    "investigation.record_scheduling_metadata",
    "investigation.case_reassessments",
)


def counts(connection):
    # Fixed table names only; no user-provided SQL identifiers.
    return {
        table: connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]
        for table in TABLES
    }


def routing_revision(connection):
    return connection.execute(
        """
        SELECT revision
        FROM investigation.routing_state
        WHERE singleton_id = 1
        """
    ).fetchone()[0]


def run_checks(connection):
    baseline = counts(connection)
    baseline_revision = routing_revision(connection)

    scope = f"step4-routing-check/{uuid.uuid4()}"
    process_guid = str(uuid.uuid4())
    unrelated_guid = str(uuid.uuid4())
    context = load_annotation_context()
    observed = datetime.now(timezone.utc).isoformat()

    def sample(source_id, guid, minute, kind="alert"):
        raw = json.dumps({
            "test_record": source_id,
            "process_guid": guid,
            "minute": minute,
            "value": "preserved\x00",
        })

        record = build_envelope(
            raw_text=raw,
            source="sysmon",
            collector="manager_routing_check",
            record_kind=kind,
            source_scope=scope,
            source_record_id=source_id,
            observed_time=observed,
        )
        record["host"]["name"] = scope
        record["event"]["provider"] = "sysmon"
        record["event_time"] = {
            "utc": f"2026-10-01T12:{minute:02d}:00Z"
        }
        record["attributes"]["process"] = {
            "guid": guid,
            "image": r"C:\Lab\fixture.exe",
        }
        record["attributes"]["source_payload"] = {
            "value": "preserved\x00"
        }
        return record

    first = sample("first", process_guid, 0)
    related = sample("related", process_guid, 1)
    unrelated = sample("unrelated", unrelated_guid, 2)
    telemetry = sample("telemetry", process_guid, 3, "telemetry")
    records = [first, related, unrelated, telemetry]

    with connection.transaction(force_rollback=True):
        baseline_snapshot = build_locked_snapshot(connection)
        for record in records:
            expect(
                store_record(connection, record),
                "inserted",
                f"fixture {record['provenance']['source_record_id']} stored",
            )

        expect(
            discover_work(connection, source_scope=scope),
            {"records_queued": 4, "conflicts_queued": 0},
            "four fixture records queued",
        )

        work_ids = dict(connection.execute(
            """
            SELECT w.record_id, w.work_id
            FROM investigation.work_items AS w
            JOIN ingestion.records AS r ON r.record_id = w.record_id
            WHERE r.source_scope = %s
              AND w.work_kind = 'record'
            """,
            (scope,),
        ).fetchall())

        def route(record):
            return process_record_work(
                connection,
                work_ids[record["record_id"]],
                context=context,
            )

        before_failure = counts(connection)

        # This fails after the view, case, decision and membership writes,
        # but before history, downstream work and acknowledgment finish.
        try:
            with patch(
                "spine.manager_routing.append_case_history",
                side_effect=RuntimeError("injected history failure"),
            ):
                route(first)
        except RuntimeError as error:
            if str(error) != "injected history failure":
                raise
        else:
            raise RuntimeError("Injected failure did not occur")

        expect(
            counts(connection),
            before_failure,
            "partial routing writes rolled back",
        )
        expect(
            routing_revision(connection),
            baseline_revision,
            "failed routing did not advance revision",
        )

        work_state = connection.execute(
            """
            SELECT status, outcome, attempt_count
            FROM investigation.work_items
            WHERE work_id = %s
            """,
            (work_ids[first["record_id"]],),
        ).fetchone()
        expect(
            work_state,
            ("pending", None, 0),
            "failed work remains pending and unacknowledged",
        )

        first_result = route(first)
        expect(first_result["status"], "completed", "first alert routed")
        expect(
            first_result["case_id"] is not None,
            True,
            "first alert receives a case",
        )

        earlier_snapshot = build_locked_snapshot(connection)

        related_result = route(related)
        expect(
            related_result["case_id"],
            first_result["case_id"],
            "same-process alert joins the existing case",
        )

        try:
            assert_snapshot_current(connection, earlier_snapshot)
        except RuntimeError as error:
            if "Case snapshot changed" not in str(error):
                raise
            print("PASS: stale snapshot rejected")
        else:
            raise RuntimeError("Stale snapshot was accepted")

        unrelated_result = route(unrelated)
        expect(
            unrelated_result["case_id"] != first_result["case_id"],
            True,
            "different process receives a separate case",
        )

        telemetry_result = route(telemetry)
        expect(telemetry_result["case_id"], None, "telemetry has no case")
        expect(
            telemetry_result["delivery"],
            "excluded",
            "telemetry exclusion recorded",
        )

        before_replay = counts(connection)
        revision_before_replay = routing_revision(connection)
        repeated = route(first)

        expect(repeated["repeated_work"], True, "completed work recognized")
        expect(
            repeated["case_id"],
            first_result["case_id"],
            "repeated work retains its original case",
        )
        expect(
            counts(connection),
            before_replay,
            "repeated work adds no database rows",
        )
        expect(
            routing_revision(connection),
            revision_before_replay,
            "repeated work does not advance routing revision",
        )

        final_counts = counts(connection)
        expected_additions = {
            "investigation.cases": 2,
            "investigation.case_memberships": 3,
            "investigation.routing_decisions": 4,
            "investigation.case_history": 3,
            "investigation.pending_investigation_work": 3,
            "investigation.evidence_views": 4,
        }
        for table, added in expected_additions.items():
            expect(
                final_counts[table] - baseline[table],
                added,
                f"expected row count in {table}",
            )

        expect(
            routing_revision(connection),
            baseline_revision + 3,
            "only case-changing routes advance the global revision",
        )

        membership_counts = connection.execute(
            """
            SELECT m.count_unit, COUNT(*)
            FROM investigation.case_memberships AS m
            JOIN ingestion.records AS r ON r.record_id = m.record_id
            WHERE r.source_scope = %s
            GROUP BY m.count_unit
            ORDER BY m.count_unit
            """,
            (scope,),
        ).fetchall()
        expect(
            membership_counts,
            [("record_not_confirmed_occurrence", 3)],
            "fixture occurrences remain explicitly uncertain",
        )

        fixture_case_ids = [
            uuid.UUID(first_result["case_id"]),
            uuid.UUID(unrelated_result["case_id"]),
        ]
        tasks = connection.execute(
            """
            SELECT target_component, status, COUNT(*)
            FROM investigation.pending_investigation_work
            WHERE case_id = ANY(%s::uuid[])
            GROUP BY target_component, status
            ORDER BY target_component, status
            """,
            (fixture_case_ids,),
        ).fetchall()
        expect(
            tasks,
            [("cyber_investigation_state", "pending", 3)],
            "fixture investigation tasks remain pending",
        )

        outcomes = connection.execute(
            """
            SELECT w.outcome, COUNT(*)
            FROM investigation.work_items AS w
            JOIN ingestion.records AS r ON r.record_id = w.record_id
            WHERE r.source_scope = %s
              AND w.status = 'completed'
            GROUP BY w.outcome
            ORDER BY w.outcome
            """,
            (scope,),
        ).fetchall()
        expect(
            outcomes,
            [("excluded", 1), ("routed", 3)],
            "all four work items acknowledged correctly",
        )

        final_snapshot = build_locked_snapshot(connection)
        baseline_cases = {
            case["case_id"]: case
            for case in baseline_snapshot["snapshot"]["cases"]
        }
        final_cases = {
            case["case_id"]: case
            for case in final_snapshot["snapshot"]["cases"]
        }
        expect(
            set(final_cases) - set(baseline_cases),
            {
                first_result["case_id"],
                unrelated_result["case_id"],
            },
            "complete snapshot adds exactly the two fixture cases",
        )
        expect(
            {
                case_id: final_cases.get(case_id)
                for case_id in baseline_cases
            },
            baseline_cases,
            "existing case snapshot content remains unchanged",
        )
        baseline_refs = baseline_snapshot["view_refs"]
        final_refs = final_snapshot["view_refs"]
        expect(
            set(final_refs) - set(baseline_refs),
            {
                first["record_id"],
                related["record_id"],
                unrelated["record_id"],
            },
            "snapshot adds exactly the three admitted fixture alerts",
        )
        expect(
            {
                record_id: final_refs.get(record_id)
                for record_id in baseline_refs
            },
            baseline_refs,
            "existing evidence-view references remain unchanged",
        )

    expect(counts(connection), baseline, "all temporary rows rolled back")
    expect(
        routing_revision(connection),
        baseline_revision,
        "routing revision restored by rollback",
    )


def main():
    password = getpass.getpass("spine_app password: ")

    with connect_manager_database(
        dbname="spine_step4_dev",
        password=password,
    ) as connection:
        if connection.execute(
            "SELECT current_database()"
        ).fetchone()[0] != "spine_step4_dev":
            raise RuntimeError("Run only against spine_step4_dev")

        run_checks(connection)

    print("SUCCESS: record routing database checks passed")
    print("Synthetic fixtures; incident accuracy and crash recovery not tested.")


if __name__ == "__main__":
    main()