"""Check retained reassessments and rollback of failed assessments."""

from datetime import datetime, timezone
import getpass
import json
from unittest.mock import patch
import uuid

from spine.association import fingerprint
from spine.envelope import build_envelope
from spine.manager_conflicts import process_conflict_work
from spine.manager_database import connect_manager_database
from spine.manager_reassessment import reassess_cases_for_work
from spine.manager_routing import process_record_work
from spine.manager_views import load_annotation_context
from spine.manager_snapshot_storage import read_stored_snapshot
from spine.manager_work import discover_work
from spine.storage import store_record

from check_manager_restart import (
    counts as existing_counts,
    expect,
    revision,
)


def counts(connection):
    result = existing_counts(connection)
    result["investigation.case_reassessments"] = connection.execute(
        "SELECT COUNT(*) FROM investigation.case_reassessments"
    ).fetchone()[0]
    return result


def work_state(connection, work_id):
    return connection.execute(
        """
        SELECT status, attempt_count, outcome, completed_at
        FROM investigation.work_items
        WHERE work_id = %s
        """,
        (work_id,),
    ).fetchone()


def assessment_rows(connection, case_id):
    rows = connection.execute(
        """
        SELECT
            reassessment_id, case_revision,
            snapshot_document, snapshot_view_refs,
            assessment_inputs, input_sha256, assessment_document
        FROM investigation.case_reassessments
        WHERE case_id = %s
        ORDER BY case_revision, reassessment_id
        """,
        (case_id,),
    ).fetchall()
    return [
        (*row[:2], read_stored_snapshot(connection, row[2], row[3]), *row[3:])
        for row in rows
    ]


def run_checks(connection):
    baseline = counts(connection)
    baseline_revision = revision(connection)
    token = str(uuid.uuid4())
    scope = f"step4-reassessment-check/{token}"
    process_guid = str(uuid.uuid4())
    context = load_annotation_context()

    def sample(source_id, version="original", minute=0):
        record = build_envelope(
            raw_text=json.dumps({
                "source_id": source_id,
                "version": version,
                "value": "preserved\x00",
            }),
            source="sysmon",
            collector="manager_reassessment_check",
            record_kind="alert",
            source_scope=scope,
            source_record_id=source_id,
            observed_time=datetime.now(timezone.utc).isoformat(),
        )
        record["host"]["name"] = f"reassessment-test-{token}"
        record["event"]["provider"] = "sysmon"
        record["event_time"] = {
            "utc": f"2026-10-01T12:{minute:02d}:00Z"
        }
        record["attributes"]["process"] = {
            "guid": process_guid,
            "image": r"C:\Lab\reassessment-fixture.exe",
        }
        record["attributes"]["fixture"] = {
            "value": "preserved\x00",
            "version": version,
        }
        return record

    first = sample("first")
    second = sample("second", minute=1)
    conflict = sample("first", version="changed")

    def queue_record(record, kind="record"):
        store_record(connection, record)
        discover_work(connection, source_scope=scope)
        return connection.execute(
            """
            SELECT work_id
            FROM investigation.work_items
            WHERE work_kind = %s
              AND record_id = %s
              AND payload_sha256 = %s
            """,
            (kind, record["record_id"], record["raw"]["sha256"]),
        ).fetchone()[0]

    def route(item_id):
        return process_record_work(
            connection, item_id, context=context
        )

    def fail_after_assessment(conn, item_id):
        reassess_cases_for_work(conn, item_id)
        raise RuntimeError("injected reassessment failure")

    def check_failure(target, action, item_id):
        before = counts(connection)
        before_revision = revision(connection)
        before_state = work_state(connection, item_id)

        with patch(target, side_effect=fail_after_assessment):
            try:
                action(item_id)
            except RuntimeError as error:
                if str(error) != "injected reassessment failure":
                    raise
            else:
                raise AssertionError("Expected reassessment failure")

        expect(
            "assessment failure rolls back all added rows",
            counts(connection),
            before,
        )
        expect(
            "assessment failure restores global revision",
            revision(connection),
            before_revision,
        )
        expect(
            "assessment failure leaves work unacknowledged",
            work_state(connection, item_id),
            before_state,
        )

    with connection.transaction(force_rollback=True):
        first_work = queue_record(first)

        check_failure(
            "spine.manager_routing.reassess_cases_for_work",
            route,
            first_work,
        )

        first_result = route(first_work)
        case_id = uuid.UUID(first_result["case_id"])
        first_rows = assessment_rows(connection, case_id)

        expect("new case gets one assessment", len(first_rows), 1)
        first_document = first_rows[0][6]
        expect(
            "singleton assessment avoids a confirmation claim",
            first_document["confirmed_incident"],
            False,
        )
        expect(
            "underlying activity count remains unknown",
            first_document["counts"]["confirmed_underlying_activities"],
            None,
        )
        expect(
            "unsupported occurrence representation retained",
            first_document["counts"]["unsupported_occurrence_representations"],
            1,
        )

        repeated_ids = reassess_cases_for_work(connection, first_work)
        expect(
            "identical reassessment reuses its identity",
            repeated_ids,
            [first_rows[0][0]],
        )
        expect(
            "identical reassessment adds no duplicate",
            assessment_rows(connection, case_id),
            first_rows,
        )

        second_work = queue_record(second)
        second_result = route(second_work)
        expect(
            "related alert retains case ownership",
            second_result["case_id"],
            str(case_id),
        )

        second_rows = assessment_rows(connection, case_id)
        expect(
            "new case revision gets a new assessment",
            [row[1] for row in second_rows],
            [1, 2],
        )
        expect(
            "earlier assessment remains unchanged",
            second_rows[0],
            first_rows[0],
        )

        pair_checks = second_rows[1][6]["pair_checks"]
        expect("two members produce one internal pair", len(pair_checks), 1)
        expect(
            "retained process relationship supports the pair",
            pair_checks[0]["pair_has_assignment_support"],
            True,
        )

        conflict_work = queue_record(conflict, "conflict")
        before_conflict_rows = assessment_rows(connection, case_id)
        before_case_revision = connection.execute(
            "SELECT revision FROM investigation.cases WHERE case_id = %s",
            (case_id,),
        ).fetchone()[0]

        check_failure(
            "spine.manager_conflicts.reassess_cases_for_work",
            lambda item_id: process_conflict_work(connection, item_id),
            conflict_work,
        )
        expect(
            "failed conflict assessment preserves earlier assessments",
            assessment_rows(connection, case_id),
            before_conflict_rows,
        )
        expect(
            "failed conflict assessment restores case revision",
            connection.execute(
                "SELECT revision FROM investigation.cases WHERE case_id = %s",
                (case_id,),
            ).fetchone()[0],
            before_case_revision,
        )

        process_conflict_work(connection, conflict_work)
        final_rows = assessment_rows(connection, case_id)
        expect(
            "conflict adds assessment for revision three",
            [row[1] for row in final_rows],
            [1, 2, 3],
        )

        latest = final_rows[-1]
        inputs = latest[4]
        document = latest[6]

        expect(
            "payload conflict remains explicitly unresolved",
            document["status"],
            "unresolved_conflicts",
        )
        expect(
            "conflict causes totals to be withheld",
            document["counts"]["totals_withheld_due_to_conflicts"],
            True,
        )
        expect(
            "assessment does not claim rerouting",
            document["routing_recomputed"],
            False,
        )
        expect(
            "exact conflicting document retained",
            inputs["payload_conflicts"][0]["document"],
            conflict,
        )
        expect(
            "null character survives assessment input storage",
            inputs["payload_conflicts"][0]["document"]
            ["attributes"]["fixture"]["value"],
            "preserved\x00",
        )
        expect(
            "all earlier assessments remain unchanged",
            final_rows[:2],
            before_conflict_rows,
        )

        for saved in final_rows:
            (
                assessment_id, case_revision, snapshot, view_refs,
                saved_inputs, input_hash, assessment,
            ) = saved

            expected_input_hash = fingerprint({
                "case_id": str(case_id),
                "case_revision": case_revision,
                "snapshot_document": snapshot,
                "assessment_inputs": saved_inputs,
            })
            expect(
                f"revision {case_revision} input fingerprint verifies",
                input_hash,
                expected_input_hash,
            )
            expect(
                f"revision {case_revision} assessment fingerprint verifies",
                assessment_id,
                fingerprint({
                    "input_sha256": input_hash,
                    "assessment_document": assessment,
                }),
            )
            expect(
                f"revision {case_revision} view references retained",
                view_refs,
                saved_inputs["snapshot_view_refs"],
            )

        before_replay = counts(connection)
        replay = process_conflict_work(connection, conflict_work)
        expect("completed conflict recognized", replay["repeated_work"], True)
        expect(
            "repeated completed work adds no assessments",
            counts(connection),
            before_replay,
        )

    expect("all temporary rows rolled back", counts(connection), baseline)
    expect(
        "global routing revision restored",
        revision(connection),
        baseline_revision,
    )


def main():
    password = getpass.getpass("spine_app password: ")
    with connect_manager_database(
        dbname="spine_step4_dev",
        password=password,
    ) as connection:
        expect(
            "connected to development database",
            connection.execute(
                "SELECT current_database()"
            ).fetchone()[0],
            "spine_step4_dev",
        )
        run_checks(connection)

    print("SUCCESS: reassessment database checks passed")
    print("Temporary fixtures rolled back; existing committed cases preserved.")
    print("This checks case consistency, not fresh routing or incident accuracy.")


if __name__ == "__main__":
    main()
