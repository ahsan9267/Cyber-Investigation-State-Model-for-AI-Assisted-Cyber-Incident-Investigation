"""Rollback-based database checks for conflict processing."""

from datetime import datetime, timezone
import getpass
import json
from unittest.mock import patch
import uuid

from spine.envelope import build_envelope
from spine.manager_conflicts import process_conflict_work
from spine.manager_database import connect_manager_database
from spine.manager_routing import process_record_work
from spine.manager_views import load_annotation_context
from spine.manager_work import discover_work
from spine.storage import store_record


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
    "investigation.conflict_events",
)


def expect(label, actual, expected):
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected!r}, got {actual!r}"
        )
    print(f"PASS: {label}")


def counts(connection):
    return {
        table: connection.execute(
            f"SELECT COUNT(*) FROM {table}"
        ).fetchone()[0]
        for table in TABLES
    }


def revision(connection):
    return connection.execute(
        """
        SELECT revision
        FROM investigation.routing_state
        WHERE singleton_id = 1
        """
    ).fetchone()[0]


def work_state(connection, work_id):
    return connection.execute(
        """
        SELECT status, outcome, attempt_count, completed_at
        FROM investigation.work_items
        WHERE work_id = %s
        """,
        (work_id,),
    ).fetchone()


def run_checks(connection):
    baseline = counts(connection)
    baseline_revision = revision(connection)

    if baseline["investigation.cases"] != 0:
        raise RuntimeError(
            "This check expects the development database to have no cases. "
            "Do not delete existing cases; report this message instead."
        )

    scope = f"step4-conflict-check/{uuid.uuid4()}"
    process_guid = str(uuid.uuid4())
    observed = datetime.now(timezone.utc).isoformat()
    context = load_annotation_context()

    def sample(source_id, payload_version, *, kind="alert"):
        raw = json.dumps({
            "source_id": source_id,
            "payload_version": payload_version,
            "value": "preserved\x00",
        })

        record = build_envelope(
            raw_text=raw,
            source="sysmon",
            collector="manager_conflict_check",
            record_kind=kind,
            source_scope=scope,
            source_record_id=source_id,
            observed_time=observed,
        )
        record["host"]["name"] = "step4-conflict-test-host"
        record["event"]["provider"] = "sysmon"
        record["event_time"] = {
            "utc": "2026-10-01T12:00:00Z"
        }
        record["attributes"]["process"] = {
            "guid": process_guid,
            "image": r"C:\Lab\fixture.exe",
        }
        record["attributes"]["source_payload"] = {
            "version": payload_version,
            "value": "preserved\x00",
        }
        return record

    original = sample("alert-one", "original")
    conflict = sample("alert-one", "changed")
    later_conflict = sample("alert-one", "changed-again")
    telemetry = sample("telemetry-one", "original", kind="telemetry")
    telemetry_conflict = sample(
        "telemetry-one", "changed", kind="telemetry"
    )

    def lookup_work(record, kind):
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

    def discover():
        return discover_work(connection, source_scope=scope)

    def route(record):
        return process_record_work(
            connection,
            lookup_work(record, "record"),
            context=context,
        )

    with connection.transaction(force_rollback=True):
        store_record(connection, original)
        store_record(connection, conflict)

        expect(
            "original and early conflict discovered",
            discover(),
            {"records_queued": 1, "conflicts_queued": 1},
        )

        conflict_work = lookup_work(conflict, "conflict")
        before_wait = counts(connection)
        before_wait_state = work_state(connection, conflict_work)

        waiting = process_conflict_work(connection, conflict_work)
        expect(
            "conflict waits for original routing",
            waiting["status"],
            "waiting_for_original",
        )
        expect(
            "waiting creates no database rows",
            counts(connection),
            before_wait,
        )
        expect(
            "waiting leaves work unacknowledged",
            work_state(connection, conflict_work),
            before_wait_state,
        )
        expect(
            "waiting does not advance routing revision",
            revision(connection),
            baseline_revision,
        )

        routed = route(original)
        case_id = uuid.UUID(routed["case_id"])

        before_failure = counts(connection)
        before_failure_revision = revision(connection)
        before_failure_work = work_state(connection, conflict_work)
        before_failure_case = connection.execute(
            """
            SELECT revision, updated_at
            FROM investigation.cases
            WHERE case_id = %s
            """,
            (case_id,),
        ).fetchone()

        # The processor calls this after inserting its receipt and
        # acknowledging work. Raising here tests rollback of all writes.
        with patch(
            "spine.manager_conflicts.completed_conflict_result",
            side_effect=RuntimeError("injected final-result failure"),
        ):
            try:
                process_conflict_work(connection, conflict_work)
            except RuntimeError as error:
                if str(error) != "injected final-result failure":
                    raise
            else:
                raise AssertionError("Injected failure did not occur")

        expect(
            "failed conflict processing rolls back all added rows",
            counts(connection),
            before_failure,
        )
        expect(
            "failed conflict processing restores work state",
            work_state(connection, conflict_work),
            before_failure_work,
        )
        expect(
            "failed conflict processing restores global revision",
            revision(connection),
            before_failure_revision,
        )
        expect(
            "failed conflict processing restores case revision",
            connection.execute(
                """
                SELECT revision, updated_at
                FROM investigation.cases
                WHERE case_id = %s
                """,
                (case_id,),
            ).fetchone(),
            before_failure_case,
        )

        result = process_conflict_work(connection, conflict_work)
        expect("conflict completed", result["status"], "completed")
        expect(
            "conflict retains original case",
            result["case_id"],
            str(case_id),
        )
        expect("conflict creates case revision two", result["case_revision"], 2)
        expect(
            "successful conflict acknowledged once",
            work_state(connection, conflict_work)[:3],
            ("completed", "conflict_recorded", 1),
        )

        receipt_details = connection.execute(
            """
            SELECT details
            FROM investigation.conflict_events
            WHERE work_id = %s
            """,
            (conflict_work,),
        ).fetchone()[0]
        expect(
            "conflict remains unresolved",
            receipt_details["conflict_resolved"],
            False,
        )
        expect(
            "receipt does not claim association reassessment",
            receipt_details["association_reassessed"],
            False,
        )

        before_repeat = counts(connection)
        before_repeat_revision = revision(connection)
        before_repeat_work = work_state(connection, conflict_work)

        repeated = process_conflict_work(connection, conflict_work)
        expect("completed conflict recognized", repeated["repeated_work"], True)
        expect(
            "repeat retains original receipt",
            repeated["conflict_event_id"],
            result["conflict_event_id"],
        )
        expect("repeat creates no rows", counts(connection), before_repeat)
        expect(
            "repeat does not advance revision",
            revision(connection),
            before_repeat_revision,
        )
        expect(
            "repeat does not increment attempts",
            work_state(connection, conflict_work),
            before_repeat_work,
        )

        store_record(connection, conflict)
        expect(
            "replayed conflict creates no new work",
            discover(),
            {"records_queued": 0, "conflicts_queued": 0},
        )

        # A different conflicting payload arriving after routing
        # must receive its own receipt and case-history revision.
        store_record(connection, later_conflict)
        expect(
            "later conflicting payload discovered",
            discover(),
            {"records_queued": 0, "conflicts_queued": 1},
        )
        later_result = process_conflict_work(
            connection, lookup_work(later_conflict, "conflict")
        )
        expect(
            "later conflict adds another case revision",
            later_result["case_revision"],
            3,
        )

        # Excluded telemetry has no case, but still needs a receipt.
        store_record(connection, telemetry)
        discover()
        excluded = route(telemetry)
        expect("telemetry excluded", excluded["delivery"], "excluded")

        store_record(connection, telemetry_conflict)
        expect(
            "excluded-record conflict discovered",
            discover(),
            {"records_queued": 0, "conflicts_queued": 1},
        )

        before_excluded = counts(connection)
        before_excluded_revision = revision(connection)

        excluded_result = process_conflict_work(
            connection, lookup_work(telemetry_conflict, "conflict")
        )
        expect("excluded conflict has no case", excluded_result["case_id"], None)
        expect(
            "excluded conflict has no case revision",
            excluded_result["case_revision"],
            None,
        )
        expect(
            "excluded conflict does not change global revision",
            revision(connection),
            before_excluded_revision,
        )
        for table in (
            "investigation.cases",
            "investigation.case_history",
            "investigation.pending_investigation_work",
        ):
            expect(
                f"excluded conflict adds no rows to {table}",
                counts(connection)[table],
                before_excluded[table],
            )

        expect(
            "original evidence remains unchanged",
            connection.execute(
                "SELECT document FROM ingestion.records WHERE record_id = %s",
                (original["record_id"],),
            ).fetchone()[0],
            original,
        )
        saved_conflict = connection.execute(
            """
            SELECT incoming_document
            FROM ingestion.record_conflicts
            WHERE record_id = %s AND incoming_raw_sha256 = %s
            """,
            (conflict["record_id"], conflict["raw"]["sha256"]),
        ).fetchone()[0]
        expect("conflicting evidence preserved", saved_conflict, conflict)
        expect(
            "null character preserved in conflicting document",
            saved_conflict["attributes"]["source_payload"]["value"],
            "preserved\x00",
        )

        expected_additions = {
            "investigation.cases": 1,
            "investigation.case_memberships": 1,
            "investigation.routing_decisions": 2,
            "investigation.evidence_views": 2,
            "investigation.case_history": 3,
            "investigation.pending_investigation_work": 3,
            "investigation.conflict_events": 3,
        }
        final_counts = counts(connection)
        for table, addition in expected_additions.items():
            expect(
                f"expected total in {table}",
                final_counts[table],
                baseline[table] + addition,
            )

        expect(
            "all investigation tasks remain pending",
            connection.execute(
                """
                SELECT COUNT(*)
                FROM investigation.pending_investigation_work
                WHERE case_id = %s AND status = 'pending'
                """,
                (case_id,),
            ).fetchone()[0],
            3,
        )
        expect(
            "only case-changing events advance global revision",
            revision(connection),
            baseline_revision + 3,
        )

    expect("all temporary rows rolled back", counts(connection), baseline)
    expect(
        "routing revision restored after rollback",
        revision(connection),
        baseline_revision,
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
            raise RuntimeError("Unexpected database")
        run_checks(connection)

    print("SUCCESS: conflict processing database checks passed")
    print("All fixtures rolled back; crash recovery and concurrency not tested.")


if __name__ == "__main__":
    main()