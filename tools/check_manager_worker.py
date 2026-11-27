"""Rollback-based database checks for the Investigation Manager worker."""

from datetime import datetime, timezone
import getpass
import json
from unittest.mock import patch
import uuid

from spine.envelope import build_envelope
from spine.manager_database import connect_manager_database
from spine.manager_routing import process_record_work
from spine.manager_work import discover_work
from spine.manager_worker import process_next_work
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
    "investigation.work_attempts",
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
        SELECT revision FROM investigation.routing_state
        WHERE singleton_id = 1
        """
    ).fetchone()[0]


def state(connection, work_id):
    return connection.execute(
        """
        SELECT status, attempt_count, outcome, completed_at
        FROM investigation.work_items WHERE work_id = %s
        """,
        (work_id,),
    ).fetchone()


def attempts(connection, work_id):
    return connection.execute(
        """
        SELECT attempt_number, result
        FROM investigation.work_attempts
        WHERE work_id = %s
        ORDER BY attempt_number
        """,
        (work_id,),
    ).fetchall()


def run_checks(connection):
    baseline = counts(connection)
    baseline_revision = revision(connection)

    if baseline["investigation.cases"] != 0:
        raise RuntimeError(
            "This check expects no cases in the development database. "
            "Do not delete existing cases; report this message instead."
        )

    scope = f"step4-worker-check/{uuid.uuid4()}"
    process_guid = str(uuid.uuid4())
    observed = datetime.now(timezone.utc).isoformat()

    def sample(source_id, version="original"):
        record = build_envelope(
            raw_text=json.dumps({
                "source_id": source_id,
                "version": version,
                "value": "preserved\x00",
            }),
            source="sysmon",
            collector="manager_worker_check",
            record_kind="alert",
            source_scope=scope,
            source_record_id=source_id,
            observed_time=observed,
        )
        record["host"]["name"] = "step4-worker-test-host"
        record["event"]["provider"] = "sysmon"
        record["event_time"] = {"utc": "2026-10-01T12:00:00Z"}
        record["attributes"]["process"] = {
            "guid": process_guid,
            "image": r"C:\Lab\fixture.exe",
        }
        return record

    def discover():
        return discover_work(connection, source_scope=scope)

    def work_id(record, kind="record"):
        return connection.execute(
            """
            SELECT work_id FROM investigation.work_items
            WHERE work_kind = %s
              AND record_id = %s
              AND payload_sha256 = %s
            """,
            (kind, record["record_id"], record["raw"]["sha256"]),
        ).fetchone()[0]

    def run_worker(**kwargs):
        return process_next_work(
            connection, source_scope=scope, **kwargs
        )

    def make_available(item_id):
        # Test-only scheduling change, rolled back with all fixtures.
        connection.execute(
            """
            UPDATE investigation.work_items
            SET available_at = clock_timestamp() - INTERVAL '1 second'
            WHERE work_id = %s
            """,
            (item_id,),
        )

    def fail_after_routing(conn, item_id):
        process_record_work(conn, item_id)
        raise ValueError("injected failure after routing")

    with connection.transaction(force_rollback=True):
        expect("empty scope is idle", run_worker(), {"status": "idle"})

        # A conflict is deliberately made older than its original work.
        original = sample("dependency-success")
        conflict = sample("dependency-success", "changed")
        store_record(connection, original)
        store_record(connection, conflict)
        discover()

        original_id = work_id(original)
        conflict_id = work_id(conflict, "conflict")

        connection.execute(
            """
            UPDATE investigation.work_items
            SET available_at = clock_timestamp() - INTERVAL '1 day'
            WHERE work_id = %s
            """,
            (conflict_id,),
        )

        first = run_worker()
        expect(
            "original selected before its older conflict",
            first["work_id"],
            str(original_id),
        )
        expect("original completed", first["status"], "completed")
        expect(
            "original success attempt recorded",
            attempts(connection, original_id),
            [(1, "completed")],
        )

        second = run_worker()
        expect(
            "conflict selected after original completion",
            second["work_id"],
            str(conflict_id),
        )
        expect(
            "conflict success attempt recorded",
            attempts(connection, conflict_id),
            [(1, "completed")],
        )

        before_idle = counts(connection)
        expect("completed queue is idle", run_worker(), {"status": "idle"})
        expect(
            "idle worker creates no attempt rows",
            counts(connection),
            before_idle,
        )

        # Inject a failure after the real processor has made its writes.
        retry_record = sample("retry-success")
        store_record(connection, retry_record)
        discover()
        retry_id = work_id(retry_record)

        before_failure = counts(connection)
        before_failure_revision = revision(connection)

        with patch(
            "spine.manager_worker.process_record_work",
            side_effect=fail_after_routing,
        ):
            failed = run_worker(
                retry_base_seconds=300,
                retry_max_seconds=300,
            )

        expect("failure schedules retry", failed["status"], "retry_scheduled")
        expect(
            "failed processing remains unacknowledged",
            state(connection, retry_id),
            ("pending", 1, None, None),
        )
        expect(
            "failure attempt retained",
            attempts(connection, retry_id),
            [(1, "retry_scheduled")],
        )

        expected_after_failure = dict(before_failure)
        expected_after_failure["investigation.work_attempts"] += 1
        expect(
            "failed routing rows rolled back while attempt retained",
            counts(connection),
            expected_after_failure,
        )
        expect(
            "failed routing revision rolled back",
            revision(connection),
            before_failure_revision,
        )
        expect(
            "retry scheduled in the future",
            connection.execute(
                """
                SELECT available_at > clock_timestamp()
                FROM investigation.work_items WHERE work_id = %s
                """,
                (retry_id,),
            ).fetchone()[0],
            True,
        )
        expect(
            "delayed retry is not immediately selected",
            run_worker(),
            {"status": "idle"},
        )

        make_available(retry_id)
        retried = run_worker()
        expect("retry succeeds", retried["status"], "completed")
        expect("successful retry is attempt two", retried["attempt_number"], 2)
        expect(
            "failure and success histories both retained",
            attempts(connection, retry_id),
            [(1, "retry_scheduled"), (2, "completed")],
        )
        expect(
            "successful retry clears current error",
            connection.execute(
                """
                SELECT last_error FROM investigation.work_items
                WHERE work_id = %s
                """,
                (retry_id,),
            ).fetchone()[0],
            None,
        )

        # A failure to persist attempt history must undo successful routing.
        atomic_record = sample("attempt-history-atomicity")
        store_record(connection, atomic_record)
        discover()
        atomic_id = work_id(atomic_record)

        before_atomic = counts(connection)
        before_atomic_revision = revision(connection)
        before_atomic_state = state(connection, atomic_id)

        with patch(
            "spine.manager_worker.append_attempt",
            side_effect=RuntimeError("injected attempt-history failure"),
        ):
            try:
                run_worker()
            except RuntimeError as error:
                if str(error) != "injected attempt-history failure":
                    raise
            else:
                raise AssertionError("Expected attempt-history failure")

        expect(
            "attempt-history failure rolls back all routing rows",
            counts(connection),
            before_atomic,
        )
        expect(
            "attempt-history failure restores routing revision",
            revision(connection),
            before_atomic_revision,
        )
        expect(
            "attempt-history failure restores pending work",
            state(connection, atomic_id),
            before_atomic_state,
        )
        expect(
            "work succeeds after history failure is removed",
            run_worker()["status"],
            "completed",
        )

        # Exhaust retries and verify dependent conflict work is retained.
        blocked_record = sample("blocked-original")
        blocked_conflict = sample("blocked-original", "changed")
        store_record(connection, blocked_record)
        store_record(connection, blocked_conflict)
        discover()

        blocked_id = work_id(blocked_record)
        dependent_id = work_id(blocked_conflict, "conflict")

        with patch(
            "spine.manager_worker.process_record_work",
            side_effect=ValueError("persistent fixture failure"),
        ):
            first_failure = run_worker(max_attempts=2)
            expect(
                "first persistent failure schedules retry",
                first_failure["status"],
                "retry_scheduled",
            )
            make_available(blocked_id)
            second_failure = run_worker(max_attempts=2)

        expect(
            "retry limit blocks failing work",
            second_failure["status"],
            "blocked",
        )
        expect(
            "blocked work is not acknowledged",
            state(connection, blocked_id),
            ("blocked", 2, None, None),
        )
        expect(
            "both failed attempts retained",
            attempts(connection, blocked_id),
            [(1, "retry_scheduled"), (2, "blocked")],
        )
        expect(
            "dependent conflict remains pending without attempts",
            state(connection, dependent_id),
            ("pending", 0, None, None),
        )

        before_blocked_idle = counts(connection)
        expect(
            "blocked original and waiting conflict are not selected",
            run_worker(),
            {"status": "idle"},
        )
        expect(
            "waiting dependency creates no attempt history",
            counts(connection),
            before_blocked_idle,
        )

    expect("all temporary rows rolled back", counts(connection), baseline)
    expect(
        "global revision restored",
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

    print("SUCCESS: worker database checks passed")
    print("All fixtures rolled back; crash recovery and concurrency not tested.")


if __name__ == "__main__":
    main()