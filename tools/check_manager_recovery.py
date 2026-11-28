"""Rollback-based checks for audited recovery of blocked work."""

from datetime import datetime, timezone
import getpass
import json
from unittest.mock import patch
import uuid

from spine.envelope import build_envelope
from spine.manager_database import connect_manager_database
from spine.manager_recovery import requeue_blocked_work
from spine.manager_work import discover_work
from spine.manager_worker import process_next_work
from spine.storage import store_record

from check_manager_restart import (
    counts as existing_counts,
    expect,
    revision,
)


def counts(connection):
    result = existing_counts(connection)
    result["investigation.work_requeues"] = connection.execute(
        "SELECT COUNT(*) FROM investigation.work_requeues"
    ).fetchone()[0]
    return result


def work_state(connection, work_id):
    return connection.execute(
        """
        SELECT
            status, attempt_count, outcome, completed_at,
            available_at, updated_at, last_error
        FROM investigation.work_items
        WHERE work_id = %s
        """,
        (work_id,),
    ).fetchone()


def attempt_history(connection, work_id):
    return connection.execute(
        """
        SELECT attempt_number, result, details
        FROM investigation.work_attempts
        WHERE work_id = %s
        ORDER BY attempt_number
        """,
        (work_id,),
    ).fetchall()


def expect_rejected(label, action, exception_type, message_fragment):
    try:
        action()
    except exception_type as error:
        if message_fragment not in str(error):
            raise
    else:
        raise AssertionError(f"{label}: expected rejection")

    print(f"PASS: {label}")


def run_checks(connection):
    baseline = counts(connection)
    baseline_revision = revision(connection)

    token = str(uuid.uuid4())
    scope = f"step4-recovery-check/{token}"

    record = build_envelope(
        raw_text=json.dumps({
            "test": "manager_recovery",
            "token": token,
        }),
        source="sysmon",
        collector="manager_recovery_check",
        record_kind="alert",
        source_scope=scope,
        source_record_id="recovery-fixture",
        observed_time=datetime.now(timezone.utc).isoformat(),
    )
    record["host"]["name"] = f"recovery-test-{token}"
    record["event"]["provider"] = "sysmon"
    record["event_time"] = {"utc": "2026-10-01T12:00:00Z"}
    record["attributes"]["process"] = {
        "guid": str(uuid.uuid4()),
        "image": r"C:\Lab\recovery-fixture.exe",
    }

    with connection.transaction(force_rollback=True):
        store_record(connection, record)
        discover_work(connection, source_scope=scope)

        work_id = connection.execute(
            """
            SELECT work_id
            FROM investigation.work_items
            WHERE work_kind = 'record' AND record_id = %s
            """,
            (record["record_id"],),
        ).fetchone()[0]

        def recover(request_id, expected_count, reason="Fixture fault removed"):
            return requeue_blocked_work(
                connection,
                work_id,
                requeue_id=request_id,
                expected_attempt_count=expected_count,
                reason=reason,
                requested_by="step4-recovery-test",
            )

        expect_rejected(
            "pending work cannot be requeued",
            lambda: recover(uuid.uuid4(), 0),
            ValueError,
            "Only blocked work",
        )

        with patch(
            "spine.manager_worker.process_record_work",
            side_effect=ValueError("injected fixture fault"),
        ):
            failed = process_next_work(
                connection,
                source_scope=scope,
                max_attempts=1,
            )

        expect("fixture becomes blocked", failed["status"], "blocked")
        blocked_state = work_state(connection, work_id)
        failed_history = attempt_history(connection, work_id)

        expect(
            "blocked work retains its first failed attempt",
            blocked_state[:4],
            ("blocked", 1, None, None),
        )
        expect(
            "failed attempt recorded",
            [(row[0], row[1]) for row in failed_history],
            [(1, "blocked")],
        )

        before_rejection = counts(connection)

        expect_rejected(
            "stale attempt count rejected",
            lambda: recover(uuid.uuid4(), 0),
            RuntimeError,
            "Attempt count changed",
        )
        expect(
            "stale request creates no rows",
            counts(connection),
            before_rejection,
        )
        expect(
            "stale request leaves blocked work unchanged",
            work_state(connection, work_id),
            blocked_state,
        )

        request_id = uuid.uuid4()

        # Explicitly roll back a successful recovery operation.
        with connection.transaction(force_rollback=True):
            temporary = recover(request_id, 1)
            expect(
                "recovery changes work inside its transaction",
                temporary["current_work_status"],
                "pending",
            )
            expect(
                "recovery audit row visible inside transaction",
                connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM investigation.work_requeues
                    WHERE requeue_id = %s
                    """,
                    (request_id,),
                ).fetchone()[0],
                1,
            )

        expect(
            "rolled-back recovery restores blocked state",
            work_state(connection, work_id),
            blocked_state,
        )
        expect(
            "rolled-back recovery removes its audit row",
            counts(connection),
            before_rejection,
        )

        result = recover(request_id, 1)
        expect("recovery succeeds", result["status"], "requeued")
        expect(
            "recovery preserves attempt count",
            result["attempt_count"],
            1,
        )
        expect(
            "recovery preserves failed attempt history",
            attempt_history(connection, work_id),
            failed_history,
        )

        pending_state = work_state(connection, work_id)
        expect(
            "recovered work is pending and unacknowledged",
            pending_state[:4],
            ("pending", 1, None, None),
        )
        expect(
            "current error retained until processing succeeds",
            pending_state[6],
            blocked_state[6],
        )

        audit = connection.execute(
            """
            SELECT prior_attempt_count, reason, requested_by, prior_state
            FROM investigation.work_requeues
            WHERE requeue_id = %s
            """,
            (request_id,),
        ).fetchone()

        expect("audit retains prior attempt count", audit[0], 1)
        expect("audit retains recovery reason", audit[1], "Fixture fault removed")
        expect(
            "audit retains prior error",
            audit[3]["last_error"],
            blocked_state[6],
        )
        expect(
            "audit identifies caller label as self-reported",
            audit[3]["requested_by_basis"],
            "caller_supplied_label",
        )

        before_repeat = counts(connection)
        repeated = recover(request_id, 1)
        expect(
            "repeated recovery request recognized",
            repeated["status"],
            "already_recorded",
        )
        expect(
            "repeated recovery changes no rows",
            counts(connection),
            before_repeat,
        )
        expect(
            "repeated recovery leaves scheduling unchanged",
            work_state(connection, work_id),
            pending_state,
        )

        expect_rejected(
            "request ID cannot be reused with a different reason",
            lambda: recover(request_id, 1, "Different reason"),
            ValueError,
            "different inputs",
        )

        completed = process_next_work(
            connection,
            source_scope=scope,
            max_attempts=1,
        )
        expect(
            "requeued work can succeed despite earlier retry limit",
            completed["status"],
            "completed",
        )
        expect(
            "successful processing continues attempt numbering",
            completed["attempt_number"],
            2,
        )
        expect(
            "failure and success remain in history",
            [
                (row[0], row[1])
                for row in attempt_history(connection, work_id)
            ],
            [(1, "blocked"), (2, "completed")],
        )
        expect(
            "successful processing clears current error",
            work_state(connection, work_id)[6],
            None,
        )

        before_completed_request = counts(connection)
        completed_state = work_state(connection, work_id)
        completed_revision = revision(connection)

        repeated_after_completion = recover(request_id, 1)
        expect(
            "old recovery request reports current completed state",
            repeated_after_completion["current_work_status"],
            "completed",
        )

        expect_rejected(
            "new recovery request cannot reopen completed work",
            lambda: recover(uuid.uuid4(), 2),
            ValueError,
            "Only blocked work",
        )
        expect(
            "completed work remains unchanged",
            work_state(connection, work_id),
            completed_state,
        )
        expect(
            "completed-work recovery requests add no rows",
            counts(connection),
            before_completed_request,
        )
        expect(
            "recovery requests do not change case revision state",
            revision(connection),
            completed_revision,
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

    print("SUCCESS: blocked-work recovery database checks passed")
    print("All temporary fixtures rolled back; existing cases preserved.")


if __name__ == "__main__":
    main()