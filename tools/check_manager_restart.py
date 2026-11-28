"""Check worker recovery across abrupt process exits.

Unlike rollback checks, this retains one committed synthetic alert,
its work item, case, decision, reassessment and investigation history.
"""

from datetime import datetime, timezone
import getpass
import json
import multiprocessing
import os
from unittest.mock import patch
import uuid

from spine.envelope import build_envelope
from spine.manager_database import connect_manager_database
from spine.manager_work import discover_work
from spine.storage import store_record


TABLES = (
    "ingestion.records",
    "ingestion.record_conflicts",
    "investigation.work_requeues",
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
    "investigation.case_reassessments",
)


def expect(label, actual, expected):
    if actual != expected:
        raise AssertionError(
            f"{label}: expected {expected!r}, got {actual!r}"
        )
    print(f"PASS: {label}", flush=True)


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


def wait_for_routing_lock(connection):
    # Acquiring this lock confirms an interrupted worker no longer
    # holds its routing transaction.
    with connection.transaction():
        connection.execute(
            """
            SELECT revision
            FROM investigation.routing_state
            WHERE singleton_id = 1
            FOR UPDATE
            """
        ).fetchone()


def child_worker(password, scope, mode):
    """Run in a separate Windows-spawned Python process."""
    from spine import manager_worker

    with connect_manager_database(
        dbname="spine_step4_dev",
        password=password,
    ) as connection:
        if mode == "before_commit":
            real_append = manager_worker.append_attempt

            def exit_after_attempt(*args, **kwargs):
                real_append(*args, **kwargs)

                # Routing, reassessment, acknowledgement and attempt
                # insertion have run, but the outer transaction has
                # not committed.
                os._exit(71)

            with patch(
                "spine.manager_worker.append_attempt",
                side_effect=exit_after_attempt,
            ):
                manager_worker.process_next_work(
                    connection,
                    source_scope=scope,
                )

            raise RuntimeError("Pre-commit exit point was not reached")

        result = manager_worker.process_next_work(
            connection,
            source_scope=scope,
        )

        if mode == "after_commit":
            if result["status"] != "completed":
                raise RuntimeError(
                    f"Expected completion, got {result}"
                )

            # The worker returned after committing. Exit abruptly
            # before reporting its processing result to the parent.
            os._exit(72)

        if mode == "restart_again":
            if result != {"status": "idle"}:
                raise RuntimeError(
                    f"Expected idle restart, got {result}"
                )

            os._exit(73)

        raise ValueError(f"Unknown child mode: {mode}")


def run_child(password, scope, mode, expected_exit):
    process = multiprocessing.get_context("spawn").Process(
        target=child_worker,
        args=(password, scope, mode),
    )
    process.start()
    process.join(timeout=25)

    if process.is_alive():
        process.terminate()
        process.join(timeout=5)
        if not process.is_alive():
            process.close()
        raise RuntimeError(f"Child timed out during {mode}")

    actual_exit = process.exitcode
    process.close()

    expect(
        f"child reached {mode} exit point",
        actual_exit,
        expected_exit,
    )


def main():
    password = getpass.getpass("spine_app password: ")
    token = str(uuid.uuid4())
    scope = f"step4-restart-check/{token}"

    record = build_envelope(
        raw_text=json.dumps({
            "test": "manager_restart",
            "token": token,
            "value": "preserved\x00",
        }),
        source="sysmon",
        collector="manager_restart_check",
        record_kind="alert",
        source_scope=scope,
        source_record_id="restart-fixture",
        observed_time=datetime.now(timezone.utc).isoformat(),
    )
    record["host"]["name"] = f"restart-test-{token}"
    record["event"]["provider"] = "sysmon"
    record["event_time"] = {
        "utc": "2026-10-01T12:00:00Z",
    }
    record["attributes"]["process"] = {
        "guid": str(uuid.uuid4()),
        "image": r"C:\Lab\restart-fixture.exe",
    }

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

        print(f"Retained test scope: {scope}", flush=True)

        # These calls commit before the child worker starts.
        store_record(connection, record)

        expect(
            "committed fixture discovered",
            discover_work(connection, source_scope=scope),
            {
                "records_queued": 1,
                "conflicts_queued": 0,
            },
        )

        work_id = connection.execute(
            """
            SELECT work_id
            FROM investigation.work_items
            WHERE work_kind = 'record'
              AND record_id = %s
            """,
            (record["record_id"],),
        ).fetchone()[0]

        before_crash = counts(connection)
        before_revision = revision(connection)

        run_child(password, scope, "before_commit", 71)
        wait_for_routing_lock(connection)

        expect(
            "pre-commit process exit leaves no partial rows",
            counts(connection),
            before_crash,
        )
        expect(
            "pre-commit process exit preserves routing revision",
            revision(connection),
            before_revision,
        )
        expect(
            "interrupted work remains pending",
            connection.execute(
                """
                SELECT
                    status,
                    attempt_count,
                    outcome,
                    completed_at
                FROM investigation.work_items
                WHERE work_id = %s
                """,
                (work_id,),
            ).fetchone(),
            ("pending", 0, None, None),
        )

        run_child(password, scope, "after_commit", 72)
        wait_for_routing_lock(connection)

        expect(
            "restart commits interrupted work",
            connection.execute(
                """
                SELECT status, attempt_count, outcome
                FROM investigation.work_items
                WHERE work_id = %s
                """,
                (work_id,),
            ).fetchone(),
            ("completed", 1, "routed"),
        )

        additions = {
            "investigation.cases": 1,
            "investigation.case_memberships": 1,
            "investigation.evidence_views": 1,
            "investigation.routing_decisions": 1,
            "investigation.case_history": 1,
            "investigation.pending_investigation_work": 1,
            "investigation.work_attempts": 1,
            "investigation.case_reassessments": 1,
        }

        expected_counts = dict(before_crash)
        for table, amount in additions.items():
            expected_counts[table] += amount

        expect(
            "exactly one committed set of routing and assessment rows",
            counts(connection),
            expected_counts,
        )
        expect(
            "successful restart advances revision once",
            revision(connection),
            before_revision + 1,
        )

        committed_counts = counts(connection)
        committed_revision = revision(connection)

        run_child(password, scope, "restart_again", 73)

        expect(
            "restart after committed exit adds no rows",
            counts(connection),
            committed_counts,
        )
        expect(
            "restart after committed exit retains revision",
            revision(connection),
            committed_revision,
        )
        expect(
            "rediscovery creates no duplicate work",
            discover_work(connection, source_scope=scope),
            {
                "records_queued": 0,
                "conflicts_queued": 0,
            },
        )
        expect(
            "original evidence remains unchanged",
            connection.execute(
                """
                SELECT document
                FROM ingestion.records
                WHERE record_id = %s
                """,
                (record["record_id"],),
            ).fetchone()[0],
            record,
        )

    print("SUCCESS: worker process-restart checks passed")
    print(f"Committed synthetic evidence retained under: {scope}")
    print(
        "Database-server crashes and concurrent workers "
        "were not tested by this script."
    )


if __name__ == "__main__":
    multiprocessing.freeze_support()
    main()