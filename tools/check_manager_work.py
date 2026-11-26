"""Check manager work discovery using temporary database evidence."""

from copy import deepcopy
from datetime import datetime, timezone
import getpass
import uuid

from spine.envelope import build_envelope
from spine.manager_database import connect_manager_database
from spine.manager_work import discover_work
from spine.storage import store_record


def expect(actual, expected, label):
    if actual != expected:
        raise RuntimeError(
            f"{label}: expected {expected!r}, received {actual!r}"
        )
    print(f"PASS: {label}")


def run_checks(connection):
    scope = f"step4-work-check/{uuid.uuid4()}"
    observed = datetime.now(timezone.utc).isoformat()

    def sample(source_id, raw_text):
        return build_envelope(
            raw_text=raw_text,
            source="manager_work_check",
            collector="manager_work_check",
            record_kind="telemetry",
            source_scope=scope,
            source_record_id=source_id,
            observed_time=observed,
        )

    original = sample("record-1", r'{"value":"original\u0000"}')
    original["attributes"]["source_payload"] = {
        "value": "original\x00"
    }
    second = sample("record-2", '{"value":"second"}')
    conflict = sample("record-1", '{"value":"changed"}')

    record_ids = [original["record_id"], second["record_id"]]

    empty_result = {
        "records_queued": 0,
        "conflicts_queued": 0,
    }
    one_record = {
        "records_queued": 1,
        "conflicts_queued": 0,
    }
    one_conflict = {
        "records_queued": 0,
        "conflicts_queued": 1,
    }

    def discover():
        return discover_work(
            connection,
            batch_size=1,
            source_scope=scope,
        )

    def work_count():
        return connection.execute(
            """
            SELECT COUNT(*)
            FROM investigation.work_items
            WHERE record_id = ANY(%s)
            """,
            (record_ids,),
        ).fetchone()[0]

    # All evidence and work inserted below must disappear on exit.
    with connection.transaction(force_rollback=True):
        expect(
            store_record(connection, original),
            "inserted",
            "temporary original stored",
        )
        expect(
            store_record(connection, second),
            "inserted",
            "temporary second record stored",
        )

        # Demonstrate rollback of discovery independently of evidence.
        with connection.transaction(force_rollback=True):
            expect(discover(), one_record, "bounded discovery queues one")
            expect(work_count(), 1, "queued work visible in transaction")

        expect(work_count(), 0, "rolled-back discovery leaves no work")

        expect(discover(), one_record, "first record rediscovered")
        expect(discover(), one_record, "remaining record discovered")
        expect(discover(), empty_result, "repeat discovery adds nothing")

        replay = deepcopy(original)
        replay["observed_time"] = {"utc": observed}
        expect(
            store_record(connection, replay),
            "replay",
            "original replay recognized",
        )
        expect(discover(), empty_result, "replay creates no extra work")

        expect(
            store_record(connection, conflict),
            "conflict",
            "changed payload preserved as conflict",
        )
        expect(
            discover(),
            one_conflict,
            "later conflict gets separate work",
        )
        expect(
            store_record(connection, conflict),
            "conflict_replay",
            "repeated conflict recognized",
        )
        expect(
            discover(),
            empty_result,
            "repeated conflict creates no extra work",
        )

        stored = connection.execute(
            """
            SELECT document
            FROM ingestion.records
            WHERE record_id = %s
            """,
            (original["record_id"],),
        ).fetchone()[0]
        expect(stored, original, "original and null escape preserved")

        rows = connection.execute(
            """
            SELECT work_kind, status, COUNT(*)
            FROM investigation.work_items
            WHERE record_id = ANY(%s)
            GROUP BY work_kind, status
            ORDER BY work_kind, status
            """,
            (record_ids,),
        ).fetchall()
        expect(
            rows,
            [("conflict", "pending", 1), ("record", "pending", 2)],
            "two records and one conflict remain pending",
        )

    for table in (
        "ingestion.records",
        "ingestion.record_conflicts",
        "investigation.work_items",
    ):
        # Table names are fixed constants above, not user input.
        remaining = connection.execute(
            f"SELECT COUNT(*) FROM {table} WHERE record_id = ANY(%s)",
            (record_ids,),
        ).fetchone()[0]
        expect(remaining, 0, f"temporary rows rolled back in {table}")


def main():
    password = getpass.getpass("spine_app password: ")

    with connect_manager_database(
        dbname="spine_step4_dev",
        password=password,
    ) as connection:
        actual_database = connection.execute(
            "SELECT current_database()"
        ).fetchone()[0]

        if actual_database != "spine_step4_dev":
            raise RuntimeError("Run only against spine_step4_dev")

        run_checks(connection)

    print("SUCCESS: work discovery database checks passed")
    print("This was a rollback check, not a crash/restart test.")


if __name__ == "__main__":
    main()