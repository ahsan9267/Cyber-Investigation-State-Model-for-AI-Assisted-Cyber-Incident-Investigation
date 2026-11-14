"""Check snapshot transaction recovery against the local PostgreSQL database."""

import getpass
from pathlib import Path
import tempfile
import uuid

import psycopg

from spine.snapshot import ingest_snapshot


class InjectedFailure(RuntimeError):
    pass


class FailBeforeCommit:
    """Execute the checkpoint update, then fail before transaction commit."""

    def __init__(self, connection):
        self.connection = connection
        self.triggered = False

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, query, params=None):
        result = self.connection.execute(query, params)

        if (
            not self.triggered
            and "UPDATE ingestion.snapshots" in query
        ):
            self.triggered = True
            raise InjectedFailure("Deliberate failure before commit")

        return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    password = getpass.getpass("spine_app password: ")
    scope = f"recovery-check/{uuid.uuid4()}"
    snapshot_id = "recovery-fixture"

    original = (
        b'{"id":"check-1","rule":{"level":3}}\n'
        b'not-json\n'
        b'{"id":"check-2","rule":{"level":3}}\n'
    )

    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname="spine",
        user="spine_app",
        password=password,
        connect_timeout=5,
        autocommit=True,
    ) as connection:
        connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "recovery.jsonl"
            path.write_bytes(original)

            options = {
                "input_format": "wazuh",
                "source_scope": scope,
                "snapshot_id": snapshot_id,
            }

            # The outer transaction removes all test data afterward.
            # Ingestion's inner transactions use real database savepoints.
            with connection.transaction(force_rollback=True):
                failing = FailBeforeCommit(connection)

                try:
                    ingest_snapshot(failing, path, **options)
                except InjectedFailure:
                    pass
                else:
                    raise RuntimeError("Expected failure was not triggered")

                state = connection.execute(
                    """
                    SELECT next_offset, processed_lines
                    FROM ingestion.snapshots
                    WHERE input_format = 'wazuh'
                      AND source_scope = %s
                      AND snapshot_id = %s
                    """,
                    (scope, snapshot_id),
                ).fetchone()
                require(state == (0, 0), "Checkpoint advanced after failure")

                for table in ("records", "snapshot_outcomes"):
                    # Table names are fixed constants from this script.
                    count = connection.execute(
                        f"SELECT COUNT(*) FROM ingestion.{table} "
                        "WHERE source_scope = %s",
                        (scope,),
                    ).fetchone()[0]
                    require(count == 0, f"{table} survived the failed transaction")

                print("PASS: record, outcome, and checkpoint rolled back")

                result = ingest_snapshot(connection, path, **options)
                require(result["completed"], "Resume did not finish")
                require(result["total_processed_lines"] == 3, "Wrong line count")
                require(
                    result["outcomes_this_run"]["inserted"] == 2,
                    "Expected two inserted records",
                )
                require(
                    result["outcomes_this_run"]["quarantined"] == 1,
                    "Expected one quarantined line",
                )
                print("PASS: resume inserted both valid records")

                rejected = connection.execute(
                    """
                    SELECT raw_bytes
                    FROM ingestion.snapshot_outcomes
                    WHERE source_scope = %s
                      AND disposition = 'quarantined'
                    """,
                    (scope,),
                ).fetchall()
                require(
                    len(rejected) == 1
                    and bytes(rejected[0][0]) == b"not-json\n",
                    "Quarantined bytes were not preserved",
                )
                print("PASS: malformed line retained without blocking progress")

                path.write_bytes(original + b"extra\n")
                try:
                    ingest_snapshot(connection, path, **options)
                except ValueError as error:
                    require(
                        "Snapshot content changed" in str(error),
                        f"Unexpected rejection: {error}",
                    )
                else:
                    raise RuntimeError("Changed snapshot was accepted")

                print("PASS: changed snapshot rejected under the same identity")

            for table in ("records", "snapshot_outcomes", "snapshots"):
                count = connection.execute(
                    f"SELECT COUNT(*) FROM ingestion.{table} "
                    "WHERE source_scope = %s",
                    (scope,),
                ).fetchone()[0]
                require(count == 0, f"Test data remained in {table}")

            print("PASS: all recovery-test data rolled back")


if __name__ == "__main__":
    main()