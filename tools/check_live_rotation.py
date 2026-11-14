"""Check daily EVE rotation and replacement detection using temporary files."""

import getpass
from pathlib import Path
import tempfile
import uuid

import psycopg

from spine.live_eve import FileGenerationChanged, ingest_file


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    password = getpass.getpass("spine_app password: ")
    scope = f"rotation-check/{uuid.uuid4()}"
    line = b'{"event_type":"future_event","example":1}\n'

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
            folder = Path(directory)
            yesterday = folder / "eve-2026-10-01.json"
            today = folder / "eve-2026-10-02.json"

            yesterday.write_bytes(line)
            today.write_bytes(line)

            with connection.transaction(force_rollback=True):
                old_result = ingest_file(
                    connection, yesterday, source_scope=scope
                )
                new_result = ingest_file(
                    connection, today, source_scope=scope
                )

                require(
                    old_result["generation_id"] != new_result["generation_id"],
                    "Daily files incorrectly share a generation",
                )
                require(
                    old_result["outcomes_this_run"]["inserted"] == 1
                    and new_result["outcomes_this_run"]["inserted"] == 1,
                    "Distinct records with identical contents were lost",
                )
                print("PASS: daily files have separate generations and records")

                # A late write to the older file must remain readable.
                with yesterday.open("ab") as stream:
                    stream.write(line)

                late_result = ingest_file(
                    connection, yesterday, source_scope=scope
                )
                require(
                    late_result["generation_id"] == old_result["generation_id"],
                    "Appending to the older file changed its generation",
                )
                require(
                    late_result["outcomes_this_run"]["inserted"] == 1,
                    "Late record in the older file was missed",
                )
                print("PASS: older file can still receive late records")

                repeated = ingest_file(
                    connection, today, source_scope=scope
                )
                require(
                    repeated["processed_this_run"] == 0,
                    "Unchanged daily file was processed again",
                )
                print("PASS: each daily file retains its own checkpoint")

                # Replace only a temporary test file.
                replacement = folder / "replacement.tmp"
                replacement.write_bytes(
                    b'{"event_type":"future_event","example":2}\n'
                )
                replacement.replace(today)

                try:
                    ingest_file(connection, today, source_scope=scope)
                except FileGenerationChanged:
                    pass
                else:
                    raise RuntimeError("Replacement was not detected")

                state = connection.execute(
                    """
                    SELECT next_offset, processed_lines
                    FROM ingestion.file_generations
                    WHERE generation_id = %s
                    """,
                    (uuid.UUID(new_result["generation_id"]),),
                ).fetchone()

                require(
                    state == (len(line), 1),
                    "Replacement changed the original checkpoint",
                )
                print("PASS: replacement rejected without changing checkpoint")

        remaining = connection.execute(
            """
            SELECT COUNT(*) FROM ingestion.file_generations
            WHERE source_scope = %s
            """,
            (scope,),
        ).fetchone()[0]
        require(remaining == 0, "Test generation remained after rollback")
        print("PASS: test transaction rolled back")


if __name__ == "__main__":
    main()