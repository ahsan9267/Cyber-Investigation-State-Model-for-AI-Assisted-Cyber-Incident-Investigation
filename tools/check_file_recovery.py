import getpass
from pathlib import Path
import tempfile
import uuid

import psycopg

from spine.file_recovery import ingest_with_recovery
from spine.live_eve import ingest_file


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    password = getpass.getpass("spine_app password: ")
    scope = f"file-recovery-check/{uuid.uuid4()}"
    first_line = b'{"event_type":"future_event","value":1}\n'

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
            path = Path(directory) / "eve-test.json"
            path.write_bytes(first_line * 2)

            with connection.transaction(force_rollback=True):
                original = ingest_file(
                    connection, path, source_scope=scope
                )

                # Truncate only the temporary test file.
                path.write_bytes(first_line)
                truncated = ingest_with_recovery(
                    connection, path, source_scope=scope
                )

                require(
                    truncated["generation_id"] != original["generation_id"],
                    "Truncation reused the old generation",
                )
                require(
                    truncated["recovery"]["reason"] == "truncation_detected",
                    "Wrong recovery reason",
                )
                require(
                    truncated["outcomes_this_run"]["inserted"] == 1,
                    "New generation did not start at byte zero",
                )
                print("PASS: truncation starts a new generation")

                replacement = Path(directory) / "replacement.tmp"
                replacement.write_bytes(first_line)
                replacement.replace(path)

                replaced = ingest_with_recovery(
                    connection, path, source_scope=scope
                )
                require(
                    replaced["generation_id"] != truncated["generation_id"],
                    "Replacement reused the previous generation",
                )
                require(
                    replaced["recovery"]["reason"] == "replacement_detected",
                    "Replacement not recorded correctly",
                )
                print("PASS: replacement starts a new generation")

                old_state = connection.execute(
                    """
                    SELECT next_offset, processed_lines,
                           retired_at IS NOT NULL
                    FROM ingestion.file_generations
                    WHERE generation_id = %s
                    """,
                    (uuid.UUID(original["generation_id"]),),
                ).fetchone()
                require(
                    old_state == (len(first_line) * 2, 2, True),
                    "Original checkpoint was changed",
                )
                print("PASS: original checkpoint preserved")

                events = connection.execute(
                    """
                    SELECT e.event_type, e.possible_evidence_gap
                    FROM ingestion.file_generation_events e
                    JOIN ingestion.file_generations g
                      ON g.generation_id = e.generation_id
                    WHERE g.source_scope = %s
                    """,
                    (scope,),
                ).fetchall()
                require(
                    set(events) == {
                        ("truncation_detected", True),
                        ("replacement_detected", True),
                    },
                    "Expected evidence-gap records are missing",
                )
                print("PASS: both changes retain possible-gap history")

        remaining = connection.execute(
            """
            SELECT COUNT(*) FROM ingestion.file_generations
            WHERE source_scope = %s
            """,
            (scope,),
        ).fetchone()[0]
        require(remaining == 0, "Test data remained")
        print("PASS: test transaction rolled back")


if __name__ == "__main__":
    main()