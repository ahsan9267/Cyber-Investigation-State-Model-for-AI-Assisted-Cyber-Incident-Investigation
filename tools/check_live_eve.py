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
    scope = f"live-check/{uuid.uuid4()}"

    first = b'{"event_type":"future_event","example":1}\n'
    partial = b'{"event_type":"future_event","example":2'

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
            path.write_bytes(first + partial)

            with connection.transaction(force_rollback=True):
                result = ingest_file(connection, path, source_scope=scope)
                require(result["processed_this_run"] == 1, "Wrong initial count")
                require(result["next_offset"] == len(first), "Partial line consumed")
                require(
                    result["status"] == "waiting_for_complete_line",
                    "Expected an incomplete-line wait",
                )
                generation = result["generation_id"]
                print("PASS: incomplete final line left pending")

                with path.open("ab") as stream:
                    stream.write(b"}\n")

                result = ingest_file(connection, path, source_scope=scope)
                require(result["processed_this_run"] == 1, "Append not processed")
                require(
                    result["generation_id"] == generation,
                    "Appending changed the generation",
                )
                print("PASS: appended line consumed in the same generation")

                result = ingest_file(connection, path, source_scope=scope)
                require(result["processed_this_run"] == 0, "Records processed twice")
                require(result["status"] == "caught_up", "Expected caught_up")
                print("PASS: unchanged file performs no further work")

                with path.open("ab") as stream:
                    stream.write(b'not-json\n{"event_type":"stats"}\n')

                result = ingest_file(connection, path, source_scope=scope)
                outcomes = result["outcomes_this_run"]
                require(outcomes["quarantined"] == 1, "Bad line not quarantined")
                require(
                    outcomes["excluded_sensor_health"] == 1,
                    "Stats not excluded",
                )
                print("PASS: malformed and health records accounted for")

                # Modify only this temporary test file.
                path.write_bytes(first)

                try:
                    ingest_file(connection, path, source_scope=scope)
                except FileGenerationChanged:
                    pass
                else:
                    raise RuntimeError("Truncation was not detected")

                print("PASS: truncation detected")

        count = connection.execute(
            """
            SELECT COUNT(*) FROM ingestion.file_generations
            WHERE source_scope = %s
            """,
            (scope,),
        ).fetchone()[0]
        require(count == 0, "Test generation remained after rollback")
        print("PASS: test transaction rolled back")


if __name__ == "__main__":
    main()