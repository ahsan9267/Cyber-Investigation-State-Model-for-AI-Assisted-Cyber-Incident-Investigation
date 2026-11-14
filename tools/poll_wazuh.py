"""Bounded Wazuh polling passes, including older registered generations."""

import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import json
import subprocess
import time
import uuid

import psycopg
from psycopg.rows import dict_row

from spine.live_wazuh import ingest_once, _state
from spine.remote_wazuh import REMOTE_PATH
from spine.wazuh_recovery import ingest_with_recovery, synchronize_sources
from spine.database import connect_database


def poll(connection, *, passes, records_per_file, interval):
    errors = 0
    scope = "lab/wazuh-server"

    for number in range(1, passes + 1):
        print(json.dumps(synchronize_sources(connection, source_scope=scope)), flush=True)
        print(
            f"Pass {number}/{passes} at "
            f"{datetime.now(timezone.utc).isoformat()}",
            flush=True,
        )

        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """
                SELECT generation_id, file_path
                FROM ingestion.file_generations
                WHERE input_format = 'wazuh'
                  AND source_scope = %s
                  AND retired_at IS NULL
                ORDER BY
                    (file_path = %s) DESC,
                    created_at,
                    generation_id
                """,
                (scope, REMOTE_PATH),
            )
            targets = cursor.fetchall()

        if not targets:
            targets = [{
                "generation_id": None,
                "file_path": REMOTE_PATH,
            }]

        for target in targets:
            try:
                result = ingest_with_recovery(
                    connection,
                    source_scope=scope,
                    generation_id=target["generation_id"],
                    max_records=records_per_file,
                )

                print(
                    json.dumps({
                        "operation": "ingest",
                        "tracked_path": target["file_path"],
                        **result,
                    }),
                    flush=True,
                )

            except (
                OSError,
                ValueError,
                RuntimeError,
                subprocess.SubprocessError,
            ) as error:
                errors += 1

                print(
                    json.dumps({
                        "operation": "collection_error",
                        "generation_id": str(target["generation_id"]),
                        "tracked_path": target["file_path"],
                        "error": str(error),
                        "action": (
                            "Other generations continue. "
                            "Earlier successful batches remain committed."
                        ),
                    }),
                    flush=True,
                )

        if number < passes:
            time.sleep(interval)

    return errors


def self_test(connection):
    scope = "test/generation-poll/" + str(uuid.uuid4())
    older_id = uuid.uuid4()
    current_id = uuid.uuid4()

    archive = "/var/ossec/logs/alerts/2026/Oct/ossec-alerts-03.json"

    raw = (
        json.dumps({
            "id": "older-file-late-record",
            "timestamp": "2026-10-03T09:00:00Z",
            "rule": {
                "id": "500",
                "level": 3,
                "groups": ["ossec"],
            },
        }) + "\n"
    ).encode()

    digest = hashlib.sha256(raw).hexdigest()

    def fake_fetch(**kwargs):
        assert kwargs["expected"]["native_file_id"] == "10"

        offset = kwargs["offset"]
        assert offset in (0, len(raw))

        body = raw if offset == 0 else b""

        return {
            "file_path": REMOTE_PATH,
            "read_path": archive,
            "archive_path": archive,
            "reading_retained_file": True,
            "device_id": "1",
            "native_file_id": "10",
            "first_line_sha256": digest,
            "offset": offset,
            "next_offset": len(raw),
            "raw_bytes": body,
            "batch_sha256": hashlib.sha256(body).hexdigest(),
            "line_count": 1 if body else 0,
            "status": "caught_up",
            "checkpoint_tail_b64": base64.b64encode(
                raw[-4096:]
            ).decode(),
        }

    with connection.transaction(force_rollback=True):
        fixtures = (
            (older_id, archive, "10"),
            (current_id, REMOTE_PATH, "11"),
        )

        for generation, path, native in fixtures:
            connection.execute(
                """
                INSERT INTO ingestion.file_generations (
                    generation_id,
                    input_format,
                    source_scope,
                    file_path,
                    device_id,
                    native_file_id,
                    first_line_sha256
                )
                VALUES (%s, 'wazuh', %s, %s, '1', %s, %s)
                """,
                (generation, scope, path, native, digest),
            )

        result = ingest_once(
            connection,
            source_scope=scope,
            generation_id=older_id,
            fetcher=fake_fetch,
        )

        assert result["generation_id"] == str(older_id)
        assert result["outcomes_this_run"]["inserted"] == 1

        assert _state(connection, scope)["generation_id"] == current_id
        assert _state(connection, scope)["next_offset"] == 0

        assert (
            _state(connection, scope, older_id)["next_offset"]
            == len(raw)
        )

        print(
            "PASS: older generation advances "
            "without changing the current file"
        )

        result = ingest_once(
            connection,
            source_scope=scope,
            generation_id=older_id,
            fetcher=fake_fetch,
        )

        assert result["processed_this_run"] == 0

        try:
            ingest_once(
                connection,
                source_scope=scope,
                generation_id=uuid.uuid4(),
                fetcher=fake_fetch,
            )
        except ValueError as error:
            assert "Unknown or retired" in str(error)
        else:
            raise AssertionError("Unknown generation was accepted")

        print(
            "PASS: unchanged old file does no work; "
            "unknown generation is rejected"
        )

    for table in ("records", "file_generations"):
        assert connection.execute(
            f"""
            SELECT count(*)
            FROM ingestion.{table}
            WHERE source_scope = %s
            """,
            (scope,),
        ).fetchone()[0] == 0

    print("PASS: all test data rolled back")

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--passes", type=int, default=1)
    parser.add_argument("--records-per-file", type=int, default=100)
    parser.add_argument("--interval", type=float, default=2)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.passes < 1 or not 1 <= args.records_per_file <= 1000:
        parser.error(
            "passes must be positive; records-per-file must be 1..1000"
        )

    if not 0 <= args.interval <= 60:
        parser.error("interval must be 0..60 seconds")

    try:
        with connect_database() as connection:
            if args.self_test:
                self_test(connection)
                return

            errors = poll(
                connection,
                passes=args.passes,
                records_per_file=args.records_per_file,
                interval=args.interval,
            )

        if errors:
            parser.exit(
                1,
                f"Finished with {errors} collection error(s); "
                "see output above.\n",
            )

    except KeyboardInterrupt:
        print("Stopped. Committed checkpoints are retained.")

    except (psycopg.Error, OSError, ValueError) as error:
        parser.exit(1, f"Collector failed: {error}\n")

if __name__ == "__main__":
    main()
