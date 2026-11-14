"""Recover from detected changes to tracked EVE files."""

import hashlib
import json
import os
from pathlib import Path
import uuid

from psycopg.rows import dict_row
from psycopg.types.json import Json

from spine.live_eve import FileGenerationChanged, ingest_file
from spine.live_lines import read_complete_line


def recover_file(connection, input_path, *, source_scope):
    """Recheck a tracked path and retire a demonstrably changed generation.

    A missing file is recorded but not retired: it may become available again.
    """
    path = Path(input_path).resolve()
    saved_path = os.path.normcase(str(path))

    # Must match the lock used by live_eve.ingest_file.
    material = json.dumps(
        ["live-eve", source_scope],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    lock_key = int.from_bytes(
        hashlib.sha256(material.encode("utf-8")).digest()[:8],
        "big",
        signed=True,
    )

    with connection.transaction():
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)", (lock_key,)
            )
            cursor.execute(
                """
                SELECT *
                FROM ingestion.file_generations
                WHERE input_format = 'eve'
                  AND source_scope = %s
                  AND file_path = %s
                  AND retired_at IS NULL
                FOR UPDATE
                """,
                (source_scope, saved_path),
            )
            state = cursor.fetchone()

            if state is None:
                return {"status": "no_tracked_generation"}

            event_type = None
            observed_size = None
            details = {"file_path": saved_path}

            try:
                with path.open("rb", buffering=0) as stream:
                    info = os.fstat(stream.fileno())
                    native = (str(info.st_dev), str(info.st_ino))
                    path_info = path.stat()

                    if native != (
                        str(path_info.st_dev), str(path_info.st_ino)
                    ):
                        raise FileGenerationChanged(
                            "File changed during recovery inspection; retry later"
                        )

                    observed_size = info.st_size
                    details["observed_device_id"] = native[0]
                    details["observed_native_file_id"] = native[1]

                    expected = (
                        state["device_id"], state["native_file_id"]
                    )

                    if native != expected:
                        event_type = "replacement_detected"

                        cursor.execute(
                            """
                            SELECT generation_id
                            FROM ingestion.file_generations
                            WHERE input_format = 'eve'
                              AND source_scope = %s
                              AND device_id = %s
                              AND native_file_id = %s
                              AND retired_at IS NULL
                              AND generation_id <> %s
                            """,
                            (source_scope, *native, state["generation_id"]),
                        )
                        if cursor.fetchone() is not None:
                            raise FileGenerationChanged(
                                "Replacement is already tracked at another path; "
                                "path reconciliation is required"
                            )

                    elif observed_size < state["next_offset"]:
                        event_type = "truncation_detected"

                    else:
                        first = read_complete_line(stream, 0)
                        first_hash = (
                            hashlib.sha256(first[0]).hexdigest()
                            if first is not None else None
                        )
                        details["observed_first_line_sha256"] = first_hash

                        if first_hash != state["first_line_sha256"]:
                            event_type = "content_change_detected"
                            details["change_basis"] = "first_line"
                        else:
                            tail = bytes(state["checkpoint_tail"])
                            stream.seek(state["next_offset"] - len(tail))
                            if stream.read(len(tail)) != tail:
                                event_type = "content_change_detected"
                                details["change_basis"] = "checkpoint_tail"

            except FileNotFoundError:
                event_type = "file_missing"

            if event_type is None:
                return {"status": "unchanged"}

            # Avoid recording the same unresolved disappearance repeatedly.
            if event_type == "file_missing":
                cursor.execute(
                    """
                    SELECT event_id
                    FROM ingestion.file_generation_events
                    WHERE generation_id = %s AND event_type = 'file_missing'
                    LIMIT 1
                    """,
                    (state["generation_id"],),
                )
                if cursor.fetchone() is not None:
                    return {"status": "missing"}

            details["old_device_id"] = state["device_id"]
            details["old_native_file_id"] = state["native_file_id"]
            details["old_processed_lines"] = state["processed_lines"]
            details["gap_assessment"] = (
                "Unread source data may be unavailable; extent is unknown"
            )

            cursor.execute(
                """
                INSERT INTO ingestion.file_generation_events (
                    event_id, generation_id, event_type,
                    checkpoint_offset, observed_size,
                    possible_evidence_gap, details
                )
                VALUES (%s, %s, %s, %s, %s, TRUE, %s)
                """,
                (
                    uuid.uuid4(), state["generation_id"], event_type,
                    state["next_offset"], observed_size, Json(details),
                ),
            )

            if event_type == "file_missing":
                return {"status": "missing"}

            cursor.execute(
                """
                UPDATE ingestion.file_generations
                SET retired_at = clock_timestamp(),
                    retirement_reason = %s,
                    updated_at = clock_timestamp()
                WHERE generation_id = %s
                """,
                (event_type, state["generation_id"]),
            )

            return {
                "status": "retired",
                "generation_id": str(state["generation_id"]),
                "reason": event_type,
                "possible_evidence_gap": True,
            }


def ingest_with_recovery(
    connection, input_path, *, source_scope, max_records=100
):
    """Try ingestion, perform verified recovery, and retry once."""
    try:
        return ingest_file(
            connection,
            input_path,
            source_scope=source_scope,
            max_records=max_records,
        )
    except (FileGenerationChanged, FileNotFoundError):
        recovery = recover_file(
            connection, input_path, source_scope=source_scope
        )

        if recovery["status"] == "missing":
            return {
                "status": "file_missing",
                "recovery": recovery,
            }

        if recovery["status"] != "retired":
            raise

        result = ingest_file(
            connection,
            input_path,
            source_scope=source_scope,
            max_records=max_records,
        )
        result["recovery"] = recovery
        return result