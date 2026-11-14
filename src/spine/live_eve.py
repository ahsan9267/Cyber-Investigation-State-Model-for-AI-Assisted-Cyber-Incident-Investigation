"""Read complete records from one growing Suricata EVE file."""

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid

from psycopg.rows import dict_row

from spine.eve import ExcludedSensorHealth
from spine.live_lines import read_complete_line
from spine.pipeline import normalize_record
from spine.storage import store_record


class FileGenerationChanged(RuntimeError):
    """The file no longer matches its saved generation."""


def _native_id(info):
    return str(info.st_dev), str(info.st_ino)


def _verify_file(stream, path, state):
    """Check identity, first line, and bytes before the checkpoint."""
    opened = os.fstat(stream.fileno())
    current = path.stat()

    expected = (state["device_id"], state["native_file_id"])

    if _native_id(opened) != expected or _native_id(current) != expected:
        raise FileGenerationChanged("File identity changed")

    offset = state["next_offset"]
    if opened.st_size < offset:
        raise FileGenerationChanged("File was truncated below its checkpoint")

    first = read_complete_line(stream, 0)
    if first is None:
        raise FileGenerationChanged("Previously complete first line is missing")

    if hashlib.sha256(first[0]).hexdigest() != state["first_line_sha256"]:
        raise FileGenerationChanged("First-line fingerprint changed")

    tail = bytes(state["checkpoint_tail"])
    stream.seek(offset - len(tail))
    if stream.read(len(tail)) != tail:
        raise FileGenerationChanged("Bytes before the checkpoint changed")


def ingest_file(connection, input_path, *, source_scope, max_records=100):
    """Process up to max_records complete lines from one file.

    Requires an autocommit connection using READ COMMITTED isolation.
    Each record, outcome, and checkpoint share one transaction.
    """
    if not connection.autocommit:
        raise ValueError("Live ingestion requires autocommit=True")

    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be a non-empty string")

    if (
        isinstance(max_records, bool)
        or not isinstance(max_records, int)
        or max_records < 1
    ):
        raise ValueError("max_records must be a positive integer")

    path = Path(input_path).resolve(strict=True)
    saved_path = os.path.normcase(str(path))

    # Serialize generation registration and progress within this source.
    lock_material = json.dumps(
        ["live-eve", source_scope],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    lock_key = int.from_bytes(
        hashlib.sha256(lock_material.encode("utf-8")).digest()[:8],
        "big",
        signed=True,
    )

    counts = {
        "inserted": 0,
        "replay": 0,
        "conflict": 0,
        "conflict_replay": 0,
        "quarantined": 0,
        "excluded_sensor_health": 0,
    }
    processed = 0
    generation_id = None
    final_offset = 0
    status = "limit_reached"

    # Unbuffered reads avoid retaining old data between checkpoint checks.
    with path.open("rb", buffering=0) as stream:
        while processed < max_records:
            with connection.transaction():
                with connection.cursor(row_factory=dict_row) as cursor:
                    cursor.execute(
                        "SELECT pg_advisory_xact_lock(%s)",
                        (lock_key,),
                    )

                    info = os.fstat(stream.fileno())
                    device_id, native_file_id = _native_id(info)

                    if info.st_ino == 0:
                        raise RuntimeError("No usable operating-system file ID")

                    if _native_id(path.stat()) != (device_id, native_file_id):
                        raise FileGenerationChanged("Path changed after opening")

                    cursor.execute(
                        """
                        SELECT *
                        FROM ingestion.file_generations
                        WHERE input_format = 'eve'
                          AND source_scope = %s
                          AND retired_at IS NULL
                          AND (
                              file_path = %s
                              OR (
                                  device_id = %s
                                  AND native_file_id = %s
                              )
                          )
                        FOR UPDATE
                        """,
                        (
                            source_scope, saved_path,
                            device_id, native_file_id,
                        ),
                    )
                    matches = cursor.fetchall()

                    if len(matches) > 1:
                        raise FileGenerationChanged(
                            "Path and native identity match different generations"
                        )

                    if matches:
                        state = matches[0]

                        if (
                            state["device_id"] != device_id
                            or state["native_file_id"] != native_file_id
                        ):
                            raise FileGenerationChanged(
                                "A different file replaced this path"
                            )

                        if state["file_path"] != saved_path:
                            raise FileGenerationChanged(
                                "Tracked file moved; directory reconciliation needed"
                            )
                    else:
                        first = read_complete_line(stream, 0)

                        if first is None:
                            status = "waiting_for_complete_line"
                            break

                        cursor.execute(
                            """
                            INSERT INTO ingestion.file_generations (
                                generation_id, input_format, source_scope,
                                file_path, device_id, native_file_id,
                                first_line_sha256
                            )
                            VALUES (%s, 'eve', %s, %s, %s, %s, %s)
                            RETURNING *
                            """,
                            (
                                uuid.uuid4(), source_scope, saved_path,
                                device_id, native_file_id,
                                hashlib.sha256(first[0]).hexdigest(),
                            ),
                        )
                        state = cursor.fetchone()

                    _verify_file(stream, path, state)

                    generation_id = state["generation_id"]
                    offset = state["next_offset"]
                    final_offset = offset
                    line_number = state["processed_lines"] + 1

                    item = read_complete_line(stream, offset)
                    if item is None:
                        size = os.fstat(stream.fileno()).st_size
                        status = (
                            "caught_up"
                            if size == offset
                            else "waiting_for_complete_line"
                        )
                        break

                    raw_bytes, next_offset = item
                    identity = json.dumps(
                        ["live-file", str(generation_id), offset],
                        separators=(",", ":"),
                    )

                    record_id = None
                    reason = None

                    try:
                        encoding = "utf-8-sig" if offset == 0 else "utf-8"
                        record = normalize_record(
                            raw_bytes.decode(encoding),
                            input_format="eve",
                            source_scope=source_scope,
                            source_record_id=identity,
                            observed_time=datetime.now(timezone.utc).isoformat(),
                        )
                    except ExcludedSensorHealth as error:
                        disposition = "excluded_sensor_health"
                        reason = str(error)
                    except (UnicodeError, ValueError) as error:
                        disposition = "quarantined"
                        reason = f"{type(error).__name__}: {error}"
                    else:
                        record["provenance"]["reader"] = {
                            "generation_id": str(generation_id),
                            "file_path": saved_path,
                            "line_number": line_number,
                            "byte_offset": offset,
                            "byte_length": len(raw_bytes),
                            "line_sha256": hashlib.sha256(raw_bytes).hexdigest(),
                        }
                        disposition = store_record(connection, record)
                        record_id = record["record_id"]

                    # Check for observable file changes during processing.
                    _verify_file(stream, path, state)
                    stream.seek(offset)
                    if stream.read(len(raw_bytes)) != raw_bytes:
                        raise FileGenerationChanged(
                            "Current line changed while being processed"
                        )

                    tail_start = max(0, next_offset - 4096)
                    stream.seek(tail_start)
                    tail = stream.read(next_offset - tail_start)
                    if len(tail) != next_offset - tail_start:
                        raise FileGenerationChanged(
                            "File shrank while reading checkpoint bytes"
                        )

                    cursor.execute(
                        """
                        INSERT INTO ingestion.file_outcomes (
                            generation_id, byte_offset, byte_length,
                            line_number, disposition, record_id,
                            raw_bytes, reason
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            generation_id, offset, len(raw_bytes),
                            line_number, disposition, record_id,
                            raw_bytes, reason,
                        ),
                    )

                    cursor.execute(
                        """
                        UPDATE ingestion.file_generations
                        SET next_offset = %s,
                            processed_lines = %s,
                            checkpoint_tail = %s,
                            updated_at = clock_timestamp()
                        WHERE generation_id = %s
                        """,
                        (next_offset, line_number, tail, generation_id),
                    )

            processed += 1
            counts[disposition] += 1
            final_offset = next_offset

    return {
        "status": status,
        "generation_id": str(generation_id) if generation_id else None,
        "processed_this_run": processed,
        "next_offset": final_offset,
        "outcomes_this_run": counts,
    }