"""Commit bounded Wazuh SSH batches with durable PostgreSQL checkpoints.

File replacement or truncation stops ingestion without moving the checkpoint.
Rotation reconciliation is a separate operation, not implemented here.
"""

import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
import json
import subprocess
import uuid

import psycopg
from psycopg.rows import dict_row

from spine.pipeline import normalize_record
from spine.remote_wazuh import REMOTE_PATH, fetch_batch
from spine.storage import store_record


class CheckpointChanged(RuntimeError):
    """Another reader advanced or replaced this checkpoint during transfer."""


def _state(connection, scope, generation_id=None):
    if generation_id is None:
        selector = "file_path = %s"
        identifier = REMOTE_PATH
    else:
        selector = "generation_id = %s"
        identifier = uuid.UUID(str(generation_id))

    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            f"""
            SELECT *
            FROM ingestion.file_generations
            WHERE input_format = 'wazuh'
              AND source_scope = %s
              AND retired_at IS NULL
              AND {selector}
            """,
            (scope, identifier),
        )
        return cursor.fetchone()


def _checkpoint(state):
    if state is None:
        return None
    return {
        "device_id": state["device_id"],
        "native_file_id": state["native_file_id"],
        "first_line_sha256": state["first_line_sha256"],
        "next_offset": state["next_offset"],
        "checkpoint_tail_b64": base64.b64encode(
            bytes(state["checkpoint_tail"])
        ).decode("ascii"),
    }


def _signature(state):
    if state is None:
        return None
    return (str(state["generation_id"]), state["processed_lines"], _checkpoint(state))

def _remember_archive_path(connection, state, batch):
    """Save the verified dated path within the ingestion transaction."""
    if state is None:
        return

    archive_path = batch.get("archive_path")

    if archive_path is None:
        return

    previous_path = state.get("remote_archive_path")

    if previous_path is not None and previous_path != archive_path:
        raise RuntimeError(
            "Dated archive path changed for this generation; "
            "reconciliation required"
        )

    if previous_path is None:
        connection.execute(
            """
            UPDATE ingestion.file_generations
            SET remote_archive_path = %s,
                updated_at = clock_timestamp()
            WHERE generation_id = %s
            """,
            (archive_path, state["generation_id"]),
        )

def ingest_once(
    connection,
    *,
    source_scope="lab/wazuh-server",
    host="192.168.0.32",
    user="spine-reader",
    max_records=100,
    generation_id=None,
    fetcher=fetch_batch,
):
    """Fetch outside the DB transaction, then atomically commit one batch.

    Requires autocommit=True and READ COMMITTED isolation. A transaction lock
    plus checkpoint comparison prevents two readers from committing the same
    offsets. A stale batch is rejected; retry fetches from the latest checkpoint.
    """
    if not connection.autocommit:
        raise ValueError("Wazuh ingestion requires autocommit=True")
    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be a non-empty string")
    if type(max_records) is not int or not 1 <= max_records <= 1000:
        raise ValueError("max_records must be 1..1000")

    previous = _state(connection, source_scope, generation_id)

    if generation_id is not None and previous is None:
        raise ValueError("Unknown or retired Wazuh generation")    
    offset = previous["next_offset"] if previous else 0
    batch = fetcher(host=host, user=user, offset=offset,
                    expected=_checkpoint(previous), max_records=max_records)
    raw = batch["raw_bytes"]
    if not isinstance(raw, bytes) or len(raw) > 4 * 1024 * 1024:
        raise ValueError("Invalid batch bytes")
    if batch["file_path"] != REMOTE_PATH or batch["offset"] != offset:
        raise ValueError("Unexpected batch provenance")
    if batch["next_offset"] != offset + len(raw):
        raise ValueError("Batch offset mismatch")
    if hashlib.sha256(raw).hexdigest() != batch["batch_sha256"]:
        raise ValueError("Batch hash mismatch")
    if raw and not raw.endswith(b"\n"):
        raise ValueError("Incomplete batch")
    # Split only LF: other control bytes must remain in their original line.
    lines = [part + b"\n" for part in raw.split(b"\n")[:-1]] if raw else []
    if len(lines) != batch["line_count"] or len(lines) > max_records:
        raise ValueError("Batch line count mismatch")
    old_tail = bytes(previous["checkpoint_tail"]) if previous else b""
    tail = (old_tail + raw)[-4096:]
    if base64.b64decode(batch["checkpoint_tail_b64"], validate=True) != tail:
        raise ValueError("Batch checkpoint tail mismatch")
    if previous and any(batch[key] != previous[key] for key in (
        "device_id", "native_file_id", "first_line_sha256"
    )):
        raise RuntimeError("Remote file generation changed; checkpoint preserved")
    if lines and not batch["first_line_sha256"]:
        raise ValueError("Missing first-line fingerprint")

    counts = dict.fromkeys(("inserted", "replay", "conflict", "conflict_replay",
                           "quarantined", "excluded_sensor_health"), 0)
    lock_material = json.dumps(["live-wazuh", source_scope],
                               ensure_ascii=False, separators=(",", ":"))
    lock_key = int.from_bytes(hashlib.sha256(lock_material.encode("utf-8"))
                              .digest()[:8], "big", signed=True)
    with connection.transaction():
        connection.execute("SELECT pg_advisory_xact_lock(%s)", (lock_key,))
        current = _state(connection, source_scope, generation_id)
        if _signature(current) != _signature(previous):
            raise CheckpointChanged("Checkpoint changed during transfer; retry ingestion")
        if not lines:
            _remember_archive_path(connection, current, batch)
            return {
                "status": batch["status"],
                "generation_id": str(current["generation_id"]) if current else None,
                "processed_this_run": 0,
                "next_offset": offset,
                "outcomes_this_run": counts,
            }
        if current is None:
            with connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute(
                    """INSERT INTO ingestion.file_generations
                       (generation_id, input_format, source_scope, file_path,
                        device_id, native_file_id, first_line_sha256)
                       VALUES (%s, 'wazuh', %s, %s, %s, %s, %s) RETURNING *""",
                    (uuid.uuid4(), source_scope, REMOTE_PATH, batch["device_id"],
                     batch["native_file_id"], batch["first_line_sha256"]),
                )
                current = cursor.fetchone()

        _remember_archive_path(connection, current, batch)
        generation = current["generation_id"]
        line_number = current["processed_lines"]
        observed = datetime.now(timezone.utc).isoformat()
        for line in lines:
            line_number += 1
            identity = json.dumps(["live-file", str(generation), offset],
                                  separators=(",", ":"))
            record_id = None
            reason = None
            try:
                text = line.decode("utf-8-sig" if offset == 0 else "utf-8")
                record = normalize_record(
                    text, input_format="wazuh", source_scope=source_scope,
                    source_record_id=identity, observed_time=observed,
                )
            except (UnicodeError, ValueError) as error:
                disposition = "quarantined"
                reason = f"{type(error).__name__}: {error}"
            else:
                record["provenance"]["reader"] = {
                    "generation_id": str(generation), "file_path": REMOTE_PATH,
                    "line_number": line_number, "byte_offset": offset,
                    "byte_length": len(line),
                    "line_sha256": hashlib.sha256(line).hexdigest(),
                    "transport": "ssh", "remote_host": host,
                    "read_path": batch.get("read_path", REMOTE_PATH),
                    "reading_retained_file": batch.get("reading_retained_file", False),
                }
                disposition = store_record(connection, record)
                record_id = record["record_id"]
            connection.execute(
                """INSERT INTO ingestion.file_outcomes
                   (generation_id, byte_offset, byte_length, line_number,
                    disposition, record_id, raw_bytes, reason)
                   VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
                (generation, offset, len(line), line_number, disposition,
                 record_id, line, reason),
            )
            counts[disposition] += 1
            offset += len(line)
        connection.execute(
            """UPDATE ingestion.file_generations
               SET next_offset = %s, processed_lines = %s, checkpoint_tail = %s,
                   updated_at = clock_timestamp()
               WHERE generation_id = %s""",
            (offset, line_number, tail, generation),
        )
    return {
        "status": batch["status"], "generation_id": str(generation),
        "processed_this_run": len(lines), "next_offset": offset,
        "outcomes_this_run": counts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="192.168.0.32")
    parser.add_argument("--user", default="spine-reader")
    parser.add_argument("--source-scope", default="lab/wazuh-server")
    parser.add_argument("--max-records", type=int, default=100)
    args = parser.parse_args()
    password = getpass.getpass("spine_app password: ")
    try:
        with psycopg.connect(host="127.0.0.1", port=5432, dbname="spine",
                             user="spine_app", password=password,
                             connect_timeout=5, autocommit=True) as connection:
            connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
            result = ingest_once(connection, host=args.host, user=args.user,
                                 source_scope=args.source_scope,
                                 max_records=args.max_records)
        print(json.dumps(result, indent=2))
    except (OSError, ValueError, RuntimeError, psycopg.Error,
            subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Wazuh ingestion failed: {error}\n")


if __name__ == "__main__":
    main()
