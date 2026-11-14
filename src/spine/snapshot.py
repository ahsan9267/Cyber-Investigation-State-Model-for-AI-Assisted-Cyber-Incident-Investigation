"""Resume ingestion of a fixed JSONL snapshot using PostgreSQL checkpoints."""

import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import io
import json
from pathlib import Path

import psycopg

from spine.batch import MAX_SNAPSHOT_BYTES
from spine.eve import ExcludedSensorHealth
from spine.pipeline import normalize_record
from spine.storage import store_record


def ingest_snapshot(
    connection,
    input_path,
    *,
    input_format,
    source_scope,
    snapshot_id,
    max_records=None,
):
    """Commit each record, outcome, and checkpoint in one transaction.

    The connection must use autocommit and READ COMMITTED isolation.
    Input must be a saved snapshot, not an actively written log.
    """
    if not connection.autocommit:
        raise ValueError("Snapshot ingestion requires autocommit=True")

    if input_format not in ("wazuh", "eve"):
        raise ValueError("Expected wazuh or eve input format")

    for name, value in (
        ("source_scope", source_scope),
        ("snapshot_id", snapshot_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")

    if max_records is not None:
        if (
            isinstance(max_records, bool)
            or not isinstance(max_records, int)
            or max_records < 1
        ):
            raise ValueError("max_records must be a positive integer")

    with Path(input_path).open("rb") as stream:
        snapshot = stream.read(MAX_SNAPSHOT_BYTES + 1)

    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot exceeds the 32 MiB limit")

    digest = hashlib.sha256(snapshot).hexdigest()
    key = (input_format, source_scope, snapshot_id)
    source = io.BytesIO(snapshot)

    counts = {
        "inserted": 0,
        "replay": 0,
        "conflict": 0,
        "conflict_replay": 0,
        "quarantined": 0,
        "excluded_sensor_health": 0,
    }

    # Register the snapshot without replacing an existing registration.
    with connection.transaction():
        connection.execute(
            """
            INSERT INTO ingestion.snapshots (
                input_format, source_scope, snapshot_id,
                snapshot_sha256, snapshot_bytes
            )
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (input_format, source_scope, snapshot_id)
            DO NOTHING
            """,
            (*key, digest, len(snapshot)),
        )

    processed_this_run = 0

    while True:
        with connection.transaction():
            # Serialize readers of the same snapshot.
            state = connection.execute(
                """
                SELECT snapshot_sha256, snapshot_bytes,
                       next_offset, processed_lines
                FROM ingestion.snapshots
                WHERE input_format = %s
                  AND source_scope = %s
                  AND snapshot_id = %s
                FOR UPDATE
                """,
                key,
            ).fetchone()

            if state is None:
                raise RuntimeError("Snapshot registration is missing")

            saved_hash, saved_size, offset, line_count = state

            if saved_hash != digest or saved_size != len(snapshot):
                raise ValueError(
                    "Snapshot content changed under an existing identity. "
                    "Restore the original snapshot, or use a new ID "
                    "for a genuinely different snapshot."
                )

            if (
                offset != len(snapshot)
                and offset > 0
                and snapshot[offset - 1:offset] != b"\n"
            ):
                raise RuntimeError("Checkpoint is not at a line boundary")

            completed = offset == len(snapshot)
            limit_reached = (
                max_records is not None
                and processed_this_run >= max_records
            )

            if completed or limit_reached:
                final_offset = offset
                total_lines = line_count
                break

            source.seek(offset)
            raw_bytes = source.readline()
            next_offset = source.tell()
            line_number = line_count + 1

            reader_identity = json.dumps(
                ["snapshot", snapshot_id, offset],
                ensure_ascii=False,
                separators=(",", ":"),
            )
            reader = {
                "snapshot_id": snapshot_id,
                "snapshot_sha256": digest,
                "line_number": line_number,
                "byte_offset": offset,
                "byte_length": len(raw_bytes),
                "line_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            }

            record_id = None
            reason = None

            try:
                encoding = "utf-8-sig" if offset == 0 else "utf-8"
                raw_text = raw_bytes.decode(encoding)

                record = normalize_record(
                    raw_text,
                    input_format=input_format,
                    source_scope=source_scope,
                    source_record_id=reader_identity,
                    observed_time=datetime.now(timezone.utc).isoformat(),
                )
            except ExcludedSensorHealth as error:
                disposition = "excluded_sensor_health"
                reason = str(error)
            except (UnicodeError, ValueError) as error:
                disposition = "quarantined"
                reason = f"{type(error).__name__}: {error}"
            else:
                record["provenance"]["reader"] = reader
                disposition = store_record(connection, record)
                record_id = record["record_id"]

            connection.execute(
                """
                INSERT INTO ingestion.snapshot_outcomes (
                    input_format, source_scope, snapshot_id,
                    byte_offset, byte_length, line_number,
                    disposition, record_id, raw_bytes, reason
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    *key, offset, len(raw_bytes), line_number,
                    disposition, record_id, raw_bytes, reason,
                ),
            )

            connection.execute(
                """
                UPDATE ingestion.snapshots
                SET next_offset = %s,
                    processed_lines = %s,
                    updated_at = clock_timestamp()
                WHERE input_format = %s
                  AND source_scope = %s
                  AND snapshot_id = %s
                """,
                (next_offset, line_number, *key),
            )

        # Increment local counters only after the transaction commits.
        processed_this_run += 1
        counts[disposition] += 1

    return {
        "completed": completed,
        "processed_this_run": processed_this_run,
        "total_processed_lines": total_lines,
        "next_offset": final_offset,
        "snapshot_bytes": len(snapshot),
        "outcomes_this_run": counts,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--format", choices=("wazuh", "eve"), required=True)
    parser.add_argument("--source-scope", required=True)
    parser.add_argument("--snapshot-id", required=True)
    parser.add_argument("--max-records", type=int)
    args = parser.parse_args()

    password = getpass.getpass("spine_app password: ")

    try:
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

            result = ingest_snapshot(
                connection,
                args.input,
                input_format=args.format,
                source_scope=args.source_scope,
                snapshot_id=args.snapshot_id,
                max_records=args.max_records,
            )

        print(json.dumps(result, indent=2))

    except (OSError, ValueError, RuntimeError, psycopg.Error) as error:
        parser.exit(1, f"Snapshot ingestion failed: {error}\n")


if __name__ == "__main__":
    main()