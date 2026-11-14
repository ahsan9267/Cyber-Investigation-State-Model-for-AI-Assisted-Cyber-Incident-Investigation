"""Store normalized records without overwriting original evidence."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path
import uuid

import psycopg
from psycopg.types.json import Json

from spine.envelope import build_envelope
from spine.wazuh import _reject_constant, _unique_keys


def validate_record(record):
    """Verify the envelope's identity and preserved-text hash."""
    if not isinstance(record, dict):
        raise ValueError("Expected a normalized record object")

    try:
        collector = record["collector"]
        scope = record["provenance"]["source_scope"]
        source_id = record["provenance"]["source_record_id"]
        raw_text = record["raw"]["text"]
        raw_hash = record["raw"]["sha256"]
        record_id = record["record_id"]
    except (KeyError, TypeError) as error:
        raise ValueError("Missing required envelope fields") from error

    for value in (collector, scope, source_id, record_id, raw_hash):
        if not isinstance(value, str) or not value.strip():
            raise ValueError("Invalid identity or hash field")

    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("Missing preserved raw text")

    identity = json.dumps(
        [collector, scope, source_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    expected_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    expected_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    if record_id != expected_id:
        raise ValueError("Record identity does not match its provenance")

    if raw_hash != expected_hash:
        raise ValueError("Raw hash does not match preserved text")

    # Reject non-JSON values before submitting anything to PostgreSQL.
    json.dumps(record, allow_nan=False)

    return record_id, collector, scope, source_id, raw_hash, raw_text


def store_record(connection, record):
    """Insert, recognize a replay, or preserve an identity conflict.

    With an outer transaction, changes commit only when that outer
    transaction succeeds. Original stored documents are never updated.
    """
    record_id, collector, scope, source_id, raw_hash, raw_text = (
        validate_record(record)
    )

    with connection.transaction():
        inserted = connection.execute(
            """
            INSERT INTO ingestion.records (
                record_id, collector, source_scope, source_record_id,
                raw_sha256, document
            )
            VALUES (%s, %s, %s, %s, %s, %s)
            ON CONFLICT (record_id) DO NOTHING
            RETURNING record_id
            """,
            (
                record_id, collector, scope, source_id,
                raw_hash, Json(record),
            ),
        ).fetchone()

        if inserted is not None:
            # Older databases without SQL 015 retain their existing behavior.
            metadata_available = connection.execute(
                """
                SELECT to_regclass(
                    'investigation.record_scheduling_metadata'
                ) IS NOT NULL
                """
            ).fetchone()[0]

            if metadata_available:
                from spine.manager_classification import (
                    capture_scheduling_metadata,
                )

                kind = record.get("record_kind")
                if not isinstance(kind, str) or not kind.strip():
                    raise ValueError("record_kind is missing or invalid")

                capture_scheduling_metadata(
                    connection,
                    record_id=record_id,
                    raw_sha256=raw_hash,
                    is_alert=kind == "alert",
                )

            return "inserted"

        existing = connection.execute(
            """
            SELECT raw_sha256, document
            FROM ingestion.records
            WHERE record_id = %s
            """,
            (record_id,),
        ).fetchone()

        if existing is None:
            raise RuntimeError("Existing record could not be read")

        existing_hash, existing_document = existing

        if existing_hash == raw_hash:
            if existing_document["raw"]["text"] != raw_text:
                raise RuntimeError("Hash collision or stored-data inconsistency")
            return "replay"

        conflict = connection.execute(
            """
            INSERT INTO ingestion.record_conflicts (
                record_id, incoming_raw_sha256, incoming_document
            )
            VALUES (%s, %s, %s)
            ON CONFLICT (record_id, incoming_raw_sha256) DO NOTHING
            RETURNING record_id
            """,
            (record_id, raw_hash, Json(record)),
        ).fetchone()

        if conflict is not None:
            return "conflict"

        previous = connection.execute(
            """
            SELECT incoming_document
            FROM ingestion.record_conflicts
            WHERE record_id = %s AND incoming_raw_sha256 = %s
            """,
            (record_id, raw_hash),
        ).fetchone()

        if previous is None or previous[0]["raw"]["text"] != raw_text:
            raise RuntimeError("Conflict hash or stored-data inconsistency")

        return "conflict_replay"


def check_storage(connection):
    """Exercise the real database, then roll back all test records."""
    scope = f"storage-check/{uuid.uuid4()}"
    observed = datetime.now(timezone.utc).isoformat()

    def sample(source_id, raw_text):
        return build_envelope(
            raw_text=raw_text,
            source="storage_check",
            collector="storage_check",
            record_kind="telemetry",
            source_scope=scope,
            source_record_id=source_id,
            observed_time=observed,
        )

    original = sample("record-1", r'{"value":"\u0000"}')
    original["attributes"]["source_payload"] = {"value": "\x00"}

    changed = sample("record-1", r'{"value":"changed\u0000"}')
    changed["attributes"]["source_payload"] = {"value": "changed\x00"}

    distinct = sample("record-2", r'{"value":"\u0000"}')
    distinct["attributes"]["source_payload"] = {"value": "\x00"}

    def expect(actual, expected):
        if actual != expected:
            raise RuntimeError(f"Expected {expected!r}; received {actual!r}")

    with connection.transaction(force_rollback=True):
        expect(store_record(connection, original), "inserted")

        replay = deepcopy(original)
        replay["observed_time"] = {
            "utc": "2026-10-03T00:00:00Z"
        }
        expect(store_record(connection, replay), "replay")

        expect(store_record(connection, changed), "conflict")
        expect(store_record(connection, changed), "conflict_replay")
        expect(store_record(connection, distinct), "inserted")

        stored = connection.execute(
            """
            SELECT document FROM ingestion.records
            WHERE record_id = %s
            """,
            (original["record_id"],),
        ).fetchone()[0]
        expect(stored, original)

        conflict_document = connection.execute(
            """
            SELECT incoming_document
            FROM ingestion.record_conflicts
            WHERE record_id = %s
            """,
            (original["record_id"],),
        ).fetchone()[0]
        expect(conflict_document, changed)

        tampered = deepcopy(original)
        tampered["raw"]["text"] = "changed without updating hash"
        try:
            store_record(connection, tampered)
        except ValueError:
            pass
        else:
            raise RuntimeError("Tampered raw hash was accepted")

    remaining = connection.execute(
        """
        SELECT COUNT(*) FROM ingestion.records
        WHERE source_scope = %s
        """,
        (scope,),
    ).fetchone()[0]
    expect(remaining, 0)

    print("PASS: new records inserted")
    print("PASS: replay ignores changed observation time")
    print("PASS: changed payload preserved as a conflict")
    print("PASS: repeated conflict recognized")
    print("PASS: distinct identities with identical text preserved")
    print("PASS: original document unchanged")
    print("PASS: invalid raw hash rejected")
    print("PASS: test records rolled back")


def import_normalized(connection, path):
    counts = {
        "inserted": 0,
        "replay": 0,
        "conflict": 0,
        "conflict_replay": 0,
    }

    # Commit the whole import, or roll it all back on an error.
    with connection.transaction():
        with Path(path).open("r", encoding="utf-8-sig") as stream:
            for number, line in enumerate(stream, start=1):
                try:
                    record = json.loads(
                        line,
                        parse_constant=_reject_constant,
                        object_pairs_hook=_unique_keys,
                    )
                    outcome = store_record(connection, record)
                except ValueError as error:
                    raise ValueError(f"Line {number}: {error}") from error

                counts[outcome] += 1

    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test == (args.input is not None):
        parser.error("Provide either an input file or --self-test")

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

            if args.self_test:
                check_storage(connection)
            else:
                counts = import_normalized(connection, args.input)
                print("Import committed")
                for name, count in counts.items():
                    print(f"{name}: {count}")

    except (OSError, ValueError, RuntimeError, psycopg.Error) as error:
        parser.exit(1, f"Storage operation failed: {error}\n")


if __name__ == "__main__":
    main()