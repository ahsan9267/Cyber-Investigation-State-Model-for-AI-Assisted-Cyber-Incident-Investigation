"""Transactional ingestion of raw Sysmon Event Log batches."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import uuid
import xml.etree.ElementTree as ET

from psycopg.rows import dict_row

from spine.database import connect_database
from spine.pipeline import normalize_record
from spine.storage import store_record
from spine.sysmon_transport import CHANNEL, NS, fetch_sysmon_batch


def read_state(connection, source_scope):
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """
            SELECT *
            FROM ingestion.eventlog_generations
            WHERE source_scope = %s
              AND channel = %s
              AND retired_at IS NULL
            """,
            (source_scope, CHANNEL),
        )
        return cursor.fetchone()


def checkpoint_from_state(state):
    if state is None or state["last_record_id"] is None:
        return None

    return {
        "channel": CHANNEL,
        "record_id": str(state["last_record_id"]),
        "raw_sha256": state["last_raw_sha256"],
        "bookmark_xml": state["bookmark_xml"],
    }


def state_signature(state):
    if state is None:
        return None

    return (
        str(state["generation_id"]),
        state["computer"],
        state["processed_records"],
        checkpoint_from_state(state),
    )


def ingest_once(
    connection,
    *,
    source_scope="lab/windows-sysmon",
    max_records=100,
    fetcher=fetch_sysmon_batch,
):
    if not connection.autocommit:
        raise ValueError("Sysmon ingestion requires an autocommit connection")

    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be a non-empty string")

    if (
        isinstance(max_records, bool)
        or not isinstance(max_records, int)
        or not 1 <= max_records <= 1000
    ):
        raise ValueError("max_records must be 1..1000")

    previous = read_state(connection, source_scope)

    # Read Windows outside the database transaction.
    # The transport verifies XML hashes and checkpoint consistency.
    batch = fetcher(
        checkpoint=checkpoint_from_state(previous),
        max_records=max_records,
    )
    observed_time = datetime.now(timezone.utc).isoformat()

    computers = set()
    for item in batch["records"]:
        root = ET.fromstring(item["raw_xml"])
        computer = root.findtext(NS + "System/" + NS + "Computer")
        if not computer or not computer.strip():
            raise ValueError("Sysmon event has no computer name")
        computers.add(computer)

    if len(computers) > 1:
        raise ValueError("A Sysmon batch contains multiple computers")

    computer = next(iter(computers)) if computers else None

    if previous is not None and computer is not None:
        if previous["computer"] != computer:
            raise ValueError("Computer changed within the Sysmon source scope")

    lock_identity = json.dumps(
        ["live-sysmon", source_scope, CHANNEL],
        separators=(",", ":"),
    )
    lock_key = int.from_bytes(
        hashlib.sha256(lock_identity.encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )

    outcomes = {
        "inserted": 0,
        "replay": 0,
        "conflict": 0,
        "conflict_replay": 0,
        "quarantined": 0,
    }

    with connection.transaction():
        connection.execute(
            "SELECT pg_advisory_xact_lock(%s)",
            (lock_key,),
        )

        current = read_state(connection, source_scope)
        if state_signature(current) != state_signature(previous):
            raise RuntimeError(
                "Sysmon checkpoint changed during the read; retry the batch"
            )

        if not batch["records"]:
            return {
                "status": batch["status"],
                "generation_id": (
                    str(current["generation_id"]) if current else None
                ),
                "processed_this_run": 0,
                "last_record_id": (
                    current["last_record_id"] if current else None
                ),
                "outcomes_this_run": outcomes,
            }

        if current is None:
            generation_id = uuid.uuid4()
            processed_records = 0

            connection.execute(
                """
                INSERT INTO ingestion.eventlog_generations (
                    generation_id, source_scope, channel, computer
                )
                VALUES (%s, %s, %s, %s)
                """,
                (generation_id, source_scope, CHANNEL, computer),
            )
        else:
            generation_id = current["generation_id"]
            processed_records = current["processed_records"]

        for item in batch["records"]:
            source_record_id = json.dumps(
                [
                    "eventlog",
                    str(generation_id),
                    item["record_id"],
                ],
                separators=(",", ":"),
            )

            record = None
            reason = None

            try:
                record = normalize_record(
                    item["raw_xml"],
                    input_format="sysmon_xml",
                    source_scope=source_scope,
                    source_record_id=source_record_id,
                    observed_time=observed_time,
                )
            except ValueError as error:
                disposition = "quarantined"
                reason = str(error) or type(error).__name__
            else:
                record["provenance"]["reader"] = {
                    "generation_id": str(generation_id),
                    "channel": CHANNEL,
                    "computer": computer,
                    "event_record_id": item["record_id"],
                    "raw_xml_sha256": item["raw_sha256"],
                    "transport": "local_windows_eventlog",
                }

                # Storage errors must abort the batch, not become quarantine.
                disposition = store_record(connection, record)

            connection.execute(
                """
                INSERT INTO ingestion.eventlog_outcomes (
                    generation_id,
                    event_record_id,
                    disposition,
                    record_id,
                    raw_xml,
                    raw_sha256,
                    bookmark_xml,
                    reason
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    generation_id,
                    int(item["record_id"]),
                    disposition,
                    record["record_id"] if record is not None else None,
                    item["raw_xml"],
                    item["raw_sha256"],
                    item["bookmark_xml"],
                    reason,
                ),
            )

            outcomes[disposition] += 1
            processed_records += 1

        checkpoint = batch["next_checkpoint"]

        connection.execute(
            """
            UPDATE ingestion.eventlog_generations
            SET last_record_id = %s,
                last_raw_sha256 = %s,
                bookmark_xml = %s,
                processed_records = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE generation_id = %s
            """,
            (
                int(checkpoint["record_id"]),
                checkpoint["raw_sha256"],
                checkpoint["bookmark_xml"],
                processed_records,
                generation_id,
            ),
        )

    return {
        "status": batch["status"],
        "generation_id": str(generation_id),
        "processed_this_run": len(batch["records"]),
        "total_processed_records": processed_records,
        "last_record_id": int(checkpoint["record_id"]),
        "outcomes_this_run": outcomes,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-records", type=int, default=100)
    args = parser.parse_args()

    with connect_database() as connection:
        result = ingest_once(
            connection,
            max_records=args.max_records,
        )

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()