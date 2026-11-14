"""Recover confirmed Sysmon checkpoint failures with recorded gap history."""

from copy import deepcopy
import hashlib
import json
import uuid
import xml.etree.ElementTree as ET

from psycopg.types.json import Json

from spine import live_sysmon
from spine.sysmon_errors import (
    SysmonCheckpointMismatch,
    SysmonCheckpointUnavailable,
    SysmonQueryStale,
)
from spine.sysmon_transport import CHANNEL, NS, fetch_sysmon_batch


CHECKPOINT_ERRORS = (
    SysmonCheckpointUnavailable,
    SysmonCheckpointMismatch,
)


def _history(connection, generation_id, event_type, details):
    connection.execute(
        """
        INSERT INTO ingestion.eventlog_generation_events (
            event_id,
            generation_id,
            event_type,
            possible_evidence_gap,
            details
        )
        VALUES (%s, %s, %s, TRUE, %s)
        """,
        (
            uuid.uuid4(),
            generation_id,
            event_type,
            Json(details),
        ),
    )


def ingest_with_recovery(
    connection,
    *,
    source_scope="lab/windows-sysmon",
    max_records=100,
    fetcher=fetch_sysmon_batch,
):
    previous = live_sysmon.read_state(connection, source_scope)

    # A stale query receives one retry. It does not authorize a reset.
    for attempt in range(2):
        try:
            return live_sysmon.ingest_once(
                connection,
                source_scope=source_scope,
                max_records=max_records,
                fetcher=fetcher,
            )
        except SysmonQueryStale:
            if attempt == 1:
                raise
        except CHECKPOINT_ERRORS as error:
            first_error = error
            break

    if previous is None:
        raise RuntimeError(
            "Checkpoint failure without a tracked generation"
        ) from first_error

    if live_sysmon.state_signature(
        live_sysmon.read_state(connection, source_scope)
    ) != live_sysmon.state_signature(previous):
        raise RuntimeError(
            "Sysmon checkpoint changed; retry before recovery"
        )

    # Confirm the failure using a new Windows reader.
    try:
        fetcher(
            checkpoint=live_sysmon.checkpoint_from_state(previous),
            max_records=1,
        )
    except CHECKPOINT_ERRORS as error:
        confirmed_error = error
    else:
        # The checkpoint is usable again. Resume normally.
        return live_sysmon.ingest_once(
            connection,
            source_scope=source_scope,
            max_records=max_records,
            fetcher=fetcher,
        )

    # Access errors, timeouts, and stale queries above propagate unchanged.
    # They never reach generation retirement.

    replacement = fetcher(
        checkpoint=None,
        max_records=max_records,
    )

    if not replacement["records"]:
        raise SysmonCheckpointUnavailable(
            "Checkpoint failed and the retained log is empty; "
            "original generation preserved"
        )

    computers = {
        ET.fromstring(item["raw_xml"]).findtext(
            NS + "System/" + NS + "Computer"
        )
        for item in replacement["records"]
    }

    if computers != {previous["computer"]}:
        raise RuntimeError(
            "Recovery batch computer differs from the tracked source"
        )

    event_type = (
        "checkpoint_mismatch"
        if isinstance(confirmed_error, SysmonCheckpointMismatch)
        else "checkpoint_unavailable"
    )

    lock_identity = json.dumps(
        ["live-sysmon", source_scope, CHANNEL],
        separators=(",", ":"),
    )
    lock_key = int.from_bytes(
        hashlib.sha256(lock_identity.encode("utf-8")).digest()[:8],
        byteorder="big",
        signed=True,
    )

    details = {
        "reason": str(confirmed_error)[:2000],
        "previous_last_record_id": previous["last_record_id"],
        "previous_processed_records": previous["processed_records"],
        "recovery_first_record_id": replacement["records"][0]["record_id"],
        "gap_assessment": (
            "Checkpoint continuity could not be established. "
            "The extent and cause of any missing evidence are unknown."
        ),
        "recovery_policy": "restart_from_oldest_retained",
    }

    def replacement_fetcher(*, checkpoint, max_records):
        if checkpoint is not None:
            raise RuntimeError("Recovery expected a fresh generation")
        if len(replacement["records"]) > max_records:
            raise RuntimeError("Recovery batch exceeds requested limit")
        return deepcopy(replacement)

    with connection.transaction():
        connection.execute(
            "SELECT pg_advisory_xact_lock(%s)",
            (lock_key,),
        )

        current = live_sysmon.read_state(connection, source_scope)
        if live_sysmon.state_signature(current) != (
            live_sysmon.state_signature(previous)
        ):
            raise RuntimeError(
                "Sysmon checkpoint changed during recovery; retry"
            )

        _history(
            connection,
            previous["generation_id"],
            event_type,
            details,
        )

        connection.execute(
            """
            UPDATE ingestion.eventlog_generations
            SET retired_at = CURRENT_TIMESTAMP,
                retirement_reason = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE generation_id = %s
            """,
            (event_type, previous["generation_id"]),
        )

        # The nested transaction remains inside this recovery transaction.
        result = live_sysmon.ingest_once(
            connection,
            source_scope=source_scope,
            max_records=max_records,
            fetcher=replacement_fetcher,
        )

        _history(
            connection,
            previous["generation_id"],
            "generation_retired",
            {
                **details,
                "successor_generation_id": result["generation_id"],
            },
        )

    result["recovery"] = {
        "previous_generation_id": str(previous["generation_id"]),
        "new_generation_id": result["generation_id"],
        "reason": event_type,
        "possible_evidence_gap": True,
        "policy": "restart_from_oldest_retained",
    }
    return result