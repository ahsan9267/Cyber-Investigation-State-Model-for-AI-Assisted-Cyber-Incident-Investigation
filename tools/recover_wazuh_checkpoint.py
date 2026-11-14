"""Recover the confirmed October 4 Wazuh checkpoint discontinuity.

Default: execute recovery inside a transaction, then roll it back.
--apply: commit recovery after the same validation.
"""

import argparse
from copy import deepcopy
import hashlib
import json
import uuid

from psycopg.types.json import Json

from spine.database import connect_database
from spine.live_wazuh import _state, _checkpoint, _signature, ingest_once
from spine.remote_wazuh import fetch_batch


SCOPE = "lab/wazuh-server"
OLD_GENERATION = "d7ce49e0-098a-43f7-8e70-42b599d31759"
OLD_OFFSET = 7200280
ARCHIVE = "/var/ossec/logs/alerts/2026/Oct/ossec-alerts-04.json"

ACCEPTED_ERRORS = {
    "File truncated below checkpoint",
    "Checkpoint is not at a line boundary",
    "Checkpoint bytes changed",
    "First-line fingerprint changed",
}


def confirm_discontinuity(previous):
    try:
        fetch_batch(
            offset=previous["next_offset"],
            expected=_checkpoint(previous),
            max_records=1,
        )
    except RuntimeError as error:
        message = str(error)
        prefix = "Remote read failed (2): "
        if not message.startswith(prefix):
            raise

        try:
            detail = json.loads(message[len(prefix):])
        except ValueError:
            raise RuntimeError("Unrecognized remote error; recovery refused")

        if (
            not isinstance(detail, dict)
            or detail.get("error") not in ("RuntimeError", "ValueError")
            or detail.get("message") not in ACCEPTED_ERRORS
        ):
            raise RuntimeError("Remote error is not an approved recovery cause")

        return detail["message"]

    raise RuntimeError(
        "The saved checkpoint now validates; this recovery must not be applied"
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    with connect_database() as connection:
        previous = _state(connection, SCOPE)

        if (
            previous is None
            or str(previous["generation_id"]) != OLD_GENERATION
            or previous["next_offset"] != OLD_OFFSET
            or previous.get("remote_archive_path") != ARCHIVE
        ):
            raise RuntimeError(
                "Current generation differs from the reviewed incident; "
                "nothing changed"
            )

        reason = confirm_discontinuity(previous)

        # Read the current file from its beginning twice.
        # Appending is allowed, but the selected batch must remain identical.
        first = fetch_batch(offset=0, expected=None, max_records=100)
        second = fetch_batch(offset=0, expected=None, max_records=100)

        if first.get("archive_path") != ARCHIVE:
            raise RuntimeError("Active archive changed; recovery refused")

        if not first["raw_bytes"] or not first["first_line_sha256"]:
            raise RuntimeError("No complete first batch; recovery refused")

        for key in (
            "archive_path", "device_id", "native_file_id",
            "first_line_sha256", "offset", "next_offset",
            "batch_sha256", "checkpoint_tail_b64", "raw_bytes",
        ):
            if first.get(key) != second.get(key):
                raise RuntimeError(
                    f"Current batch changed during validation: {key}; retry"
                )

        # Confirm that the original checkpoint still fails.
        confirm_discontinuity(previous)

        material = json.dumps(
            ["live-wazuh", SCOPE],
            ensure_ascii=False,
            separators=(",", ":"),
        )
        lock_key = int.from_bytes(
            hashlib.sha256(material.encode("utf-8")).digest()[:8],
            "big",
            signed=True,
        )

        history_id = uuid.uuid4()

        def verified_batch(**request):
            if request.get("offset") != 0 or request.get("expected") is not None:
                raise RuntimeError("Unexpected successor read request")
            return deepcopy(second)

        with connection.transaction(force_rollback=not args.apply):
            connection.execute("SET LOCAL lock_timeout = '10s'")
            connection.execute(
                "SELECT pg_advisory_xact_lock(%s)", (lock_key,)
            )

            current = _state(connection, SCOPE)
            if (
                _signature(current) != _signature(previous)
                or current.get("remote_archive_path") != ARCHIVE
            ):
                raise RuntimeError("Checkpoint changed; recovery refused")

            connection.execute(
                """
                UPDATE ingestion.file_generations
                SET retired_at = clock_timestamp(),
                    retirement_reason = %s,
                    updated_at = clock_timestamp()
                WHERE generation_id = %s AND retired_at IS NULL
                """,
                (
                    "Confirmed checkpoint discontinuity after observed "
                    "truncation; successor restarts from retained file beginning",
                    previous["generation_id"],
                ),
            )

            # Reuse the existing validation, storage, outcomes and checkpoint
            # transaction logic. The outer transaction controls final commit.
            result = ingest_once(
                connection,
                source_scope=SCOPE,
                max_records=100,
                fetcher=verified_batch,
            )

            successor = result["generation_id"]
            if not successor or successor == OLD_GENERATION:
                raise RuntimeError("Expected a new generation")

            connection.execute(
                """
                INSERT INTO ingestion.file_generation_events (
                    event_id, generation_id, event_type,
                    checkpoint_offset, observed_size,
                    possible_evidence_gap, details
                )
                VALUES (%s, %s, 'content_change_detected',
                        %s, %s, TRUE, %s)
                """,
                (
                    history_id,
                    previous["generation_id"],
                    previous["next_offset"],
                    second["size_at_open"],
                    Json({
                        "reason": reason,
                        "previous_processed_lines": previous["processed_lines"],
                        "successor_generation_id": successor,
                        "archive_path": ARCHIVE,
                        "recovery_policy": "restart_from_retained_file_beginning",
                        "earlier_observation": {
                            "file_size": 7151320,
                            "saved_checkpoint": OLD_OFFSET,
                        },
                        "gap_assessment": (
                            "File continuity was lost. Extent of any "
                            "uncollected evidence loss is unknown."
                        ),
                    }),
                ),
            )

            retained = connection.execute(
                """
                SELECT next_offset, processed_lines, retired_at
                FROM ingestion.file_generations
                WHERE generation_id = %s
                """,
                (previous["generation_id"],),
            ).fetchone()

            if (
                retained[0] != previous["next_offset"]
                or retained[1] != previous["processed_lines"]
                or retained[2] is None
            ):
                raise RuntimeError("Old generation was not preserved correctly")

        if not args.apply:
            restored = _state(connection, SCOPE)
            if restored != previous:
                raise RuntimeError("Dry-run rollback did not restore old state")

            successor_exists = connection.execute(
                """
                SELECT 1 FROM ingestion.file_generations
                WHERE generation_id = %s
                """,
                (successor,),
            ).fetchone()

            history_exists = connection.execute(
                """
                SELECT 1 FROM ingestion.file_generation_events
                WHERE event_id = %s
                """,
                (history_id,),
            ).fetchone()

            if successor_exists or history_exists:
                raise RuntimeError("Dry-run recovery rows survived rollback")

        print(json.dumps({
            "mode": "committed" if args.apply else "dry_run_rolled_back",
            "previous_generation_id": OLD_GENERATION,
            "previous_checkpoint_preserved": OLD_OFFSET,
            "confirmed_error": reason,
            "first_batch_result": result,
            "possible_evidence_gap": True,
            "recovery_changes_persisted": args.apply,
        }, indent=2))


if __name__ == "__main__":
    main()