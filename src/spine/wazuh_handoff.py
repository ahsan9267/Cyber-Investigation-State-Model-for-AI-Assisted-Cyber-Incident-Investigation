"""Transactional handoff between adjacent Wazuh daily files.

Older generations remain registered for later polling/reconciliation.
Background polling and multi-day recovery are separate components.
"""

import argparse
from datetime import date, timedelta
import getpass
import hashlib
import json
from pathlib import PurePosixPath
import uuid

import psycopg
from psycopg.types.json import Json

from spine.live_wazuh import _state, _checkpoint, _signature
from spine.remote_wazuh import REMOTE_PATH, fetch_batch


def archive_date(path):
    root = PurePosixPath("/var/ossec/logs/alerts")
    parts = PurePosixPath(path).relative_to(root).parts

    months = (
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    )

    if len(parts) != 3:
        raise ValueError("Unexpected dated archive path")

    year, month, name = parts

    if (
        not name.startswith("ossec-alerts-")
        or not name.endswith(".json")
    ):
        raise ValueError("Expected a dated plain JSON archive")

    day = date(
        int(year),
        months.index(month) + 1,
        int(name[len("ossec-alerts-"):-len(".json")]),
    )

    if name != f"ossec-alerts-{day.day:02d}.json":
        raise ValueError("Unexpected archive filename")

    return day


def handoff_if_ready(
    connection,
    *,
    source_scope="lab/wazuh-server",
    fetcher=fetch_batch,
):
    if not connection.autocommit:
        raise ValueError("Handoff requires autocommit=True")

    previous = _state(connection, source_scope)

    if previous is None:
        return {"status": "no_current_generation"}

    active = fetcher(
        offset=0,
        expected=None,
        max_records=1,
    )

    old_identity = (
        previous["device_id"],
        previous["native_file_id"],
    )
    new_identity = (
        active["device_id"],
        active["native_file_id"],
    )

    if old_identity == new_identity:
        if (
            active.get("first_line_sha256")
            != previous["first_line_sha256"]
        ):
            raise RuntimeError(
                "Current file content changed; recovery is required"
            )

        return {"status": "not_rotated"}

    old_path = previous.get("remote_archive_path")
    new_path = active.get("archive_path")

    if not old_path or not new_path:
        raise RuntimeError(
            "A dated archive locator is missing; checkpoint preserved"
        )

    if archive_date(new_path) != archive_date(old_path) + timedelta(days=1):
        raise RuntimeError(
            "Non-adjacent daily files; recover intervening archives first"
        )

    if not active.get("first_line_sha256"):
        return {"status": "waiting_for_new_file_first_line"}

    old = fetcher(
        offset=previous["next_offset"],
        expected=_checkpoint(previous),
        max_records=1,
    )

    if (old["device_id"], old["native_file_id"]) != old_identity:
        raise RuntimeError("Old file identity mismatch")

    if old.get("archive_path") != old_path:
        raise RuntimeError("Old archive locator mismatch")

    if old["raw_bytes"] or old["status"] != "caught_up":
        return {"status": "old_file_still_pending"}

    if old["next_offset"] != previous["next_offset"]:
        raise RuntimeError("Unexpected old-file offset")

    material = json.dumps(
        ["live-wazuh", source_scope],
        ensure_ascii=False,
        separators=(",", ":"),
    )
    lock_key = int.from_bytes(
        hashlib.sha256(material.encode()).digest()[:8],
        "big",
        signed=True,
    )

    new_generation = uuid.uuid4()

    with connection.transaction():
        connection.execute(
            "SELECT pg_advisory_xact_lock(%s)",
            (lock_key,),
        )

        current = _state(connection, source_scope)

        if (
            _signature(current) != _signature(previous)
            or current.get("remote_archive_path") != old_path
        ):
            raise RuntimeError(
                "Checkpoint changed during handoff; retry"
            )

        # Preserve the old generation and checkpoint.
        # Move its lookup path to the dated archive.
        connection.execute(
            """
            UPDATE ingestion.file_generations
            SET file_path = %s,
                updated_at = clock_timestamp()
            WHERE generation_id = %s
            """,
            (old_path, previous["generation_id"]),
        )

        # Register the successor without consuming its first record.
        connection.execute(
            """
            INSERT INTO ingestion.file_generations (
                generation_id,
                input_format,
                source_scope,
                file_path,
                device_id,
                native_file_id,
                first_line_sha256,
                remote_archive_path
            )
            VALUES (%s, 'wazuh', %s, %s, %s, %s, %s, %s)
            """,
            (
                new_generation,
                source_scope,
                REMOTE_PATH,
                new_identity[0],
                new_identity[1],
                active["first_line_sha256"],
                new_path,
            ),
        )

        connection.execute(
            """
            INSERT INTO ingestion.file_generation_events (
                event_id,
                generation_id,
                event_type,
                checkpoint_offset,
                observed_size,
                possible_evidence_gap,
                details
            )
            VALUES (
                %s, %s, 'replacement_detected',
                %s, %s, %s, %s
            )
            """,
            (
                uuid.uuid4(),
                previous["generation_id"],
                previous["next_offset"],
                old["size_at_open"],
                True,
                Json({
                    "reason": "daily_file_handoff",
                    "successor_generation_id": str(new_generation),
                    "old_archive_path": old_path,
                    "new_archive_path": new_path,
                    "gap_assessment": (
                        "No missing bytes observed; "
                        "late writes require continued polling"
                    ),
                    "old_generation_retained": True,
                }),
            ),
        )

    return {
        "status": "handoff_registered",
        "previous_generation_id": str(previous["generation_id"]),
        "generation_id": str(new_generation),
        "next_offset": 0,
    }


def self_test(connection):
    scope = "test/handoff/" + str(uuid.uuid4())
    old_id = uuid.uuid4()

    old_path = "/var/ossec/logs/alerts/2026/Oct/ossec-alerts-03.json"
    new_path = "/var/ossec/logs/alerts/2026/Oct/ossec-alerts-04.json"

    digest = hashlib.sha256(b'{}\n').hexdigest()
    mode = {"value": "same"}

    def fake_fetch(**kwargs):
        if kwargs["expected"] is None:
            return {
                "device_id": "1",
                "native_file_id": (
                    "10" if mode["value"] == "same" else "11"
                ),
                "archive_path": (
                    new_path.replace("04.json", "06.json")
                    if mode["value"] == "gap"
                    else new_path
                ),
                "first_line_sha256": digest,
            }

        return {
            "device_id": "1",
            "native_file_id": "10",
            "archive_path": old_path,
            "raw_bytes": (
                b'{}\n' if mode["value"] == "pending" else b""
            ),
            "status": "caught_up",
            "next_offset": 3,
            "size_at_open": 3,
        }

    with connection.transaction(force_rollback=True):
        connection.execute(
            """
            INSERT INTO ingestion.file_generations (
                generation_id,
                input_format,
                source_scope,
                file_path,
                device_id,
                native_file_id,
                first_line_sha256,
                next_offset,
                processed_lines,
                checkpoint_tail,
                remote_archive_path
            )
            VALUES (
                %s, 'wazuh', %s, %s, '1', '10',
                %s, 3, 1, %s, %s
            )
            """,
            (
                old_id,
                scope,
                REMOTE_PATH,
                digest,
                b'{}\n',
                old_path,
            ),
        )

        result = handoff_if_ready(
            connection,
            source_scope=scope,
            fetcher=fake_fetch,
        )
        assert result["status"] == "not_rotated"

        mode["value"] = "pending"

        result = handoff_if_ready(
            connection,
            source_scope=scope,
            fetcher=fake_fetch,
        )
        assert result["status"] == "old_file_still_pending"

        print("PASS: unchanged and unread files do not hand off")

        mode["value"] = "gap"

        try:
            handoff_if_ready(
                connection,
                source_scope=scope,
                fetcher=fake_fetch,
            )
        except RuntimeError as error:
            assert "Non-adjacent" in str(error)
        else:
            raise AssertionError("Multi-day gap was accepted")

        print("PASS: multi-day gap requires archive recovery")

        mode["value"] = "ready"

        class InjectedFailure(RuntimeError):
            pass

        class FailingConnection:
            def __getattr__(self, name):
                return getattr(connection, name)

            def execute(self, query, params=None):
                result = connection.execute(query, params)

                if "INSERT INTO ingestion.file_generation_events" in query:
                    raise InjectedFailure("Failure after handoff writes")

                return result

        try:
            handoff_if_ready(
                FailingConnection(),
                source_scope=scope,
                fetcher=fake_fetch,
            )
        except InjectedFailure:
            pass
        else:
            raise AssertionError("Fault injection did not run")

        assert _state(connection, scope)["generation_id"] == old_id

        assert connection.execute(
            """
            SELECT count(*)
            FROM ingestion.file_generations
            WHERE source_scope = %s
            """,
            (scope,),
        ).fetchone()[0] == 1

        assert connection.execute(
            """
            SELECT count(*)
            FROM ingestion.file_generation_events
            WHERE generation_id = %s
            """,
            (old_id,),
        ).fetchone()[0] == 0

        print(
            "PASS: failed handoff rolled back "
            "path change, successor, and history"
        )

        result = handoff_if_ready(
            connection,
            source_scope=scope,
            fetcher=fake_fetch,
        )
        assert result["status"] == "handoff_registered"

        old = connection.execute(
            """
            SELECT file_path, next_offset, retired_at
            FROM ingestion.file_generations
            WHERE generation_id = %s
            """,
            (old_id,),
        ).fetchone()

        assert old == (old_path, 3, None)

        current = _state(connection, scope)

        assert str(current["generation_id"]) == result["generation_id"]
        assert current["next_offset"] == 0

        assert connection.execute(
            """
            SELECT count(*)
            FROM ingestion.file_generation_events
            WHERE generation_id = %s
            """,
            (old_id,),
        ).fetchone()[0] == 1

        print(
            "PASS: successor registered; "
            "old checkpoint and handoff history preserved"
        )

    assert connection.execute(
        """
        SELECT count(*)
        FROM ingestion.file_generations
        WHERE source_scope = %s
        """,
        (scope,),
    ).fetchone()[0] == 0

    print("PASS: test generations and history rolled back")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    password = getpass.getpass("spine_app password: ")

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
            self_test(connection)
        else:
            result = handoff_if_ready(connection)
            print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()