"""Test Sysmon recovery using temporary database data."""

from copy import deepcopy
import hashlib
import uuid

from spine.database import connect_database
from spine import live_sysmon
from spine.sysmon_errors import (
    SysmonReadError,
    SysmonCheckpointMismatch,
)
from spine.sysmon_recovery import ingest_with_recovery
from spine.sysmon_transport import fetch_sysmon_batch


class InjectedFailure(Exception):
    pass


class RollBackTest(Exception):
    pass


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    original_batch = fetch_sysmon_batch(max_records=3)
    require(len(original_batch["records"]) == 3, "Need three events")

    # Simulate different evidence reusing record IDs in a new generation.
    replacement = deepcopy(original_batch)
    for item in replacement["records"]:
        item["raw_xml"] += "\n"
        item["raw_sha256"] = hashlib.sha256(
            item["raw_xml"].encode("utf-8")
        ).hexdigest()

    replacement["xml_bytes"] = sum(
        len(item["raw_xml"].encode("utf-8"))
        for item in replacement["records"]
    )
    replacement["next_checkpoint"]["raw_sha256"] = (
        replacement["records"][-1]["raw_sha256"]
    )

    scope = "test/sysmon-recovery/" + str(uuid.uuid4())
    original_store = live_sysmon.store_record

    def initial_fetcher(**kwargs):
        return deepcopy(original_batch)

    def denied_fetcher(**kwargs):
        raise SysmonReadError("Simulated access denied")

    def reset_fetcher(*, checkpoint, max_records):
        if checkpoint is not None:
            raise SysmonCheckpointMismatch("Simulated changed checkpoint")
        return deepcopy(replacement)

    with connect_database() as connection:
        try:
            with connection.transaction():
                live_sysmon.ingest_once(
                    connection,
                    source_scope=scope,
                    max_records=3,
                    fetcher=initial_fetcher,
                )
                before = live_sysmon.read_state(connection, scope)

                try:
                    ingest_with_recovery(
                        connection,
                        source_scope=scope,
                        max_records=3,
                        fetcher=denied_fetcher,
                    )
                except SysmonReadError:
                    pass
                else:
                    raise AssertionError("Expected access failure")

                require(
                    live_sysmon.state_signature(
                        live_sysmon.read_state(connection, scope)
                    ) == live_sysmon.state_signature(before),
                    "Access failure changed the checkpoint",
                )
                print("PASS: access failure preserves the generation")

                calls = 0

                def fail_on_second(connection, record):
                    nonlocal calls
                    disposition = original_store(connection, record)
                    calls += 1
                    if calls == 2:
                        raise InjectedFailure()
                    return disposition

                live_sysmon.store_record = fail_on_second
                try:
                    ingest_with_recovery(
                        connection,
                        source_scope=scope,
                        max_records=3,
                        fetcher=reset_fetcher,
                    )
                except InjectedFailure:
                    pass
                else:
                    raise AssertionError("Injected failure did not occur")
                finally:
                    live_sysmon.store_record = original_store

                require(
                    live_sysmon.state_signature(
                        live_sysmon.read_state(connection, scope)
                    ) == live_sysmon.state_signature(before),
                    "Failed recovery changed the original checkpoint",
                )

                generation_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM ingestion.eventlog_generations
                    WHERE source_scope = %s
                    """,
                    (scope,),
                ).fetchone()[0]
                require(generation_count == 1, "Successor survived rollback")

                history_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM ingestion.eventlog_generation_events
                    WHERE generation_id = %s
                    """,
                    (before["generation_id"],),
                ).fetchone()[0]
                require(history_count == 0, "History survived rollback")
                print("PASS: failed recovery rolls back retirement and successor")

                result = ingest_with_recovery(
                    connection,
                    source_scope=scope,
                    max_records=3,
                    fetcher=reset_fetcher,
                )

                require(
                    result["generation_id"] != str(before["generation_id"]),
                    "Recovery reused the old generation",
                )

                old = connection.execute(
                    """
                    SELECT last_record_id, processed_records,
                           retired_at IS NOT NULL
                    FROM ingestion.eventlog_generations
                    WHERE generation_id = %s
                    """,
                    (before["generation_id"],),
                ).fetchone()

                require(
                    old == (
                        before["last_record_id"],
                        before["processed_records"],
                        True,
                    ),
                    "Original checkpoint was not preserved",
                )

                history_count = connection.execute(
                    """
                    SELECT COUNT(*)
                    FROM ingestion.eventlog_generation_events
                    WHERE generation_id = %s AND possible_evidence_gap
                    """,
                    (before["generation_id"],),
                ).fetchone()[0]
                require(history_count == 2, "Missing recovery history")

                record_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM ingestion.records
                    WHERE source_scope = %s
                    """,
                    (scope,),
                ).fetchone()[0]
                require(record_count == 6, "Old or replacement evidence missing")

                print("PASS: new generation retains old evidence and gap history")
                raise RollBackTest()

        except RollBackTest:
            pass
        finally:
            live_sysmon.store_record = original_store

        require(
            live_sysmon.read_state(connection, scope) is None,
            "Test generation survived outer rollback",
        )
        require(
            connection.execute(
                "SELECT COUNT(*) FROM ingestion.records WHERE source_scope = %s",
                (scope,),
            ).fetchone()[0] == 0,
            "Test evidence survived outer rollback",
        )
        print("PASS: all recovery-test data rolled back")


if __name__ == "__main__":
    main()