"""Verify atomic Sysmon ingestion using temporary test data."""

from copy import deepcopy
import uuid

from spine.database import connect_database
import spine.live_sysmon as live
from spine.sysmon_transport import CHANNEL, fetch_sysmon_batch


class InjectedFailure(Exception):
    pass


class RollBackTest(Exception):
    pass


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    batch = fetch_sysmon_batch(max_records=3)
    require(len(batch["records"]) == 3, "Need three retained test events")

    scope = "test/live-sysmon/" + str(uuid.uuid4())
    original_store = live.store_record

    def fetcher(*, checkpoint, max_records):
        if checkpoint is None:
            return deepcopy(batch)

        require(
            checkpoint == batch["next_checkpoint"],
            "Unexpected resume checkpoint",
        )
        return {
            "protocol_version": 1,
            "channel": CHANNEL,
            "status": "caught_up",
            "record_count": 0,
            "xml_bytes": 0,
            "records": [],
            "next_checkpoint": deepcopy(checkpoint),
            "database_written": False,
        }

    with connect_database() as connection:
        try:
            with connection.transaction():
                calls = 0

                def fail_on_second(connection, record):
                    nonlocal calls
                    disposition = original_store(connection, record)
                    calls += 1
                    if calls == 2:
                        raise InjectedFailure("Intentional storage failure")
                    return disposition

                live.store_record = fail_on_second
                failed = False

                try:
                    live.ingest_once(
                        connection,
                        source_scope=scope,
                        max_records=3,
                        fetcher=fetcher,
                    )
                except InjectedFailure:
                    failed = True
                finally:
                    live.store_record = original_store

                require(failed, "Injected failure did not occur")
                require(
                    live.read_state(connection, scope) is None,
                    "Generation survived failed batch",
                )
                require(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM ingestion.records
                        WHERE source_scope = %s
                        """,
                        (scope,),
                    ).fetchone()[0] == 0,
                    "Evidence survived failed batch",
                )
                print("PASS: failed batch rolled back evidence and generation")

                result = live.ingest_once(
                    connection,
                    source_scope=scope,
                    max_records=3,
                    fetcher=fetcher,
                )
                require(
                    result["outcomes_this_run"]["inserted"] == 3,
                    "Expected three inserted records",
                )

                state = live.read_state(connection, scope)
                require(
                    live.checkpoint_from_state(state)
                    == batch["next_checkpoint"],
                    "Saved checkpoint differs from reader checkpoint",
                )

                outcome_count = connection.execute(
                    """
                    SELECT COUNT(*) FROM ingestion.eventlog_outcomes
                    WHERE generation_id = %s
                    """,
                    (state["generation_id"],),
                ).fetchone()[0]
                require(outcome_count == 3, "Expected three outcomes")
                print("PASS: evidence, outcomes, and bookmark stored together")

                idle = live.ingest_once(
                    connection,
                    source_scope=scope,
                    max_records=3,
                    fetcher=fetcher,
                )
                require(idle["processed_this_run"] == 0, "Idle read did work")
                require(
                    live.state_signature(live.read_state(connection, scope))
                    == live.state_signature(state),
                    "Idle read changed checkpoint",
                )
                print("PASS: unchanged checkpoint performs no further work")

                raise RollBackTest()

        except RollBackTest:
            pass
        finally:
            live.store_record = original_store

        require(
            live.read_state(connection, scope) is None,
            "Test generation was not rolled back",
        )
        require(
            connection.execute(
                """
                SELECT COUNT(*) FROM ingestion.records
                WHERE source_scope = %s
                """,
                (scope,),
            ).fetchone()[0] == 0,
            "Test records were not rolled back",
        )
        print("PASS: all test data rolled back")


if __name__ == "__main__":
    main()