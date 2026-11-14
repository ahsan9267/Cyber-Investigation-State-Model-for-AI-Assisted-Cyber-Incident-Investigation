"""Exercise Wazuh batch transactions; all test data is rolled back."""

import base64
import getpass
import json
from pathlib import Path
import tempfile
import uuid

import psycopg

from spine.live_wazuh import ingest_once
from spine.remote_wazuh import REMOTE_PATH, REMOTE_PROGRAM


class InjectedFailure(RuntimeError):
    pass


class FailAfterCheckpoint:
    def __init__(self, connection):
        self.connection = connection

    def __getattr__(self, name):
        return getattr(self.connection, name)

    def execute(self, query, params=None):
        result = self.connection.execute(query, params)
        if "UPDATE ingestion.file_generations" in query:
            raise InjectedFailure("Simulated failure after checkpoint update")
        return result


def main():
    password = getpass.getpass("spine_app password: ")
    scope = "test/live-wazuh/" + str(uuid.uuid4())
    namespace = {"__name__": "test_remote"}
    exec(compile(REMOTE_PROGRAM, "remote_reader", "exec"), namespace)
    read = namespace["read_batch"]
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "alerts.json"
        def alert(identifier):
            return (json.dumps({
                "id": identifier, "timestamp": "2026-10-03T09:00:00+0000",
                "rule": {"id": "500", "level": 3, "groups": ["ossec"]},
                "agent": {"id": "001", "name": "test-host"},
            }) + "\n").encode("utf-8")
        first = alert("test-one")
        second = alert("test-two")
        bad = b'\xff\x00\n'
        path.write_bytes(first + bad + second[:-1])
        def fetcher(**kwargs):
            result = read(str(path), {
                "offset": kwargs["offset"], "expected": kwargs["expected"],
                "max_records": kwargs["max_records"],
            })
            result["file_path"] = REMOTE_PATH
            result["raw_bytes"] = base64.b64decode(result.pop("raw_b64"))
            return result
        with psycopg.connect(host="127.0.0.1", port=5432, dbname="spine",
                             user="spine_app", password=password,
                             connect_timeout=5, autocommit=True) as connection:
            connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
            with connection.transaction(force_rollback=True):
                try:
                    ingest_once(FailAfterCheckpoint(connection),
                                source_scope=scope, fetcher=fetcher)
                except InjectedFailure:
                    pass
                else:
                    raise AssertionError("Fault injection did not run")
                assert connection.execute(
                    "SELECT count(*) FROM ingestion.file_generations WHERE source_scope=%s",
                    (scope,),
                ).fetchone()[0] == 0
                assert connection.execute(
                    "SELECT count(*) FROM ingestion.records WHERE source_scope=%s", (scope,),
                ).fetchone()[0] == 0
                print("PASS: failed batch rolled back records and generation checkpoint")

                result = ingest_once(connection, source_scope=scope, fetcher=fetcher)
                assert result["processed_this_run"] == 2
                assert result["outcomes_this_run"]["inserted"] == 1
                assert result["outcomes_this_run"]["quarantined"] == 1
                assert result["status"] == "waiting_for_complete_line"
                generation = result["generation_id"]
                saved = connection.execute(
                    "SELECT raw_bytes FROM ingestion.file_outcomes WHERE generation_id=%s "
                    "AND disposition='quarantined'", (generation,),
                ).fetchone()[0]
                assert bytes(saved) == bad
                print("PASS: malformed bytes retained; incomplete final line remains pending")

                with path.open("ab") as stream:
                    stream.write(b'\n')
                try:
                    ingest_once(FailAfterCheckpoint(connection),
                                source_scope=scope, fetcher=fetcher)
                except InjectedFailure:
                    pass
                else:
                    raise AssertionError("Resume fault injection did not run")
                assert connection.execute(
                    "SELECT next_offset FROM ingestion.file_generations WHERE generation_id=%s",
                    (generation,),
                ).fetchone()[0] == result["next_offset"]
                assert connection.execute(
                    "SELECT count(*) FROM ingestion.file_outcomes WHERE generation_id=%s",
                    (generation,),
                ).fetchone()[0] == 2
                assert connection.execute(
                    "SELECT count(*) FROM ingestion.records WHERE source_scope=%s", (scope,),
                ).fetchone()[0] == 1
                print("PASS: failed resumed batch preserved existing records, outcomes, and checkpoint")
                resumed = ingest_once(connection, source_scope=scope, fetcher=fetcher)
                assert resumed["generation_id"] == generation
                assert resumed["outcomes_this_run"]["inserted"] == 1
                assert resumed["processed_this_run"] == 1
                idle = ingest_once(connection, source_scope=scope, fetcher=fetcher)
                assert idle["processed_this_run"] == 0
                print("PASS: append resumed in the same generation; unchanged file did no work")

                with path.open("ab") as stream:
                    stream.write(first)
                replay = ingest_once(connection, source_scope=scope, fetcher=fetcher)
                assert replay["outcomes_this_run"]["replay"] == 1
                assert connection.execute(
                    "SELECT count(*) FROM ingestion.file_outcomes WHERE generation_id=%s",
                    (generation,),
                ).fetchone()[0] == 4
                print("PASS: replayed Wazuh ID retained as an outcome without duplicating the record")

                before = connection.execute(
                    "SELECT next_offset FROM ingestion.file_generations WHERE generation_id=%s",
                    (generation,),
                ).fetchone()[0]
                path.write_bytes(b'{}\n')
                try:
                    ingest_once(connection, source_scope=scope, fetcher=fetcher)
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("Truncation was not rejected")
                assert connection.execute(
                    "SELECT next_offset FROM ingestion.file_generations WHERE generation_id=%s",
                    (generation,),
                ).fetchone()[0] == before
                print("PASS: truncation rejected without advancing checkpoint")
            for table in ("records", "file_generations"):
                assert connection.execute(
                    f"SELECT count(*) FROM ingestion.{table} WHERE source_scope=%s", (scope,),
                ).fetchone()[0] == 0
            print("PASS: all test data rolled back")


if __name__ == "__main__":
    main()
