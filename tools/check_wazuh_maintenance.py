"""Real database recovery checks with local simulated Wazuh files.

All fixture writes roll back. Development database only; never accepts spine.
"""

import argparse
import base64
from copy import deepcopy
import getpass
import json
import os
from pathlib import Path
import tempfile
import uuid

import psycopg

from spine.live_wazuh import CheckpointChanged, _checkpoint, _signature, _state
from spine.remote_wazuh import REMOTE_PATH, REMOTE_PROGRAM, RemoteReadError
from spine.wazuh_recovery import ingest_with_recovery, recover_generation, synchronize_sources


ROOT = "/var/ossec/logs/alerts"


def expect(label, condition):
    if not condition:
        raise AssertionError(label)
    print("PASS:", label, flush=True)


class SimulatedWazuh:
    def __init__(self, folder):
        self.root = Path(folder)
        self.active = self.root / "alerts.json"
        self.dated = self.root / "2026" / "Oct"
        self.dated.mkdir(parents=True)
        self.archive = self.dated / "ossec-alerts-11.json"
        self.ns = {"__name__": "fixture_exporter"}
        exec(compile(REMOTE_PROGRAM, "remote_reader", "exec"), self.ns)

    def map_paths(self, value):
        if isinstance(value, dict):
            return {k: self.map_paths(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.map_paths(v) for v in value]
        if isinstance(value, str) and value.startswith(str(self.root) + os.sep):
            return ROOT + "/" + Path(value).relative_to(self.root).as_posix()
        return value

    def initialize(self, raw):
        self.active.write_bytes(raw)
        os.link(self.active, self.archive)

    def rotate(self, raw, day=12):
        self.active.unlink()
        self.active.write_bytes(raw)
        os.link(self.active, self.dated / f"ossec-alerts-{day:02d}.json")

    def fetch(self, **request):
        try:
            batch = self.ns["read_source_batch"](
                {"offset": request["offset"], "expected": request["expected"],
                 "max_records": request["max_records"]}, root=str(self.root),
            )
        except (OSError, RuntimeError, ValueError) as error:
            raise RemoteReadError({"error": type(error).__name__, "message": str(error)}) from error
        batch = self.map_paths(batch)
        batch["raw_bytes"] = base64.b64decode(batch.pop("raw_b64"))
        return batch

    def inventory(self):
        return self.map_paths(self.ns["inspect_sources"](root=str(self.root)))

    def inspect(self, *, expected, archive_path):
        local_path = str(self.root / Path(archive_path).relative_to(ROOT)) if archive_path else None
        return self.map_paths(self.ns["inspect_checkpoint"](
            {"expected": expected, "archive_path": local_path}, root=str(self.root),
        ))


class FailAudit:
    def __init__(self, connection):
        self.connection = connection
    def __getattr__(self, name):
        return getattr(self.connection, name)
    def execute(self, query, params=None):
        if "INSERT INTO ingestion.file_generation_events" in query:
            raise RuntimeError("injected audit write failure")
        return self.connection.execute(query, params)


def alert(identifier, message="original"):
    return (json.dumps({
        "id": identifier, "timestamp": "2026-10-11T09:00:00+0000",
        "rule": {"id": "500", "level": 3, "groups": ["ossec"]},
        "agent": {"id": "001", "name": "maintenance-fixture"},
        "full_log": message,
    }) + "\n").encode()


def rows(connection, table, scope):
    if table in ("records", "record_conflicts"):
        if table == "records":
            return connection.execute("SELECT record_id, raw_sha256, document::text FROM ingestion.records WHERE source_scope=%s ORDER BY record_id", (scope,)).fetchall()
        return connection.execute("SELECT c.record_id, c.incoming_raw_sha256, c.incoming_document::text FROM ingestion.record_conflicts c JOIN ingestion.records r ON r.record_id=c.record_id WHERE r.source_scope=%s ORDER BY c.record_id", (scope,)).fetchall()
    if table == "file_generations":
        return connection.execute("SELECT generation_id, file_path, next_offset, processed_lines, checkpoint_tail, retired_at, retirement_reason FROM ingestion.file_generations WHERE source_scope=%s ORDER BY generation_id", (scope,)).fetchall()
    if table == "file_outcomes":
        return connection.execute("SELECT o.* FROM ingestion.file_outcomes o JOIN ingestion.file_generations g ON g.generation_id=o.generation_id WHERE g.source_scope=%s ORDER BY o.generation_id,o.byte_offset", (scope,)).fetchall()
    return connection.execute("SELECT e.* FROM ingestion.file_generation_events e JOIN ingestion.file_generations g ON g.generation_id=e.generation_id WHERE g.source_scope=%s ORDER BY e.event_id", (scope,)).fetchall()


TABLES = ("records", "record_conflicts", "file_generations", "file_outcomes", "file_generation_events")


def run_checks(connection):
    scopes = []
    routing_revision = connection.execute(
        "SELECT revision FROM investigation.routing_state WHERE singleton_id=1"
    ).fetchone()[0]
    def fixture():
        folder = tempfile.TemporaryDirectory()
        source = SimulatedWazuh(folder.name)
        scope = "maintenance-check/" + str(uuid.uuid4())
        scopes.append(scope)
        return folder, source, scope
    def sync(source, scope, conn=connection):
        return synchronize_sources(conn, source_scope=scope, inventory_fetcher=source.inventory)
    def ingest(source, scope, generation=None, conn=connection):
        return ingest_with_recovery(conn, source_scope=scope, generation_id=generation,
                                    max_records=100, fetcher=source.fetch, inspector=source.inspect)

    with connection.transaction(force_rollback=True):
        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("old-one") + alert("old-two"))
            sync(source, scope)
            ingest(source, scope)
            old = deepcopy(_state(connection, scope))
            originals = rows(connection, "records", scope)
            outcomes = rows(connection, "file_outcomes", scope)
            source.rotate(alert("today"))
            source.archive.write_bytes(alert("old-one"))
            result = sync(source, scope)
            expect("rotation registers today's source before old archive recovery", result["registered_generations"] == 1 and result["moved_aliases"] == 1)
            current = _state(connection, scope)
            expect("new active generation has a zero checkpoint", current["next_offset"] == 0 and current["native_file_id"] != old["native_file_id"])
            expect("today's alert progresses while old archive is damaged", ingest(source, scope)["outcomes_this_run"]["inserted"] == 1)
            old_id = old["generation_id"]
            before = {t: rows(connection, t, scope) for t in TABLES}
            try:
                ingest(source, scope, old_id, FailAudit(connection))
            except RuntimeError as error:
                expect("recovery audit failure injected", str(error) == "injected audit write failure")
            else:
                raise AssertionError("audit failure was not reached")
            expect("failed recovery restores every evidence, outcome, checkpoint and audit row", before == {t: rows(connection, t, scope) for t in TABLES})
            repaired = ingest(source, scope, old_id)
            expect("damaged archive replays in a new generation", repaired["generation_id"] != str(old_id) and repaired["outcomes_this_run"]["replay"] == 1)
            kept = connection.execute("SELECT next_offset, processed_lines, checkpoint_tail, retired_at FROM ingestion.file_generations WHERE generation_id=%s", (old_id,)).fetchone()
            expect("original committed offset, count and tail are preserved", kept[:3] == (old["next_offset"], old["processed_lines"], old["checkpoint_tail"]) and kept[3] is not None)
            expect("historical evidence remains byte-for-byte unchanged", all(row in rows(connection, "records", scope) for row in originals))
            expect("historical outcomes remain unchanged", all(row in rows(connection, "file_outcomes", scope) for row in outcomes))
            expect("continuity audit flags uncertainty", repaired["recovery"]["possible_evidence_gap"] and repaired["recovery"]["reason"] == "truncation_detected")
            after = {t: rows(connection, t, scope) for t in TABLES}
            sync(source, scope)
            ingest(source, scope, repaired["generation_id"])
            expect("repeat synchronization and idle poll add no rows", after == {t: rows(connection, t, scope) for t in TABLES})

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("rewrite"))
            sync(source, scope)
            ingest(source, scope)
            original = rows(connection, "records", scope)
            source.archive.write_bytes(alert("rewrite", "MODIFIED"))
            repaired = ingest(source, scope)
            expect("changed payload is retained as a conflict", repaired["outcomes_this_run"]["conflict"] == 1 and len(rows(connection, "record_conflicts", scope)) == 1)
            expect("rewrite recovery preserves original evidence", rows(connection, "records", scope) == original)

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("tail-first") + alert("tail-last"))
            sync(source, scope)
            ingest(source, scope)
            source.archive.write_bytes(alert("tail-first") + alert("tail-last", "MODIFIED"))
            repaired = ingest(source, scope)
            expect("checkpoint-tail rewrite replays and retains conflict", repaired["outcomes_this_run"]["replay"] == 1 and repaired["outcomes_this_run"]["conflict"] == 1)

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("before-outage"))
            sync(source, scope)
            ingest(source, scope)
            source.rotate(alert("middle-day"), day=12)
            source.rotate(alert("after-outage"), day=13)
            result = sync(source, scope)
            expect("multi-day outage registers available intermediate archives", result["registered_generations"] == 2)
            for generation, in connection.execute("SELECT generation_id FROM ingestion.file_generations WHERE source_scope=%s AND retired_at IS NULL", (scope,)).fetchall():
                ingest(source, scope, generation)
            expect("all available days are ingested once", len(rows(connection, "records", scope)) == 3)
            gaps = connection.execute("SELECT e.possible_evidence_gap FROM ingestion.file_generation_events e JOIN ingestion.file_generations g ON g.generation_id=e.generation_id WHERE g.source_scope=%s", (scope,)).fetchall()
            expect("ordinary complete rotation has no declared evidence gap", gaps == [(False,)])
            middle = connection.execute("SELECT generation_id, next_offset FROM ingestion.file_generations WHERE source_scope=%s AND file_path=%s", (scope, ROOT + "/2026/Oct/ossec-alerts-12.json")).fetchone()
            source.active.unlink()
            os.link(source.dated / "ossec-alerts-12.json", source.active)
            sync(source, scope)
            known = _state(connection, scope)
            expect("a known retained file becoming active keeps its generation and checkpoint", known["generation_id"] == middle[0] and known["next_offset"] == middle[1])
            expect("reactivated file alias does not duplicate already stored records", ingest(source, scope)["processed_this_run"] == 0 and len(rows(connection, "records", scope)) == 3)

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("unavailable-old"))
            sync(source, scope)
            ingest(source, scope)
            old = deepcopy(_state(connection, scope))
            source.rotate(alert("available-current"))
            source.archive.rename(str(source.archive) + ".gz")
            sync(source, scope)
            result = ingest(source, scope, old["generation_id"])
            expect("unavailable plain source is retained in an explicit audit", result["status"] == "generation_unavailable" and result["recovery"]["compressed_archive_available"])
            expect("current source continues after old plain source becomes unavailable", ingest(source, scope)["outcomes_this_run"]["inserted"] == 1)
            expect("unavailable recovery does not pretend to restore archive bytes", result["recovery"]["successor_generation_id"] is None)

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("access-error"))
            sync(source, scope)
            ingest(source, scope)
            previous = {t: rows(connection, t, scope) for t in TABLES}
            for error in (RuntimeError("SSH connection refused"), RemoteReadError({"error": "PermissionError", "message": "denied"})):
                def unavailable(**request):
                    raise error
                try:
                    ingest_with_recovery(connection, source_scope=scope, fetcher=unavailable,
                                         inspector=lambda **kw: (_ for _ in ()).throw(AssertionError("unexpected inspection")))
                except RuntimeError:
                    pass
                else:
                    raise AssertionError("access/transport error was accepted")
            expect("transport and permission failures never change checkpoints", previous == {t: rows(connection, t, scope) for t in TABLES})
            def changed_inventory():
                value = source.inventory()
                changed_inventory.calls += 1
                if changed_inventory.calls == 2:
                    value["active"]["first_line_sha256"] = "0" * 64
                return value
            changed_inventory.calls = 0
            try:
                synchronize_sources(connection, source_scope=scope, inventory_fetcher=changed_inventory)
            except CheckpointChanged:
                pass
            else:
                raise AssertionError("changed inventory was accepted")
            expect("rotation during inventory leaves all rows unchanged", previous == {t: rows(connection, t, scope) for t in TABLES})

        folder, source, scope = fixture()
        with folder:
            source.initialize(b"".join(alert("append-" + str(n)) for n in range(5)))
            sync(source, scope)
            ingest(source, scope)
            source.archive.write_bytes(alert("append-0"))
            def growing_inspection(**request):
                growing_inspection.calls += 1
                if growing_inspection.calls == 2:
                    with source.archive.open("ab") as stream:
                        stream.write(alert("append-new"))
                return source.inspect(**request)
            growing_inspection.calls = 0
            repaired = recover_generation(connection, source_scope=scope, fetcher=source.fetch, inspector=growing_inspection)
            expect("append-only growth does not invalidate a verified recovery prefix", repaired["outcomes_this_run"]["replay"] == 1)
            resumed = ingest(source, scope, repaired["generation_id"])
            expect("append after recovery is ingested without losing bytes", resumed["outcomes_this_run"]["inserted"] == 1)

        folder, source, scope = fixture()
        with folder:
            raw = alert("healed-first") + alert("healed-last")
            source.initialize(raw)
            sync(source, scope)
            ingest(source, scope)
            source.archive.write_bytes(alert("healed-first"))
            previous = {t: rows(connection, t, scope) for t in TABLES}
            def healed_inspection(**request):
                healed_inspection.calls += 1
                if healed_inspection.calls == 2:
                    source.archive.write_bytes(raw)
                return source.inspect(**request)
            healed_inspection.calls = 0
            try:
                recover_generation(connection, source_scope=scope, fetcher=source.fetch, inspector=healed_inspection)
            except CheckpointChanged:
                pass
            else:
                raise AssertionError("healed checkpoint was retired")
            expect("a healed checkpoint cannot be retired", previous == {t: rows(connection, t, scope) for t in TABLES})

        folder, source, scope = fixture()
        with folder:
            source.initialize(alert("stale-first") + alert("stale-last"))
            sync(source, scope)
            ingest(source, scope)
            source.archive.write_bytes(alert("stale-first"))
            original = deepcopy(_state(connection, scope))
            def inspect_and_advance(**request):
                inspected = source.inspect(**request)
                inspect_and_advance.calls += 1
                if inspect_and_advance.calls == 1:
                    connection.execute("UPDATE ingestion.file_generations SET processed_lines=processed_lines+1 WHERE generation_id=%s", (original["generation_id"],))
                return inspected
            inspect_and_advance.calls = 0
            try:
                recover_generation(connection, source_scope=scope, fetcher=source.fetch, inspector=inspect_and_advance)
            except CheckpointChanged:
                pass
            else:
                raise AssertionError("stale checkpoint was retired")
            expect("stale recovery preparation cannot retire an advanced checkpoint", _state(connection, scope)["retired_at"] is None and _state(connection, scope)["processed_lines"] == original["processed_lines"] + 1)

    for scope in scopes:
        expect("temporary maintenance fixtures rolled back", all(not rows(connection, t, scope) for t in TABLES))
    expect("maintenance ingestion preserves the global routing revision", routing_revision == connection.execute(
        "SELECT revision FROM investigation.routing_state WHERE singleton_id=1"
    ).fetchone()[0])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dbname", default="spine_step4_dev")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5432)
    parser.add_argument("--user", default="spine_app")
    args = parser.parse_args()
    if args.dbname not in ("spine_step4_dev", "spine_maintenance_test"):
        parser.error("Only development databases are accepted; never use spine")
    password = getpass.getpass(args.user + " password: ")
    with psycopg.connect(host=args.host, port=args.port, dbname=args.dbname,
                         user=args.user, password=password, autocommit=True) as connection:
        connection.isolation_level = psycopg.IsolationLevel.READ_COMMITTED
        run_checks(connection)
    print("SUCCESS: Wazuh maintenance database checks passed")
    print("All fixtures rolled back; no live database, SSH source or runtime files changed.")


if __name__ == "__main__":
    main()
