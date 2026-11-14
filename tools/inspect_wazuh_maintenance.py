"""Read-only Wazuh checkpoints, continuity history and maintenance verification."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from psycopg.rows import dict_row

from spine.database import connect_database


def checkpoint_rows(connection):
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """SELECT generation_id, file_path, remote_archive_path, device_id,
                      native_file_id, first_line_sha256, next_offset, processed_lines,
                      checkpoint_tail, updated_at, retired_at, retirement_reason
               FROM ingestion.file_generations
               WHERE input_format='wazuh' AND source_scope='lab/wazuh-server'
               ORDER BY created_at, generation_id"""
        )
        result = []
        for row in cursor.fetchall():
            row["checkpoint_tail_sha256"] = hashlib.sha256(bytes(row.pop("checkpoint_tail"))).hexdigest()
            result.append({k: str(v) if k == "generation_id" or isinstance(v, datetime) else v for k, v in row.items()})
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--check-exporter", action="store_true")
    args = parser.parse_args()
    if args.check_exporter:
        from spine.remote_wazuh import fetch_inventory
        inventory = fetch_inventory()
        active = inventory.get("active")
        if not active:
            raise RuntimeError("Exporter is reachable but the active Wazuh file is missing")
        print("PASS: maintenance exporter supports read-only inventory")
        print("Current dated source:", active.get("archive_path"))
    with connect_database() as connection:
        with connection.transaction():
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout='20s'")
            database, user = connection.execute("SELECT current_database(), current_user").fetchone()
            if database != "spine":
                raise RuntimeError("Expected the live spine database")
            rows = checkpoint_rows(connection)
            report = {"checked_at": datetime.now(timezone.utc).isoformat(),
                      "database": database, "database_user": user, "generations": rows}
            if args.snapshot:
                args.snapshot.parent.mkdir(parents=True, exist_ok=True)
                with args.snapshot.open("x", encoding="utf-8") as stream:
                    json.dump(report, stream, indent=2)
                print("PASS: read-only checkpoint baseline saved:", args.snapshot)
            for row in rows:
                if row["retired_at"] is None:
                    print(json.dumps(row, sort_keys=True))
            if args.baseline:
                baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
                if baseline.get("database") != "spine":
                    raise ValueError("Baseline is not for spine")
                by_id = {r["generation_id"]: r for r in rows}
                for old in baseline["generations"]:
                    current = by_id.get(old["generation_id"])
                    if current is None:
                        raise AssertionError("A prior generation is missing")
                    if any(current[k] != old[k] for k in ("device_id", "native_file_id", "first_line_sha256")):
                        raise AssertionError("A prior generation's identity was overwritten")
                    if current["retired_at"] is not None:
                        if any(current[k] != old[k] for k in ("next_offset", "processed_lines", "checkpoint_tail_sha256")):
                            raise AssertionError("A retired original checkpoint was overwritten")
                    elif current["next_offset"] < old["next_offset"] or current["processed_lines"] < old["processed_lines"]:
                        raise AssertionError("An original generation's checkpoint moved backwards")
                print("PASS: all prior generation identities and committed checkpoints preserved")
            events = connection.execute(
                """SELECT e.event_type, e.detected_at, e.generation_id,
                          e.checkpoint_offset, e.observed_size,
                          e.possible_evidence_gap, e.details
                   FROM ingestion.file_generation_events e
                   JOIN ingestion.file_generations g ON g.generation_id=e.generation_id
                   WHERE g.input_format='wazuh' AND g.source_scope='lab/wazuh-server'
                   ORDER BY e.detected_at DESC, e.event_id DESC LIMIT 5"""
            ).fetchall()
            for event in events:
                print("Recent continuity event:", json.dumps(event, default=str, ensure_ascii=True))
            latest = connection.execute(
                """SELECT record_id, stored_at FROM ingestion.records
                   WHERE collector='wazuh_alerts' AND source_scope='lab/wazuh-server'
                   ORDER BY stored_at DESC, record_id DESC LIMIT 1"""
            ).fetchone()
            print("Latest stored Wazuh record:", latest)
    print("Read-only inspection finished; no evidence, checkpoint, work or case changes made.")


if __name__ == "__main__":
    main()
