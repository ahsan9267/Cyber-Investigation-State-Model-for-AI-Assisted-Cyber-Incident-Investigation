"""Run Wazuh and Suricata collection independently."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from pathlib import Path
import re
import threading
from contextlib import contextmanager
import msvcrt
import time

from spine.sysmon_recovery import ingest_with_recovery as ingest_sysmon_once

import psycopg
from psycopg.rows import dict_row

from spine.database import connect_database
from spine.file_recovery import ingest_with_recovery
from spine.eve_retention_status import historical_missing_warning
from spine.wazuh_recovery import (
    ingest_with_recovery as ingest_wazuh_once,
    synchronize_sources,
)
from spine.remote_wazuh import REMOTE_PATH


PROJECT = Path(__file__).resolve().parents[1]
STATUS_PATH = PROJECT / "data/checkpoints/collector_status.json"
LOG_PATH = PROJECT / "data/logs/collector.log"

EVE_FOLDER = Path(r"C:\Program Files\Suricata\log")
EVE_PATTERN = re.compile(r"eve-\d{4}-\d{2}-\d{2}\.json")

LOGGER = logging.getLogger("spine.collector")


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def emit(source, operation, **details):
    message = {
        "time": utc_now(),
        "source": source,
        "operation": operation,
        **details,
    }
    LOGGER.info(json.dumps(message, default=str))

class Status:
    def __init__(self):
        self.lock = threading.Lock()
        self.publication_failed = False
        self.document = {
            "pid": os.getpid(),
            "started_at": utc_now(),
            "sources": {},
        }
        STATUS_PATH.parent.mkdir(parents=True, exist_ok=True)

    def update(self, source, **fields):
        with self.lock:
            state = self.document["sources"].setdefault(source, {})
            state.update(fields)
            state["updated_at"] = utc_now()

            temporary = STATUS_PATH.with_suffix(
                f".{os.getpid()}.tmp"
            )
            encoded = json.dumps(
                self.document, indent=2, default=str
            )
            delays = (0.05, 0.1, 0.2, 0.4)
            failure = None

            for attempt in range(len(delays) + 1):
                try:
                    temporary.write_text(encoded, encoding="utf-8")
                    os.replace(temporary, STATUS_PATH)
                except OSError as error:
                    failure = error
                    if attempt < len(delays):
                        time.sleep(delays[attempt])
                else:
                    if self.publication_failed:
                        emit(
                            "runner",
                            "status_publication_recovered",
                        )
                    self.publication_failed = False
                    return

            if not self.publication_failed:
                emit(
                    "runner",
                    "status_publication_failed",
                    error_type=type(failure).__name__,
                    error=str(failure),
                    previous_snapshot_preserved=True,
                    collection_continues=True,
                )
            self.publication_failed = True

def wazuh_targets(connection):
    with connection.cursor(row_factory=dict_row) as cursor:
        cursor.execute(
            """
            SELECT generation_id, file_path
            FROM ingestion.file_generations
            WHERE input_format = 'wazuh'
              AND source_scope = 'lab/wazuh-server'
              AND retired_at IS NULL
            ORDER BY (file_path = %s) DESC,
                     created_at,
                     generation_id
            """,
            (REMOTE_PATH,),
        )
        return cursor.fetchall() or [
            {
                "generation_id": None,
                "file_path": REMOTE_PATH,
            }
        ]


def suricata_targets(connection):
    paths = set()
    discovery_error = None

    try:
        for path in EVE_FOLDER.iterdir():
            if path.is_file() and EVE_PATTERN.fullmatch(path.name):
                paths.add(os.path.normcase(str(path.resolve())))
    except OSError as error:
        discovery_error = str(error)

    rows = connection.execute(
        """
        SELECT file_path
        FROM ingestion.file_generations
        WHERE input_format = 'eve'
          AND source_scope = 'lab/windows-suricata'
          AND retired_at IS NULL
        """
    ).fetchall()

    # Include tracked paths even if they have disappeared.
    paths.update(row[0] for row in rows)

    if not paths:
        raise RuntimeError(
            discovery_error or "No dated security EVE files found"
        )

    return sorted(paths, reverse=True), discovery_error


def collect_pass(connection, source, limit, stop):
    summary = {
        "files_checked": 0,
        "errors": 0,
        "last_error": None,
        "backlog_files": 0,
        "processed_lines": 0,
        "outcomes": {},
        "historical_source_warnings": [],
    }


    if source == "sysmon":
        if stop.is_set():
            return summary

        result = ingest_sysmon_once(
            connection,
            source_scope="lab/windows-sysmon",
            max_records=limit,
        )

        emit(source, "ingest", **result)

        summary["channels_checked"] = 1
        summary["processed_events"] = result["processed_this_run"]
        summary["backlog_channels"] = (
            1 if result["status"] in (
                "limit_reached",
                "byte_limit_reached",
            ) else 0
        )
        summary["outcomes"] = result["outcomes_this_run"]

        if "recovery" in result:
            summary["recovery"] = result["recovery"]

        return summary

    if source == "wazuh":
        synchronization = synchronize_sources(connection)
        emit(source, "source_synchronization", **synchronization)
        summary["source_synchronization"] = synchronization
        targets = wazuh_targets(connection)
    else:
        targets, discovery_error = suricata_targets(connection)
        if discovery_error:
            summary["errors"] += 1
            summary["last_error"] = f"File discovery failed: {discovery_error}"
            emit(source, "discovery_error", error=discovery_error)

    for target in targets:
        if stop.is_set():
            break

        summary["files_checked"] += 1

        try:
            if source == "wazuh":
                result = ingest_wazuh_once(
                    connection,
                    source_scope="lab/wazuh-server",
                    generation_id=target["generation_id"],
                    max_records=limit,
                )
            else:
                result = ingest_with_recovery(
                    connection,
                    target,
                    source_scope="lab/windows-suricata",
                    max_records=limit,
                )

            emit(source, "ingest", target=target, **result)

            if source == "wazuh" and "recovery" in result:
                summary.setdefault("continuity_events", []).append(result["recovery"])

            summary["processed_lines"] += result.get(
                "processed_this_run", 0
            )

            for name, count in result.get(
                "outcomes_this_run", {}
            ).items():
                summary["outcomes"][name] = (
                    summary["outcomes"].get(name, 0) + count
                )

            if result["status"] in (
                "limit_reached",
                "byte_limit_reached",
            ):
                summary["backlog_files"] += 1

            if result["status"] == "file_missing":
                warning = (
                    historical_missing_warning(target, directory=EVE_FOLDER)
                    if source == "suricata" and discovery_error is None
                    else None
                )
                if warning is not None:
                    # recover_file has already retained the idempotent
                    # file_missing audit. Keep the generation and checkpoint
                    # intact so a restored matching file can resume normally.
                    summary["historical_source_warnings"].append(warning)
                else:
                    summary["errors"] += 1
                    summary["last_error"] = f"Tracked file is missing: {target}"

        except psycopg.Error:
            # Reconnect on the next pass after a database failure.
            raise
        except Exception as error:
            summary["errors"] += 1
            target_path = (
                target.get("file_path")
                if isinstance(target, dict)
                else str(target)
            )
            summary["last_error"] = (
                f"{target_path}: {type(error).__name__}: {error}"
            )
            emit(
                source,
                "collection_error",
                target=target,
                error_type=type(error).__name__,
                error=str(error),
            )

    return summary


def worker(source, args, stop, status):
    number = 0
    failures = 0

    try:
        while (
            not stop.is_set()
            and (args.continuous or number < args.passes)
        ):
            number += 1
            status.update(
                source,
                state="running",
                pass_number=number,
            )

            try:
                with connect_database() as connection:
                    connection.execute(
                        "SET statement_timeout = '60s'"
                    )
                    connection.execute(
                        "SET lock_timeout = '10s'"
                    )

                    result = collect_pass(
                        connection,
                        source,
                        args.records_per_file,
                        stop,
                    )

                if result["errors"]:
                    failures += 1
                    pass_state = "degraded"
                else:
                    failures = 0
                    has_backlog = (
                        result.get("backlog_files", 0) > 0
                        or result.get("backlog_channels", 0) > 0
                    )
                    pass_state = (
                        "catching_up" if has_backlog
                        else "healthy_with_history_warnings"
                        if result["historical_source_warnings"]
                        else "healthy"
                    )

                status.update(
                    source,
                    state=pass_state,
                    last_pass_state=pass_state,
                    last_result=result,
                    last_error=result["last_error"],
                    consecutive_failed_passes=failures,
                )

                emit(
                    source,
                    "pass_complete",
                    pass_number=number,
                    state=pass_state,
                    **result,
                )

            except Exception as error:
                failures += 1
                status.update(
                    source,
                    state="error",
                    last_pass_state="error",
                    last_result=None,
                    last_error=str(error),
                    consecutive_failed_passes=failures,
                )
                emit(
                    source,
                    "pass_failed",
                    error_type=type(error).__name__,
                    error=str(error),
                )

            if not args.continuous and number >= args.passes:
                break

            if failures:
                delay = min(
                    60,
                    max(args.interval, 2)
                    * (2 ** min(failures, 4)),
                )
            else:
                delay = args.interval

            stop.wait(delay)

    finally:
        status.update(source, state="stopped")
        emit(source, "worker_stopped")

    return failures == 0

STOP_PATH = PROJECT / "data/checkpoints/collectors.stop"
LOCK_PATH = PROJECT / "data/checkpoints/collectors.lock"


@contextmanager
def collector_lock():
    """Hold a Windows byte-range lock for this runner's lifetime."""
    LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)

    with LOCK_PATH.open("a+b") as stream:
        stream.seek(0)

        try:
            msvcrt.locking(
                stream.fileno(),
                msvcrt.LK_NBLCK,
                1,
            )
        except OSError as error:
            raise RuntimeError(
                "Cannot acquire the collector lock. "
                "Another combined runner may already be running."
            ) from error

        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(
                stream.fileno(),
                msvcrt.LK_UNLCK,
                1,
            )


def run_workers(args):
    # Only the lock holder may clear an old stop request.
    STOP_PATH.unlink(missing_ok=True)

    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.setLevel(logging.INFO)
    LOGGER.addHandler(logging.StreamHandler())
    LOGGER.addHandler(
        RotatingFileHandler(
            LOG_PATH,
            maxBytes=5 * 1024 * 1024,
            backupCount=3,
            encoding="utf-8",
        )
    )

    status = Status()
    stop = threading.Event()
    success = True
    stop_requested = False
    pending_error = None

    executor = ThreadPoolExecutor(max_workers=3)
    futures = []

    def request_stop(reason):
        nonlocal stop_requested

        if stop_requested:
            return

        stop_requested = True
        stop.set()

        print(
            f"Stop requested ({reason}). "
            "Waiting for in-flight operations to finish.",
            flush=True,
        )
        emit("runner", "stop_requested", reason=reason)

    try:
        futures = [
            executor.submit(worker, source, args, stop, status)
            for source in ("wazuh", "suricata", "sysmon")
        ]

        while True:
            try:
                if STOP_PATH.exists():
                    request_stop("stop file")

                # Detect a worker that exited unexpectedly.
                for future in futures:
                    if future.done() and future.exception() is not None:
                        pending_error = future.exception()
                        request_stop("worker failure")

                if all(future.done() for future in futures):
                    break

                time.sleep(0.5)

            except KeyboardInterrupt:
                request_stop("Ctrl+C")

            except Exception as error:
                pending_error = error
                request_stop("runner failure")
                break

    finally:
        stop.set()

        # Poll while workers finish so the main thread stays responsive.
        while any(not future.done() for future in futures):
            try:
                time.sleep(0.5)
            except KeyboardInterrupt:
                print(
                    "Shutdown is already in progress; "
                    "waiting for the current operations.",
                    flush=True,
                )

        executor.shutdown(wait=True)

        for future in futures:
            try:
                if not future.result():
                    success = False
            except Exception as error:
                success = False
                if pending_error is None:
                    pending_error = error

        STOP_PATH.unlink(missing_ok=True)

    if pending_error is not None:
        LOGGER.error(
            "Collector runner failed",
            exc_info=(
                type(pending_error),
                pending_error,
                pending_error.__traceback__,
            ),
        )
        print(
            f"Runner failed: {type(pending_error).__name__}: "
            f"{pending_error}",
            flush=True,
        )
        return 1

    print("Collectors stopped. Checkpoints retained.", flush=True)
    return 0 if success else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)

    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--passes", type=int, default=2)
    mode.add_argument("--continuous", action="store_true")

    parser.add_argument(
        "--records-per-file",
        type=int,
        default=100,
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=5,
    )
    args = parser.parse_args()

    if args.passes < 1:
        parser.error("passes must be positive")

    if not 1 <= args.records_per_file <= 1000:
        parser.error("records-per-file must be 1..1000")

    if not 1 <= args.interval <= 60:
        parser.error("interval must be 1..60 seconds")

    try:
        with collector_lock():
            return run_workers(args)
    except RuntimeError as error:
        print(str(error), flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
