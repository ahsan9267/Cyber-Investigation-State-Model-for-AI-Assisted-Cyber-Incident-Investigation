"""Independent daily sources and audited Wazuh continuity recovery.

Old evidence, outcomes, offsets and checkpoint bytes are retained. Recovery
uses the existing per-scope ingestion lock and commits its audit with the
successor's first batch. Transport and access failures never retire a source.
"""

from copy import deepcopy
from datetime import timedelta
import hashlib
import json
import uuid

from psycopg.rows import dict_row
from psycopg.types.json import Json

from spine.live_wazuh import CheckpointChanged, _checkpoint, _signature, _state, ingest_once
from spine.remote_wazuh import (
    REMOTE_PATH, RemoteReadError, fetch_batch, fetch_inspection, fetch_inventory,
)
from spine.wazuh_handoff import archive_date


CONTINUITY_ERRORS = {
    ("RuntimeError", "File truncated below checkpoint"),
    ("ValueError", "Checkpoint is not at a line boundary"),
    ("RuntimeError", "First-line fingerprint changed"),
    ("RuntimeError", "Checkpoint bytes changed"),
    ("RuntimeError", "Checkpoint file is not available as retained plain JSON; "
                     "archive recovery is required. Checkpoint must remain unchanged."),
}


def _lock(connection, scope):
    material = json.dumps(["live-wazuh", scope], ensure_ascii=False, separators=(",", ":"))
    key = int.from_bytes(hashlib.sha256(material.encode("utf-8")).digest()[:8], "big", signed=True)
    connection.execute("SELECT pg_advisory_xact_lock(%s)", (key,))


def _descriptor(source):
    if not isinstance(source, dict):
        raise ValueError("Invalid source inspection")
    for name in ("device_id", "native_file_id"):
        value = source.get(name)
        if not isinstance(value, str) or not value.isascii() or not value.isdigit() or len(value) > 32:
            raise ValueError("Invalid inspected native identity")
    fingerprint = source.get("first_line_sha256")
    if fingerprint is not None and (
        not isinstance(fingerprint, str) or len(fingerprint) != 64
        or any(c not in "0123456789abcdef" for c in fingerprint)
    ):
        raise ValueError("Invalid inspected first-line fingerprint")
    if type(source.get("size_at_open")) is not int or source["size_at_open"] < 0:
        raise ValueError("Invalid inspected source size")
    archive = source.get("archive_path")
    if archive is not None:
        archive_date(archive)
    if source.get("read_path") != REMOTE_PATH:
        archive_date(source.get("read_path"))
        if source["read_path"] != archive:
            raise ValueError("Inspected archive locator disagrees with read path")
    return source


def _identity(source):
    return source["device_id"], source["native_file_id"]


def _stable(source):
    return (*_identity(source), source["first_line_sha256"], source["archive_path"])


def _inventory(response):
    if response.get("protocol_version") != 2 or not isinstance(response.get("sources"), list):
        raise ValueError("Invalid source inventory")
    if len(response["sources"]) > 512:
        raise ValueError("Source inventory exceeds limit")
    active = response.get("active")
    if active is None:
        raise RuntimeError("Wazuh active source is unavailable; checkpoints preserved")
    _descriptor(active)
    if active["read_path"] != REMOTE_PATH:
        raise ValueError("Invalid active source locator")
    seen = set()
    for source in response["sources"]:
        _descriptor(source)
        if source["read_path"] != source["archive_path"] or _identity(source) in seen:
            raise ValueError("Duplicate or invalid dated source")
        seen.add(_identity(source))
    return active, response["sources"]


def _register(connection, scope, source, path):
    identifier = uuid.uuid4()
    connection.execute(
        """INSERT INTO ingestion.file_generations
           (generation_id, input_format, source_scope, file_path, device_id,
            native_file_id, first_line_sha256, remote_archive_path)
           VALUES (%s, 'wazuh', %s, %s, %s, %s, %s, %s)""",
        (identifier, scope, path, *_identity(source),
         source["first_line_sha256"], source["archive_path"]),
    )
    return identifier


def _event(connection, previous, kind, size, details, *, gap):
    connection.execute(
        """INSERT INTO ingestion.file_generation_events
           (event_id, generation_id, event_type, checkpoint_offset, observed_size,
            possible_evidence_gap, details)
           VALUES (%s, %s, %s, %s, %s, %s, %s)""",
        (uuid.uuid4(), previous["generation_id"], kind, previous["next_offset"],
         size, gap, Json(details)),
    )


def synchronize_sources(connection, *, source_scope="lab/wazuh-server",
                        inventory_fetcher=fetch_inventory):
    """Register today's alias and every available plain dated source independently.

    Ordinary rotation does not wait for old files to finish. Intermediate
    available days are registered too, so a multi-day outage is recoverable.
    """
    if not connection.autocommit:
        raise ValueError("Wazuh source synchronization requires autocommit=True")
    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be nonempty text")
    first_active, first_sources = _inventory(inventory_fetcher())
    prepared = sorted(_stable(s) for s in first_sources)
    registered, moved = 0, 0
    with connection.transaction():
        _lock(connection, source_scope)
        active, sources = _inventory(inventory_fetcher())
        if _stable(active) != _stable(first_active) or sorted(_stable(s) for s in sources) != prepared:
            raise CheckpointChanged("Source inventory changed during synchronization; retry")
        with connection.cursor(row_factory=dict_row) as cursor:
            cursor.execute(
                """SELECT * FROM ingestion.file_generations
                   WHERE input_format = 'wazuh' AND source_scope = %s
                     AND retired_at IS NULL""", (source_scope,),
            )
            states = cursor.fetchall()
        by_native = {_identity(s): s for s in states}
        by_path = {s["file_path"]: s for s in states}
        old = by_path.get(REMOTE_PATH)
        if old is not None and _identity(old) != _identity(active):
            old_source = next((s for s in sources if _identity(s) == _identity(old)), None)
            path = old.get("remote_archive_path") or (old_source or {}).get("archive_path")
            if path is None:
                raise RuntimeError("Old dated locator is missing; source synchronization refused")
            archive_date(path)
            if path in by_path:
                raise RuntimeError("Old dated locator is already tracked by another generation")
            connection.execute(
                """UPDATE ingestion.file_generations
                   SET file_path = %s, remote_archive_path = %s, updated_at = clock_timestamp()
                   WHERE generation_id = %s""", (path, path, old["generation_id"]),
            )
            by_path.pop(REMOTE_PATH)
            by_path[path] = old
            moved += 1
            new_path = active["archive_path"]
            available = {archive_date(s["archive_path"]) for s in sources}
            gap = new_path is None
            if new_path is not None:
                start, finish = archive_date(path), archive_date(new_path)
                gap = finish <= start or any(
                    start + timedelta(days=n) not in available
                    for n in range(1, (finish - start).days)
                )
            _event(connection, old, "replacement_detected",
                   (old_source or {}).get("size_at_open"), {
                       "reason": "independent_daily_source_registration",
                       "old_archive_path": path, "new_archive_path": new_path,
                       "old_checkpoint_preserved": True,
                       "intervening_plain_sources_complete": not gap,
                       "gap_assessment": "Available files remain independently polled; "
                                         "missing intermediate days require archive review.",
                   }, gap=gap)
        active_state = by_native.get(_identity(active))
        if active_state is not None and active_state["file_path"] != REMOTE_PATH:
            # A known retained file can become the alias again (for example
            # after a producer restart). Reuse its committed checkpoint.
            previous_path = active_state["file_path"]
            connection.execute(
                """UPDATE ingestion.file_generations
                   SET file_path = %s, updated_at = clock_timestamp()
                   WHERE generation_id = %s""", (REMOTE_PATH, active_state["generation_id"]),
            )
            by_path.pop(previous_path)
            by_path[REMOTE_PATH] = active_state
            active_state["file_path"] = REMOTE_PATH
            _event(connection, active_state, "replacement_detected", active["size_at_open"], {
                "reason": "known_generation_became_active_alias",
                "previous_path": previous_path,
                "committed_checkpoint_preserved": True,
            }, gap=False)
        # The active alias takes precedence over its hard-linked dated path.
        descriptors = [active] + [s for s in sources if _identity(s) != _identity(active)]
        for source in descriptors:
            if source["first_line_sha256"] is None or _identity(source) in by_native:
                continue
            path = REMOTE_PATH if source is active else source["archive_path"]
            if path in by_path:
                # Recovery of the displaced identity is audited by its next poll.
                continue
            identifier = _register(connection, source_scope, source, path)
            by_native[_identity(source)] = {"generation_id": identifier}
            by_path[path] = {"generation_id": identifier}
            registered += 1
    return {"status": "sources_synchronized", "registered_generations": registered,
            "moved_aliases": moved}


def _inspection(response, previous):
    if response.get("protocol_version") != 2 or response.get("status") not in (
        "valid", "unavailable", "truncation_detected", "content_change_detected",
    ):
        raise ValueError("Invalid checkpoint inspection")
    source = response.get("source")
    if response["status"] == "unavailable":
        if source is not None or type(response.get("compressed_archive_available")) is not bool:
            raise ValueError("Invalid unavailable-source inspection")
    else:
        _descriptor(source)
        if _identity(source) != _identity(previous):
            raise ValueError("Inspection changed the saved native identity")
        path = previous.get("remote_archive_path")
        if path is not None and source["archive_path"] != path:
            raise ValueError("Inspection changed the saved archive locator")
        if response["status"] == "truncation_detected" and source["size_at_open"] >= previous["next_offset"]:
            raise CheckpointChanged("Source is no longer shorter than its checkpoint; retry")
        if response["status"] not in ("valid", "unavailable") and (
            ("RuntimeError", response.get("issue")) not in CONTINUITY_ERRORS
            and ("ValueError", response.get("issue")) not in CONTINUITY_ERRORS
        ):
            raise ValueError("Unrecognized inspected continuity issue")
    return response


def _start_batch(source, fetcher, max_records):
    expected = {"device_id": source["device_id"], "native_file_id": source["native_file_id"],
                "first_line_sha256": source["first_line_sha256"], "next_offset": 0,
                "checkpoint_tail_b64": ""}
    return fetcher(offset=0, expected=expected, max_records=max_records)


def recover_generation(connection, *, source_scope="lab/wazuh-server", generation_id=None,
                       max_records=100, fetcher=fetch_batch, inspector=fetch_inspection):
    """Confirm the same discontinuity twice and preserve the original checkpoint."""
    if not connection.autocommit:
        raise ValueError("Wazuh recovery requires autocommit=True")
    if type(max_records) is not int or not 1 <= max_records <= 1000:
        raise ValueError("max_records must be 1..1000")
    if not isinstance(source_scope, str) or not source_scope.strip():
        raise ValueError("source_scope must be nonempty text")
    previous = _state(connection, source_scope, generation_id)
    if previous is None:
        raise CheckpointChanged("Generation no longer exists or was already retired")
    def inspect():
        return _inspection(inspector(expected=_checkpoint(previous),
                                     archive_path=previous.get("remote_archive_path")), previous)
    first = inspect()
    if first["status"] == "valid":
        raise CheckpointChanged("Checkpoint now validates; retirement refused")
    source = first["source"]
    prefix = None
    if source is not None:
        if source["first_line_sha256"] is None:
            raise RuntimeError("Waiting for a complete recovery line; checkpoint preserved")
        prefix = _start_batch(source, fetcher, max_records)
        if type(prefix.get("line_count")) is not int or not 1 <= prefix["line_count"] <= max_records:
            raise ValueError("Recovery prefix has no complete bounded records")
    with connection.transaction():
        _lock(connection, source_scope)
        current = _state(connection, source_scope, generation_id)
        if current is None or (_signature(current), current["file_path"], current.get("remote_archive_path")) != (
            _signature(previous), previous["file_path"], previous.get("remote_archive_path"),
        ):
            raise CheckpointChanged("Checkpoint changed during recovery preparation")
        second = inspect()
        if second["status"] != first["status"]:
            raise CheckpointChanged("Checkpoint condition changed; retirement refused")
        verified = None
        if source is not None:
            if _stable(source) != _stable(second["source"]):
                raise CheckpointChanged("Recovery source changed during preparation")
            # Append-only growth must not make a stable prefix look rewritten.
            verified = _start_batch(second["source"], fetcher, prefix["line_count"])
            for key in ("device_id", "native_file_id", "first_line_sha256", "raw_bytes",
                        "next_offset", "checkpoint_tail_b64", "archive_path"):
                if prefix.get(key) != verified.get(key):
                    raise CheckpointChanged("Recovery prefix changed during preparation")
        elif first["compressed_archive_available"] != second["compressed_archive_available"]:
            raise CheckpointChanged("Archive availability changed; retirement refused")
        kind = "file_missing" if source is None else second["status"]
        retired = connection.execute(
            """UPDATE ingestion.file_generations
               SET retired_at = clock_timestamp(), retirement_reason = %s,
                   updated_at = clock_timestamp()
               WHERE generation_id = %s AND retired_at IS NULL RETURNING generation_id""",
            ("audited_wazuh_recovery: " + kind, previous["generation_id"]),
        ).fetchone()
        if retired is None:
            raise CheckpointChanged("Generation was already retired")
        result = {"status": "generation_unavailable", "processed_this_run": 0}
        successor = None
        if source is not None:
            successor = _register(connection, source_scope, second["source"], previous["file_path"])
            def cached_batch(**request):
                if request.get("offset") != 0 or request.get("expected") != _checkpoint(
                    _state(connection, source_scope, successor)
                ):
                    raise ValueError("Unexpected successor read")
                return deepcopy(verified)
            result = ingest_once(connection, source_scope=source_scope, generation_id=successor,
                                 max_records=max_records, fetcher=cached_batch)
        recovery = {
            "reason": kind, "previous_generation_id": str(previous["generation_id"]),
            "successor_generation_id": str(successor) if successor is not None else None,
            "previous_checkpoint_preserved": True,
            "previous_offset": previous["next_offset"],
            "previous_processed_lines": previous["processed_lines"],
            "observed_size": second["source"]["size_at_open"] if source is not None else None,
            "archive_path": previous.get("remote_archive_path"),
            "possible_evidence_gap": True,
            "compressed_archive_available": second.get("compressed_archive_available", False),
            "recovery_policy": "replay_available_source_in_successor" if source is not None
                               else "retain_unavailable_checkpoint_for_archive_review",
            "root_cause": "not_established",
            "gap_assessment": "Source continuity is uncertain; missing event count is unknown. "
                              "Previously stored evidence and outcomes are retained.",
        }
        _event(connection, previous, kind, recovery["observed_size"], recovery, gap=True)
        result["recovery"] = recovery
    return result


def ingest_with_recovery(connection, *, source_scope="lab/wazuh-server", generation_id=None,
                         max_records=100, fetcher=fetch_batch, inspector=fetch_inspection):
    try:
        return ingest_once(connection, source_scope=source_scope, generation_id=generation_id,
                           max_records=max_records, fetcher=fetcher)
    except RemoteReadError as error:
        if (error.detail["error"], error.detail["message"]) not in CONTINUITY_ERRORS:
            raise
        return recover_generation(connection, source_scope=source_scope, generation_id=generation_id,
                                  max_records=max_records, fetcher=fetcher, inspector=inspector)
