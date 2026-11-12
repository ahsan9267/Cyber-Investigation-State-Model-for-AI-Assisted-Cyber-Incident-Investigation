"""Common record envelope for SPINE Step 2."""

from copy import deepcopy
import hashlib
import json

from spine.timestamps import normalize_timestamp


SCHEMA_VERSION = "0.1.0"


def build_envelope(
    *,
    raw_text: str,
    source: str,
    collector: str,
    record_kind: str,
    source_scope: str,
    source_record_id: str,
    observed_time: str,
) -> dict:
    """Build a fresh envelope from a record and its ingestion identity.

    source_scope identifies the originating system/stream.
    source_record_id must identify a particular record in that scope.
    It must remain unchanged when the same record is replayed.
    """
    required = {
        "source": source,
        "collector": collector,
        "source_scope": source_scope,
        "source_record_id": source_record_id,
    }

    for name, value in required.items():
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")

    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("raw_text must be a non-empty string")

    if record_kind not in ("alert", "telemetry"):
        raise ValueError("record_kind must be alert or telemetry")

    # Identity is based on provenance, not event contents or read time.
    # Two genuine events may have identical payloads.
    identity = json.dumps(
        [collector, source_scope, source_record_id],
        ensure_ascii=False,
        separators=(",", ":"),
    )

    record_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    raw_hash = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()

    return {
        "schema_version": SCHEMA_VERSION,
        "record_id": record_id,
        "source": source,
        "collector": collector,
        "record_kind": record_kind,
        "provenance": {
            "source_scope": source_scope,
            "source_record_id": source_record_id,
        },
        "event_time": None,
        "alert_time": None,
        "observed_time": normalize_timestamp(observed_time),
        "host": {},
        "agent": {},
        "event": {},
        "rule": {},
        "priority": {
            "wazuh_level": None,
            "priority_band": None,
            "actionable": None,
        },
        "attributes": {},

                "entities": [],
        "enrichment": [],
        "raw": {
            "text": raw_text,
            "sha256": raw_hash,
            "hash_basis": "UTF-8 encoding of preserved input text",
        },
        "normalization": {
            "parser": None,
            "status": "unmapped",
            "warnings": [],
        },
    }


def snapshot_record(record: dict) -> dict:
    """Return an independent copy for subsequent processing."""
    return deepcopy(record)