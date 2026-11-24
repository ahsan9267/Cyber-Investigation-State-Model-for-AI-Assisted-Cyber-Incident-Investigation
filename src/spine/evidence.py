"""Read original evidence alongside explicitly derived annotations."""

from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import re

from psycopg.pq import TransactionStatus

from spine.entities import extract_entities
from spine.identity import load_config as load_host_config
from spine.identity import map_host_identities
from spine.mitre import normalize_mitre
from spine.storage import validate_record
from spine.user_identity import load_config as load_user_config
from spine.user_identity import map_user_identities


VIEW_VERSION = "evidence_annotations/0.1.0"


def config_hash(config):
    text = json.dumps(
        config, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def annotate_document(document, *, host_config, user_config):
    """Derive annotations from stored normalized fields, preserving input."""
    validate_record(document)

    result = normalize_mitre(document)
    result = extract_entities(result)
    result = map_host_identities(result, config=host_config)
    result = map_user_identities(result, config=user_config)

    if result["raw"] != document["raw"]:
        raise RuntimeError("Annotation processing changed raw evidence")

    if result["record_id"] != document["record_id"]:
        raise RuntimeError("Annotation processing changed record identity")

    return result


def read_evidence(connection, record_id, *, conflict_limit=20):
    """Read one evidence bundle in a consistent, read-only transaction.

    Requires an idle autocommit connection. No database writes are made.
    This is a lookup by identity, not an incremental consumption cursor.
    """
    if (
        not isinstance(record_id, str)
        or re.fullmatch(r"[0-9a-f]{64}", record_id) is None
    ):
        raise ValueError("Expected a 64-character lowercase record ID")

    if type(conflict_limit) is not int or not 1 <= conflict_limit <= 100:
        raise ValueError("conflict_limit must be between 1 and 100")

    if (
        not connection.autocommit
        or connection.info.transaction_status != TransactionStatus.IDLE
    ):
        raise RuntimeError("Use an idle autocommit connection")

    with connection.transaction():
        connection.execute(
            "SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"
        )
        connection.execute("SET LOCAL statement_timeout = '15s'")

        original_row = connection.execute(
            """
            SELECT
                record_id, collector, source_scope, source_record_id,
                raw_sha256, document, stored_at
            FROM ingestion.records
            WHERE record_id = %s
            """,
            (record_id,),
        ).fetchone()

        if original_row is None:
            raise LookupError(f"Evidence record not found: {record_id}")

        conflict_rows = connection.execute(
            """
            SELECT
                incoming_raw_sha256,
                incoming_document,
                detected_at,
                COUNT(*) OVER ()
            FROM ingestion.record_conflicts
            WHERE record_id = %s
            ORDER BY detected_at, incoming_raw_sha256
            LIMIT %s
            """,
            (record_id, conflict_limit),
        ).fetchall()

    (
        stored_id, collector, scope, source_id,
        raw_hash, original, stored_at,
    ) = original_row

    validated = validate_record(original)
    expected = (stored_id, collector, scope, source_id, raw_hash)
    if validated[:5] != expected:
        raise RuntimeError("Stored columns disagree with original document")

    conflicts = []
    for incoming_hash, document, detected_at, total in conflict_rows:
        validated = validate_record(document)

        if validated[:4] != expected[:4] or validated[4] != incoming_hash:
            raise RuntimeError("Conflict columns disagree with its document")

        conflicts.append({
            "incoming_raw_sha256": incoming_hash,
            "detected_at": detected_at.isoformat(),
            "stored_document": deepcopy(document),
        })

    # Load each configuration once for this derived view.
    host_config = load_host_config()
    user_config = load_user_config()

    annotated = annotate_document(
        original,
        host_config=host_config,
        user_config=user_config,
    )

    conflict_total = conflict_rows[0][3] if conflict_rows else 0

    return {
        "record_id": stored_id,
        "stored_at": stored_at.isoformat(),
        "stored_document": deepcopy(original),
        "current_annotation_view": {
            "version": VIEW_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "basis": "stored_normalized_fields",
            "source_parser_rerun": False,
            "persisted": False,
            "host_config_sha256": config_hash(host_config),
            "user_config_sha256": config_hash(user_config),
            "document": annotated,
        },
        "conflict_count": conflict_total,
        "conflicts_returned": len(conflicts),
        "conflicts_truncated": conflict_total > len(conflicts),
        "conflicts": conflicts,
    }