"""Preserve reproducible evidence views for investigation decisions."""

from copy import deepcopy
import re

from psycopg.pq import TransactionStatus
from psycopg.types.json import Json

from spine.association import fingerprint
from spine.evidence import VIEW_VERSION, annotate_document, config_hash
from spine.identity import load_config as load_host_config
from spine.identity import validate_config as validate_host_config
from spine.storage import validate_record
from spine.user_identity import load_config as load_user_config
from spine.user_identity import validate_config as validate_user_config


CONTEXT_VERSION = "manager_annotation_context/1"
VIEW_SCHEMA_VERSION = "manager_evidence_view/1"


def require_transaction(connection):
    """Require the caller to own the transaction boundary."""
    if connection.info.transaction_status != TransactionStatus.INTRANS:
        raise RuntimeError(
            "Evidence views require an explicit outer transaction"
        )


def validate_hash(value, label):
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{64}", value) is None
    ):
        raise ValueError(f"Invalid {label}")


def validate_context(context):
    """Check the retained configuration and its declared fingerprints."""
    required = {
        "schema_version",
        "annotation_version",
        "basis",
        "source_parser_rerun",
        "host_config",
        "user_config",
        "host_config_sha256",
        "user_config_sha256",
    }

    if not isinstance(context, dict) or set(context) != required:
        raise ValueError("Invalid annotation context fields")

    if (
        context["schema_version"] != CONTEXT_VERSION
        or context["annotation_version"] != VIEW_VERSION
        or context["basis"] != "stored_normalized_fields"
        or context["source_parser_rerun"] is not False
    ):
        raise ValueError("Unsupported annotation context")

    validate_host_config(context["host_config"])
    validate_user_config(context["user_config"])

    for prefix in ("host", "user"):
        actual = config_hash(context[f"{prefix}_config"])
        if actual != context[f"{prefix}_config_sha256"]:
            raise ValueError(f"{prefix} configuration hash mismatch")


def load_annotation_context():
    """Load each mapping file once and retain its complete contents."""
    host_config = deepcopy(load_host_config())
    user_config = deepcopy(load_user_config())

    context = {
        "schema_version": CONTEXT_VERSION,
        "annotation_version": VIEW_VERSION,
        "basis": "stored_normalized_fields",
        "source_parser_rerun": False,
        "host_config": host_config,
        "user_config": user_config,
        "host_config_sha256": config_hash(host_config),
        "user_config_sha256": config_hash(user_config),
    }

    validate_context(context)
    return context


def view_fingerprint(record_id, raw_sha256, document, context):
    return fingerprint({
        "schema_version": VIEW_SCHEMA_VERSION,
        "record_id": record_id,
        "raw_sha256": raw_sha256,
        "document": document,
        "annotation_context": context,
    })

def _validated_evidence_view(view_id, row):
    """Validate a retained view loaded individually or in a batch."""
    if row is None:
        raise LookupError(f"Evidence view not found: {view_id}")

    record_id, raw_hash, document, context = row
    validated = validate_record(document)

    if validated[0] != record_id or validated[4] != raw_hash:
        raise RuntimeError("Evidence view columns disagree with document")

    validate_context(context)

    expected_id = view_fingerprint(
        record_id, raw_hash, document, context
    )
    if expected_id != view_id:
        raise RuntimeError("Stored evidence view fingerprint mismatch")

    return {
        "view_id": view_id,
        "record_id": record_id,
        "raw_sha256": raw_hash,
        "document": deepcopy(document),
        "annotation_context": deepcopy(context),
    }


def read_evidence_view(connection, view_id):
    """Read a retained view without loading today's mapping files."""
    validate_hash(view_id, "view ID")

    row = connection.execute(
        """
        SELECT record_id, raw_sha256, document, annotation_context
        FROM investigation.evidence_views
        WHERE view_id = %s
        """,
        (view_id,),
    ).fetchone()

    return _validated_evidence_view(view_id, row)


def read_evidence_views(connection, view_ids):
    """Batch-read retained views using the same validation as single reads."""
    identifiers = list(dict.fromkeys(view_ids))

    for view_id in identifiers:
        validate_hash(view_id, "view ID")

    if not identifiers:
        return {}

    rows = connection.execute(
        """
        SELECT
            view_id, record_id, raw_sha256, document, annotation_context
        FROM investigation.evidence_views
        WHERE view_id = ANY(%s::text[])
        """,
        (identifiers,),
    ).fetchall()

    loaded = {
        row[0]: _validated_evidence_view(row[0], row[1:])
        for row in rows
    }

    for view_id in identifiers:
        if view_id not in loaded:
            raise LookupError(f"Evidence view not found: {view_id}")

    return loaded


def capture_evidence_view(
    connection,
    record_id,
    *,
    expected_raw_sha256,
    context,
):
    """Capture an original record using one explicit annotation context.

    Intended for original-record work items. Conflicting payloads remain
    separate evidence and must not replace the original input.

    Requires an outer transaction; this function does not commit.
    """
    require_transaction(connection)
    validate_hash(record_id, "record ID")
    validate_hash(expected_raw_sha256, "expected raw hash")

    frozen_context = deepcopy(context)
    validate_context(frozen_context)

    row = connection.execute(
        """
        SELECT
            record_id, collector, source_scope, source_record_id,
            raw_sha256, document
        FROM ingestion.records
        WHERE record_id = %s
        """,
        (record_id,),
    ).fetchone()

    if row is None:
        raise LookupError(f"Evidence record not found: {record_id}")

    stored_id, collector, scope, source_id, raw_hash, original = row
    validated = validate_record(original)

    if validated[:5] != (
        stored_id, collector, scope, source_id, raw_hash
    ):
        raise RuntimeError("Stored evidence columns disagree with document")

    if raw_hash != expected_raw_sha256:
        raise RuntimeError("Work-item payload hash disagrees with original")

    annotated = annotate_document(
        original,
        host_config=frozen_context["host_config"],
        user_config=frozen_context["user_config"],
    )
    validate_record(annotated)

    view_id = view_fingerprint(
        record_id, raw_hash, annotated, frozen_context
    )

    connection.execute(
        """
        INSERT INTO investigation.evidence_views (
            view_id, record_id, raw_sha256,
            document, annotation_context
        )
        VALUES (%s, %s, %s, %s, %s)
        ON CONFLICT (view_id) DO NOTHING
        """,
        (
            view_id,
            record_id,
            raw_hash,
            Json(annotated),
            Json(frozen_context),
        ),
    )

    saved = read_evidence_view(connection, view_id)

    # Do not silently accept a conflicting row under an existing view ID.
    expected = {
        "view_id": view_id,
        "record_id": record_id,
        "raw_sha256": raw_hash,
        "document": annotated,
        "annotation_context": frozen_context,
    }
    if saved != expected:
        raise RuntimeError("Existing evidence view differs from input")

    return saved