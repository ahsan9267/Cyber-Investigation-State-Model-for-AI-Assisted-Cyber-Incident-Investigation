"""Verify immutable evidence views using rollback-only test evidence."""

from copy import deepcopy
from datetime import datetime, timezone
import getpass
import uuid

from spine.envelope import build_envelope
from spine.evidence import config_hash
from spine.manager_database import connect_manager_database
from spine.manager_views import (
    capture_evidence_view,
    load_annotation_context,
    read_evidence_view,
)
from spine.storage import store_record


def expect(actual, expected, label):
    if actual != expected:
        raise RuntimeError(
            f"{label}: expected {expected!r}, received {actual!r}"
        )
    print(f"PASS: {label}")


def expect_error(operation, error_type, message_part, label):
    try:
        operation()
    except error_type as error:
        if message_part not in str(error):
            raise RuntimeError(f"Unexpected error: {error}") from error
        print(f"PASS: {label}")
    else:
        raise RuntimeError(f"{label}: expected an error")


def run_checks(connection):
    scope = f"step4-view-check/{uuid.uuid4()}"

    original = build_envelope(
        raw_text=r'{"value":"preserved\u0000"}',
        source="manager_view_check",
        collector="manager_view_check",
        record_kind="telemetry",
        source_scope=scope,
        source_record_id="record-1",
        observed_time=datetime.now(timezone.utc).isoformat(),
    )
    original["attributes"]["source_payload"] = {
        "value": "preserved\x00"
    }

    record_id = original["record_id"]
    raw_hash = original["raw"]["sha256"]
    context = load_annotation_context()
    context_before = deepcopy(context)

    def capture(selected_context=context, expected_hash=raw_hash):
        return capture_evidence_view(
            connection,
            record_id,
            expected_raw_sha256=expected_hash,
            context=selected_context,
        )

    def view_count():
        return connection.execute(
            """
            SELECT COUNT(*)
            FROM investigation.evidence_views
            WHERE record_id = %s
            """,
            (record_id,),
        ).fetchone()[0]

    expect_error(
        capture,
        RuntimeError,
        "explicit outer transaction",
        "capture outside a transaction is rejected",
    )

    with connection.transaction(force_rollback=True):
        expect(
            store_record(connection, original),
            "inserted",
            "temporary evidence stored",
        )

        with connection.transaction(force_rollback=True):
            rolled_back_view = capture()
            expect(view_count(), 1, "view inserted inside transaction")

        expect(view_count(), 0, "view insertion rolls back")

        first = capture()
        expected_first = deepcopy(first)

        expect(
            first["view_id"],
            rolled_back_view["view_id"],
            "same input retains the same view identity",
        )
        expect(capture(), expected_first, "repeat capture reuses the view")
        expect(view_count(), 1, "repeat capture creates no duplicate")

        expect(
            first["document"]["raw"],
            original["raw"],
            "annotated view preserves raw evidence",
        )
        expect(
            first["document"]["attributes"]["source_payload"],
            {"value": "preserved\x00"},
            "null character survives view storage",
        )
        expect(context, context_before, "caller configuration is unchanged")

        # Mutating the returned Python object must not change saved history.
        first["document"]["attributes"]["caller_only"] = True
        expect(
            read_evidence_view(connection, first["view_id"]),
            expected_first,
            "returned-object changes do not alter the saved view",
        )

        # Change configuration in memory only; no configuration file is edited.
        changed_context = deepcopy(context)
        changed_context["host_config"]["host_mappings"].append({
            "mapping_id": f"view-check-{uuid.uuid4()}",
            "collector": "manager_view_check",
            "source_scope": scope,
            "field": "host.name",
            "value": "test-host",
            "entity_role": "event_host",
            "canonical_host_id": "test/host/view-check",
        })

        expect_error(
            lambda: capture(changed_context),
            ValueError,
            "configuration hash mismatch",
            "modified configuration with stale hash is rejected",
        )

        changed_context["host_config_sha256"] = config_hash(
            changed_context["host_config"]
        )
        changed_view = capture(changed_context)

        expect(
            changed_view["view_id"] != expected_first["view_id"],
            True,
            "configuration change produces a distinct view",
        )
        expect(view_count(), 2, "both historical views are retained")
        expect(
            changed_view["annotation_context"],
            changed_context,
            "complete changed configuration is retained",
        )
        expect(
            read_evidence_view(connection, expected_first["view_id"]),
            expected_first,
            "earlier view remains unchanged",
        )

        wrong_hash = (
            ("0" if raw_hash[0] != "0" else "1") + raw_hash[1:]
        )
        expect_error(
            lambda: capture(expected_hash=wrong_hash),
            RuntimeError,
            "payload hash disagrees",
            "work item with incorrect raw hash is rejected",
        )

        stored_original = connection.execute(
            """
            SELECT document
            FROM ingestion.records
            WHERE record_id = %s
            """,
            (record_id,),
        ).fetchone()[0]
        expect(stored_original, original, "stored original remains unchanged")

    expect(view_count(), 0, "temporary views removed by rollback")

    remaining = connection.execute(
        "SELECT COUNT(*) FROM ingestion.records WHERE record_id = %s",
        (record_id,),
    ).fetchone()[0]
    expect(remaining, 0, "temporary original removed by rollback")


def main():
    password = getpass.getpass("spine_app password: ")

    with connect_manager_database(
        dbname="spine_step4_dev",
        password=password,
    ) as connection:
        actual_database = connection.execute(
            "SELECT current_database()"
        ).fetchone()[0]

        if actual_database != "spine_step4_dev":
            raise RuntimeError("Run only against spine_step4_dev")

        run_checks(connection)

    print("SUCCESS: evidence view database checks passed")
    print("All test evidence and views were rolled back.")


if __name__ == "__main__":
    main()