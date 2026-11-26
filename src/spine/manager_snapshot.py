"""Complete, transaction-locked case snapshots for Step 3."""

from spine.manager_views import (
    read_evidence_views,
    require_transaction,
)

from spine.occurrences import describe_occurrence


def build_locked_snapshot(connection, *, include_closed=False):
    """Read all active cases while holding the shared routing lock.

    The caller must own an explicit transaction. The routing lock remains
    held until that transaction commits or rolls back.

    All manager operations that change cases, memberships or the routing
    revision must follow this same locking protocol.
    """
    require_transaction(connection)

    if type(include_closed) is not bool:
        raise ValueError("include_closed must be a boolean")

    state = connection.execute(
        """
        SELECT revision
        FROM investigation.routing_state
        WHERE singleton_id = 1
        FOR UPDATE
        """
    ).fetchone()

    if state is None:
        raise RuntimeError("Investigation routing-state row is missing")

    routing_revision = state[0]

    case_rows = connection.execute(
        """
        SELECT case_id, revision, status
        FROM investigation.cases
        WHERE status = 'active'
           OR (%s AND status = 'closed')
        ORDER BY case_id
        """,
        (include_closed,),
    ).fetchall()

    all_memberships = connection.execute(
        """
        SELECT
            m.case_id,
            m.record_id,
            m.input_view_id,
            m.occurrence_id,
            m.occurrence_profile,
            m.representation_matching_supported,
            m.count_unit
        FROM investigation.case_memberships AS m
        JOIN investigation.cases AS c ON c.case_id = m.case_id
        WHERE c.status = 'active'
           OR (%s AND c.status = 'closed')
        ORDER BY m.case_id, m.record_id
        """,
        (include_closed,),
    ).fetchall()

    memberships_by_case = {}
    for row in all_memberships:
        memberships_by_case.setdefault(row[0], []).append(row[1:])

    retained_views = read_evidence_views(
        connection,
        (row[2] for row in all_memberships),
    )

    cases = []
    view_refs = {}
    occurrence_owners = {}

    for case_id, case_revision, case_status in case_rows:
        case_id_text = str(case_id)

        membership_rows = memberships_by_case.get(case_id, [])

        if not membership_rows:
            raise RuntimeError(
                f"Active case has no alert memberships: {case_id_text}"
            )

        alerts = []

        for (
            record_id,
            view_id,
            occurrence_id,
            occurrence_profile,
            matching_supported,
            count_unit,
        ) in membership_rows:
            if record_id in view_refs:
                raise RuntimeError(
                    "One record appears in multiple active cases"
                )

            retained = retained_views[view_id]

            if retained["record_id"] != record_id:
                raise RuntimeError(
                    "Membership and evidence-view identity disagree"
                )

            document = retained["document"]
            priority = document.get("priority", {})

            if (
                document.get("record_kind") != "alert"
                or not isinstance(priority, dict)
                or priority.get("actionable") is False
            ):
                raise RuntimeError(
                    "Case context contains a non-admitted record"
                )

            occurrence = describe_occurrence(document)
            expected_occurrence = (
                occurrence["id"],
                occurrence["profile"],
                occurrence["representation_matching_supported"],
                occurrence["count_unit"],
            )

            if (
                occurrence_id,
                occurrence_profile,
                matching_supported,
                count_unit,
            ) != expected_occurrence:
                raise RuntimeError(
                    "Membership occurrence metadata disagrees with view"
                )

            if matching_supported:
                previous_owner = occurrence_owners.setdefault(
                    occurrence_id, case_id_text
                )
                if previous_owner != case_id_text:
                    raise RuntimeError(
                        "One supported occurrence has multiple case owners"
                    )

            alerts.append(document)
            view_refs[record_id] = view_id

        cases.append({
            "case_id": case_id_text,
            "revision": case_revision,
            "status": case_status,
            "alerts": alerts,
        })

    snapshot = {
        "revision": routing_revision,
        "complete": True,
        "cases": cases,
    }
    if include_closed:
        snapshot["includes_closed_cases"] = True
    return {
        "snapshot": snapshot,
        "view_refs": view_refs,
    }


def assert_snapshot_current(connection, expected_bundle):
    """Reject a changed snapshot before applying a routing decision.

    Rebuild under the routing lock, checking both case state and retained
    evidence-view references. Do not pass a bundle across transactions
    and assume that its old revision is still current.
    """
    current_bundle = build_locked_snapshot(
        connection,
        include_closed=expected_bundle["snapshot"].get(
            "includes_closed_cases", False
        ),
    )

    if current_bundle != expected_bundle:
        raise RuntimeError(
            "Case snapshot changed; recompute the association decision"
        )


def advance_routing_revision(connection, *, expected_revision):
    """Advance the revision inside the caller's case-changing transaction.

    The caller must already hold the routing lock acquired by
    build_locked_snapshot().
    """
    require_transaction(connection)

    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("Expected a nonnegative integer revision")

    row = connection.execute(
        """
        UPDATE investigation.routing_state
        SET revision = revision + 1,
            updated_at = CURRENT_TIMESTAMP
        WHERE singleton_id = 1
          AND revision = %s
        RETURNING revision
        """,
        (expected_revision,),
    ).fetchone()

    if row is None:
        raise RuntimeError(
            "Routing revision changed; transaction must be rolled back"
        )

    return row[0]