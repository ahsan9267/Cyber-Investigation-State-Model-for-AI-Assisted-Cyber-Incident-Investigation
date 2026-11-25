"""Controlled diagnostics; no policy changes or persistent test writes."""

import argparse
import getpass
import json

from spine.ait_dataset import SCOPE, adapt_annotations
from spine.association_prototype import (
    DATABASE,
    apply_records,
    digest,
    empty_state,
    observe,
    report,
)
from spine.envelope import build_envelope


def fixture(
    identity,
    clock,
    *,
    account="control-user",
    session="A",
    success=False,
):
    body = (
        "Login: "
        if success
        else "Disconnected (auth failed, 3 attempts in 14 secs): "
    )

    payload = {
        "id": identity,
        "_test_fixture": "synthetic; not an AIT recording",
        "@timestamp": f"2022-01-24T{clock}Z",
        "agent": {"id": "synthetic-agent"},
        "predecoder": {"hostname": "synthetic-mail"},
        "decoder": {"name": "dovecot"},
        "full_log": (
            f"Jan 24 {clock} synthetic-mail dovecot: imap-login: "
            + body
            + f"user=<{account}>, method=PLAIN, rip=192.0.2.10, "
            + f"lip=192.0.2.20, TLS, session=<{session}>"
        ),
    }

    # The prototype requires this adapter namespace. Fixtures remain
    # in memory or in an uncommitted temporary table.
    record = build_envelope(
        raw_text=json.dumps(payload),
        source="wazuh",
        collector="wazuh_alerts",
        record_kind="alert",
        source_scope=SCOPE,
        source_record_id=identity,
        observed_time="2026-10-05T00:00:00Z",
    )
    record["agent"] = payload["agent"]
    return adapt_annotations(record)


def policy_checks():
    results = []

    failed = fixture("separate-1", "09:00:00")
    unrelated = fixture(
        "separate-2",
        "09:30:00",
        session="B",
        success=True,
    )

    # Controlled truth: independent actors/tasks. This label is kept
    # outside engine input; the observed context is the same.
    state = empty_state()
    apply_records(state, [failed, unrelated])
    decision = state["decisions"][observe(unrelated)["id"]]

    results.append({
        "test": "unrelated_activity_with_identical_context",
        "required": (
            "Keep causal membership unresolved; "
            "candidate/unassigned is acceptable"
        ),
        "observed_status": decision["status"],
        "passes_conservative_membership_requirement": (
            decision["status"] != "linked"
        ),
        "interpretation": (
            "Identity and time alone cannot distinguish "
            "the controlled actors."
        ),
    })

    state = empty_state()
    apply_records(state, [
        fixture("ambiguous-1", "09:00:00"),
        fixture("ambiguous-2", "11:00:00", session="B"),
    ])
    bridge = fixture("ambiguous-3", "10:00:00", session="C")
    apply_records(state, [bridge])
    decision = state["decisions"][observe(bridge)["id"]]

    results.append({
        "test": "two_eligible_cases",
        "passes": (
            decision["status"] == "pending_review"
            and len(decision["candidate_case_ids"]) == 2
            and len(state["cases"]) == 2
        ),
        "observed_status": decision["status"],
        "candidate_count": len(decision["candidate_case_ids"]),
    })

    state = empty_state()
    disconnected = fixture(
        "contradiction-1", "09:00:00", session="terminal-A"
    )
    logged_in = fixture(
        "contradiction-2",
        "09:00:00",
        session="terminal-A",
        success=True,
    )

    apply_records(state, [disconnected])
    apply_records(state, [logged_in])

    statuses = [
        state["decisions"][observe(record)["id"]]["status"]
        for record in (disconnected, logged_in)
    ]
    case = report(state)["cases"][0]

    # Controlled definition: inconsistent terminal reports for one
    # session, not failures and success in different sessions.
    results.append({
        "test": "late_conflicting_terminal_session_reports",
        "required": (
            "Withhold conflicting counting/association "
            "and flag the conflict"
        ),
        "observed_statuses": statuses,
        "reported_failure_groups": case["failure_session_messages"],
        "reported_success_groups": case["success_sessions"],
        "passes_withholding_requirement": (
            "pending_review" in statuses
        ),
        "interpretation": (
            "The v0.1 engine has no explicit "
            "session-conflict reassessment."
        ),
    })

    return results


def rollback_check():
    import psycopg
    from psycopg.types.json import Json

    class InjectedFailure(Exception):
        pass

    password = getpass.getpass(
        "spine_app password for isolated test database: "
    )

    with psycopg.connect(
        host="127.0.0.1",
        port=5432,
        dbname=DATABASE,
        user="spine_app",
        password=password,
        autocommit=True,
        connect_timeout=5,
    ) as connection:
        actual_database = connection.execute(
            "SELECT current_database()"
        ).fetchone()[0]

        if actual_database != DATABASE:
            raise RuntimeError("Unexpected database")

        with connection.transaction(force_rollback=True):
            connection.execute("SET LOCAL lock_timeout = '5s'")
            connection.execute(
                "SELECT pg_advisory_xact_lock(20261005, 3)"
            )

            original = connection.execute(
                """
                SELECT document
                FROM public.spine_case_prototype
                WHERE singleton = 1
                """
            ).fetchone()[0]
            baseline_hash = digest(original)

            connection.execute(
                """
                CREATE TEMP TABLE association_rollback_probe (
                    id INTEGER PRIMARY KEY,
                    document JSON NOT NULL
                ) ON COMMIT DROP
                """
            )

            baseline = empty_state()
            connection.execute(
                "INSERT INTO association_rollback_probe VALUES (1, %s)",
                (Json(baseline),),
            )

            try:
                with connection.transaction():
                    working = empty_state()
                    apply_records(working, [
                        fixture("rollback-1", "09:00:00")
                    ])

                    connection.execute(
                        """
                        UPDATE association_rollback_probe
                        SET document = %s
                        WHERE id = 1
                        """,
                        (Json(working),),
                    )

                    inside = connection.execute(
                        """
                        SELECT document
                        FROM association_rollback_probe
                        WHERE id = 1
                        """
                    ).fetchone()[0]

                    if digest(inside) == digest(baseline):
                        raise RuntimeError(
                            "Probe did not write its test state"
                        )

                    raise InjectedFailure(
                        "Simulated failure after database write"
                    )

            except InjectedFailure:
                pass

            restored = connection.execute(
                """
                SELECT document
                FROM association_rollback_probe
                WHERE id = 1
                """
            ).fetchone()[0]

            after = connection.execute(
                """
                SELECT document
                FROM public.spine_case_prototype
                WHERE singleton = 1
                """
            ).fetchone()[0]

            result = {
                "temporary_state_rollback_passed": restored == baseline,
                "saved_ait_state_unchanged": (
                    digest(after) == baseline_hash
                ),
                "saved_ait_state_sha256": baseline_hash,
                "scope": (
                    "temporary-table savepoint rollback; "
                    "not a process-crash test"
                ),
            }

            if not all(result[key] for key in (
                "temporary_state_rollback_passed",
                "saved_ait_state_unchanged",
            )):
                raise RuntimeError("Rollback verification failed")

        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-check", action="store_true")
    args = parser.parse_args()

    result = {"synthetic_policy_checks": policy_checks()}

    if args.database_check:
        result["postgresql_check"] = rollback_check()

    print(json.dumps(result, indent=2))

    # Exit code zero means diagnostics completed.
    # Read each individual requirement's result.


if __name__ == "__main__":
    main()