"""Offline, deterministic case prototype in spine_association_test only."""

import argparse
from copy import deepcopy
from datetime import datetime, timezone
import getpass
import hashlib
import json
from pathlib import Path
import uuid

DATABASE = "spine_association_test"
SCOPE = "dataset/ait-ads/8263181/russellmitchell"

POLICY = {
    "version": "auth_case/0.1.0",
    "gap_seconds": 3600,
    "maximum_span_seconds": 7200,
}


def digest(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def seconds(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        raise ValueError("A timezone is required")
    return dt.timestamp()


def empty_state():
    return {
        "version": 1,
        "policy": deepcopy(POLICY),
        "revision": 0,
        "evidence": {},
        "occurrences": {},
        "cases": {},
        "decisions": {},
        "deferred": [],
        "history": [],
    }


def audit(state, action, **details):
    state["history"].append({
        "sequence": len(state["history"]) + 1,
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "action": action,
        **details,
    })


def observe(record):
    """Exact message grouping; failures can summarize many attempts."""
    auth = record["attributes"].get("authentication")

    if (
        not auth
        or record.get("event", {}).get("provider") != "dovecot"
    ):
        return None

    source = json.loads(record["raw"]["text"])

    key = [
        record["provenance"]["source_scope"],
        record["agent"].get("id"),
        record["host"].get("name"),
        auth.get("service"),
        auth.get("target", {}).get("name"),
        auth.get("source_ip"),
        auth.get("destination_ip"),
    ]

    if not all(
        isinstance(value, str) and value.strip()
        for value in key
    ):
        return None

    session = auth.get("session_id")
    outcome = auth.get("outcome")
    event_time = record.get("event_time", {}).get("utc")
    log = source.get("full_log")

    if (
        not session
        or outcome not in ("failure", "success")
        or not log
    ):
        return None

    when = seconds(event_time)
    attempts = auth.get("reported_failed_attempts")

    if outcome == "failure" and (
        type(attempts) is not int or attempts < 1
    ):
        return None

    identity = [key, session, event_time, outcome, log]

    return {
        "id": digest(identity),
        "key": key,
        "session": session,
        "time": when,
        "event_time": event_time,
        "outcome": outcome,
        "reported_failed_attempts": attempts,
        "evidence_ids": [],
    }


def decide(state, occurrence, status, reason, candidates):
    value = {
        "status": status,
        "reason": reason,
        "candidate_case_ids": sorted(candidates),
        "policy": POLICY["version"],
    }

    oid = occurrence["id"]

    if state["decisions"].get(oid) != value:
        state["decisions"][oid] = value
        audit(
            state,
            "association_decision",
            occurrence_id=oid,
            **value,
        )


def route(state):
    # Revisit unassigned successes after failures, including successes
    # received in an earlier import. Existing assignments remain stable.
    ordered = sorted(
        state["occurrences"].values(),
        key=lambda item: (
            item["outcome"] != "failure",
            item["time"],
            item["id"],
        ),
    )

    for occurrence in ordered:
        oid = occurrence["id"]

        if (
            state["decisions"].get(oid, {}).get("status")
            == "linked"
        ):
            continue

        candidates = []

        for cid, case in state["cases"].items():
            if case["key"] != occurrence["key"]:
                continue

            members = [
                state["occurrences"][member_id]
                for member_id in case["occurrence_ids"]
            ]
            times = [member["time"] for member in members]
            failures = [
                member["time"]
                for member in members
                if member["outcome"] == "failure"
            ]

            near_failure = (
                min(
                    abs(occurrence["time"] - time)
                    for time in failures
                )
                <= POLICY["gap_seconds"]
            )

            combined_times = times + [occurrence["time"]]
            within_span = (
                max(combined_times) - min(combined_times)
                <= POLICY["maximum_span_seconds"]
            )

            valid_order = (
                occurrence["outcome"] == "failure"
                or occurrence["time"] >= min(failures)
            )

            if near_failure and within_span and valid_order:
                candidates.append(cid)

        if len(candidates) > 1:
            decide(
                state,
                occurrence,
                "pending_review",
                "multiple_eligible_cases",
                candidates,
            )
            continue

        if not candidates:
            if occurrence["outcome"] == "success":
                decide(
                    state,
                    occurrence,
                    "unassigned",
                    "no_eligible_failure_case",
                    [],
                )
                continue

            cid = str(uuid.uuid4())
            state["cases"][cid] = {
                "case_id": cid,
                "key": occurrence["key"],
                "occurrence_ids": [],
                "status": "analyst_review_required",
                "confirmed_incident": False,
                "uncertainties": [
                    "Dataset capture completeness is not established.",
                    "Shared account and timing do not establish "
                    "a common actor or compromise.",
                    "Failed attempts are source-reported session totals.",
                ],
            }

            audit(
                state,
                "case_created",
                case_id=cid,
                trigger_occurrence_id=oid,
            )
            candidates = [cid]

        cid = candidates[0]
        state["cases"][cid]["occurrence_ids"].append(oid)

        decide(
            state,
            occurrence,
            "linked",
            "same_scoped_account_service_endpoints_and_time",
            [cid],
        )

        audit(
            state,
            "case_occurrence_added",
            case_id=cid,
            occurrence_id=oid,
        )


def apply_records(state, records):
    """Caller supplies the transaction; original evidence stays unchanged."""
    from spine.storage import validate_record

    if state["version"] != 1 or state["policy"] != POLICY:
        raise ValueError(
            "State/policy version mismatch; explicit migration required"
        )

    counts = {"inserted": 0, "replay": 0}

    for record in records:
        validate_record(record)

        if record["provenance"]["source_scope"] != SCOPE:
            raise ValueError(
                "Only the isolated AIT source scope is accepted"
            )

        rid = record["record_id"]
        previous = state["evidence"].get(rid)

        if previous is not None:
            if previous["raw"] != record["raw"]:
                raise ValueError(
                    "Evidence identity conflict; import must roll back"
                )

            counts["replay"] += 1
            continue

        state["evidence"][rid] = deepcopy(record)
        counts["inserted"] += 1
        occurrence = observe(record)

        if occurrence is None:
            state["deferred"].append(rid)
            continue

        oid = occurrence["id"]
        existing = state["occurrences"].setdefault(oid, occurrence)

        if any(
            existing[key] != occurrence[key]
            for key in occurrence
            if key != "evidence_ids"
        ):
            raise ValueError(
                "Conflicting occurrence annotations; import must roll back"
            )

        existing["evidence_ids"].append(rid)

        audit(
            state,
            "occurrence_evidence_added",
            occurrence_id=oid,
            evidence_id=rid,
        )

    if counts["inserted"]:
        route(state)
        state["revision"] += 1
        audit(
            state,
            "import_completed",
            inserted=counts["inserted"],
            revision=state["revision"],
        )

    return counts


def report(state):
    cases = []

    for case in state["cases"].values():
        occurrences = [
            state["occurrences"][oid]
            for oid in case["occurrence_ids"]
        ]
        failures = [
            item for item in occurrences
            if item["outcome"] == "failure"
        ]
        successes = [
            item for item in occurrences
            if item["outcome"] == "success"
        ]

        finding = (
            "Failed sessions followed by successful sessions; "
            "cause unconfirmed."
            if successes
            else "Failed sessions observed; cause unconfirmed."
        )

        cases.append({
            **case,
            "account": case["key"][4],
            "failure_session_messages": len(failures),
            "success_sessions": len(successes),
            "source_reported_failed_attempts": sum(
                item["reported_failed_attempts"]
                for item in failures
            ),
            "evidence_representations": sum(
                len(item["evidence_ids"])
                for item in occurrences
            ),
            "finding": finding,
            "evidence_ids": sorted({
                rid
                for item in occurrences
                for rid in item["evidence_ids"]
            }),
        })

    return {
        "database": DATABASE,
        "revision": state["revision"],
        "evidence_records": len(state["evidence"]),
        "session_message_groups": len(state["occurrences"]),
        "deferred_records": len(state["deferred"]),
        "case_count": len(cases),
        "unassigned_or_ambiguous_groups": sum(
            decision["status"] != "linked"
            for decision in state["decisions"].values()
        ),
        "history_entries": len(state["history"]),
        "state_sha256": digest(state),
        "cases": cases,
    }


def main():
    import psycopg
    from psycopg.types.json import Json

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("apply", "show"))
    parser.add_argument("--input", type=Path)
    parser.add_argument(
        "--before",
        help="Exclusive event-time cutoff for staged replay",
    )
    args = parser.parse_args()

    if args.command == "apply" and args.input is None:
        parser.error("apply requires --input")

    if args.command == "show" and (args.input or args.before):
        parser.error("show does not accept input/cutoff")

    records = []

    if args.command == "apply":
        cutoff = seconds(args.before) if args.before else None

        with args.input.open(encoding="utf-8") as stream:
            for line in stream:
                record = json.loads(line)
                stamp = record["attributes"]["dataset_time"]["value"]["utc"]

                if cutoff is None or seconds(stamp) < cutoff:
                    records.append(record)

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

        if args.command == "show":
            row = connection.execute(
                """
                SELECT document
                FROM public.spine_case_prototype
                WHERE singleton = 1
                """
            ).fetchone()

            if row is None:
                raise RuntimeError("Prototype not initialized")

            print(json.dumps(report(row[0]), indent=2))
            return

        # Serialize the small prototype. Evidence, decisions and history
        # commit together, including initial table creation.
        with connection.transaction():
            connection.execute(
                "SELECT pg_advisory_xact_lock(20261005, 3)"
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS public.spine_case_prototype (
                    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
                    document JSON NOT NULL
                )
                """
            )
            connection.execute(
                """
                INSERT INTO public.spine_case_prototype
                VALUES (1, %s)
                ON CONFLICT (singleton) DO NOTHING
                """,
                (Json(empty_state()),),
            )

            state = connection.execute(
                """
                SELECT document
                FROM public.spine_case_prototype
                WHERE singleton = 1
                FOR UPDATE
                """
            ).fetchone()[0]

            counts = apply_records(state, records)

            if counts["inserted"]:
                connection.execute(
                    """
                    UPDATE public.spine_case_prototype
                    SET document = %s
                    WHERE singleton = 1
                    """,
                    (Json(state),),
                )

        print(json.dumps({
            "import": counts,
            **report(state),
        }, indent=2))


if __name__ == "__main__":
    main()