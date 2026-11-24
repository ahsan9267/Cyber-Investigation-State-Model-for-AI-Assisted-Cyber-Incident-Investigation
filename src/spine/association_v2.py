"""Candidate association and session-conflict review; isolated prototype v2."""

import argparse
from copy import deepcopy
import getpass
import json
from pathlib import Path
import uuid

from spine.association_prototype import (
    DATABASE, SCOPE, audit, digest, observe, seconds,
)

POLICY = {"version": "auth_case/0.2.0", "gap_seconds": 3600,
          "maximum_span_seconds": 7200, "automatic_membership": "candidate_only"}
TABLE = "public.spine_case_prototype_v2"


def empty_state():
    return {"version": 2, "policy": deepcopy(POLICY), "revision": 0,
            "evidence": {}, "occurrences": {}, "cases": {}, "decisions": {},
            "deferred": [], "history": [], "session_conflicts": {}}


def conflict_index(state):
    sessions = {}
    for oid, occ in state["occurrences"].items():
        # Scope session identifiers to dataset, agent, host and service.
        # A changed username/address must not hide a session identity conflict.
        key = occ["key"][:4] + [occ["session"]]
        sessions.setdefault(digest(key), []).append(oid)
    conflicts = {}
    for sid, ids in sessions.items():
        records = [state["occurrences"][oid] for oid in ids]
        signatures = {(tuple(o["key"]), o["time"], o["outcome"],
                       o["reported_failed_attempts"]) for o in records}
        if len(signatures) > 1:
            conflicts[sid] = {"occurrence_ids": sorted(ids),
                "reason": "inconsistent_terminal_reports_or_session_id_reuse",
                "status": "unresolved", "analyst_review_required": True}
    return conflicts


def reassess(state):
    previous = deepcopy(state["decisions"])
    conflicts = conflict_index(state)
    for sid, details in conflicts.items():
        if state["session_conflicts"].get(sid) != details:
            audit(state, "session_conflict_detected", session_key=sid, **details)
    state["session_conflicts"] = conflicts
    blocked = {oid for c in conflicts.values() for oid in c["occurrence_ids"]}
    case_ids = list(state["cases"])
    decisions = {}
    supports = {cid: [] for cid in case_ids}

    def decision(occ, status, reason, candidates):
        decisions[occ["id"]] = {"status": status, "reason": reason,
            "candidate_case_ids": sorted(candidates), "policy": POLICY["version"]}

    for case in state["cases"].values():
        case["candidate_occurrence_ids"] = []
        case["conflicted_occurrence_ids"] = []
        case["confirmed_incident"] = False
        case["status"] = "analyst_review_required"

    ordered = sorted(state["occurrences"].values(),
        key=lambda o: (o["outcome"] != "failure", o["time"], o["id"]))
    for occ in ordered:
        oid = occ["id"]
        prior = previous.get(oid, {}).get("candidate_case_ids", [])
        anchors = [cid for cid, c in state["cases"].items()
                   if c["anchor_occurrence_id"] == oid]
        if oid in blocked:
            decision(occ, "pending_review", "session_conflict", prior + anchors)
            continue
        if anchors:
            decision(occ, "candidate", "failure_observation_anchors_hypothesis", anchors)
            supports[anchors[0]].append(oid)
            continue

        eligible, uncertain = [], []
        for cid, case in state["cases"].items():
            if case["key"] != occ["key"]:
                continue
            anchor = state["occurrences"][case["anchor_occurrence_id"]]
            if anchor["id"] in blocked:
                if (cid in prior or abs(occ["time"] - anchor["time"])
                        <= POLICY["maximum_span_seconds"]):
                    uncertain.append(cid)
                continue
            if occ["outcome"] == "failure":
                times = [anchor["time"]]
            else:
                times = [state["occurrences"][x]["time"] for x in supports[cid]]
                if not times:
                    continue
            near = min(abs(occ["time"] - t) for t in times) <= POLICY["gap_seconds"]
            ordered_ok = occ["outcome"] == "failure" or occ["time"] >= min(times)
            span = max(times + [occ["time"]]) - min(times + [occ["time"]])
            if near and ordered_ok and span <= POLICY["maximum_span_seconds"]:
                eligible.append(cid)
        if uncertain or len(eligible) > 1:
            decision(occ, "pending_review", "conflicted_anchor_or_multiple_cases",
                     sorted(set(eligible + uncertain)))
        elif eligible:
            decision(occ, "candidate", "context_and_time_only_causality_unresolved", eligible)
            if occ["outcome"] == "failure":
                supports[eligible[0]].append(oid)
        elif occ["outcome"] == "success":
            decision(occ, "unassigned", "no_eligible_failure_hypothesis", [])
        elif prior:
            # Do not silently create a replacement case for evidence whose
            # previous hypothesis lost support during reassessment.
            decision(occ, "pending_review", "previous_hypothesis_requires_reassessment", prior)
        else:
            cid = str(uuid.uuid4())
            state["cases"][cid] = {"case_id": cid, "key": occ["key"],
                "anchor_occurrence_id": oid, "candidate_occurrence_ids": [],
                "conflicted_occurrence_ids": [], "confirmed_incident": False,
                "status": "analyst_review_required"}
            supports[cid] = [oid]
            decision(occ, "candidate", "failure_observation_anchors_hypothesis", [cid])
            audit(state, "case_created", case_id=cid, trigger_occurrence_id=oid)

    for oid, value in decisions.items():
        value["candidate_case_ids"] = sorted(set(value["candidate_case_ids"]))
        if previous.get(oid) != value:
            audit(state, "association_reassessed", occurrence_id=oid,
                  previous_decision=previous.get(oid), current_decision=value)
        for cid in value["candidate_case_ids"]:
            case = state["cases"][cid]
            if value["status"] == "candidate":
                case["candidate_occurrence_ids"].append(oid)
            elif value["status"] == "pending_review":
                case["status"] = "needs_reassessment"
            if oid in blocked:
                case["conflicted_occurrence_ids"].append(oid)
    state["decisions"] = decisions
    for case in state["cases"].values():
        case["candidate_occurrence_ids"] = sorted(set(case["candidate_occurrence_ids"]))
        case["conflicted_occurrence_ids"] = sorted(set(case["conflicted_occurrence_ids"]))


def migrate_state(original):
    if original["version"] != 1 or original["policy"]["version"] != "auth_case/0.1.0":
        raise ValueError("Expected the v0.1 baseline")
    result = deepcopy(original)
    result.update(version=2, policy=deepcopy(POLICY), session_conflicts={},
                  parent_state_sha256=digest(original))
    for cid, case in result["cases"].items():
        trigger = next(h["trigger_occurrence_id"] for h in result["history"]
                       if h["action"] == "case_created" and h["case_id"] == cid)
        case["anchor_occurrence_id"] = trigger
        case["legacy_occurrence_ids"] = case.pop("occurrence_ids")
    audit(result, "policy_migration", previous_policy=original["policy"],
          current_policy=POLICY, parent_state_sha256=digest(original))
    reassess(result)
    result["revision"] += 1
    if result["evidence"] != original["evidence"] or result["history"][:len(original["history"])] != original["history"]:
        raise RuntimeError("Migration changed original evidence or history")
    return result


def apply_records(state, records):
    from spine.storage import validate_record
    if state["version"] != 2 or state["policy"] != POLICY:
        raise ValueError("Wrong state/policy version")
    counts = {"inserted": 0, "replay": 0}
    for record in records:
        validate_record(record)
        if record["provenance"]["source_scope"] != SCOPE:
            raise ValueError("Unexpected evidence scope")
        rid = record["record_id"]
        if rid in state["evidence"]:
            if state["evidence"][rid]["raw"] != record["raw"]:
                raise ValueError("Evidence identity conflict; transaction must roll back")
            counts["replay"] += 1
            continue
        state["evidence"][rid] = deepcopy(record)
        counts["inserted"] += 1
        occ = observe(record)
        if occ is None:
            state["deferred"].append(rid)
            continue
        existing = state["occurrences"].setdefault(occ["id"], occ)
        if any(existing[k] != occ[k] for k in occ if k != "evidence_ids"):
            raise ValueError("Inconsistent occurrence annotations")
        existing["evidence_ids"].append(rid)
        audit(state, "occurrence_evidence_added", occurrence_id=occ["id"], evidence_id=rid)
    if counts["inserted"]:
        reassess(state)
        state["revision"] += 1
        audit(state, "import_completed", inserted=counts["inserted"])
    return counts


def report(state):
    cases = []
    for case in state["cases"].values():
        members = [state["occurrences"][x] for x in case["candidate_occurrence_ids"]]
        failed = [o for o in members if o["outcome"] == "failure"]
        success = [o for o in members if o["outcome"] == "success"]
        cases.append({"case_id": case["case_id"], "account": case["key"][4],
            "status": case["status"], "confirmed_incident": False,
            "association_basis": "candidate context/time match; causal membership unresolved",
            "candidate_failure_session_messages": len(failed),
            "candidate_success_sessions": len(success),
            "candidate_source_reported_failed_attempts": sum(o["reported_failed_attempts"] for o in failed),
            "candidate_evidence_representations": sum(len(o["evidence_ids"]) for o in members),
            "conflicted_occurrence_ids": case["conflicted_occurrence_ids"],
            "candidate_evidence_ids": sorted({r for o in members for r in o["evidence_ids"]}),
            "uncertainties": ["Capture completeness is not established.",
                "Same context and timing do not establish a common actor or incident.",
                "Failure attempt counts are source-reported summaries."]})
    statuses = {}
    for d in state["decisions"].values():
        statuses[d["status"]] = statuses.get(d["status"], 0) + 1
    return {"policy": POLICY, "revision": state["revision"],
        "evidence_records": len(state["evidence"]), "session_message_groups": len(state["occurrences"]),
        "deferred_records": len(state["deferred"]), "decision_counts": statuses,
        "session_conflicts": state["session_conflicts"], "case_count": len(cases),
        "history_entries": len(state["history"]), "state_sha256": digest(state), "cases": cases}


def main():
    import psycopg
    from psycopg.types.json import Json
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("command", choices=("migrate", "apply", "show"))
    p.add_argument("--input", type=Path)
    p.add_argument("--expected-baseline")
    args = p.parse_args()
    if args.command == "migrate" and not args.expected_baseline:
        p.error("migrate requires --expected-baseline")
    if args.command == "apply" and args.input is None:
        p.error("apply requires --input")
    if args.command != "apply" and args.input is not None:
        p.error("--input is only valid with apply")
    if args.command != "migrate" and args.expected_baseline is not None:
        p.error("--expected-baseline is only valid with migrate")
    records = []
    if args.command == "apply":
        with args.input.open(encoding="utf-8") as f:
            records = [json.loads(line) for line in f]
    password = getpass.getpass("spine_app password for isolated test database: ")
    with psycopg.connect(host="127.0.0.1", port=5432, dbname=DATABASE,
            user="spine_app", password=password, autocommit=True, connect_timeout=5) as conn:
        if conn.execute("SELECT current_database()").fetchone()[0] != DATABASE:
            raise RuntimeError("Unexpected database")
        counts = None
        with conn.transaction():
            conn.execute("SET LOCAL lock_timeout = '5s'")
            if args.command != "show":
                conn.execute("SELECT pg_advisory_xact_lock(20261005, 3)")
            if args.command == "migrate":
                original = conn.execute("SELECT document FROM public.spine_case_prototype WHERE singleton=1").fetchone()[0]
                if digest(original) != args.expected_baseline:
                    raise ValueError("Baseline hash differs; migration cancelled")
                conn.execute("CREATE TABLE IF NOT EXISTS public.spine_case_prototype_v2 (singleton INTEGER PRIMARY KEY CHECK(singleton=1), document JSON NOT NULL)")
                if conn.execute("SELECT 1 FROM public.spine_case_prototype_v2").fetchone():
                    raise ValueError("v2 already exists; use show/apply, do not reset it")
                state = migrate_state(original)
                conn.execute("INSERT INTO public.spine_case_prototype_v2 VALUES (1,%s)", (Json(state),))
            else:
                state = conn.execute("SELECT document FROM public.spine_case_prototype_v2 WHERE singleton=1" +
                                     (" FOR UPDATE" if args.command == "apply" else "")).fetchone()[0]
                if state["policy"] != POLICY:
                    raise ValueError("Policy mismatch")
                if args.command == "apply":
                    counts = apply_records(state, records)
                    if counts["inserted"]:
                        conn.execute("UPDATE public.spine_case_prototype_v2 SET document=%s WHERE singleton=1", (Json(state),))
        result = report(state)
        if counts is not None:
            result["import"] = counts
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
