"""Lossless snapshot storage using existing immutable evidence views.

Only the physical JSON representation changes. Association inputs, policy,
snapshot fingerprints and exported historical handoffs keep their original
meaning. Legacy full-document rows remain readable.
"""

from copy import deepcopy

from spine.association import fingerprint
from spine.manager_views import read_evidence_views, validate_hash


STORAGE_FORMAT = "spine_snapshot_view_refs/1"
_FIELDS = {"storage_format", "snapshot", "snapshot_sha256", "view_refs_sha256"}


def _validate_snapshot(snapshot, view_refs, *, references):
    if not isinstance(snapshot, dict) or snapshot.get("complete") is not True:
        raise ValueError("A complete snapshot is required")
    if type(snapshot.get("revision")) is not int or snapshot["revision"] < 0:
        raise ValueError("Invalid snapshot revision")
    if not isinstance(snapshot.get("cases"), list) or not isinstance(view_refs, dict):
        raise ValueError("Invalid snapshot cases or view references")
    seen_records, seen_cases = set(), set()
    for case in snapshot["cases"]:
        if not isinstance(case, dict) or not isinstance(case.get("case_id"), str):
            raise ValueError("Invalid snapshot case")
        if case["case_id"] in seen_cases:
            raise ValueError("Duplicate snapshot case")
        seen_cases.add(case["case_id"])
        if type(case.get("revision")) is not int or case["revision"] < 1:
            raise ValueError("Invalid case revision")
        if case.get("status") not in ("active", "closed"):
            raise ValueError("Invalid case status")
        if not isinstance(case.get("alerts"), list) or not case["alerts"]:
            raise ValueError("A retained case requires alert memberships")
        for alert in case["alerts"]:
            if references:
                record_id = alert
            else:
                if not isinstance(alert, dict):
                    raise ValueError("Invalid retained alert document")
                record_id = alert.get("record_id")
            validate_hash(record_id, "snapshot record ID")
            if record_id in seen_records:
                raise ValueError("Duplicate snapshot record ownership")
            seen_records.add(record_id)
            if record_id not in view_refs:
                raise ValueError("Missing snapshot evidence-view reference")
            validate_hash(view_refs[record_id], "snapshot evidence-view ID")
    if seen_records != set(view_refs):
        raise ValueError("Unexpected snapshot evidence-view references")


def pack_snapshot(snapshot, view_refs):
    """Replace copied alert documents with their ordered record identities."""
    _validate_snapshot(snapshot, view_refs, references=False)
    compact = {key: deepcopy(value) for key, value in snapshot.items() if key != "cases"}
    compact["cases"] = []
    for case in snapshot["cases"]:
        saved_case = {key: deepcopy(value) for key, value in case.items() if key != "alerts"}
        saved_case["alerts"] = [alert["record_id"] for alert in case["alerts"]]
        compact["cases"].append(saved_case)
    return {
        "storage_format": STORAGE_FORMAT,
        "snapshot": compact,
        "snapshot_sha256": fingerprint(snapshot),
        "view_refs_sha256": fingerprint(view_refs),
    }


def read_stored_snapshot(connection, stored, view_refs, *, expected_snapshot_hash=None):
    """Reconstruct exact historical inputs, never today's case memberships.

    The existing evidence-view reader validates retained document identity,
    annotation configuration and view fingerprint. Full snapshot and mapping
    fingerprints also bind the compact representation to those exact views.
    """
    if not isinstance(stored, dict):
        raise ValueError("Invalid stored snapshot")
    if "storage_format" not in stored:
        _validate_snapshot(stored, view_refs, references=False)
        result = deepcopy(stored)
    else:
        if set(stored) != _FIELDS or stored["storage_format"] != STORAGE_FORMAT:
            raise ValueError("Unsupported snapshot storage format")
        validate_hash(stored["snapshot_sha256"], "stored snapshot hash")
        validate_hash(stored["view_refs_sha256"], "stored view-reference hash")
        if fingerprint(view_refs) != stored["view_refs_sha256"]:
            raise RuntimeError("Stored snapshot view-reference fingerprint mismatch")
        compact = stored["snapshot"]
        _validate_snapshot(compact, view_refs, references=True)
        views = read_evidence_views(connection, view_refs.values())
        result = deepcopy(compact)
        for case in result["cases"]:
            alerts = []
            for record_id in case["alerts"]:
                view = views[view_refs[record_id]]
                if view["record_id"] != record_id:
                    raise RuntimeError("Snapshot reference points to a different record")
                alerts.append(deepcopy(view["document"]))
            case["alerts"] = alerts
        if fingerprint(result) != stored["snapshot_sha256"]:
            raise RuntimeError("Reconstructed snapshot fingerprint mismatch")
    if expected_snapshot_hash is not None:
        validate_hash(expected_snapshot_hash, "expected snapshot hash")
        if fingerprint({"revision": result["revision"], "cases": result["cases"]}) != expected_snapshot_hash:
            raise RuntimeError("Snapshot does not match its decision or assessment")
    return result
