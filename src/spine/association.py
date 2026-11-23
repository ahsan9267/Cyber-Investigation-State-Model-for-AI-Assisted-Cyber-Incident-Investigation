"""Step 3 routing only. No case creation, database writes or investigation."""

from copy import deepcopy
from datetime import datetime
import hashlib
import ipaddress
import json
import uuid


POLICY = {
    "version": "alert_association/1.6.0",
    "authentication_context": "possible_relationship_only",
    "gap_seconds": 3600,
    "maximum_case_span_seconds": 7200,
    "ambiguity": "new_case",
    "episode_limits_seconds": {
        "windows_remote_logon_episode": 600,
        "service_configured_command_execution": 300,
        "dns_alert_episode": 60,
    },
    "profiles": [
        "authentication_context",
        "same_process_guid",
        "direct_parent_child_process",
        "same_sensor_flow",
        "windows_remote_logon_episode",
        "service_configured_command_execution",
        "dns_alert_episode",
    ],
}


def fingerprint(value):
    data = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    )
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def text(value):
    if isinstance(value, str) and value.strip() and value != "-":
        return value
    return None


def timestamp(record):
    value = (record.get("event_time") or {}).get("utc")
    if value is None:
        return None

    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.timestamp()
    except (ValueError, TypeError, AttributeError):
        return None


def address(value):
    try:
        if isinstance(value, str):
            return str(ipaddress.ip_address(value))
        return None
    except ValueError:
        return None


def host_identity(record):
    mapped = {
        entity.get("details", {})
        .get("configured_host_identity", {})
        .get("canonical_host_id")
        for entity in record.get("entities", [])
        if entity.get("type") == "host"
        and entity.get("role") == "event_host"
    } - {None}

    if len(mapped) > 1:
        return None

    if mapped:
        return ["configured_host", next(iter(mapped))]

    name = text(record.get("host", {}).get("name"))
    if name is None:
        return None

    # Unmapped names are only comparable within their source context.
    return [
        "source_host",
        record["collector"],
        record["provenance"]["source_scope"],
        record.get("agent", {}).get("id"),
        name,
    ]


def process_guid(value):
    try:
        parsed = uuid.UUID(value) if isinstance(value, str) else None
        return str(parsed) if parsed and parsed.int else None
    except ValueError:
        return None


def session_conflict(left, right):
    """Flag inconsistent Dovecot terminal-session reports conservatively."""
    a = left.get("attributes", {}).get("authentication", {})
    b = right.get("attributes", {}).get("authentication", {})

    if (
        left.get("event", {}).get("provider") != "dovecot"
        or right.get("event", {}).get("provider") != "dovecot"
    ):
        return False

    session = text(a.get("session_id"))
    host = host_identity(left)

    if not (
        session
        and session == b.get("session_id")
        and host is not None
        and host == host_identity(right)
        and a.get("service") == b.get("service")
    ):
        return False

    fields = (
        "target",
        "source_ip",
        "destination_ip",
        "outcome",
        "reported_failed_attempts",
    )
    return (
        any(a.get(key) != b.get(key) for key in fields)
        or timestamp(left) != timestamp(right)
    )


def account_matches(left, right):
    a = left.get("target", {})
    b = right.get("target", {})

    sid_a = text(a.get("sid"))
    sid_b = text(b.get("sid"))
    sid_a = None if sid_a == "S-1-0-0" else sid_a
    sid_b = None if sid_b == "S-1-0-0" else sid_b

    if sid_a and sid_b:
        return sid_a == sid_b

    # Exact comparison avoids inventing aliases or case-folding rules.
    name_a = text(a.get("name"))
    name_b = text(b.get("name"))

    return bool(
        name_a
        and name_a == name_b
        and text(a.get("domain")) == text(b.get("domain"))
    )

def process_relations(left, right):
    """Match a process instance or an explicit direct parent-child edge."""
    host = host_identity(left)

    if host is None or host != host_identity(right):
        return []

    a = left.get("attributes", {}).get("process", {})
    b = right.get("attributes", {}).get("process", {})

    a_guid = process_guid(a.get("guid"))
    b_guid = process_guid(b.get("guid"))
    a_parent = process_guid((a.get("parent") or {}).get("guid"))
    b_parent = process_guid((b.get("parent") or {}).get("guid"))

    if not a_guid or not b_guid:
        return []

    # A process cannot be its own parent.
    if a_parent == a_guid or b_parent == b_guid:
        return []

    if a_guid == b_guid:
        # Conflicting reported parents undermine this relationship.
        if a_parent and b_parent and a_parent != b_parent:
            return []

        return [{
            "rule": "same_process_guid",
            "host": host,
            "process_guid": a_guid,
            "caveat": (
                "Same process does not prove one malicious incident."
            ),
        }]

    a_is_parent = b_parent == a_guid
    b_is_parent = a_parent == b_guid

    # Reject contradictory two-node lineage.
    if a_is_parent and b_is_parent:
        return []

    # Sharing a parent alone does not establish a direct edge.
    if not a_is_parent and not b_is_parent:
        return []

    parent_record, child_record = (
        (left, right) if a_is_parent else (right, left)
    )
    parent_guid, child_guid = (
        (a_guid, b_guid) if a_is_parent else (b_guid, a_guid)
    )

    return [{
        "rule": "direct_parent_child_process",
        "host": host,
        "parent_process_guid": parent_guid,
        "child_process_guid": child_guid,
        "parent_alert_id": parent_record["record_id"],
        "child_alert_id": child_record["record_id"],
        "caveat": (
            "Direct process lineage supports investigation grouping; "
            "it does not establish maliciousness or common incident membership."
        ),
    }]


def sensor_flow_relations(left, right):
    """Compare scoped flow references; this does not identify duplicates."""
    if (
        left.get("event", {}).get("provider") != "suricata"
        or right.get("event", {}).get("provider") != "suricata"
    ):
        return []

    a = left.get("attributes", {}).get("network") or {}
    b = right.get("attributes", {}).get("network") or {}
    if not isinstance(a, dict) or not isinstance(b, dict):
        return []

    def sensor(record):
        return [
            record["collector"],
            record["provenance"]["source_scope"],
            record.get("agent", {}).get("id"),
            record.get("host", {}).get("name"),
        ]

    sensor_a = sensor(left)
    if sensor_a != sensor(right):
        return []

    flow = text(a.get("flow_id"))
    if not flow or flow != text(b.get("flow_id")):
        return []

    interface_a = text(a.get("interface"))
    interface_b = text(b.get("interface"))
    if interface_a != interface_b:
        return []

    protocol = text(a.get("protocol"))
    other_protocol = text(b.get("protocol"))
    if not protocol or not other_protocol:
        return []
    protocol = protocol.upper()
    if protocol != other_protocol.upper():
        return []

    source = address(a.get("source_ip"))
    destination = address(a.get("destination_ip"))
    if (
        source is None
        or destination is None
        or source != address(b.get("source_ip"))
        or destination != address(b.get("destination_ip"))
    ):
        return []

    family = ipaddress.ip_address(source).version
    if family != ipaddress.ip_address(destination).version:
        return []

    ports_a = [a.get("source_port"), a.get("destination_port")]
    ports_b = [b.get("source_port"), b.get("destination_port")]

    if protocol in ("ICMP", "ICMPV6"):
        expected_family = 4 if protocol == "ICMP" else 6
        if (
            family != expected_family
            or interface_a is None
            or any(port is not None for port in ports_a + ports_b)
        ):
            return []
        endpoint_basis = "ordered_ip_pair_without_ports"
    elif protocol in ("TCP", "UDP", "SCTP"):
        if (
            not all(
                type(port) is int and 0 <= port <= 65535
                for port in ports_a + ports_b
            )
            or ports_a != ports_b
        ):
            return []
        endpoint_basis = "ordered_ip_port_pair"
    else:
        return []

    return [{
        "rule": "same_sensor_flow",
        "sensor": sensor_a,
        "interface": interface_a,
        "interface_basis": (
            "matching_reported_interface"
            if interface_a is not None
            else "not_reported_on_either_record"
        ),
        "flow_id": flow,
        "endpoints": [
            source, ports_a[0], destination, ports_a[1], protocol
        ],
        "endpoint_basis": endpoint_basis,
        "caveat": (
            "Source-scoped flow matching is bounded by the time policy; "
            "sensor restart continuity is not established. It supports "
            "operational grouping, not duplicate occurrence identity "
            "or a confirmed incident."
        ),
    }]

def relations(left, right):
    """Return supported relationship rules and their observed values."""
    matches = []

    la = left.get("attributes", {})
    ra = right.get("attributes", {})
    lh = host_identity(left)
    rh = host_identity(right)
    lp = left.get("event", {}).get("provider")
    rp = right.get("event", {}).get("provider")

    if lh is not None and lh == rh:
        a = la.get("authentication", {})
        b = ra.get("authentication", {})

        service_a = [lp, a.get("service"), a.get("logon_type")]
        service_b = [rp, b.get("service"), b.get("logon_type")]

        valid_service = text(lp) and (
            text(a.get("service"))
            or type(a.get("logon_type")) is int
        )
        source = address(a.get("source_ip"))

        if (
            a.get("outcome") in ("success", "failure")
            and b.get("outcome") in ("success", "failure")
            and valid_service
            and service_a == service_b
            and source
            and source == address(b.get("source_ip"))
            and address(a.get("destination_ip"))
            == address(b.get("destination_ip"))
            and account_matches(a, b)
        ):
            matches.append({
                "rule": "authentication_context",
                "host": lh,
                "service": service_a,
                "source_ip": source,
                "target": deepcopy(a.get("target")),
                "caveat": (
                    "Same context does not establish a common actor."
                ),
            })

        matches.extend(process_relations(left, right))

    matches.extend(sensor_flow_relations(left, right))
    from spine.association_profiles import episode_relations
    matches.extend(episode_relations(left, right))

    return matches

def has_assignment_support(rules):
    """Only explicitly supported and eligible rules may assign a case."""
    supported = {
        "same_process_guid",
        "direct_parent_child_process",
        "same_sensor_flow",
        "windows_remote_logon_episode",
        "service_configured_command_execution",
        "dns_alert_episode",
    }
    return any(rule.get("rule") in supported and rule.get("assignment_eligible", True) is True for rule in rules)


def associate_alert(alert, snapshot):
    """Evaluate an alert against a complete active-case snapshot.

    snapshot:
        {
            "revision": int,
            "complete": True,
            "cases": [
                {
                    "case_id": str,
                    "revision": int,
                    "status": "active",
                    "alerts": [normalized_record, ...]
                }
            ]
        }

    The caller must persist the decision and recheck snapshot freshness
    before Step 4 changes case membership.
    """
    from spine.storage import validate_record
    from spine.occurrences import describe_occurrence

    validate_record(alert)

    if (
        type(snapshot.get("revision")) is not int
        or snapshot["revision"] < 0
        or snapshot.get("complete") is not True
        or not isinstance(snapshot.get("cases"), list)
    ):
        raise ValueError(
            "A complete, versioned active-case snapshot is required"
        )
    
    include_closed = snapshot.get("includes_closed_cases", False)
    if type(include_closed) is not bool:
        raise ValueError("includes_closed_cases must be a boolean")

    allowed_statuses = (
        {"active", "closed"} if include_closed else {"active"}
    )

    cases = sorted(snapshot["cases"], key=lambda case: case["case_id"])
    ids = set()
    owners = {}

    for case in cases:
        cid = text(case.get("case_id"))

        if (
            not cid
            or cid in ids
            or case.get("status") not in allowed_statuses
            or type(case.get("revision")) is not int
            or case["revision"] < 0
            or not isinstance(case.get("alerts"), list)
            or not case["alerts"]
        ):
            raise ValueError("Invalid active case context")

        ids.add(cid)
        local_ids = set()

        for existing in case["alerts"]:
            validate_record(existing)

            if (
                existing.get("record_kind") != "alert"
                or existing.get("priority", {}).get("actionable") is False
            ):
                raise ValueError(
                    "Case association context must contain admitted alerts"
                )

            rid = existing["record_id"]

            if rid in local_ids or rid in owners:
                raise ValueError(
                    "An alert must have one owner in the snapshot"
                )

            local_ids.add(rid)
            owners[rid] = (cid, existing)

    snapshot_token = fingerprint({
        "revision": snapshot["revision"],
        "cases": [
            {
                **case,
                "alerts": sorted(
                    case["alerts"],
                    key=lambda record: record["record_id"],
                ),
            }
            for case in cases
        ],
    })

    result = {
        "schema_version": "1",
        "alert_id": alert["record_id"],
        "alert_sha256": fingerprint(alert),
        "policy": deepcopy(POLICY),
        "snapshot_revision": snapshot["revision"],
        "snapshot_sha256": snapshot_token,
        "decision": None,
        "case_id": None,
        "delivery": "new",
        "occurrence": describe_occurrence(alert),
        "duplicate_of_alert_ids": [],
        "reason": None,
        "candidate_case_ids": [],
        "possible_case_ids": [],
        "comparisons": [],
        "uncertainties": [
            "Association is an operational grouping, not a confirmed incident.",
            "Telemetry completeness is not established by this decision.",
        ],
    }

    def finish():
        if include_closed:
            selected = next(
                (
                    case for case in cases
                    if case["case_id"] == result["case_id"]
                ),
                None,
            )
            previous_status = (
                selected["status"] if selected is not None else None
            )
            result["case_lifecycle"] = {
                "candidate_scope": "active_and_closed",
                "selected_case_previous_status": previous_status,
                "reactivation_required": (
                    previous_status == "closed"
                    and result["decision"] == "EXISTING_CASE"
                    and result["delivery"] == "new"
                ),
                "replay_or_duplicate_reactivates": False,
            }

        result["decision_id"] = fingerprint(result)
        return result

    if (
        alert.get("record_kind") != "alert"
        or alert.get("priority", {}).get("actionable") is False
    ):
        result["reason"] = "not_an_admitted_alert"
        result["delivery"] = "excluded"
        return finish()

    if alert["record_id"] in owners:
        cid, prior = owners[alert["record_id"]]

        if prior["raw"] != alert["raw"]:
            raise ValueError(
                "Existing alert identity has conflicting source content"
            )

        result.update(
            decision="EXISTING_CASE",
            case_id=cid,
            delivery="replay",
            reason="already_assigned_record",
        )
        return finish()

        # Reuse an established occurrence owner before ordinary case matching.
    # A duplicate representation must not create a new case through ambiguity.
    occurrence = result["occurrence"]
    duplicate_owners = {}

    if occurrence["representation_matching_supported"]:
        for cid, existing in owners.values():
            if describe_occurrence(existing)["id"] == occurrence["id"]:
                duplicate_owners.setdefault(cid, []).append(
                    existing["record_id"]
                )

    if len(duplicate_owners) > 1:
        raise ValueError(
            "One supported occurrence is assigned to multiple cases"
        )

    if duplicate_owners:
        cid = next(iter(duplicate_owners))

        conflicting = sorted({
            owner
            for owner, existing in owners.values()
            if session_conflict(alert, existing)
        })

        result.update(
            decision="EXISTING_CASE",
            case_id=cid,
            delivery="duplicate_representation",
            reason="same_supported_source_session_message",
            duplicate_of_alert_ids=sorted(duplicate_owners[cid]),
            occurrence_conflicted=bool(conflicting),
            conflicting_case_ids=conflicting,
        )

        if conflicting:
            result["uncertainties"].append(
                "Conflicting session reports exist; withhold session totals "
                "until automatic reassessment resolves their interpretation."
            )

        return finish()

    incoming_time = timestamp(alert)
    eligible = []
    possible = []
    conflicting_cases = []

    for case in cases:
        comparisons = []
        has_conflict = any(
            session_conflict(alert, record)
            for record in case["alerts"]
        )

        if has_conflict:
            conflicting_cases.append(case["case_id"])

        times = [timestamp(record) for record in case["alerts"]]
        known_times = [value for value in times if value is not None]

        span = (
            max(known_times + [incoming_time])
            - min(known_times + [incoming_time])
            if incoming_time is not None and known_times
            else None
        )

        for existing in sorted(
            case["alerts"], key=lambda record: record["record_id"]
        ):
            previous_time = timestamp(existing)

            gap = (
                abs(incoming_time - previous_time)
                if incoming_time is not None and previous_time is not None
                else None
            )

            from spine.association_profiles import constrain_episode_rules
            rules = constrain_episode_rules(relations(alert, existing), alert, case["alerts"])

            time_ok = (
                gap is not None
                and gap <= POLICY["gap_seconds"]
                and span is not None
                and span <= POLICY["maximum_case_span_seconds"]
                and all(value is not None for value in times)
            )

            comparisons.append({
                "alert_id": existing["record_id"],
                "relationship_rules": rules,
                "gap_seconds": gap,
                "time_eligible": time_ok,
                "supports_match": has_assignment_support(rules) and time_ok,
                "possible_match": bool(rules) and time_ok,
            })

        matched = not has_conflict and any(
            comparison["supports_match"]
            for comparison in comparisons
        )

        result["comparisons"].append({
            "case_id": case["case_id"],
            "case_revision": case["revision"],
            "case_span_seconds": span,
            "eligible": matched,
            "session_conflict": has_conflict,
            "alert_comparisons": comparisons,
        })

        if matched:
            eligible.append(case["case_id"])
        elif not has_conflict and any(
            comparison["possible_match"]
            for comparison in comparisons
        ):
            possible.append(case["case_id"])

    result["candidate_case_ids"] = eligible
    result["possible_case_ids"] = possible

    if possible:
        result["uncertainties"].append(
            "Contextual similarity is retained as a possible relationship. "
            "Separate routing does not establish that the activities are unrelated."
        )

    if conflicting_cases:
        result.update(
            decision="NEW_CASE",
            reason="conflicting_session_context",
            conflicting_case_ids=conflicting_cases,
        )
    elif len(eligible) == 1:
        result.update(
            decision="EXISTING_CASE",
            case_id=eligible[0],
            reason=(
                "one_supported_closed_case"
                if next(
                    case["status"] for case in cases
                    if case["case_id"] == eligible[0]
                ) == "closed"
                else "one_supported_active_case"
            ),
        )
    else:
        reason = (
            "multiple_plausible_cases"
            if eligible
            else "weak_context_only"
            if possible
            else "no_active_cases"
            if not cases
            else "missing_event_time"
            if incoming_time is None
            else "no_supported_active_case"
        )
        result.update(decision="NEW_CASE", reason=reason)

    return finish()
