"""Count ingestion separately from source events and case association.

Windows references describe a source's reported event, not proof of an attack.
Different collectors are never silently treated as the same occurrence.
"""

from collections import defaultdict
import hashlib
import json


def _digest(value):
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")).hexdigest()


def describe_source_event(record):
    """Use a bounded Windows reference or explicitly retain record counting."""
    fallback = {
        "profile": "ingested_record/1",
        "id": _digest(["ingested_record/1", record["record_id"]]),
        "count_unit": "record_not_confirmed_occurrence",
        "content_sha256": record["raw"]["sha256"],
        "event_code": None,
        "event_time": None,
    }
    if record.get("source") not in ("sysmon", "windows_eventchannel"):
        return fallback

    win = record.get("attributes", {}).get("source_payload", {}).get("data", {}).get("win")
    if not isinstance(win, dict):
        return fallback
    system = win.get("system")
    fields = win.get("eventdata")
    if not isinstance(system, dict) or not isinstance(fields, dict):
        return fallback
    event = record.get("event", {})
    timestamp = record.get("attributes", {}).get("windows_system", {}).get("time_created")
    when = timestamp.get("utc") if isinstance(timestamp, dict) else None
    required = [event.get("provider"), event.get("channel"),
                record.get("host", {}).get("name"), event.get("record_id"),
                event.get("code"), when]
    if not all(isinstance(value, str) and value.strip() for value in required):
        return fallback
    if not required[3].isascii() or not required[3].isdecimal() or int(required[3]) < 1:
        return fallback

    profile = "reported_windows_event/1"
    provenance = record["provenance"]
    identity = [profile, record["collector"], provenance["source_scope"],
                record.get("agent", {}).get("id"), *required]
    # Native reader identity includes channel generation; never discard it.
    if record["collector"] == "sysmon_eventlog":
        identity.append(provenance["source_record_id"])
    return {
        "profile": profile,
        "id": _digest(identity),
        "count_unit": "reported_windows_event",
        "content_sha256": _digest(win),
        "event_code": event["code"],
        "event_time": when,
    }


def summarize_deliveries(records):
    """Retain replay/conflict counts without inflating distinct login events.

    Disputed native references are reported and excluded from source-event
    totals. Raw and normalized records remain available in ingestion storage.
    This function makes no case-association decision.
    """
    from spine.storage import validate_record

    originals, variants, events = {}, set(), defaultdict(list)
    conflicting_ids = set()
    result = dict(deliveries=0, unique_record_ids=0, replay_deliveries=0,
                  conflict_deliveries=0, conflict_variants=0,
                  reported_source_events=0, ambiguous_source_references=0,
                  unconfirmed_record_references=0,
                  failed_logon_events=0, successful_logon_events=0)
    for record in records:
        validate_record(record)
        result["deliveries"] += 1
        rid, raw_hash = record["record_id"], record["raw"]["sha256"]
        key = rid, raw_hash
        if rid in originals:
            if originals[rid] == raw_hash:
                result["replay_deliveries"] += 1
            else:
                result["conflict_deliveries"] += 1
                conflicting_ids.add(rid)
        else:
            originals[rid] = raw_hash
        if key in variants:
            continue
        variants.add(key)
        event = describe_source_event(record)
        if event["count_unit"] == "reported_windows_event":
            events[event["id"]].append((event, record))

    result["unique_record_ids"] = len(originals)
    result["conflict_variants"] = len(variants) - len(originals)
    reported_records = set()
    for values in events.values():
        references = {record["record_id"] for _, record in values}
        reported_records.update(references)
        if len({event["content_sha256"] for event, _ in values}) != 1 or references & conflicting_ids:
            result["ambiguous_source_references"] += 1
            continue
        event, record = values[0]
        result["reported_source_events"] += 1
        auth = record.get("attributes", {}).get("authentication", {})
        if record.get("event", {}).get("provider") != "Microsoft-Windows-Security-Auditing":
            continue
        if record.get("event", {}).get("channel") != "Security":
            continue
        if event["event_code"] == "4625" and auth.get("outcome") == "failure":
            result["failed_logon_events"] += 1
        elif event["event_code"] == "4624" and auth.get("outcome") == "success":
            result["successful_logon_events"] += 1
    result["unconfirmed_record_references"] = len(set(originals) - reported_records)
    return result
