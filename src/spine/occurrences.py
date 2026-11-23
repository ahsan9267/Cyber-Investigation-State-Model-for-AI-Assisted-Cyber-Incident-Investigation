"""Occurrence references; the initial shared-message profile is AIT Dovecot."""

import hashlib
import json


PROFILE = "ait_dovecot_session_message/1"
AIT_SCOPE = "dataset/ait-ads/8263181/russellmitchell"


def digest(value):
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def describe_occurrence(record):
    """Preserve every record; share occurrence IDs only for supported profiles."""
    from spine.storage import validate_record

    validate_record(record)

    fallback = {
        "id": digest(["record_reference/1", record["record_id"]]),
        "profile": "record_reference/1",
        "count_unit": "record_not_confirmed_occurrence",
        "representation_matching_supported": False,
        "source_reported_failed_attempts": None,
    }

    provenance = record["provenance"]

    if (
        provenance["source_scope"] != AIT_SCOPE
        or provenance.get("dataset_adapter") != "ait_dataset/0.1.0"
        or record.get("event", {}).get("provider") != "dovecot"
    ):
        return fallback

    auth = record.get("attributes", {}).get("authentication", {})
    host = record.get("host", {}).get("name")
    agent = record.get("agent", {}).get("id")
    when = (record.get("event_time") or {}).get("utc")

    fields = (
        "session_id",
        "service",
        "source_ip",
        "destination_ip",
        "authentication_method",
    )

    if not all(
        isinstance(auth.get(key), str) and auth[key]
        for key in fields
    ):
        return fallback

    if not all(
        isinstance(value, str) and value
        for value in (host, agent, when)
    ):
        return fallback

    if not auth.get("target", {}).get("name"):
        return fallback

    if auth.get("outcome") not in ("success", "failure"):
        return fallback

    attempts = auth.get("reported_failed_attempts")

    if auth["outcome"] == "failure":
        if type(attempts) is not int or attempts < 1:
            return fallback
    elif attempts is not None:
        return fallback

    try:
        payload = json.loads(record["raw"]["text"])
    except (ValueError, TypeError):
        return fallback

    if not isinstance(payload, dict):
        return fallback

    message = payload.get("full_log")
    if not isinstance(message, str) or not message:
        return fallback

    # Wrapper alert IDs and log locations deliberately do not identify
    # the underlying session message. All original records remain retained.
    identity = [
        PROFILE,
        record["collector"],
        provenance["source_scope"],
        agent,
        host,
        when,
        message,
        {
            key: auth.get(key)
            for key in (
                "session_id",
                "service",
                "source_ip",
                "destination_ip",
                "authentication_method",
                "target",
                "outcome",
                "reported_failed_attempts",
                "count_unit",
            )
        },
    ]

    return {
        "id": digest(identity),
        "profile": PROFILE,
        "count_unit": "source_session_message",
        "representation_matching_supported": True,
        "source_reported_failed_attempts": attempts,
    }