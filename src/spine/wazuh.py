"""Common-envelope parsing for Wazuh alerts."""

import json
from copy import deepcopy

from spine.envelope import build_envelope
from spine.priority import normalize_wazuh_priority
from spine.timestamps import normalize_timestamp


def _reject_constant(value):
    raise ValueError(f"Invalid JSON constant: {value}")


def _unique_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_wazuh_alert(
    raw_text: str,
    *,
    source_scope: str,
    observed_time: str,
    fallback_record_id: str | None = None,
) -> dict:
    """Parse one Wazuh alert.

    source_scope is a configured stable identity for the Wazuh instance.
    fallback_record_id, when needed, must come from the reader's durable
    file-generation/offset identity. Never generate it from read time.
    """
    payload = json.loads(
        raw_text,
        parse_constant=_reject_constant,
        object_pairs_hook=_unique_keys,
    )
    if not isinstance(payload, dict):
        raise ValueError("Expected a JSON object")

    warnings = []

    def object_field(parent, key):
        value = parent.get(key)
        if value is None:
            return {}
        if not isinstance(value, dict):
            warnings.append(f"Expected object field: {key}")
            return {}
        return value

    alert_id = payload.get("id")
    if isinstance(alert_id, str) and alert_id.strip():
        identity = f"wazuh-id:{alert_id}"
    else:
        if (
            not isinstance(fallback_record_id, str)
            or not fallback_record_id.strip()
        ):
            raise ValueError(
                "Missing valid Wazuh alert ID and reader fallback identity"
            )
        identity = f"reader-id:{fallback_record_id}"
        warnings.append("Missing valid Wazuh alert ID; used reader identity")

    rule = object_field(payload, "rule")
    agent = object_field(payload, "agent")
    manager = object_field(payload, "manager")
    decoder = object_field(payload, "decoder")
    data = object_field(payload, "data")
    win = object_field(data, "win")
    system = object_field(win, "system")

    groups = rule.get("groups", [])
    if not isinstance(groups, list):
        warnings.append("Expected list field: rule.groups")
        groups = []
    clean_groups = [
        item.strip().lower() for item in groups if isinstance(item, str)
    ]

    channel = system.get("channel")
    provider = system.get("providerName")

    if (
        channel == "Microsoft-Windows-Sysmon/Operational"
        or provider == "Microsoft-Windows-Sysmon"
    ):
        source = "sysmon"
    elif win:
        source = "windows_eventchannel"
    elif "suricata" in clean_groups:
        source = "suricata"
    elif "syscheck" in payload:
        source = "wazuh_syscheck"
    else:
        source = "wazuh"

    record = build_envelope(
        raw_text=raw_text,
        source=source,
        collector="wazuh_alerts",
        record_kind="alert",
        source_scope=source_scope,
        source_record_id=identity,
        observed_time=observed_time,
    )

    record["agent"] = deepcopy(agent)
    record["rule"] = deepcopy(rule)
    record["provenance"].update({
        "wazuh_alert_id": alert_id,
        "manager": deepcopy(manager),
        "decoder": deepcopy(decoder),
        "location": deepcopy(payload.get("location")),
    })

    hostname = system.get("computer")
    if isinstance(hostname, str) and hostname.strip():
        record["host"]["name"] = hostname

    # Preserve parsed source sections as well as the original JSON text.
    # Detailed normalized mappings will be added by source-specific parsers.
    record["attributes"]["source_payload"] = {
        key: deepcopy(payload[key])
        for key in ("data", "syscheck", "full_log")
        if key in payload
    }

    try:
        record["priority"] = normalize_wazuh_priority(rule.get("level"))
    except ValueError as error:
        warnings.append(f"Invalid rule.level: {error}")

    if rule.get("level") is None:
        warnings.append("Missing Wazuh rule level")

    timestamp = payload.get("timestamp")
    if timestamp is None:
        warnings.append("Missing Wazuh alert timestamp")
    else:
        try:
            record["alert_time"] = normalize_timestamp(timestamp)
        except ValueError as error:
            warnings.append(f"Invalid Wazuh alert timestamp: {error}")

    # Source event time remains unset until the relevant mapper handles it.
    record["normalization"] = {
        "parser": "wazuh_common/0.1.0",
        "status": "common_only",
        "warnings": warnings,
    }
    return record