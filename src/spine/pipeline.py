"""Shared normalization pipeline for SPINE Step 2."""

from spine.entities import extract_entities
from spine.eve import parse_eve
from spine.suricata import map_suricata
from spine.syscheck import map_syscheck
from spine.sysmon_xml import parse_sysmon_xml
from spine.wazuh import parse_wazuh_alert
from spine.windows import map_windows
from spine.mitre import normalize_mitre
from spine.identity import map_host_identities
from spine.user_identity import map_user_identities
from spine.ingestion_accounting import describe_source_event


def normalize_record(
    raw_text: str,
    *,
    input_format: str,
    source_scope: str,
    source_record_id: str,
    observed_time: str,
) -> dict:
    """Normalize one record using its reader-supplied identity."""
    if input_format == "sysmon_xml":
        record = parse_sysmon_xml(
            raw_text,
            source_scope=source_scope,
            source_record_id=source_record_id,
            observed_time=observed_time,
        )

    elif input_format == "eve":
        record = parse_eve(
            raw_text,
            source_scope=source_scope,
            source_record_id=source_record_id,
            observed_time=observed_time,
        )

    elif input_format == "wazuh":
        record = parse_wazuh_alert(
            raw_text,
            source_scope=source_scope,
            fallback_record_id=source_record_id,
            observed_time=observed_time,
        )

        if record["source"] == "suricata":
            record = map_suricata(record)
        elif record["source"] in ("sysmon", "windows_eventchannel"):
            record = map_windows(record)
        elif record["source"] == "wazuh_syscheck":
            record = map_syscheck(record)

    else:
        raise ValueError(f"Unsupported input format: {input_format}")

    record = normalize_mitre(record)
    record = extract_entities(record)
    record = map_host_identities(record)
    record = map_user_identities(record)
    record["attributes"]["source_event_reference"] = describe_source_event(record)
    return record
