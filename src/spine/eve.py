"""Parse individual records from Suricata security EVE files."""

import json

from spine.envelope import build_envelope
from spine.suricata import map_suricata
from spine.wazuh import _reject_constant, _unique_keys


class ExcludedSensorHealth(ValueError):
    """An operational stats record, excluded from security normalization."""


def parse_eve(
    raw_text: str,
    *,
    source_scope: str,
    source_record_id: str,
    observed_time: str,
) -> dict:
    """Parse one EVE record using a reader-supplied durable identity.

    Live readers must identify the file generation and record offset.
    flow_id alone is not a record identity: many events share a flow.
    """
    payload = json.loads(
        raw_text,
        parse_constant=_reject_constant,
        object_pairs_hook=_unique_keys,
    )

    if not isinstance(payload, dict):
        raise ValueError("Expected an EVE JSON object")

    event_type = payload.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("Missing or invalid EVE event_type")

    if event_type == "stats":
        raise ExcludedSensorHealth(
            "Suricata stats belong to sensor health, not security events"
        )

    record = build_envelope(
        raw_text=raw_text,
        source="suricata",
        collector="suricata_eve",
        record_kind="alert" if event_type == "alert" else "telemetry",
        source_scope=source_scope,
        source_record_id=source_record_id,
        observed_time=observed_time,
    )

    record["attributes"]["source_payload"] = {"data": payload}
    record = map_suricata(record)
    record["normalization"]["parser"] = (
        "suricata_eve/0.1.0+suricata_common/0.2.0"
    )
    return record
