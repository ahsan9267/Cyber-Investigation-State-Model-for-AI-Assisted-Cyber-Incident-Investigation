"""Preview normalization of one saved Wazuh or Suricata EVE record."""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

from spine.eve import ExcludedSensorHealth, parse_eve
from spine.suricata import map_suricata
from spine.wazuh import parse_wazuh_alert
from spine.windows import map_windows
from spine.syscheck import map_syscheck
from spine.entities import extract_entities


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--source-scope", required=True)
    parser.add_argument(
        "--format",
        choices=("wazuh", "eve"),
        default="wazuh",
    )
    parser.add_argument(
        "--source-record-id",
        help="Required for EVE; use a stable identity for this sample record",
    )
    args = parser.parse_args()

    if args.input.resolve() == args.output.resolve():
        parser.error("Input and output must be different files")

    if args.format == "eve" and not args.source_record_id:
        parser.error("--source-record-id is required for EVE")

    try:
        raw_text = args.input.read_bytes().decode("utf-8-sig")
        observed_time = datetime.now(timezone.utc).isoformat()

        if args.format == "eve":
            record = parse_eve(
                raw_text,
                source_scope=args.source_scope,
                source_record_id=args.source_record_id,
                observed_time=observed_time,
            )
        else:
            record = parse_wazuh_alert(
                raw_text,
                source_scope=args.source_scope,
                observed_time=observed_time,
            )
            
            if record["source"] == "suricata":
                record = map_suricata(record)
            elif record["source"] in ("sysmon", "windows_eventchannel"):
                record = map_windows(record)
            elif record["source"] == "wazuh_syscheck":
                record = map_syscheck(record)

        record = extract_entities(record)
        args.output.parent.mkdir(parents=True, exist_ok=True)

        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(record, stream, ensure_ascii=False, indent=2)
            stream.write("\n")

    except ExcludedSensorHealth as error:
        print(f"Excluded sensor-health record: {error}")
        return
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(1, f"Preview failed: {error}\n")

    print(f"Output: {args.output}")
    print(f"Source: {record['source']}")
    print(f"Collector: {record['collector']}")
    print(f"Record kind: {record['record_kind']}")
    print(f"Wazuh level: {record['priority']['wazuh_level']}")
    print(f"Priority: {record['priority']['priority_band']}")

    event_time = record["event_time"]
    print(f"Event time: {event_time['utc'] if event_time else None}")

    dns = record["attributes"].get("dns")
    if isinstance(dns, dict):
        print(f"DNS message type: {dns['message_type']}")
        print(f"DNS questions: {dns['questions']}")
        print(f"DNS answers: {dns['answers']}")

    print(f"Mapping status: {record['normalization']['status']}")
    print(f"Warnings: {len(record['normalization']['warnings'])}")

    for warning in record["normalization"]["warnings"]:
        print(f"  - {warning}")


if __name__ == "__main__":
    main()