"""Normalize a saved JSONL snapshot, up to 32 MiB.

Use only with saved snapshots, not actively written logs.
Each input line receives an explicit disposition.
"""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path

from spine.eve import ExcludedSensorHealth
from spine.pipeline import normalize_record


MAX_SNAPSHOT_BYTES = 32 * 1024 * 1024


def write_json_line(stream, value):
    stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False))
    stream.write("\n")


def ingest_snapshot(
    input_path,
    output_directory,
    *,
    input_format,
    source_scope,
    snapshot_id,
):
    """Process a fixed input snapshot into a new output directory.

    snapshot_id identifies this particular saved file generation.
    Reuse it when replaying the SAME unchanged snapshot.
    Different snapshots need different IDs.
    """
    if input_format not in ("wazuh", "eve"):
        raise ValueError("input_format must be wazuh or eve")

    for name, value in (
        ("source_scope", source_scope),
        ("snapshot_id", snapshot_id),
    ):
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{name} must be a non-empty string")

    input_path = Path(input_path)
    output_directory = Path(output_directory)

    # Read a bounded, fixed byte sequence before processing.
    with input_path.open("rb") as stream:
        snapshot = stream.read(MAX_SNAPSHOT_BYTES + 1)

    if len(snapshot) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Snapshot exceeds the 32 MiB limit")

    snapshot_sha256 = hashlib.sha256(snapshot).hexdigest()
    observed_time = datetime.now(timezone.utc).isoformat()

    # A new directory prevents accidental overwriting of an earlier run.
    output_directory.mkdir(parents=True, exist_ok=False)

    counts = {
        "lines": 0,
        "normalized": 0,
        "quarantined": 0,
        "excluded": 0,
    }

    with (
        (output_directory / "normalized.jsonl").open(
            "x", encoding="utf-8", newline="\n"
        ) as accepted,
        (output_directory / "quarantine.jsonl").open(
            "x", encoding="utf-8", newline="\n"
        ) as quarantine,
        (output_directory / "excluded.jsonl").open(
            "x", encoding="utf-8", newline="\n"
        ) as excluded,
    ):
        source = io.BytesIO(snapshot)

        while True:
            offset = source.tell()
            raw_bytes = source.readline()
            if not raw_bytes:
                break

            counts["lines"] += 1

            reader_identity = json.dumps(
                ["snapshot", snapshot_id, offset],
                ensure_ascii=False,
                separators=(",", ":"),
            )

            reader = {
                "snapshot_id": snapshot_id,
                "snapshot_sha256": snapshot_sha256,
                "line_number": counts["lines"],
                "byte_offset": offset,
                "byte_length": len(raw_bytes),
                "line_sha256": hashlib.sha256(raw_bytes).hexdigest(),
            }

            try:
                # Accept a UTF-8 BOM only at the start of the snapshot.
                encoding = "utf-8-sig" if offset == 0 else "utf-8"
                raw_text = raw_bytes.decode(encoding)

                record = normalize_record(
                    raw_text,
                    input_format=input_format,
                    source_scope=source_scope,
                    source_record_id=reader_identity,
                    observed_time=observed_time,
                )

            except ExcludedSensorHealth as error:
                write_json_line(excluded, {
                    "disposition": "excluded_sensor_health",
                    "source_scope": source_scope,
                    "input_format": input_format,
                    "reader": reader,
                    "reason": str(error),
                    "raw_base64": base64.b64encode(raw_bytes).decode("ascii"),
                })
                counts["excluded"] += 1

            except (UnicodeError, ValueError) as error:
                write_json_line(quarantine, {
                    "disposition": "quarantined",
                    "source_scope": source_scope,
                    "input_format": input_format,
                    "reader": reader,
                    "error_type": type(error).__name__,
                    "reason": str(error),
                    "raw_base64": base64.b64encode(raw_bytes).decode("ascii"),
                })
                counts["quarantined"] += 1

            else:
                record["provenance"]["reader"] = reader
                write_json_line(accepted, record)
                counts["normalized"] += 1

    summary = {
        "status": "completed",
        "input_path": str(input_path.resolve()),
        "input_format": input_format,
        "source_scope": source_scope,
        "snapshot_id": snapshot_id,
        "snapshot_sha256": snapshot_sha256,
        "snapshot_bytes": len(snapshot),
        "observed_time": observed_time,
        "counts": counts,
    }

    # Written last: missing summary means the run did not finish.
    with (output_directory / "summary.json").open(
        "x", encoding="utf-8", newline="\n"
    ) as stream:
        json.dump(summary, stream, ensure_ascii=False, indent=2)
        stream.write("\n")

    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument("--format", choices=("wazuh", "eve"), required=True)
    parser.add_argument("--source-scope", required=True)
    parser.add_argument("--snapshot-id", required=True)
    args = parser.parse_args()

    try:
        summary = ingest_snapshot(
            args.input,
            args.output_directory,
            input_format=args.format,
            source_scope=args.source_scope,
            snapshot_id=args.snapshot_id,
        )
    except (OSError, ValueError) as error:
        parser.exit(1, f"Batch failed: {error}\n")

    print(f"Output directory: {args.output_directory}")
    for name, count in summary["counts"].items():
        print(f"{name}: {count}")


if __name__ == "__main__":
    main()