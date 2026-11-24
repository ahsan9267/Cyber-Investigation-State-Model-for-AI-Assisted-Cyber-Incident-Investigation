"""Offline AIT-ADS adapter; no database or collector operations."""

import argparse
from collections import Counter
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from spine.entities import extract_entities
from spine.timestamps import normalize_timestamp

SCOPE = "dataset/ait-ads/8263181/russellmitchell"
VERSION = "ait_dataset/0.1.0"

PREFIX = re.compile(
    r"(?P<clock>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"(?P<host>\S+) dovecot: (?P<service>imap|pop3)-login: (?P<body>.*)"
)

FAILURE = re.compile(
    r"Disconnected \(auth failed, ([1-9][0-9]*) attempts in [0-9]+ secs\): (.*)"
)


def adapt_annotations(record):
    """Map supported dataset fields on a copy; retain source record identity."""
    if record["provenance"]["source_scope"] != SCOPE:
        raise ValueError("AIT adapter requires its dataset-specific scope")

    result = deepcopy(record)
    payload = json.loads(result["raw"]["text"])
    attrs = result["attributes"]
    timestamp = normalize_timestamp(payload["@timestamp"])

    attrs["dataset_time"] = {
        "field": "@timestamp",
        "value": timestamp,
        "basis": "AIT exported timestamp",
    }

    result["provenance"]["dataset_adapter"] = VERSION
    warnings = result["normalization"]["warnings"]
    result["normalization"]["parser"] = (
        (result["normalization"].get("parser") or "unmapped")
        + "+"
        + VERSION
    )

    pre = payload.get("predecoder", {})
    host = pre.get("hostname") if isinstance(pre, dict) else None

    if isinstance(host, str) and host.strip():
        if result["host"].get("name") not in (None, host):
            warnings.append(
                "AIT hostname conflicts with normalized hostname"
            )
            return result
        result["host"]["name"] = host

    decoder = payload.get("decoder", {})
    if (
        not isinstance(decoder, dict)
        or decoder.get("name") != "dovecot"
    ):
        return extract_entities(result)

    try:
        log = payload.get("full_log")
        match = PREFIX.fullmatch(log) if isinstance(log, str) else None

        if match is None or not host or match["host"] != host:
            raise ValueError(
                "unsupported Dovecot message or hostname conflict"
            )

        # Cross-check the source clock against the exported timestamp.
        # Never infer time from this machine or from the Wazuh alert ID.
        dt = datetime.fromisoformat(
            timestamp["utc"].replace("Z", "+00:00")
        )
        months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
        clock = f"{months[dt.month - 1]} {dt.day} {dt:%H:%M:%S}"

        if " ".join(match["clock"].split()) != clock:
            raise ValueError(
                "source clock disagrees with dataset timestamp"
            )

        body = match["body"]
        failed = FAILURE.fullmatch(body)

        if failed:
            outcome = "failure"
            attempts = int(failed[1])
            fields = failed[2]
        elif body.startswith("Login: "):
            outcome = "success"
            attempts = None
            fields = body[7:]
        else:
            raise ValueError("unsupported Dovecot outcome")

        def field(name, pattern):
            values = re.findall(
                r"(?:^|, )" + name + "=" + pattern + r"(?=, |$)",
                fields,
            )
            if len(values) != 1 or not values[0]:
                raise ValueError(
                    f"missing or ambiguous Dovecot {name}"
                )
            return values[0]

        user = field("user", r"<([^>]*)>")
        session = field("session", r"<([^>]*)>")
        source_ip = str(
            ipaddress.ip_address(field("rip", r"([^, ]+)"))
        )
        destination_ip = str(
            ipaddress.ip_address(field("lip", r"([^, ]+)"))
        )
        method = field("method", r"([^, ]+)")

        data = payload.get("data", {})
        if not isinstance(data, dict):
            raise ValueError("invalid structured Dovecot data")

        for key, expected in (
            ("srcuser", f"<{user}>"),
            ("srcip", source_ip),
            ("dstip", destination_ip),
        ):
            if key in data and data[key] != expected:
                raise ValueError(
                    f"structured {key} conflicts with full_log"
                )

        if attrs.get("authentication") is not None:
            raise ValueError("authentication mapping already exists")

        auth = {
            "outcome": outcome,
            "target": {
                "name": user,
                "sid": None,
                "domain": None,
            },
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "service": match["service"],
            "session_id": session,
            "authentication_method": method,
            "reported_failed_attempts": attempts,
            "count_unit": "session_summary" if failed else "session",
            "basis": (
                "parsed full_log; timestamp from dataset @timestamp"
            ),
        }

    except ValueError as error:
        warnings.append(f"AIT Dovecot mapping withheld: {error}")
        return extract_entities(result)

    attrs["authentication"] = auth
    result["event"] = {
        "provider": "dovecot",
        "type": "authentication",
    }
    result["event_time"] = deepcopy(timestamp)
    result["provenance"]["event_time_basis"] = (
        "dataset @timestamp; source clock cross-checked"
    )
    result["normalization"]["status"] = "partial"

    return extract_entities(result)


def run(dataset_directory, output_directory):
    # Lazy import keeps annotation tests independent of collector dependencies.
    from spine.pipeline import normalize_record

    folder = Path(dataset_directory)
    output = Path(output_directory)
    manifest = json.loads(
        (folder / "manifest.json").read_text(encoding="utf-8")
    )

    inputs = {}
    for name in (
        "auth_window.jsonl",
        "auth_window_lineage.json",
    ):
        data = (folder / name).read_bytes()

        if len(data) > 32 * 1024 * 1024:
            raise ValueError(f"Input exceeds 32 MiB: {name}")

        if (
            hashlib.sha256(data).hexdigest()
            != manifest["files"][name]["sha256"]
        ):
            raise ValueError(f"Checksum mismatch: {name}")

        inputs[name] = data

    lines = inputs["auth_window.jsonl"].splitlines(keepends=True)
    lineage = json.loads(inputs["auth_window_lineage.json"])

    if len(lines) != len(lineage):
        raise ValueError("Lineage length mismatch")

    observed = datetime.now(timezone.utc).isoformat()
    output.mkdir(parents=True, exist_ok=False)

    counts = Counter()
    warning_counts = Counter()

    with (output / "normalized.jsonl").open(
        "x", encoding="utf-8", newline="\n"
    ) as stream:
        for number, (raw, ref) in enumerate(
            zip(lines, lineage), 1
        ):
            if (
                ref["subset_line"] != number
                or hashlib.sha256(raw).hexdigest()
                != ref["sha256_including_line_ending"]
            ):
                raise ValueError(
                    f"Lineage mismatch on line {number}"
                )

            text = raw.decode("utf-8")
            record = normalize_record(
                text,
                input_format="wazuh",
                source_scope=SCOPE,
                source_record_id=(
                    f"russellmitchell_wazuh:line:{ref['source_line']}"
                ),
                observed_time=observed,
            )

            original_id = record["record_id"]
            record = adapt_annotations(record)

            if (
                record["raw"]["text"] != text
                or record["raw"]["sha256"]
                != hashlib.sha256(raw).hexdigest()
                or record["record_id"] != original_id
            ):
                raise RuntimeError(
                    "Adapter changed evidence or identity"
                )

            record["provenance"]["dataset_reader"] = ref
            json.dump(
                record,
                stream,
                ensure_ascii=False,
                allow_nan=False,
            )
            stream.write("\n")

            counts["records"] += 1
            auth = record["attributes"].get("authentication")
            counts[
                "authentication_records" if auth else "other_records"
            ] += 1

            if auth:
                counts["authentication_" + auth["outcome"]] += 1

            warning_counts.update(
                record["normalization"]["warnings"]
            )

    summary = {
        "status": "completed",
        "adapter": VERSION,
        "source_scope": SCOPE,
        "counts": dict(counts),
        "warnings": dict(warning_counts),
        "input_sha256": hashlib.sha256(
            inputs["auth_window.jsonl"]
        ).hexdigest(),
        "observed_time": observed,
        "database_written": False,
        "association_performed": False,
    }

    # A missing summary marks an incomplete run.
    # Never import partial output.
    (output / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n",
        encoding="utf-8",
    )

    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset_directory", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    print(json.dumps(
        run(args.dataset_directory, args.output_directory),
        indent=2,
    ))


if __name__ == "__main__":
    main()