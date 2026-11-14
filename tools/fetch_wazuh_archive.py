"""Fetch a dated Wazuh gzip archive as an immutable local snapshot."""

import argparse
from datetime import date
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tempfile


MAX_COMPRESSED = 16 * 1024 * 1024
MAX_EXPANDED = 32 * 1024 * 1024

MONTHS = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

REMOTE = r'''
from datetime import date
import hashlib
import json
import os
import sys

day = date.fromisoformat(sys.argv[1])
months = (
    "Jan", "Feb", "Mar", "Apr", "May", "Jun",
    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
)

path = "/var/ossec/logs/alerts/{}/{}/ossec-alerts-{:02d}.json.gz".format(
    day.year, months[day.month - 1], day.day
)

limit = 16 * 1024 * 1024

def signature(info):
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )

with open(path, "rb", buffering=0) as stream:
    before = os.fstat(stream.fileno())

    if before.st_size > limit:
        raise ValueError("Compressed archive exceeds 16 MiB")

    raw = stream.read(limit + 1)
    after = os.fstat(stream.fileno())
    current = os.stat(path)

    if len(raw) != before.st_size:
        raise RuntimeError("Archive size changed while reading")

    if signature(before) != signature(after):
        raise RuntimeError("Archive changed while reading")

    if signature(after) != signature(current):
        raise RuntimeError("Archive path changed while reading")

header = json.dumps({
    "path": path,
    "bytes": len(raw),
    "sha256": hashlib.sha256(raw).hexdigest(),
}).encode("ascii")

sys.stdout.buffer.write(header + b"\n" + raw)
'''


def expand_archive(raw):
    if len(raw) > MAX_COMPRESSED:
        raise ValueError("Compressed archive exceeds 16 MiB")

    with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
        expanded = stream.read(MAX_EXPANDED + 1)

    if len(expanded) > MAX_EXPANDED:
        raise ValueError("Expanded archive exceeds 32 MiB")

    if expanded and not expanded.endswith(b"\n"):
        raise ValueError("Archived file has an incomplete final line")

    return expanded


def save_snapshot(folder, day, expanded):
    digest = hashlib.sha256(expanded).hexdigest()
    folder.mkdir(parents=True, exist_ok=True)

    path = folder / f"wazuh-{day.isoformat()}-{digest}.jsonl"

    try:
        with path.open("xb") as stream:
            stream.write(expanded)
    except FileExistsError:
        with path.open("rb") as stream:
            existing = stream.read(MAX_EXPANDED + 1)

        if existing != expanded:
            raise ValueError(
                "Existing snapshot differs; refusing to overwrite it"
            )

    identity = f"wazuh-archive:{day.isoformat()}:{digest}"
    return path, identity


def self_test():
    raw = b'{"id":"one"}\r\n\xff\x00\n'

    assert expand_archive(gzip.compress(raw)) == raw
    print("PASS: exact bytes preserved, including malformed records")

    invalid_archives = (
        gzip.compress(raw)[:-4],
        gzip.compress(b'{"id":'),
    )

    for bad in invalid_archives:
        try:
            expand_archive(bad)
        except (OSError, EOFError, ValueError):
            pass
        else:
            raise AssertionError("Invalid archive was accepted")

    print("PASS: truncated gzip and incomplete final line rejected")

    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        day = date(2026, 9, 28)

        first = save_snapshot(folder, day, raw)

        assert save_snapshot(folder, day, raw) == first
        assert save_snapshot(folder, day, raw + b'{}\n') != first
        assert first[0].read_bytes() == raw

    print("PASS: stable snapshot identity; changed content stays separate")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--date", type=date.fromisoformat)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()

    if args.self_test:
        self_test()
        return

    if args.date is None:
        parser.error("--date YYYY-MM-DD is required")

    try:
        # Only the validated ISO date enters the remote command.
        result = subprocess.run(
            [
                "ssh",
                "-T",
                "-o", "ConnectTimeout=10",
                "-o", "ServerAliveInterval=15",
                "-o", "ServerAliveCountMax=2",
                "wazuh-user@192.168.0.32",
                "sudo -n python3 - " + args.date.isoformat(),
            ],
            input=REMOTE.encode("ascii"),
            stdout=subprocess.PIPE,
            timeout=90,
            check=True,
        )

        header, separator, raw = result.stdout.partition(b"\n")

        if not separator or len(header) > 4096:
            raise ValueError("Invalid archive response")

        metadata = json.loads(header)
        day = args.date

        expected_path = (
            f"/var/ossec/logs/alerts/{day.year}/"
            f"{MONTHS[day.month - 1]}/"
            f"ossec-alerts-{day.day:02d}.json.gz"
        )

        if metadata["path"] != expected_path:
            raise ValueError("Unexpected archive path")

        if metadata["bytes"] != len(raw):
            raise ValueError("Archive length mismatch")

        if metadata["sha256"] != hashlib.sha256(raw).hexdigest():
            raise ValueError("Archive checksum mismatch")

        expanded = expand_archive(raw)

        path, identity = save_snapshot(
            Path("data/snapshots/wazuh"),
            day,
            expanded,
        )

    except (
        OSError,
        EOFError,
        ValueError,
        KeyError,
        subprocess.SubprocessError,
    ) as error:
        parser.exit(1, f"Archive fetch failed: {error}\n")

    print(f"Saved: {path}")
    print(f"Compressed bytes: {len(raw)}")
    print(f"Expanded bytes: {len(expanded)}")
    print(f"Complete lines: {expanded.count(bytes([10]))}")
    print("Database written: false")

    print("\nImport command (first 100 lines):")
    print(
        f'python -m spine.snapshot "{path}" '
        f'--format wazuh '
        f'--source-scope "lab/wazuh-server" '
        f'--snapshot-id "{identity}" '
        f'--max-records 100'
    )


if __name__ == "__main__":
    main()