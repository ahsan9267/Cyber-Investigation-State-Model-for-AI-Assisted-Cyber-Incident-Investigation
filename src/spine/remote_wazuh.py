"""Bounded, read-only Wazuh SSH transport for SPINE Step 2.

No database writes or checkpoint persistence happen in this module.
The remote program uses only the Python 3.9 standard library.
"""

import argparse
import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REMOTE_PATH = "/var/ossec/logs/alerts/alerts.json"

# Tested reader source used by tools/build_wazuh_exporter.py for the fixed,
# restricted server exporter. Runtime requests contain JSON only.
REMOTE_PROGRAM = r'''
import base64
import hashlib
import json
import os
import sys
from datetime import date
from pathlib import Path

MAX_LINE = 1024 * 1024
MAX_BATCH = 4 * 1024 * 1024

def digest(value):
    return hashlib.sha256(value).hexdigest()

def encode(value):
    return base64.b64encode(value).decode("ascii")

def read_batch(path, request):
    offset = request["offset"]
    limit = request["max_records"]
    expected = request.get("expected")
    if type(offset) is not int or offset < 0:
        raise ValueError("Invalid offset")
    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("max_records must be 1..1000")
    if offset and expected is None:
        raise ValueError("Nonzero offset requires a checkpoint")

    with open(path, "rb", buffering=0) as stream:
        info = os.fstat(stream.fileno())
        identity = (str(info.st_dev), str(info.st_ino))
        size = info.st_size
        if offset > size:
            raise RuntimeError("File truncated below checkpoint")
        first = stream.readline(min(MAX_LINE + 1, size))
        if len(first) > MAX_LINE:
            raise ValueError("First line exceeds 1 MiB; offset unchanged")
        first_hash = digest(first) if first.endswith(b"\n") else None
        tail_start = max(0, offset - 4096)
        stream.seek(tail_start)
        old_tail = stream.read(offset - tail_start)
        if offset and not old_tail.endswith(b"\n"):
            raise ValueError("Checkpoint is not at a line boundary")
        if expected is not None:
            if expected["next_offset"] != offset:
                raise ValueError("Checkpoint offset mismatch")
            if identity != (expected["device_id"], expected["native_file_id"]):
                raise RuntimeError("Remote file replaced")
            if expected["first_line_sha256"] != first_hash:
                raise RuntimeError("First-line fingerprint changed")
            if base64.b64decode(expected["checkpoint_tail_b64"], validate=True) != old_tail:
                raise RuntimeError("Checkpoint bytes changed")

        stream.seek(offset)
        chunks = []
        used = 0
        status = "limit_reached"
        while len(chunks) < limit:
            available = size - offset - used
            if available == 0:
                status = "caught_up"
                break
            line = stream.readline(min(MAX_LINE + 1, available))
            if len(line) > MAX_LINE:
                raise ValueError("Line exceeds 1 MiB; batch not returned")
            if not line.endswith(b"\n"):
                status = "waiting_for_complete_line"
                break
            if used + len(line) > MAX_BATCH:
                status = "byte_limit_reached"
                break
            chunks.append(line)
            used += len(line)

        raw = b"".join(chunks)
        next_offset = offset + used
        stream.seek(max(0, next_offset - 4096))
        new_tail = stream.read(min(4096, next_offset))
        if new_tail != (old_tail + raw)[-4096:]:
            raise RuntimeError("New checkpoint bytes changed during read")

        # Detect observable replacement/truncation/rewrites during the read.
        current = os.stat(path)
        after = os.fstat(stream.fileno())
        if (str(current.st_dev), str(current.st_ino)) != identity:
            raise RuntimeError("Path replaced during read")
        if after.st_size < size:
            raise RuntimeError("File shrank during read")
        stream.seek(0)
        if stream.read(len(first)) != first:
            raise RuntimeError("First line changed during read")
        stream.seek(tail_start)
        if stream.read(len(old_tail)) != old_tail:
            raise RuntimeError("Checkpoint bytes changed during read")
        stream.seek(offset)
        if stream.read(len(raw)) != raw:
            raise RuntimeError("Batch changed during read")

        return {
            "protocol_version": 1,
            "file_path": path,
            "device_id": identity[0],
            "native_file_id": identity[1],
            "first_line_sha256": first_hash,
            "offset": offset,
            "next_offset": next_offset,
            "size_at_open": size,
            "line_count": len(chunks),
            "status": status,
            "batch_sha256": digest(raw),
            "raw_b64": encode(raw),
            "checkpoint_tail_b64": encode(new_tail),
        }
def find_archive_path(root, device_id, native_file_id):
    wanted = (device_id, native_file_id)
    matches = []

    for directory, folders, names in os.walk(root, onerror=raise_walk_error):
        folders.sort()

        for name in sorted(names):
            if (
                not name.startswith("ossec-alerts-")
                or not name.endswith(".json")
            ):
                continue

            path = os.path.join(directory, name)

            try:
                info = os.stat(path)
            except FileNotFoundError:
                continue

            if (str(info.st_dev), str(info.st_ino)) == wanted:
                matches.append(path)

    if len(matches) > 1:
        raise RuntimeError(
            "Multiple dated paths match this file; reconciliation required"
        )

    return matches[0] if matches else None

def read_source_batch(request, root="/var/ossec/logs/alerts"):
    """Follow the saved native file identity into retained plain JSON files."""
    active = os.path.join(root, "alerts.json")
    expected = request.get("expected")
    selected = active

    if expected is not None:
        wanted = (expected["device_id"], expected["native_file_id"])

        def matches(path):
            try:
                info = os.stat(path)
            except FileNotFoundError:
                return False
            return (str(info.st_dev), str(info.st_ino)) == wanted

        if not matches(active):
            selected = None

            for directory, folders, names in os.walk(root, onerror=raise_walk_error):
                folders.sort()

                for name in sorted(names):
                    if (
                        not name.startswith("ossec-alerts-")
                        or not name.endswith(".json")
                    ):
                        continue

                    candidate = os.path.join(directory, name)

                    if matches(candidate):
                        selected = candidate
                        break

                if selected is not None:
                    break

            if selected is None:
                raise RuntimeError(
                    "Checkpoint file is not available as retained plain JSON; "
                    "archive recovery is required. Checkpoint must remain unchanged."
                )

    response = read_batch(selected, request)

    # Keep the logical stream path stable for existing database checkpoints.
    response["file_path"] = active
    response["read_path"] = selected
    response["reading_retained_file"] = selected != active
    response["archive_path"] = find_archive_path(
        root,
        response["device_id"],
        response["native_file_id"],
    )


    return response

def raise_walk_error(error):
    # An unreadable directory must never look like an absent generation.
    raise error

def dated_path(path, root):
    # Native Path also permits the exact reader to be tested on Windows.
    # The deployed exporter runs on Linux and uses POSIX paths.
    parts = Path(path).relative_to(Path(root)).parts
    months = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")
    if len(parts) != 3 or parts[1] not in months:
        raise ValueError("Invalid dated source path")
    name = parts[2]
    if not name.startswith("ossec-alerts-") or not name.endswith(".json"):
        raise ValueError("Invalid dated source path")
    day = date(int(parts[0]), months.index(parts[1]) + 1,
               int(name[len("ossec-alerts-"):-len(".json")]))
    canonical = os.path.join(root, str(day.year), months[day.month - 1],
                             "ossec-alerts-{:02d}.json".format(day.day))
    if path != canonical or os.path.commonpath((os.path.realpath(root),
                                              os.path.realpath(path))) != os.path.realpath(root):
        raise ValueError("Invalid dated source path")
    return path

def source_descriptor(path, root):
    batch = read_batch(path, {"offset": 0, "max_records": 1, "expected": None})
    archive = find_archive_path(root, batch["device_id"], batch["native_file_id"])
    if archive is not None:
        dated_path(archive, root)
    return {
        "device_id": batch["device_id"],
        "native_file_id": batch["native_file_id"],
        "first_line_sha256": batch["first_line_sha256"],
        "size_at_open": batch["size_at_open"],
        "read_path": path,
        "archive_path": archive,
    }

def inspect_sources(root="/var/ossec/logs/alerts"):
    """Bounded inventory of retained plain daily files and the active alias."""
    active_path = os.path.join(root, "alerts.json")
    try:
        active = source_descriptor(active_path, root)
    except FileNotFoundError:
        active = None
    paths = []
    for directory, folders, names in os.walk(root, onerror=raise_walk_error):
        folders.sort()
        for name in sorted(names):
            if name.startswith("ossec-alerts-") and name.endswith(".json"):
                path = dated_path(os.path.join(directory, name), root)
                paths.append(path)
                if len(paths) > 512:
                    raise RuntimeError("More than 512 plain daily files; inventory refused")
    sources = []
    identities = set()
    for path in paths:
        descriptor = source_descriptor(path, root)
        identity = (descriptor["device_id"], descriptor["native_file_id"])
        if identity in identities:
            raise RuntimeError("Multiple dated paths match this file; reconciliation required")
        identities.add(identity)
        sources.append(descriptor)
    if active is not None:
        after = os.stat(active_path)
        if (str(after.st_dev), str(after.st_ino)) != (active["device_id"], active["native_file_id"]):
            raise RuntimeError("Active alias changed during inventory")
    return {"protocol_version": 2, "active": active, "sources": sources}

def inspect_checkpoint(request, root="/var/ossec/logs/alerts"):
    expected = request["expected"]
    archive_hint = request["archive_path"]
    if archive_hint is not None:
        dated_path(archive_hint, root)
    active = os.path.join(root, "alerts.json")
    wanted = (expected["device_id"], expected["native_file_id"])
    try:
        info = os.stat(active)
        selected = active if (str(info.st_dev), str(info.st_ino)) == wanted else None
    except FileNotFoundError:
        selected = None
    if selected is None:
        selected = find_archive_path(root, *wanted)
    if selected is None:
        compressed = False
        if archive_hint is not None:
            try:
                os.stat(archive_hint + ".gz")
                compressed = True
            except FileNotFoundError:
                pass
        return {"protocol_version": 2, "status": "unavailable",
                "source": None, "compressed_archive_available": compressed}
    source = source_descriptor(selected, root)
    if (source["device_id"], source["native_file_id"]) != wanted:
        raise RuntimeError("Source changed during inspection")
    issues = {
        "File truncated below checkpoint": "truncation_detected",
        "Checkpoint is not at a line boundary": "content_change_detected",
        "First-line fingerprint changed": "content_change_detected",
        "Checkpoint bytes changed": "content_change_detected",
    }
    try:
        read_batch(selected, {"offset": expected["next_offset"],
                              "expected": expected, "max_records": 1})
    except (RuntimeError, ValueError) as error:
        status = issues.get(str(error))
        if status is None:
            raise
        issue = str(error)
    else:
        status, issue = "valid", None
    # Verify native identity and the first complete line again after inspection.
    after = source_descriptor(selected, root)
    for key in ("device_id", "native_file_id", "first_line_sha256", "archive_path"):
        if source[key] != after[key]:
            raise RuntimeError("Source changed during inspection")
    return {"protocol_version": 2, "status": status,
            "issue": issue, "source": after,
            "compressed_archive_available": False}

if __name__ == "__main__":
    request = json.loads(base64.b64decode(sys.argv[1], validate=True))

    try:
        response = read_source_batch(request)
    except (OSError, ValueError, RuntimeError, KeyError) as error:
        print(json.dumps({
            "error": type(error).__name__,
            "message": str(error),
        }))
        sys.exit(2)

    print(json.dumps(response, separators=(",", ":")))
'''


def checkpoint_from_batch(batch):
    """Transport checkpoint only; the database must commit it with outcomes."""
    if batch["first_line_sha256"] is None:
        raise ValueError("Cannot register a generation before its first complete line")
    return {key: batch[key] for key in (
        "device_id", "native_file_id", "first_line_sha256",
        "next_offset", "checkpoint_tail_b64",
    )}


class RemoteReadError(RuntimeError):
    """Structured exporter rejection; SSH/network failures stay ordinary errors."""
    def __init__(self, detail):
        self.detail = detail
        super().__init__("Remote read failed (2): " + json.dumps(detail))


def _request(request, *, host="192.168.0.32", user="spine-reader", timeout=90):
    if not host or host.startswith("-"):
        raise ValueError("Invalid SSH host")
    if user != "spine-reader":
        raise ValueError("This transport requires the spine-reader account")
    key = Path.home() / ".ssh" / "spine_wazuh_rsa"
    if not key.is_file():
        raise ValueError(f"Collector SSH key not found: {key}")
    result = subprocess.run(
        ["ssh", "-T", "-i", str(key), "-o", "IdentitiesOnly=yes",
         "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
         "-o", "PubkeyAcceptedAlgorithms=rsa-sha2-512,rsa-sha2-256",
         "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
         "-o", "ServerAliveCountMax=2", "-l", user, host],
        input=json.dumps(request).encode("utf-8"), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode:
        if result.returncode == 2 and not result.stderr.strip():
            try:
                detail = json.loads(result.stdout)
            except (ValueError, UnicodeError):
                detail = None
            if (isinstance(detail, dict) and set(detail) == {"error", "message"}
                    and all(isinstance(v, str) for v in detail.values())):
                raise RemoteReadError(detail)
        detail = (result.stderr.decode("utf-8", errors="replace")
                  + result.stdout.decode("utf-8", errors="replace"))[:2000]
        raise RuntimeError(f"Remote read failed ({result.returncode}): {detail}")
    response = json.loads(result.stdout)
    if not isinstance(response, dict):
        raise ValueError("Expected a remote response object")
    return response


def fetch_inventory(**transport):
    response = _request({"action": "inspect_sources"}, **transport)
    if response.get("protocol_version") != 2:
        raise ValueError("Install the maintenance exporter before enabling recovery")
    return response


def fetch_inspection(*, expected, archive_path, **transport):
    response = _request({"action": "inspect_checkpoint", "expected": expected,
                         "archive_path": archive_path}, **transport)
    if response.get("protocol_version") != 2:
        raise ValueError("Unexpected checkpoint inspection response")
    return response


def fetch_batch(
    *,
    host="192.168.0.32",
    user="spine-reader",
    offset=0,
    expected=None,
    max_records=100,
    timeout=90,
):
    """Fetch a verified batch through the restricted server exporter."""
    batch = _request({"action": "read_batch", "offset": offset,
                      "expected": expected, "max_records": max_records},
                     host=host, user=user, timeout=timeout)
    if batch.get("protocol_version") != 1 or batch.get("file_path") != REMOTE_PATH:
        raise ValueError("Unexpected remote response")

    raw = base64.b64decode(batch.pop("raw_b64"), validate=True)

    if len(raw) > 4 * 1024 * 1024:
        raise ValueError("Remote batch exceeds byte limit")

    if (
        batch["offset"] != offset
        or batch["next_offset"] != offset + len(raw)
    ):
        raise ValueError("Remote offsets do not match batch length")

    if hashlib.sha256(raw).hexdigest() != batch["batch_sha256"]:
        raise ValueError("Remote batch checksum mismatch")

    if raw and not raw.endswith(b"\n"):
        raise ValueError("Incomplete batch received")

    if batch["line_count"] != raw.count(b"\n"):
        raise ValueError("Remote line count mismatch")

    if batch["line_count"] > max_records:
        raise ValueError("Remote record limit exceeded")

    batch["raw_bytes"] = raw
    return batch


def self_test():
    """Exercise the exact remote program against temporary local files."""
    namespace = {"__name__": "remote_reader_test"}
    exec(compile(REMOTE_PROGRAM, "remote_reader", "exec"), namespace)
    read = namespace["read_batch"]
    def request(offset=0, expected=None, limit=100):
        return {"offset": offset, "expected": expected, "max_records": limit}
    def rejected(path, req):
        try:
            read(str(path), req)
        except (ValueError, RuntimeError):
            return
        raise AssertionError("Expected read to be rejected")

    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "alerts.json"
        path.write_bytes(b'{"id":"one"}\n{"id":')
        first = read(str(path), request())
        assert first["line_count"] == 1
        assert first["status"] == "waiting_for_complete_line"
        checkpoint = checkpoint_from_batch(first)
        with path.open("ab") as stream:
            stream.write(b'"two"}\n')
        second = read(str(path), request(first["next_offset"], checkpoint))
        assert base64.b64decode(second["raw_b64"]) == b'{"id":"two"}\n'
        end = checkpoint_from_batch(second)
        assert read(str(path), request(end["next_offset"], end))["line_count"] == 0
        print("PASS: complete lines, append, and checkpoint resume")

        original = path.read_bytes()
        path.write_bytes(original.replace(b"one", b"ONE"))
        rejected(path, request(end["next_offset"], end))
        path.write_bytes(b'{}\n')
        rejected(path, request(end["next_offset"], end))
        path.write_bytes(original)
        replacement = Path(folder) / "replacement"
        replacement.write_bytes(original)
        replacement.replace(path)
        rejected(path, request(end["next_offset"], end))
        print("PASS: changed content, truncation, and replacement rejected")

        path.write_bytes(b'\xff\x00\r\n{}\n')
        raw = read(str(path), request(limit=1))
        assert base64.b64decode(raw["raw_b64"]) == b'\xff\x00\r\n'
        print("PASS: invalid UTF-8 and CRLF retained as exact bytes")
        path.write_bytes(b'x' * (1024 * 1024 + 1))
        rejected(path, request())
        print("PASS: oversized line rejected without returning progress")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--host", default="192.168.0.32")
    parser.add_argument("--user", default="spine-reader")
    parser.add_argument("--max-records", type=int, default=100)
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    try:
        batch = fetch_batch(host=args.host, user=args.user, max_records=args.max_records)
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Read failed: {error}\n")
    raw = batch.pop("raw_bytes")
    batch.pop("checkpoint_tail_b64")
    batch["bytes_received"] = len(raw)
    batch["database_written"] = False
    print(json.dumps(batch, indent=2))


if __name__ == "__main__":
    main()
