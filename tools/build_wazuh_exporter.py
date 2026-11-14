"""Build the fixed server exporter from the tested remote reader."""

import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from spine.remote_wazuh import REMOTE_PROGRAM


ENTRY = r'''

def unique_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate request key")
        result[key] = value

    return result


def reject_constant(value):
    raise ValueError("Invalid JSON constant")


def serve():
    raw = sys.stdin.buffer.read(16385)

    if len(raw) > 16384:
        raise ValueError("Request exceeds 16 KiB")

    request = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=unique_keys,
        parse_constant=reject_constant,
    )

    if not isinstance(request, dict):
        raise ValueError("Expected a JSON object")

    action = request.pop("action", None)

    if action == "ping":
        if request:
            raise ValueError("Unexpected ping fields")

        return {
            "status": "ready",
            "exporter": "spine-wazuh-export/0.2.0",
            "python": sys.version.split()[0],
        }

    if action == "inspect_sources":
        if request:
            raise ValueError("Unexpected inventory fields")
        return inspect_sources()

    inspection = action == "inspect_checkpoint"
    if inspection:
        if set(request) != {"expected", "archive_path"} or not isinstance(request["expected"], dict):
            raise ValueError("Unexpected inspection fields")
        request["offset"] = request["expected"].get("next_offset")
        request["max_records"] = 1
    elif action != "read_batch":
        raise ValueError("Unsupported action")

    if not inspection and set(request) != {"offset", "max_records", "expected"}:
        raise ValueError("Unexpected batch request fields")

    if type(request["offset"]) is not int or request["offset"] < 0:
        raise ValueError("Invalid offset")

    if (
        type(request["max_records"]) is not int
        or not 1 <= request["max_records"] <= 1000
    ):
        raise ValueError("max_records must be 1..1000")

    expected = request["expected"]

    if expected is None:
        if request["offset"] != 0:
            raise ValueError("Nonzero offset requires a checkpoint")

    else:
        keys = {
            "device_id",
            "native_file_id",
            "first_line_sha256",
            "next_offset",
            "checkpoint_tail_b64",
        }

        if not isinstance(expected, dict) or set(expected) != keys:
            raise ValueError("Invalid checkpoint fields")

        if (
            type(expected["next_offset"]) is not int
            or expected["next_offset"] != request["offset"]
        ):
            raise ValueError("Checkpoint offset mismatch")

        for name in ("device_id", "native_file_id"):
            value = expected[name]

            if (
                not isinstance(value, str)
                or not value.isascii()
                or not value.isdigit()
                or len(value) > 32
            ):
                raise ValueError("Invalid native identity")

        fingerprint = expected["first_line_sha256"]

        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(c not in "0123456789abcdef" for c in fingerprint)
        ):
            raise ValueError("Invalid first-line fingerprint")

        if not isinstance(expected["checkpoint_tail_b64"], str):
            raise ValueError("Invalid checkpoint bytes")

        tail = base64.b64decode(
            expected["checkpoint_tail_b64"],
            validate=True,
        )

        if len(tail) != min(4096, request["offset"]):
            raise ValueError("Invalid checkpoint byte length")

    if inspection:
        return inspect_checkpoint(request)
    return read_source_batch(request)


if __name__ == "__main__":
    try:
        response = serve()
    except (OSError, ValueError, RuntimeError, KeyError, TypeError) as error:
        print(json.dumps({
            "error": type(error).__name__,
            "message": str(error),
        }))
        sys.exit(2)

    print(json.dumps(response, separators=(",", ":")))
'''


def main():
    tree = ast.parse(REMOTE_PROGRAM)

    expected_guard = ast.parse(
        'if __name__ == "__main__": pass'
    ).body[0].test

    guards = [
        node
        for node in tree.body
        if isinstance(node, ast.If)
        and ast.dump(node.test) == ast.dump(expected_guard)
    ]

    if len(guards) != 1 or tree.body[-1] is not guards[0]:
        raise ValueError(
            "Unexpected remote program structure; no exporter generated"
        )

    prefix = "\n".join(
        REMOTE_PROGRAM.splitlines()[:guards[0].lineno - 1]
    )
    source = prefix + "\n" + ENTRY

    ast.parse(source, feature_version=(3, 9))
    compile(source, "wazuh_export.py", "exec")

    path = Path("data/deployment/wazuh_export.py")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(source.encode("utf-8"))

    checks = (
        (b'{"action":"ping"}', 0),
        (b'{"action":"shell"}', 2),
        (b'{"action":"ping","action":"ping"}', 2),
        (b'x' * 16385, 2),
    )

    for request, status in checks:
        result = subprocess.run(
            [sys.executable, "-I", str(path.resolve())],
            input=request,
            capture_output=True,
            timeout=10,
        )

        if result.returncode != status:
            raise RuntimeError(
                result.stderr.decode("utf-8", errors="replace")
            )

        response = json.loads(result.stdout)

        if status == 0:
            assert response["status"] == "ready"
        else:
            assert "error" in response

    print("PASS: exporter syntax is compatible with Python 3.9")
    print(
        "PASS: ping accepted; unknown action, "
        "duplicate keys, oversized input rejected"
    )
    print(f"Exporter: {path}")
    print(f"SHA256: {hashlib.sha256(path.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    main()
