"""Distinguish reader failures without resetting ingestion state."""

import json


class SysmonReadError(RuntimeError):
    pass


class SysmonCheckpointUnavailable(SysmonReadError):
    pass


class SysmonCheckpointMismatch(SysmonReadError):
    pass


class SysmonQueryStale(SysmonReadError):
    pass


def raise_reader_error(stderr: bytes):
    detail = stderr.decode("utf-8-sig", errors="replace").strip()

    try:
        payload = json.loads(detail)
    except ValueError:
        raise SysmonReadError(
            f"Sysmon read failed: {detail[:2000]}"
        ) from None

    if not isinstance(payload, dict):
        raise SysmonReadError("Invalid Sysmon reader error response")

    message = str(payload.get("message", "Unspecified reader failure"))[:2000]
    kind = payload.get("kind")

    error_class = {
        "checkpoint_unavailable": SysmonCheckpointUnavailable,
        "checkpoint_mismatch": SysmonCheckpointMismatch,
        "query_stale": SysmonQueryStale,
    }.get(kind, SysmonReadError)

    raise error_class(f"Sysmon read failed: {message}")