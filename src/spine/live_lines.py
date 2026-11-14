"""Read complete lines from an append-only binary log."""

MAX_LINE_BYTES = 1024 * 1024


class OversizedLineError(ValueError):
    """Reading stopped because a line exceeded the configured limit."""


def read_complete_line(stream, offset, *, max_line_bytes=MAX_LINE_BYTES):
    """Return (raw_bytes, next_offset), or None if no complete line exists.

    The caller advances its durable checkpoint only after saving the
    returned line. Incomplete lines leave the stream at the given offset.
    """
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or offset < 0
    ):
        raise ValueError("offset must be a non-negative integer")

    if (
        isinstance(max_line_bytes, bool)
        or not isinstance(max_line_bytes, int)
        or max_line_bytes < 1
    ):
        raise ValueError("max_line_bytes must be a positive integer")

    stream.seek(offset)
    raw_bytes = stream.readline(max_line_bytes + 1)

    if len(raw_bytes) > max_line_bytes:
        stream.seek(offset)
        raise OversizedLineError(
            f"Line at byte {offset} exceeds {max_line_bytes} bytes"
        )

    if not raw_bytes.endswith(b"\n"):
        stream.seek(offset)
        return None

    return raw_bytes, offset + len(raw_bytes)