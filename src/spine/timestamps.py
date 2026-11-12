"""Convert source timestamps to UTC without losing fractional precision."""

import re
from datetime import datetime, timedelta, timezone


_PATTERN = re.compile(
    r"(?P<date>\d{4}-\d{2}-\d{2})[T ]"
    r"(?P<time>\d{2}:\d{2}:\d{2})"
    r"(?P<fraction>\.\d{1,9})?"
    r"(?P<zone>Z|[+-]\d{2}:?\d{2})?",
    flags=re.ASCII,
)


def normalize_timestamp(
    value: str,
    *,
    source_timezone: str | None = None,
) -> dict:
    """Return UTC time and provenance.

    source_timezone="UTC" is permitted only when the source field is
    explicitly defined as UTC. Never infer a timezone from this computer.
    """
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Timestamp must be a non-empty string")

    if source_timezone not in (None, "UTC"):
        raise ValueError("Only an explicit UTC source timezone is supported")

    match = _PATTERN.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"Unsupported timestamp format: {value!r}")

    zone = match.group("zone")
    fraction = match.group("fraction") or ""
    timezone_basis = "explicit_offset"

    if zone is None:
        if source_timezone != "UTC":
            raise ValueError("Timestamp has no timezone")
        offset = timezone.utc
        timezone_basis = "source_field_definition"
        original_offset = None
    elif zone == "Z":
        offset = timezone.utc
        original_offset = "Z"
    else:
        digits = zone[1:].replace(":", "")
        hours = int(digits[:2])
        minutes = int(digits[2:])

        if hours > 23 or minutes > 59:
            raise ValueError("Invalid UTC offset")

        # Negative zero can mean an unknown local offset.
        if zone.startswith("-") and hours == 0 and minutes == 0:
            raise ValueError("Unknown negative-zero offset is not supported")

        delta = timedelta(hours=hours, minutes=minutes)
        if zone.startswith("-"):
            delta = -delta

        offset = timezone(delta)
        original_offset = zone

    # Convert whole seconds separately so datetime cannot truncate
    # the source's seventh, eighth, or ninth fractional digit.
    base = datetime.strptime(
        f"{match.group('date')}T{match.group('time')}",
        "%Y-%m-%dT%H:%M:%S",
    )
    utc = base.replace(tzinfo=offset).astimezone(timezone.utc)

    return {
        "utc": utc.isoformat(timespec="seconds").removesuffix("+00:00")
        + fraction
        + "Z",
        "original": value,
        "original_offset": original_offset,
        "timezone_basis": timezone_basis,
        "fractional_digits": len(fraction.lstrip(".")),
    }