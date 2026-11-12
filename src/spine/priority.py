"""Project priority bands derived from the original Wazuh rule level."""


def normalize_wazuh_priority(value: object) -> dict:
    """Preserve valid levels; distinguish missing values from invalid input."""
    if value is None:
        return {
            "wazuh_level": None,
            "priority_band": None,
            "actionable": None,
        }

    # bool is a subclass of int in Python, but is not a valid severity.
    if isinstance(value, bool):
        raise ValueError("Wazuh rule level cannot be a boolean")

    if isinstance(value, int):
        level = value
    elif isinstance(value, str):
        text = value.strip()
        if not text or not text.isascii() or not text.isdecimal():
            raise ValueError(f"Invalid Wazuh rule level: {value!r}")
        level = int(text)
    else:
        raise ValueError(f"Invalid Wazuh rule level: {value!r}")

    if not 0 <= level <= 16:
        raise ValueError("Wazuh rule level must be between 0 and 16")

    if level == 0:
        band = None
    elif level <= 5:
        band = "low"
    elif level <= 11:
        band = "medium"
    elif level <= 14:
        band = "high"
    else:
        band = "critical"

    return {
        "wazuh_level": level,
        "priority_band": band,
        "actionable": level > 0,
    }