"""Preserve source-provided MITRE labels in a consistent structure."""

from copy import deepcopy
import re


TECHNIQUE_ID = re.compile(r"T[0-9]{4}(?:\.[0-9]{3})?")


def normalize_mitre(record: dict) -> dict:
    """Normalize Wazuh rule labels without inferring attack activity."""
    result = deepcopy(record)

    # This mapper owns only Wazuh rule.mitre interpretation.
    if result.get("collector") != "wazuh_alerts":
        return result

    attributes = result.setdefault("attributes", {})
    attributes.pop("mitre", None)

    rule = result.get("rule")
    if not isinstance(rule, dict) or "mitre" not in rule:
        return result

    warnings = result["normalization"]["warnings"]

    def warn(message):
        if message not in warnings:
            warnings.append(message)

    original = rule["mitre"]
    if not isinstance(original, dict):
        warn("Invalid rule.mitre: expected an object")
        return result

    def text_list(key, *, technique_ids=False):
        if key not in original:
            return []

        values = original[key]
        if not isinstance(values, list):
            warn(f"Invalid rule.mitre.{key}: expected a list")
            return []

        accepted = []
        for index, value in enumerate(values):
            if not isinstance(value, str) or not value.strip():
                warn(f"Invalid rule.mitre.{key}[{index}]: expected text")
                continue

            value = value.strip()

            if technique_ids and TECHNIQUE_ID.fullmatch(value) is None:
                warn(
                    f"Invalid rule.mitre.{key}[{index}]: "
                    "unexpected technique ID syntax"
                )
                continue

            if value not in accepted:
                accepted.append(value)

        return accepted

    attributes["mitre"] = {
        "technique_ids": text_list("id", technique_ids=True),
        "technique_names": text_list("technique"),
        "tactic_names": text_list("tactic"),
        "provenance": {
            "collector": "wazuh_alerts",
            "field": "rule.mitre",
            "rule_id": deepcopy(rule.get("id")),
        },
        "interpretation": "source_rule_labels",
        "catalog_validated": False,
    }

    return result