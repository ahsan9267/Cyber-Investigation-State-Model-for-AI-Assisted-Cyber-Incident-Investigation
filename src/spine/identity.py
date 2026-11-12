"""Apply explicit, scoped host mappings without changing source evidence."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path


CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "identity_mappings.json"
)

ALLOWED_FIELDS = {
    "agent.id": "reporting_agent",
    "host.name": "event_host",
}

REQUIRED_FIELDS = {
    "mapping_id",
    "collector",
    "source_scope",
    "field",
    "value",
    "entity_role",
    "canonical_host_id",
}


def validate_config(config):
    if not isinstance(config, dict) or config.get("version") != "1":
        raise ValueError("Expected identity configuration version 1")

    mappings = config.get("host_mappings")
    if not isinstance(mappings, list):
        raise ValueError("host_mappings must be a list")

    mapping_ids = set()
    selectors = set()

    for item in mappings:
        if not isinstance(item, dict) or set(item) != REQUIRED_FIELDS:
            raise ValueError("Invalid host mapping fields")

        for key in REQUIRED_FIELDS:
            if (
                not isinstance(item[key], str)
                or not item[key].strip()
                or item[key] != item[key].strip()
            ):
                raise ValueError(f"Invalid host mapping value: {key}")

        if ALLOWED_FIELDS.get(item["field"]) != item["entity_role"]:
            raise ValueError("Host mapping field and role do not agree")

        if item["mapping_id"] in mapping_ids:
            raise ValueError("Duplicate host mapping ID")
        mapping_ids.add(item["mapping_id"])

        selector = (
            item["collector"],
            item["source_scope"],
            item["field"],
            item["value"],
        )
        if selector in selectors:
            raise ValueError("Duplicate or conflicting host selector")
        selectors.add(selector)

    return config


def load_config():
    try:
        text = CONFIG_PATH.read_text(encoding="utf-8-sig")

        def unique_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"Duplicate configuration key: {key}")
                result[key] = value
            return result

        config = json.loads(text, object_pairs_hook=unique_keys)
        return validate_config(config)
    except (OSError, UnicodeError, ValueError) as error:
        # Configuration failures must stop processing, not quarantine evidence.
        raise RuntimeError(
            f"Cannot load identity configuration {CONFIG_PATH}: {error}"
        ) from error


def map_host_identities(record, *, config=None):
    """Return a copy with explicit identity annotations on host entities."""
    if config is None:
        config = load_config()
    else:
        validate_config(config)

    result = deepcopy(record)

    config_text = json.dumps(
        config,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    )
    config_hash = hashlib.sha256(config_text.encode("utf-8")).hexdigest()

    collector = result.get("collector")
    scope = result.get("provenance", {}).get("source_scope")

    for entity in result.get("entities", []):
        if entity.get("type") != "host":
            continue

        details = entity.setdefault("details", {})
        # Replace only this mapper's annotation on repeated application.
        details.pop("configured_host_identity", None)

        for mapping in config["host_mappings"]:
            if (
                mapping["collector"] != collector
                or mapping["source_scope"] != scope
                or mapping["entity_role"] != entity.get("role")
            ):
                continue

            section_name, field_name = mapping["field"].split(".")
            section = result.get(section_name)
            if not isinstance(section, dict):
                continue
            if section.get(field_name) != mapping["value"]:
                continue

            details["configured_host_identity"] = {
                "canonical_host_id": mapping["canonical_host_id"],
                "mapping_id": mapping["mapping_id"],
                "basis": "explicit_configuration",
                "matched_field": mapping["field"],
                "matched_value": mapping["value"],
                "config_version": config["version"],
                "config_sha256": config_hash,
            }
            break

    return result