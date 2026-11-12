"""Annotate user entities using explicit, host-scoped account bindings."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import re

from spine.wazuh import _unique_keys, _reject_constant


CONFIG_PATH = (
    Path(__file__).resolve().parents[2] / "config" / "user_mappings.json"
)

AUTH_ROLES = {"authentication_subject", "authentication_target"}
PROCESS_ROLES = {"process_user", "parent_process_user"}


def validate_config(config):
    if (
        not isinstance(config, dict)
        or config.get("version") != "1"
        or not isinstance(config.get("accounts"), list)
    ):
        raise ValueError("Expected user mapping configuration version 1")

    def text(value):
        return (
            isinstance(value, str)
            and bool(value.strip())
            and value == value.strip()
        )

    account_ids = set()
    selectors = set()

    for account in config["accounts"]:
        if not isinstance(account, dict) or set(account) != {
            "account_id", "host_id", "sid", "bindings"
        }:
            raise ValueError("Invalid account configuration fields")

        if not all(text(account[key]) for key in (
            "account_id", "host_id", "sid"
        )):
            raise ValueError("Account identifiers must be nonempty text")

        if (
            re.fullmatch(r"S-1-(?:[0-9]+-)*[0-9]+", account["sid"]) is None
            or account["sid"] == "S-1-0-0"
        ):
            raise ValueError("Invalid configured account SID")

        if account["account_id"] in account_ids:
            raise ValueError("Duplicate account ID")
        account_ids.add(account["account_id"])

        bindings = account["bindings"]
        if not isinstance(bindings, list) or not bindings:
            raise ValueError("Account bindings must be a nonempty list")

        for binding in bindings:
            if not isinstance(binding, dict) or set(binding) != {
                "collector", "source_scope", "match", "value", "roles"
            }:
                raise ValueError("Invalid account binding fields")

            if not all(text(binding[key]) for key in (
                "collector", "source_scope", "match", "value"
            )):
                raise ValueError("Invalid account binding text")

            mode = binding["match"]
            if mode == "sid":
                allowed_roles = AUTH_ROLES
                if binding["value"] != account["sid"]:
                    raise ValueError("SID binding disagrees with account SID")
            elif mode == "qualified_name":
                allowed_roles = PROCESS_ROLES
                domain, separator, name = binding["value"].partition("\\")
                if not separator or not domain or not name.strip("\\"):
                    raise ValueError("A qualified account name is required")
            else:
                raise ValueError("Unsupported account match type")

            roles = binding["roles"]
            if (
                not isinstance(roles, list)
                or not roles
                or any(
                    not isinstance(role, str) or role not in allowed_roles
                    for role in roles
                )
                or len(set(roles)) != len(roles)
            ):
                raise ValueError("Invalid account binding roles")

            for role in roles:
                selector = (
                    account["host_id"],
                    binding["collector"],
                    binding["source_scope"],
                    mode,
                    binding["value"],
                    role,
                )
                if selector in selectors:
                    raise ValueError("Duplicate or conflicting account selector")
                selectors.add(selector)

    return config


def load_config():
    try:
        config = json.loads(
            CONFIG_PATH.read_text(encoding="utf-8-sig"),
            object_pairs_hook=_unique_keys,
            parse_constant=_reject_constant,
        )
        return validate_config(config)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(
            f"Cannot load user mappings {CONFIG_PATH}: {error}"
        ) from error


def map_user_identities(record, *, config=None):
    if config is None:
        config = load_config()
    else:
        validate_config(config)

    result = deepcopy(record)
    entities = result.get("entities", [])

    config_hash = hashlib.sha256(
        json.dumps(
            config, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    ).hexdigest()

    # Only an explicitly mapped event host provides account context.
    # Reporting-agent identity alone is insufficient.
    host_ids = set()
    for entity in entities:
        if entity.get("type") == "host" and entity.get("role") == "event_host":
            mapping = entity.get("details", {}).get(
                "configured_host_identity", {}
            )
            host_id = mapping.get("canonical_host_id")
            if host_id:
                host_ids.add(host_id)

    host_id = next(iter(host_ids)) if len(host_ids) == 1 else None
    collector = result.get("collector")
    scope = result.get("provenance", {}).get("source_scope")

    for entity in entities:
        if entity.get("type") != "user":
            continue

        details = entity.setdefault("details", {})
        details.pop("configured_user_identity", None)

        if host_id is None:
            continue

        matches = []
        for account in config["accounts"]:
            if account["host_id"] != host_id:
                continue

            # A conflicting source SID must never be overridden by a name.
            source_sid = details.get("sid")
            if source_sid is not None and source_sid != account["sid"]:
                continue

            for binding in account["bindings"]:
                if (
                    binding["collector"] != collector
                    or binding["source_scope"] != scope
                    or entity.get("role") not in binding["roles"]
                ):
                    continue

                mode = binding["match"]
                observed = (
                    source_sid if mode == "sid" else entity.get("value")
                )
                if observed == binding["value"]:
                    matches.append((account, binding))

        if len(matches) > 1:
            raise RuntimeError("Ambiguous configured account identity")

        if matches:
            account, binding = matches[0]
            details["configured_user_identity"] = {
                "canonical_account_id": account["account_id"],
                "canonical_host_id": host_id,
                "configured_sid": account["sid"],
                "basis": "explicit_configuration",
                "matched_by": binding["match"],
                "matched_value": binding["value"],
                "config_version": config["version"],
                "config_sha256": config_hash,
            }

    return result