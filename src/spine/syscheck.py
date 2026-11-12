"""Normalize Wazuh syscheck records while preserving source fields."""

from copy import deepcopy


def map_syscheck(record: dict) -> dict:
    result = deepcopy(record)

    payload = (
        result.get("attributes", {})
        .get("source_payload", {})
    )
    syscheck = payload.get("syscheck")

    if result.get("source") != "wazuh_syscheck":
        raise ValueError("Expected a Wazuh syscheck record")
    if not isinstance(syscheck, dict):
        raise ValueError("Missing Wazuh syscheck object")

    warnings = result["normalization"]["warnings"]

    def text(key):
        value = syscheck.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            warnings.append(f"Invalid syscheck text field: {key}")
            return None
        return value

    event = text("event")
    decoder = result.get("provenance", {}).get("decoder", {})
    decoder_name = (
        decoder.get("name") if isinstance(decoder, dict) else None
    )

    is_registry = (
        "syscheck_registry" in (
            result.get("rule", {}).get("groups") or []
        )
        or "registry" in (text("path") or "").lower()
    )

    details = {
        "path_original": text("path"),
        "mode": text("mode"),
        "architecture": text("arch"),
        "event": event,
        "decoder": decoder_name,
        "size_before": text("size_before"),
        "size_after": text("size_after"),
                "hashes": {
            algorithm: {
                phase: text(f"{algorithm}_{phase}")
                for phase in ("before", "after")
                if f"{algorithm}_{phase}" in syscheck
            }
            for algorithm in ("md5", "sha1", "sha256")
            if any(
                f"{algorithm}_{phase}" in syscheck
                for phase in ("before", "after")
            )
        },
        
        "changed_attributes": deepcopy(
            syscheck.get("changed_attributes")
        ),
        "modified_time_after": text("mtime_after"),
    }

    if is_registry:
        details.update({
            "registry_value_name": text("value_name"),
            "registry_value_type": text("value_type"),
            "permissions_after": deepcopy(syscheck.get("win_perm_after")),
            "owner_after": text("uname_after"),
            "owner_sid_after": text("uid_after"),
            "group_after": text("gname_after"),
            "group_sid_after": text("gid_after"),
        })
        result["event"] = {
            **result["event"],
            "type": f"registry_{event or 'change'}",
        }
        result["attributes"]["registry"] = details
    else:
        # Keep future syscheck families available without claiming
        # a detailed file mapping we have not yet verified.
        result["event"] = {
            **result["event"],
            "type": f"syscheck_{event or 'change'}",
        }
        result["attributes"]["syscheck"] = details

    result["normalization"]["parser"] = (
        "wazuh_common/0.1.0+syscheck/0.1.0"
    )
    result["normalization"]["status"] = "partial"
    return result