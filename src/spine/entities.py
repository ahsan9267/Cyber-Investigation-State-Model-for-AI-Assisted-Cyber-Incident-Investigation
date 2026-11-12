"""Extract entity references from normalized evidence.

References describe what this record contains.
Cross-record identity resolution belongs to later processing.
"""

from copy import deepcopy
import ipaddress


def extract_entities(record: dict) -> dict:
    """Return an independent record with repeatable entity references."""
    result = deepcopy(record)
    entities = []
    record_id = result["record_id"]

    def section(value):
        return value if isinstance(value, dict) else {}

    def add(entity_type, value, role, field, **details):
        if value is None:
            return

        if isinstance(value, str):
            if not value.strip() or value.strip() == "-":
                return
        elif isinstance(value, bool) or not isinstance(value, int):
            return

        entities.append({
            "type": entity_type,
            "value": value,
            "role": role,
            "field": field,
            "record_id": record_id,
            "details": {
                key: deepcopy(item)
                for key, item in details.items()
                if item is not None
            },
        })

    def add_ip(value, role, field):
        if not isinstance(value, str):
            return
        try:
            address = str(ipaddress.ip_address(value))
        except ValueError:
            return
        add("ip_address", address, role, field)

    host = section(result.get("host"))
    agent = section(result.get("agent"))
    attributes = section(result.get("attributes"))

    add("host", host.get("name"), "event_host", "host.name")
    add(
        "host",
        agent.get("name"),
        "reporting_agent",
        "agent.name",
        agent_id=agent.get("id"),
        source_scope=result["provenance"]["source_scope"],
    )
    add_ip(agent.get("ip"), "reporting_agent", "agent.ip")

    process = section(attributes.get("process"))
    parent = section(process.get("parent"))

    for item, role, prefix in (
        (process, "process", "attributes.process"),
        (parent, "parent_process", "attributes.process.parent"),
    ):
        guid = item.get("guid")
        pid = item.get("id")

        if isinstance(guid, str) and guid.strip():
            add(
                "process", guid, role, f"{prefix}.guid",
                pid=pid,
                host_name=host.get("name"),
                image=item.get("image"),
                identity_basis="source_process_guid",
            )
        elif isinstance(pid, int) and not isinstance(pid, bool):
            add(
                "process", pid, role, f"{prefix}.id",
                host_name=host.get("name"),
                image=item.get("image"),
                identity_basis="record_local_pid",
            )

        add(
            "file", item.get("image"), f"{role}_image",
            f"{prefix}.image",
            host_name=host.get("name"),
        )
        add("user", item.get("user"), f"{role}_user", f"{prefix}.user")

    authentication = section(attributes.get("authentication"))

    for role in ("subject", "target"):
        account = section(authentication.get(role))
        prefix = f"attributes.authentication.{role}"

        sid = account.get("sid")
        name = account.get("name")

        has_name = (
            isinstance(name, str)
            and bool(name.strip())
            and name.strip() != "-"
        )
        has_sid = (
            isinstance(sid, str)
            and bool(sid.strip())
            and sid.strip() not in ("-", "S-1-0-0")
        )

        if not has_name and not has_sid:
            continue

        value = name if has_name else sid
        field = f"{prefix}.name" if has_name else f"{prefix}.sid"

        add(
            "user", value, f"authentication_{role}", field,
            sid=sid,
            domain=account.get("domain"),
            logon_id=account.get("logon_id"),
        )

    add_ip(
        authentication.get("source_ip"),
        "authentication_source",
        "attributes.authentication.source_ip",
    )

    caller = section(authentication.get("caller_process"))
    add(
        "process", caller.get("id"), "authentication_caller",
        "attributes.authentication.caller_process.id",
        image=caller.get("image"),
        identity_basis="record_local_pid",
    )
    add(
        "file", caller.get("image"), "authentication_caller_image",
        "attributes.authentication.caller_process.image",
        host_name=host.get("name"),
    )

    network = section(attributes.get("network"))
    for key, role in (
        ("source_ip", "network_source"),
        ("destination_ip", "network_destination"),
    ):
        add_ip(network.get(key), role, f"attributes.network.{key}")

    service = section(attributes.get("service"))
    add(
        "user", service.get("account"), "service_account",
        "attributes.service.account",
    )

    dns = section(attributes.get("dns"))
    add("domain_name", dns.get("query_name"), "dns_query", "attributes.dns.query_name")
    for index, question in enumerate(dns.get("questions") or []):
        if isinstance(question, dict):
            add("domain_name", question.get("name"), "dns_query",
                f"attributes.dns.questions[{index}].name")
    for index, answer in enumerate(dns.get("answers") or []):
        if isinstance(answer, dict) and answer.get("type") in ("A", "AAAA"):
            add_ip(answer.get("data"), "dns_answer",
                   f"attributes.dns.answers[{index}].data")

    # A service image path may contain arguments.
    # Keep it in attributes.service until path parsing is implemented.

    syscheck = section(attributes.get("syscheck"))
    add(
        "file", syscheck.get("path_original"), "monitored_file",
        "attributes.syscheck.path_original",
        host_name=host.get("name"),
        agent_id=agent.get("id"),
    )

    # Registry paths remain in attributes.registry, not File entities.

    add(
        "event", record_id, "evidence_record", "record_id",
        event_type=section(result.get("event")).get("type"),
    )

    if result.get("record_kind") == "alert":
        add(
            "alert", record_id, "alert_record", "record_id",
            rule_id=section(result.get("rule")).get("id"),
        )

    result["entities"] = entities
    return result
