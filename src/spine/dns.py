"""Map the DNS version 3 structure observed in the lab's Suricata EVE."""

from copy import deepcopy


def map_dns(data: dict, warnings: list) -> dict | None:
    """Map supported DNS fields; retain unsupported structures in raw data."""
    dns = data.get("dns")
    if not isinstance(dns, dict):
        warnings.append("Missing or invalid Suricata DNS object")
        return None

    version = dns.get("version")
    if not ((type(version) is int and version == 3) or version == "3"):
        warnings.append("Unsupported or missing Suricata DNS version")
        return None

    def text(value, field):
        if value is None:
            return None
        if not isinstance(value, str):
            warnings.append(f"Invalid DNS text field: {field}")
            return None
        return value

    def unsigned(value, field, maximum):
        if value is None:
            return None
        if isinstance(value, bool):
            warnings.append(f"Invalid DNS integer: {field}")
            return None

        if isinstance(value, int):
            number = value
        elif (
            isinstance(value, str)
            and value.isascii()
            and value.isdecimal()
            and len(value) <= 20
        ):
            number = int(value)
        else:
            warnings.append(f"Invalid DNS integer: {field}")
            return None

        if not 0 <= number <= maximum:
            warnings.append(f"Invalid DNS integer: {field}")
            return None
        return number

    def entries(field, answers=False):
        values = dns.get(field)
        if values is None:
            return None
        if not isinstance(values, list):
            warnings.append(f"Expected DNS array: {field}")
            return None

        mapped = []
        for index, value in enumerate(values):
            if not isinstance(value, dict):
                warnings.append(f"Invalid DNS entry: {field}[{index}]")
                continue

            item = {
                "name": text(value.get("rrname"), f"{field}[{index}].rrname"),
                "type": text(value.get("rrtype"), f"{field}[{index}].rrtype"),
            }

            if answers:
                item["ttl"] = unsigned(
                    value.get("ttl"), f"{field}[{index}].ttl", 2**32 - 1
                )
                # RDATA may represent an address, a name, or another
                # record-specific value. Do not force every answer into an IP.
                item["data"] = deepcopy(value.get("rdata"))

            mapped.append(item)
        return mapped

    message_type = text(dns.get("type"), "type")
    # Preserve the source vocabulary in the existing message_type field.
    # Suricata 8 DNS v3 emits request/answer; older development fixtures use
    # query/response. Consumers can use normalized_message_type consistently.
    normalized_type = {
        "request": "query", "query": "query",
        "answer": "response", "response": "response",
    }.get(message_type)
    if normalized_type is None:
        warnings.append("Missing or unsupported DNS message type")

    transaction_source = "tx_id" if "tx_id" in data else "dns.tx_id"
    transaction_id = unsigned(
        data.get("tx_id") if "tx_id" in data else dns.get("tx_id"),
        transaction_source, 2**64 - 1,
    )
    if "tx_id" in data and "tx_id" in dns:
        nested = unsigned(dns["tx_id"], "dns.tx_id", 2**64 - 1)
        if nested is not None and nested != transaction_id:
            warnings.append("Conflicting DNS transaction IDs; used EVE tx_id")

    grouped = dns.get("grouped")
    grouped_answers = None
    if grouped is not None:
        if not isinstance(grouped, dict):
            warnings.append("Expected DNS grouped answer object")
        else:
            grouped_answers = {}
            for rrtype, values in grouped.items():
                if not isinstance(values, list) or any(
                    not isinstance(value, str) for value in values
                ):
                    warnings.append(f"Invalid DNS grouped answers: {rrtype}")
                    continue
                # Grouped output provides neither owner names nor TTLs.
                grouped_answers[rrtype] = deepcopy(values)

    return {
        "version": 3,
        "message_type": message_type,
        "normalized_message_type": normalized_type,
        "id": unsigned(dns.get("id"), "id", 65535),
        "transaction_id": transaction_id,
        "transaction_id_source": transaction_source if transaction_id is not None else None,
        "response_code": text(dns.get("rcode"), "rcode"),
        "questions": entries("queries"),
        "answers": entries("answers", answers=True),
        "grouped_answers": grouped_answers,
    }
