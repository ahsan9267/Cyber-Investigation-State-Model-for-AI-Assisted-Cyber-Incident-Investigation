"""Normalize common Suricata fields from a Wazuh-wrapped record."""

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import ipaddress
from spine.dns import map_dns
from spine.timestamps import normalize_timestamp


def map_suricata(record: dict) -> dict:
    """Return an independent record with supported Suricata fields mapped."""
    result = deepcopy(record)

    if result.get("source") != "suricata":
        raise ValueError("Expected a Suricata record")

    data = (
        result.get("attributes", {})
        .get("source_payload", {})
        .get("data")
    )
    if not isinstance(data, dict):
        raise ValueError("Missing Suricata data object")

    warnings = result["normalization"]["warnings"]

    def integer(value, field, maximum=None):
        if value is None:
            return None
        try:
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                raise ValueError
            number = Decimal(str(value))
            if (
                not number.is_finite()
                or number < 0
                or number != number.to_integral_value()
                or number > (2**64 - 1)
            ):
                raise ValueError
            converted = int(number)
            if maximum is not None and converted > maximum:
                raise ValueError
            return converted
        except (InvalidOperation, ValueError):
            warnings.append(f"Invalid Suricata integer: {field}")
            return None

    def address(value, field):
        if value is None:
            return None
        try:
            if not isinstance(value, str):
                raise ValueError
            return str(ipaddress.ip_address(value))
        except ValueError:
            warnings.append(f"Invalid Suricata IP address: {field}")
            return None

    timestamp = data.get("timestamp")
    if timestamp is None:
        warnings.append("Missing Suricata event timestamp")
    else:
        try:
            result["event_time"] = normalize_timestamp(timestamp)
        except ValueError as error:
            warnings.append(f"Invalid Suricata event timestamp: {error}")

    event_type = data.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        warnings.append("Missing or invalid Suricata event_type")
        event_type = None

    result["event"] = {
        "provider": "suricata",
        "type": event_type,
    }

    flow_id = integer(data.get("flow_id"), "flow_id")

    result["attributes"]["network"] = {
        "source_ip": address(data.get("src_ip"), "src_ip"),
        "destination_ip": address(data.get("dest_ip"), "dest_ip"),
        "source_port": integer(data.get("src_port"), "src_port", 65535),
        "destination_port": integer(data.get("dest_port"), "dest_port", 65535),
        "protocol": data.get("proto"),
        "application_protocol": data.get("app_proto"),
        "interface": data.get("in_iface"),
        # An identifier is represented as a string to avoid downstream
        # numeric precision loss.
        "flow_id": str(flow_id) if flow_id is not None else None,
        "direction": data.get("direction"),
    }

    alert = data.get("alert")
    if isinstance(alert, dict):
        signature_id = integer(alert.get("signature_id"), "signature_id")
        result["attributes"]["suricata_alert"] = {
            "signature_id": (
                str(signature_id) if signature_id is not None else None
            ),
            "signature": alert.get("signature"),
            "revision": integer(alert.get("rev"), "rev"),
            "severity": integer(alert.get("severity"), "severity"),
            "action": alert.get("action"),
            "category": alert.get("category"),
        }
    elif alert is not None:
        warnings.append("Expected Suricata alert object")

    if event_type == "dns":
        result["attributes"]["dns"] = map_dns(data, warnings)
        
    result["normalization"]["parser"] = (
        "wazuh_common/0.1.0+suricata_common/0.2.0"
    )
    result["normalization"]["status"] = "partial"
    return result
