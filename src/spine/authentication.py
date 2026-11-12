"""Map Windows authentication fields without inferring missing identities."""

from copy import deepcopy
import ipaddress


def map_authentication(event_code, fields, warnings):
    if event_code not in ("4624", "4625"):
        raise ValueError("Unsupported authentication event code")

    def text(key):
        value = fields.get(key)
        if value is None or value == "-":
            return None
        if not isinstance(value, str):
            warnings.append(f"Invalid authentication text field: {key}")
            return None
        return value if value.strip() else None

    def number(key, maximum, hexadecimal=False):
        value = fields.get(key)
        if value is None or value == "-":
            return None
        if isinstance(value, str) and not value.strip():
            return None

        try:
            if isinstance(value, bool):
                raise ValueError
            if isinstance(value, int):
                parsed = value
            elif isinstance(value, str) and len(value) <= 20:
                if hexadecimal and value.lower().startswith("0x"):
                    digits = value[2:]
                    if not digits or any(
                        char not in "0123456789abcdefABCDEF"
                        for char in digits
                    ):
                        raise ValueError
                    parsed = int(digits, 16)
                elif value.isascii() and value.isdecimal():
                    parsed = int(value)
                else:
                    raise ValueError
            else:
                raise ValueError

            if not 0 <= parsed <= maximum:
                raise ValueError
            return parsed
        except ValueError:
            warnings.append(f"Invalid authentication integer: {key}")
            return None

    def account(prefix):
        return {
            "sid": text(f"{prefix}UserSid"),
            "name": text(f"{prefix}UserName"),
            "domain": text(f"{prefix}DomainName"),
            "logon_id": text(f"{prefix}LogonId"),
        }

    source_ip = text("ipAddress")
    if source_ip is not None:
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            warnings.append("Invalid authentication IP address: ipAddress")
            source_ip = None

    return {
        # This is the authentication outcome, not an incident verdict.
        "outcome": "success" if event_code == "4624" else "failure",
        "subject": account("subject"),
        "target": account("target"),
        "logon_type": number("logonType", 2**32 - 1),
        "source_ip": source_ip,
        "source_port": number("ipPort", 65535),
        "workstation": text("workstationName"),
        "logon_process": text("logonProcessName"),
        "authentication_package": text("authenticationPackageName"),
        "status": text("status"),
        "sub_status": text("subStatus"),
        "failure_reason_original": text("failureReason"),
        "logon_guid": text("logonGuid"),
        "linked_logon_id": text("targetLinkedLogonId"),
        "caller_process": {
            "id": number("processId", 2**32 - 1, hexadecimal=True),
            "image": text("processName"),
        },
        # Preserve flags without guessing the meanings of message tokens.
        "flags_original": {
            key: deepcopy(fields[key])
            for key in ("elevatedToken", "virtualAccount", "impersonationLevel")
            if key in fields
        },
    }