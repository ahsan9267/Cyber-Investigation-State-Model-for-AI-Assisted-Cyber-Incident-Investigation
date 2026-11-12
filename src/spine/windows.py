"""Map Windows events and supported Sysmon process, network and DNS fields."""

from copy import deepcopy
import ipaddress
from spine.service import map_service_installation
from spine.timestamps import normalize_timestamp
from spine.authentication import map_authentication


def map_windows(record: dict) -> dict:
    result = deepcopy(record)

    if result.get("source") not in ("sysmon", "windows_eventchannel"):
        raise ValueError("Expected a Windows event record")

    data = (
        result.get("attributes", {})
        .get("source_payload", {})
        .get("data")
    )
    if not isinstance(data, dict):
        raise ValueError("Missing Windows source data")

    win = data.get("win")
    if not isinstance(win, dict):
        raise ValueError("Missing Windows win object")

    system = win.get("system")
    if not isinstance(system, dict):
        raise ValueError("Missing Windows system object")

    warnings = result["normalization"]["warnings"]
    fields = win.get("eventdata", {})
    if not isinstance(fields, dict):
        warnings.append("Invalid Windows eventdata object")
        fields = {}

    def text(value, field):
        if value is None:
            return None
        if not isinstance(value, str):
            warnings.append(f"Invalid Windows text field: {field}")
            return None
        return value

    def integer(value, field):
        if value is None:
            return None
        if isinstance(value, bool):
            warnings.append(f"Invalid Windows integer: {field}")
            return None

        if isinstance(value, int):
            number = value
        elif isinstance(value, str) and len(value) <= 20:
            try:
                if value.lower().startswith("0x"):
                    digits = value[2:]
                    if not digits or any(
                        char not in "0123456789abcdefABCDEF"
                        for char in digits
                    ):
                        raise ValueError
                    number = int(digits, 16)
                elif value.isascii() and value.isdecimal():
                    number = int(value)
                else:
                    raise ValueError
            except ValueError:
                warnings.append(f"Invalid Windows integer: {field}")
                return None
        else:
            warnings.append(f"Invalid Windows integer: {field}")
            return None

        if not 0 <= number <= 2**64 - 1:
            warnings.append(f"Invalid Windows integer: {field}")
            return None
        return number

    event_id = integer(system.get("eventID"), "eventID")
    record_id = integer(system.get("eventRecordID"), "eventRecordID")

    result["event"] = {
        "provider": text(system.get("providerName"), "providerName"),
        "channel": text(system.get("channel"), "channel"),
        "code": str(event_id) if event_id is not None else None,
        "record_id": str(record_id) if record_id is not None else None,
    }

    hostname = text(system.get("computer"), "computer")
    if hostname:
        result["host"]["name"] = hostname

    # These describe the event provider's execution context.
    # They are not the created process or its parent.
    result["attributes"]["windows_system"] = {
        "execution_process_id": integer(system.get("processID"), "processID"),
        "execution_thread_id": integer(system.get("threadID"), "threadID"),
        "level": integer(system.get("level"), "level"),
        "severity_label": text(system.get("severityValue"), "severityValue"),
        "time_created": None,
    }

    system_time = system.get("systemTime")
    if system_time is not None:
        try:
            timestamp = normalize_timestamp(system_time)
            result["attributes"]["windows_system"]["time_created"] = timestamp
            result["event_time"] = deepcopy(timestamp)
            result["event"]["time_source"] = "data.win.system.systemTime"
        except ValueError as error:
            warnings.append(f"Invalid Windows systemTime: {error}")
    else:
        warnings.append("Missing Windows systemTime")

    supported_sysmon = (
        result["source"] == "sysmon"
        and system.get("providerName") == "Microsoft-Windows-Sysmon"
        and system.get("channel") == "Microsoft-Windows-Sysmon/Operational"
        and event_id in (1, 3, 22)
    )
    if supported_sysmon:
        result["event"]["type"] = {
            1: "process_create", 3: "network_connection", 22: "dns_query"
        }[event_id]

        utc_time = fields.get("utcTime")
        if utc_time is not None:
            try:
                result["event_time"] = normalize_timestamp(
                    utc_time, source_timezone="UTC"
                )
                result["event"]["time_source"] = "data.win.eventdata.utcTime"
            except ValueError as error:
                warnings.append(f"Invalid Sysmon utcTime: {error}")

        process = {
            "id": integer(fields.get("processId"), "eventdata.processId"),
            "guid": text(fields.get("processGuid"), "processGuid"),
            "image": text(fields.get("image"), "image"),
            "command_line": text(fields.get("commandLine"), "commandLine"),
            "current_directory": text(
                fields.get("currentDirectory"), "currentDirectory"
            ),
            "user": text(fields.get("user"), "user"),
            "integrity_level": text(fields.get("integrityLevel"), "integrityLevel"),
            "hashes_original": text(fields.get("hashes"), "hashes"),
            "parent": {
                "id": integer(
                    fields.get("parentProcessId"), "parentProcessId"
                ),
                "guid": text(fields.get("parentProcessGuid"), "parentProcessGuid"),
                "image": text(fields.get("parentImage"), "parentImage"),
                "command_line": text(
                    fields.get("parentCommandLine"), "parentCommandLine"
                ),
                "user": text(fields.get("parentUser"), "parentUser"),
            },
        }
        if event_id != 1:
            # A connection/query reports a process reference, not a new process.
            process = {key: process[key] for key in ("id", "guid", "image", "user")}
        result["attributes"]["process"] = process

    if supported_sysmon and event_id == 3:
        def address(value, field):
            if value is None or value in ("", "-"):
                return None
            try:
                if not isinstance(value, str):
                    raise ValueError
                return str(ipaddress.ip_address(value))
            except ValueError:
                warnings.append(f"Invalid Sysmon IP address: {field}")
                return None

        def port(value, field):
            number = integer(value, field)
            if number is not None and number > 65535:
                warnings.append(f"Invalid Sysmon port: {field}")
                return None
            return number

        def boolean(value, field):
            if value is None:
                return None
            if isinstance(value, bool):
                return value
            if isinstance(value, str) and value.lower() in ("true", "false"):
                return value.lower() == "true"
            warnings.append(f"Invalid Sysmon boolean: {field}")
            return None

        result["attributes"]["network"] = {
            "source_ip": address(fields.get("sourceIp"), "sourceIp"),
            "destination_ip": address(fields.get("destinationIp"), "destinationIp"),
            "source_port": port(fields.get("sourcePort"), "sourcePort"),
            "destination_port": port(fields.get("destinationPort"), "destinationPort"),
            "protocol": text(fields.get("protocol"), "protocol"),
            "initiated": boolean(fields.get("initiated"), "initiated"),
            "source_hostname": text(fields.get("sourceHostname"), "sourceHostname"),
            "destination_hostname": text(fields.get("destinationHostname"), "destinationHostname"),
        }

    if supported_sysmon and event_id == 22:
        status = integer(fields.get("queryStatus"), "queryStatus")
        if status is not None and status > 2**32 - 1:
            warnings.append("Invalid Sysmon query status: queryStatus")
            status = None
        result["attributes"]["dns"] = {
            "query_name": text(fields.get("queryName"), "queryName"),
            "query_status": status,
            # Results may contain names, addresses and status-specific values.
            "query_results_original": text(fields.get("queryResults"), "queryResults"),
        }
    
    if (
        system.get("channel") == "Security"
        and system.get("providerName") == "Microsoft-Windows-Security-Auditing"
        and event_id in (4624, 4625)
    ):
        result["event"]["type"] = "authentication"
        result["attributes"]["authentication"] = map_authentication(
            str(event_id), fields, warnings
        )
    
    if (
        system.get("channel") == "System"
        and system.get("providerName") == "Service Control Manager"
        and event_id == 7045
    ):
        result["event"]["type"] = "service_install"
        result["attributes"]["service"] = map_service_installation(
            fields, warnings
        )

    result["normalization"]["parser"] = (
        "wazuh_common/0.1.0+windows_common/0.2.0"
    )
    result["normalization"]["status"] = "partial"
    return result
