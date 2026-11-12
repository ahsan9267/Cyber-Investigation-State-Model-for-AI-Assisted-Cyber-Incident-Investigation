"""Normalize individual Sysmon Event XML records."""

import xml.etree.ElementTree as ET

from spine.envelope import build_envelope
from spine.windows import map_windows


NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
PROVIDER = "Microsoft-Windows-Sysmon"

# Explicit aliases shared with the Wazuh Windows adapter.
PROCESS_FIELDS = {
    "UtcTime": "utcTime",
    "ProcessGuid": "processGuid",
    "ProcessId": "processId",
    "Image": "image",
    "CommandLine": "commandLine",
    "CurrentDirectory": "currentDirectory",
    "User": "user",
    "IntegrityLevel": "integrityLevel",
    "Hashes": "hashes",
    "ParentProcessGuid": "parentProcessGuid",
    "ParentProcessId": "parentProcessId",
    "ParentImage": "parentImage",
    "ParentCommandLine": "parentCommandLine",
    "ParentUser": "parentUser",
    "Protocol": "protocol",
    "Initiated": "initiated",
    "SourceIsIpv6": "sourceIsIpv6",
    "SourceIp": "sourceIp",
    "SourceHostname": "sourceHostname",
    "SourcePort": "sourcePort",
    "SourcePortName": "sourcePortName",
    "DestinationIsIpv6": "destinationIsIpv6",
    "DestinationIp": "destinationIp",
    "DestinationHostname": "destinationHostname",
    "DestinationPort": "destinationPort",
    "DestinationPortName": "destinationPortName",
    "QueryName": "queryName",
    "QueryStatus": "queryStatus",
    "QueryResults": "queryResults",
}


def parse_sysmon_xml(
    raw_text: str,
    *,
    source_scope: str,
    source_record_id: str,
    observed_time: str,
) -> dict:
    """Parse one Event XML using a durable reader-supplied identity.

    EventRecordID alone is insufficient across log clears.
    The future live reader must include the channel generation.
    """
    if not isinstance(raw_text, str) or not raw_text.strip():
        raise ValueError("Expected non-empty Sysmon XML")

    if len(raw_text.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Sysmon XML exceeds the 1 MiB record limit")

    # Event.ToXml() needs no DTD, entities, comments, or CDATA.
    # Reject declarations before passing input to the XML parser.
    if "<!" in raw_text:
        raise ValueError("XML declarations beginning with <! are unsupported")

    try:
        root = ET.fromstring(raw_text)
    except ET.ParseError as error:
        raise ValueError(f"Invalid Sysmon XML: {error}") from error

    if root.tag != NS + "Event":
        raise ValueError("Expected a Windows Event XML root")

    def single(parent, name, required=False):
        elements = parent.findall(NS + name)
        if len(elements) > 1:
            raise ValueError(f"Duplicate XML element: {name}")
        if not elements:
            if required:
                raise ValueError(f"Missing XML element: {name}")
            return None
        return elements[0]

    def element_text(parent, name, required=False):
        element = single(parent, name, required)
        value = None if element is None else element.text
        if required and (value is None or not value.strip()):
            raise ValueError(f"Empty XML element: {name}")
        return value

    system_xml = single(root, "System", required=True)
    provider = single(system_xml, "Provider", required=True)
    channel = element_text(system_xml, "Channel", required=True)

    if provider.get("Name") != PROVIDER or channel != CHANNEL:
        raise ValueError("Expected the Sysmon provider and Operational channel")

    event_id = element_text(system_xml, "EventID", required=True)
    event_record_id = element_text(
        system_xml, "EventRecordID", required=True
    )

    for name, value in (
        ("EventID", event_id),
        ("EventRecordID", event_record_id),
    ):
        if (
            not value.isascii()
            or not value.isdecimal()
            or len(value) > 20
            or int(value) > 2**64 - 1
        ):
            raise ValueError(f"Invalid XML {name}")

    system = {
        "providerName": provider.get("Name"),
        "providerGuid": provider.get("Guid"),
        "channel": channel,
        "eventID": event_id,
        "eventRecordID": event_record_id,
        "computer": element_text(
            system_xml, "Computer", required=True
        ),
    }

    for xml_name, mapped_name in (
        ("Version", "version"),
        ("Level", "level"),
        ("Task", "task"),
        ("Opcode", "opcode"),
        ("Keywords", "keywords"),
    ):
        system[mapped_name] = element_text(system_xml, xml_name)

    time_created = single(system_xml, "TimeCreated")
    system["systemTime"] = (
        None if time_created is None
        else time_created.get("SystemTime")
    )

    execution = single(system_xml, "Execution")
    if execution is not None:
        system["processID"] = execution.get("ProcessID")
        system["threadID"] = execution.get("ThreadID")

    original_fields = {}
    event_data = single(root, "EventData")

    if event_data is not None:
        for child in event_data:
            if child.tag != NS + "Data":
                raise ValueError("Unsupported child inside EventData")
            name = child.get("Name")
            if not name or not name.strip():
                raise ValueError("EventData field has no name")
            if name in original_fields:
                raise ValueError(f"Duplicate EventData field: {name}")
            if len(child):
                raise ValueError(f"Nested EventData field: {name}")

            original_fields[name] = (
                child.text if child.text is not None else ""
            )

    mapped_fields = {
        mapped_name: original_fields[xml_name]
        for xml_name, mapped_name in PROCESS_FIELDS.items()
        if xml_name in original_fields
    }

    record = build_envelope(
        raw_text=raw_text,
        source="sysmon",
        collector="sysmon_eventlog",
        record_kind="telemetry",
        source_scope=source_scope,
        source_record_id=source_record_id,
        observed_time=observed_time,
    )

    # This is an adapter view for the existing mapper, not Wazuh output.
    record["attributes"]["source_payload"] = {
        "format": "windows_event_xml",
        "eventdata_original": original_fields,
        "data": {
            "win": {
                "system": system,
                "eventdata": mapped_fields,
            }
        },
    }

    record = map_windows(record)
    record["normalization"]["parser"] = (
        "sysmon_xml/0.2.0+windows_common/0.2.0"
    )

    # Refer to the original XML when explaining timestamp provenance.
    if record["event"].get("time_source") == "data.win.eventdata.utcTime":
        record["event"]["time_source"] = "Event/EventData/Data[@Name='UtcTime']"
    elif record["event"].get("time_source") == "data.win.system.systemTime":
        record["event"]["time_source"] = "Event/System/TimeCreated/@SystemTime"

    return record
