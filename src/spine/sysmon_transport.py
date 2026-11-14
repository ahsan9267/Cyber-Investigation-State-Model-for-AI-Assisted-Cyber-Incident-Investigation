"""Read bounded Sysmon batches through Windows PowerShell."""

import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

from spine.wazuh import _reject_constant, _unique_keys
from spine.sysmon_errors import raise_reader_error


CHANNEL = "Microsoft-Windows-Sysmon/Operational"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
PROJECT = Path(__file__).resolve().parents[2]


def _validate_bookmark(text, record_id):
    if (
        not isinstance(text, str)
        or not text.strip()
        or len(text) > 16384
        or "<!" in text
    ):
        raise ValueError("Invalid bookmark text")

    try:
        root = ET.fromstring(text)
    except ET.ParseError as error:
        raise ValueError("Malformed bookmark XML") from error

    bookmarks = root.findall("Bookmark")

    if root.tag != "BookmarkList" or len(bookmarks) != 1:
        raise ValueError("Expected one bookmark")

    bookmark = bookmarks[0]
    if (
        bookmark.get("Channel") != CHANNEL
        or bookmark.get("RecordId") != record_id
    ):
        raise ValueError("Bookmark does not match its event")


def fetch_sysmon_batch(*, checkpoint=None, max_records=100, timeout=90):
    """Fetch and validate a batch without writing database state."""
    if os.name != "nt":
        raise RuntimeError("The Sysmon reader requires Windows")

    if (
        isinstance(max_records, bool)
        or not isinstance(max_records, int)
        or not 1 <= max_records <= 1000
    ):
        raise ValueError("max_records must be 1..1000")

    if checkpoint is not None:
        if not isinstance(checkpoint, dict):
            raise ValueError("checkpoint must be an object")
        if checkpoint.get("channel") != CHANNEL:
            raise ValueError("Checkpoint channel mismatch")
        _validate_bookmark(
            checkpoint.get("bookmark_xml"),
            checkpoint.get("record_id"),
        )

    reader = PROJECT / "tools" / "sysmon_reader.ps1"
    if not reader.is_file():
        raise ValueError(f"Missing reader: {reader}")

    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32/WindowsPowerShell/v1.0/powershell.exe"
    )

    # Quote the fixed local script path as a PowerShell string.
    reader_literal = str(reader).replace("'", "''")

    script = """
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
    . '__READER__'
    $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $batch = Read-SpineSysmonBatch `
        -MaxRecords $request.max_records `
        -Checkpoint $request.checkpoint
    $json = ConvertTo-Json -InputObject $batch -Depth 8 -Compress
    [Console]::Out.Write($json)
} catch {
    $message = $_.Exception.Message
    $kind = "read_error"
    $nativeCode = $null

    $exception = $_.Exception
    while ($null -ne $exception) {
        if (
            $exception -is
            [System.Diagnostics.Eventing.Reader.EventLogException]
        ) {
            $nativeCode = $exception.ErrorCode -band 65535
            break
        }
        $exception = $exception.InnerException
    }

    if ($message -eq "Checkpoint event is unavailable; recovery is required.") {
        $kind = "checkpoint_unavailable"
    } elseif ($message -eq "Checkpoint event mismatch; recovery is required.") {
        $kind = "checkpoint_mismatch"
    } elseif ($nativeCode -in @(15011, 15012)) {
        # Retry using a fresh reader before drawing conclusions about loss.
        $kind = "query_stale"
    }

    $failure = [ordered]@{
        kind = $kind
        message = $message
        native_code = $nativeCode
    }

    [Console]::Error.WriteLine(
        (ConvertTo-Json -InputObject $failure -Compress)
    )
    exit 1
}
""".replace("__READER__", reader_literal)

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    request = json.dumps({
        "max_records": max_records,
        "checkpoint": checkpoint,
    }).encode("utf-8")

    result = subprocess.run(
        [
            str(powershell),
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "RemoteSigned",
            "-EncodedCommand",
            encoded,
        ],
        input=request,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        creationflags=subprocess.CREATE_NO_WINDOW,
        check=False,
    )

    if result.returncode != 0:
        raise_reader_error(result.stderr)

    # XML escaping makes the JSON response larger than its XML payload.
    if len(result.stdout) > 32 * 1024 * 1024:
        raise ValueError("Sysmon response exceeds the transport limit")

    batch = json.loads(
        result.stdout.decode("utf-8-sig"),
        parse_constant=_reject_constant,
        object_pairs_hook=_unique_keys,
    )

    if not isinstance(batch, dict):
        raise ValueError("Expected a batch object")

    if (
        batch.get("protocol_version") != 1
        or batch.get("channel") != CHANNEL
        or batch.get("database_written") is not False
        or batch.get("status") not in (
            "caught_up", "limit_reached", "byte_limit_reached"
        )
    ):
        raise ValueError("Invalid Sysmon batch metadata")

    records = batch.get("records")
    if not isinstance(records, list) or len(records) > max_records:
        raise ValueError("Invalid batch records")

    if batch.get("record_count") != len(records):
        raise ValueError("Batch record count mismatch")

    previous_id = int(checkpoint["record_id"]) if checkpoint else -1
    total_bytes = 0

    for item in records:
        if not isinstance(item, dict):
            raise ValueError("Invalid event object")

        record_id = item.get("record_id")
        if (
            not isinstance(record_id, str)
            or not record_id.isascii()
            or not record_id.isdecimal()
            or len(record_id) > 19
            or not previous_id < int(record_id) <= 2**63 - 1
        ):
            raise ValueError("Invalid or non-increasing event record ID")

        raw_xml = item.get("raw_xml")
        if not isinstance(raw_xml, str) or "<!" in raw_xml:
            raise ValueError("Invalid event XML")

        raw_bytes = raw_xml.encode("utf-8")
        if not raw_bytes or len(raw_bytes) > 1024 * 1024:
            raise ValueError("Invalid event XML size")

        actual_hash = hashlib.sha256(raw_bytes).hexdigest()
        if item.get("raw_sha256") != actual_hash:
            raise ValueError("Event XML hash mismatch")

        try:
            root = ET.fromstring(raw_xml)
        except ET.ParseError as error:
            raise ValueError("Malformed event XML") from error

        system = root.find(NS + "System")
        if root.tag != NS + "Event" or system is None:
            raise ValueError("Invalid Windows event structure")

        if (
            system.findtext(NS + "EventRecordID") != record_id
            or system.findtext(NS + "Channel") != CHANNEL
        ):
            raise ValueError("Event XML identity mismatch")

        _validate_bookmark(item.get("bookmark_xml"), record_id)
        total_bytes += len(raw_bytes)
        previous_id = int(record_id)

    if total_bytes > 4 * 1024 * 1024 or batch.get("xml_bytes") != total_bytes:
        raise ValueError("Batch XML byte count mismatch")

    if records:
        last = records[-1]
        expected_checkpoint = {
            "channel": CHANNEL,
            "record_id": last["record_id"],
            "raw_sha256": last["raw_sha256"],
            "bookmark_xml": last["bookmark_xml"],
        }
    else:
        expected_checkpoint = checkpoint

    if batch.get("next_checkpoint") != expected_checkpoint:
        raise ValueError("Batch checkpoint mismatch")

    return batch