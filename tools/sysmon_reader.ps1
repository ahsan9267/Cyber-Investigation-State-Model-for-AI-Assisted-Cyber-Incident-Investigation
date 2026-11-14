# Read bounded Sysmon batches without updating persistent checkpoints.

. (Join-Path $PSScriptRoot "sysmon_bookmarks.ps1")


function Get-SpineXmlHash {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Text
    )

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Text)
        return [BitConverter]::ToString(
            $sha.ComputeHash($bytes)
        ).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}


function Read-SpineSysmonBatch {
    param(
        [ValidateRange(1, 1000)]
        [int]$MaxRecords = 100,

        # Null for an initial read. Otherwise use next_checkpoint
        # from an earlier successfully processed batch.
        [object]$Checkpoint = $null
    )

    $ErrorActionPreference = "Stop"
    $channel = "Microsoft-Windows-Sysmon/Operational"

    $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new(
        $channel,
        [System.Diagnostics.Eventing.Reader.PathType]::LogName,
        "*"
    )
    $query.ReverseDirection = $false
    $query.TolerateQueryErrors = $false

    $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new(
        $query
    )

    $records = [System.Collections.Generic.List[object]]::new()
    $xmlBytes = 0
    $previousId = [long]-1
    $nextCheckpoint = $Checkpoint
    $batchStatus = "limit_reached"

    try {
        if ($null -ne $Checkpoint) {
            if ($Checkpoint.channel -ne $channel) {
                throw "Checkpoint channel does not match Sysmon."
            }

            $bookmarkText = [string]$Checkpoint.bookmark_xml
            $expectedHash = [string]$Checkpoint.raw_sha256
            $idText = [string]$Checkpoint.record_id

            if (
                [string]::IsNullOrWhiteSpace($bookmarkText) -or
                $bookmarkText.Length -gt 16384 -or
                $bookmarkText.Contains("<!") -or
                $expectedHash -cnotmatch '^[0-9a-f]{64}$' -or
                $idText -notmatch '^[0-9]{1,19}$'
            ) {
                throw "Invalid checkpoint fields."
            }

            $previousId = [long]$idText
            $bookmark = [Spine.EventBookmarkCompat]::Restore(
                $bookmarkText
            )

            $reader.Seek($bookmark, [long]0)
            $anchor = $reader.ReadEvent()

            if ($null -eq $anchor) {
                throw "Checkpoint event is unavailable; recovery is required."
            }

            try {
                if (
                    $anchor.RecordId -ne $previousId -or
                    $anchor.LogName -ne $channel -or
                    (Get-SpineXmlHash -Text $anchor.ToXml()) -cne $expectedHash
                ) {
                    throw "Checkpoint event mismatch; recovery is required."
                }
            } finally {
                $anchor.Dispose()
            }

            # Reading the anchor above positioned us after that event.
        }

        while ($records.Count -lt $MaxRecords) {
            $event = $reader.ReadEvent()

            if ($null -eq $event) {
                $batchStatus = "caught_up"
                break
            }

            try {
                if (
                    $null -eq $event.RecordId -or
                    $event.RecordId -le $previousId -or
                    $event.LogName -ne $channel
                ) {
                    throw "Unexpected event sequence; recovery is required."
                }

                $xml = $event.ToXml()
                $length = [System.Text.Encoding]::UTF8.GetByteCount($xml)

                if ($length -gt 1MB) {
                    throw "A Sysmon event exceeds the 1 MiB limit."
                }

                if (($xmlBytes + $length) -gt 4MB) {
                    # No checkpoint is returned for this unaccepted event.
                    $batchStatus = "byte_limit_reached"
                    break
                }

                $hash = Get-SpineXmlHash -Text $xml
                $bookmarkText = [Spine.EventBookmarkCompat]::Export(
                    $event.Bookmark
                )

                if ([string]::IsNullOrWhiteSpace($bookmarkText)) {
                    throw "Event bookmark is empty."
                }

                $nextCheckpoint = [PSCustomObject]@{
                    channel = $channel
                    record_id = [string]$event.RecordId
                    raw_sha256 = $hash
                    bookmark_xml = $bookmarkText
                }

                $records.Add([PSCustomObject]@{
                    record_id = [string]$event.RecordId
                    raw_xml = $xml
                    raw_sha256 = $hash
                    bookmark_xml = $bookmarkText
                })

                $previousId = [long]$event.RecordId
                $xmlBytes += $length
            } finally {
                $event.Dispose()
            }
        }

        # Recheck the last accepted event before returning the batch.
        if ($records.Count -gt 0) {
            $bookmark = [Spine.EventBookmarkCompat]::Restore(
                $nextCheckpoint.bookmark_xml
            )
            $reader.Seek($bookmark, [long]0)
            $anchor = $reader.ReadEvent()

            if ($null -eq $anchor) {
                throw "Final batch event became unavailable."
            }

            try {
                if (
                    [string]$anchor.RecordId -ne $nextCheckpoint.record_id -or
                    (Get-SpineXmlHash -Text $anchor.ToXml()) -cne
                        $nextCheckpoint.raw_sha256
                ) {
                    throw "Final batch event changed; batch rejected."
                }
            } finally {
                $anchor.Dispose()
            }
        }

        return [PSCustomObject]@{
            protocol_version = 1
            channel = $channel
            status = $batchStatus
            record_count = $records.Count
            xml_bytes = $xmlBytes
            records = $records.ToArray()
            next_checkpoint = $nextCheckpoint
            database_written = $false
        }
    } finally {
        $reader.Dispose()
    }
}