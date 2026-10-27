param(
    [int]$RetentionDays = 14,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

$SuricataLogDir = 'C:\Program Files\Suricata\log'
$MaintenanceLog = 'C:\ProgramData\FYP\Logs\suricata-log-maintenance.log'

$Today = (Get-Date).Date
$OldestDateToKeep = $Today.AddDays(-($RetentionDays - 1))

function Write-MaintenanceLog {
    param([string]$Message)

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $MaintenanceLog -Value "$timestamp $Message"
}

Write-MaintenanceLog "Starting EVE maintenance. RetentionDays=$RetentionDays DryRun=$DryRun"

Get-ChildItem -Path $SuricataLogDir -File -Filter 'eve-*.json' |
ForEach-Object {

    if ($_.BaseName -match '^eve(?:-health)?-(\d{4}-\d{2}-\d{2})$') {

        $fileDate = [datetime]::ParseExact(
            $Matches[1],
            'yyyy-MM-dd',
            [System.Globalization.CultureInfo]::InvariantCulture
        )

        if ($fileDate -lt $OldestDateToKeep) {

            if ($DryRun) {
                Write-MaintenanceLog "DRY RUN: Would delete $($_.FullName)"
            }
            else {
                Remove-Item -LiteralPath $_.FullName -Force
                Write-MaintenanceLog "Deleted $($_.FullName)"
            }
        }
    }
}

Write-MaintenanceLog "Maintenance completed."
