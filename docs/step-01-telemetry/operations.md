# Step 1 operations and service lifecycle

This runbook separates the original automatic-start Step 1 baseline from
the current on-demand development laptop. Publishing these files updates
the Git repository; it does not deploy or execute the maintenance script.

## Recorded service configuration

| Setting | Original 1 October baseline | 26 October inspection |
|---|---|---|
| Suricata startup | Automatic, delayed | Manual, stopped |
| Suricata account | LocalSystem | LocalSystem |
| Suricata dependency | `npcap` | `npcap` |
| Failure reset | 86,400 seconds | 86,400 seconds |
| Failure actions | Three restarts, 5 seconds each | Same actions retained |
| Non-crash failure actions | Enabled | Enabled |
| Wazuh agent | Automatic in original baseline | Manual, stopped |
| Sysmon64 | Automatic | Automatic, running |

On-demand mode was installed on 20 October for development. The Manual
startup values are intentional. Use the existing `Start-FYP.cmd` and
`Stop-FYP.cmd` controls for test sessions on that laptop. The controller
manages the configured Wazuh VM as well as the selected local workers and
services; its implementation belongs to the later runtime publication.
Sysmon keeps its existing Windows configuration and can continue producing
local events while SPINE is stopped.

## Suricata command and inspection

The installed service uses the following correctly quoted command:

```text
"C:\Program Files\Suricata\suricata.exe" -c "C:\Program Files\Suricata\suricata.yaml" --pcap
```

Quoting the YAML path fixed the initial service start/stop problem. Inspect
the current setup without changing it:

```powershell
Get-CimInstance Win32_Service -Filter "Name='Suricata'" |
    Select-Object Name, State, StartMode, StartName, PathName
sc.exe qc Suricata
sc.exe qfailure Suricata
sc.exe qfailureflag Suricata
```

For a separate new lab reproducing the original always-on baseline, the
recorded hardening values correspond to these administrator commands:

```powershell
sc.exe config Suricata start= delayed-auto depend= npcap
sc.exe failure Suricata reset= 86400 actions= restart/5000/restart/5000/restart/5000
sc.exe failureflag Suricata 1
```

Those commands change service configuration. Applying them to the current
on-demand laptop would change its chosen startup policy. Service account
and binary-path changes are not needed for this publication.

## Retention files and prerequisites

| Item | Installed location |
|---|---|
| Script | `C:\ProgramData\FYP\Scripts\Suricata-LogMaintenance.ps1` |
| Maintenance log | `C:\ProgramData\FYP\Logs\suricata-log-maintenance.log` |
| Source EVE files | `C:\Program Files\Suricata\log` |
| Task | `FYP-Suricata-LogMaintenance` |

The published script is copied from the export without changing its
behavior; line endings are normalized for Git. Before installing it on a
new machine, review the fixed paths, create both ProgramData directories,
verify the Suricata log directory, and copy the script to the listed path.
The script itself does not create its log directory.

Preview retention on the prepared new lab:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File 'C:\ProgramData\FYP\Scripts\Suricata-LogMaintenance.ps1' -DryRun
Get-Content 'C:\ProgramData\FYP\Logs\suricata-log-maintenance.log' -Tail 20
```

Review candidate files and the retention window before enabling actual
deletion. The installed script accepts `-RetentionDays`, default 14;
use a positive value. It does not validate that value or check collector
progress. The current laptop already has this script and task installed.

## Daily scheduled task

`config/windows/FYP-Suricata-LogMaintenance.example.xml` is the actual
exported task definition. It records SYSTEM (`S-1-5-18`), highest run level,
daily scheduling near 03:15, `StartWhenAvailable`, and `IgnoreNew` for
overlapping instances. It also disallows starting on battery and stops
the task if the machine switches to battery. The captured start boundary
is a historical date with a `+05:00` offset, not a universal new-lab time.

To register the reviewed XML on a new lab, first set a future local start
boundary. The following example creates the next 03:15 boundary and
registers the task after the script and directories have been prepared:

```powershell
$spineTaskXml = New-Object System.Xml.XmlDocument
$spineTaskXml.Load((Resolve-Path '.\config\windows\FYP-Suricata-LogMaintenance.example.xml').Path)
$spineNamespaces = New-Object System.Xml.XmlNamespaceManager($spineTaskXml.NameTable)
$spineNamespaces.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
$spineNextRun = (Get-Date).Date.AddHours(3).AddMinutes(15)
if ($spineNextRun -le (Get-Date)) { $spineNextRun = $spineNextRun.AddDays(1) }
$spineTaskXml.SelectSingleNode('//t:StartBoundary', $spineNamespaces).InnerText = $spineNextRun.ToString('yyyy-MM-ddTHH:mm:ss')
Register-ScheduledTask -TaskName 'FYP-Suricata-LogMaintenance' -Xml $spineTaskXml.OuterXml
```

This registration example is for a new lab. It will fail if a same-named
task already exists because it does not use `-Force`. It is not a command
to run merely to publish Step 1. The daily task can continue maintaining
retained files while the on-demand sensor services are stopped.

Inspect the installed task:

```powershell
Get-ScheduledTask -TaskName 'FYP-Suricata-LogMaintenance' |
    Select-Object TaskName, State
Get-ScheduledTaskInfo -TaskName 'FYP-Suricata-LogMaintenance' |
    Select-Object LastRunTime, NextRunTime, LastTaskResult, NumberOfMissedRuns
```

## Backup and verification practice

Before changing a live configuration, keep dated copies of its YAML,
Wazuh collection configuration, service settings and task definition.
Historical automatic-start backups should be interpreted against the
current on-demand mode before restoration. Git publication is not a full
Windows or virtual-machine recovery backup.

See [verification](validation.md) for the dated acceptance evidence and
[log lifecycle](log-lifecycle.md) for the limits of filename-based retention.
