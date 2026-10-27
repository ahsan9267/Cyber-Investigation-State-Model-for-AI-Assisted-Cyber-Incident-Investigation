# Step 1 verification record

This record distinguishes tests reported on 1 October 2026 from the
read-only file and configuration inspection on 26 October 2026. The latter
did not restart sensors, generate traffic or repeat the reboot exercise.

## Original functional acceptance

The source is `FYP_Step_1_Security_Telemetry_and_Alerts_Detailed_Documentation.docx`,
dated 1 October 2026, especially sections 6, 8-12 and 17 and Appendix B.
The following results are historical recorded observations:

| Check | Recorded result |
|---|---|
| Wazuh endpoint enrollment | Agent 001, `FYP-Windows`, active against the lab manager |
| Sysmon collection | Agent analyzes `Microsoft-Windows-Sysmon/Operational` |
| Controlled endpoint event | Notepad process creation, Event ID 1, observed through temporarily enabled raw archives |
| Suricata configuration | Final configuration test succeeded after logger/rule corrections |
| Wi-Fi capture | Controlled gateway ICMP produced the diagnostic alert |
| Host-Only capture | Kali-to-Windows ICMP observed through the intended Npcap interface |
| Forwarded network alert | Wazuh JSON decoder and rule 86601 retained diagnostic SID 1000001, revision 2 |
| Rule refinement | Four requests from Windows and four from Kali produced request alerts; replies were excluded by revision 2 |
| Genuine reboot | Boot time changed to 1 October 2026 at 14:36:25 local; required services returned |
| Capture after reboot | Suricata reported two live devices; fresh controlled traffic reached Wazuh |
| Daily security EVE | Wazuh received events from `eve-2026-10-01.json` |
| Health separation | Main EVE statistics count stayed 88 while health EVE advanced during the recorded interval |
| Standalone statistics | Historical `stats.log` remained 20,595,751 bytes with unchanged modification time during the 65-second check |
| Retention preview and deletion | Deliberately old, zero-byte security and health EVE fixtures were identified in dry run and deleted in the real run |
| Scheduled retention | Manual task invocation returned `LastTaskResult = 0` |

A Fast Startup shutdown was not accepted as reboot evidence: it preserved
the kernel session and old boot timestamp. The explicit Windows restart
was used for the recorded persistence check.

## Export inspection on 26 October

The private source export was collected at 08:34:15 UTC (13:34:15 Pakistan
time). All 19 files listed in its manifest matched their lengths and
SHA-256 hashes. The export reported no missing required items or inspection
warnings. Its five repository text files, after normal line-ending
normalization, matched the Git blobs at `08d23f4` on `main`.

The installed sources confirmed both dated EVE loggers, a 60-second
statistics interval, disabled standalone statistics, the revision-2
diagnostic rule, an empty local-rule file, and the dated Wazuh EVE path.
The task definition matched the maintenance script path. The latest
captured task result was zero with zero missed runs; that status is not
proof that every source file had been ingested before deletion.

Suricata and WazuhSvc were stopped with Manual startup, consistent with
the selected development mode. Sysmon64 remained running with Automatic
startup. Service inspection retained the Npcap dependency, three
five-second restart actions, daily reset and non-crash failure handling.

The export contains configuration and operational metadata, not raw event
samples, secrets or a new live acceptance run. The private export folder
and manifests are not added to this repository.

## Rechecking a running test session

On the current development laptop, start the session using its existing
on-demand controls, allow collection to make progress, then use the
existing maintenance health command:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
    -File 'D:\FYP\SPINE_Wazuh_Maintenance_Fix_2026-10-12\Check-SPINEHealth.ps1' `
    -Project 'D:\FYP\SPINE'
```

That installed script is a later diagnostic tool and is not included in
this Step 1 publication. It reports health; invoking it does not repair
missing files or start a powered-off Wazuh VM.

For a new lab, reproduce configuration validation and harmless controlled
Echo Requests on authorized lab interfaces. Check actual EVE content,
matching Wazuh fields and the recorded file location. Test retention only
against disposable fixtures after understanding its fixed paths.

## Acceptance boundary

Step 1 is complete as the documented laboratory telemetry foundation.
A single diagnostic signature does not establish broad attack coverage.
The host sensor is not a full-network monitor. Collection and alerting
remain distinct; source outage, rotation and retention can cause evidence
gaps. Database ingestion, association, investigation management and local
LLM reasoning are outside the code published in this Step 1 release.

Public examples require adaptation on another host. Neither this static
inspection nor packaging checks establish unattended production behavior,
a complete backup restore, bounded latency or gap-free collection.
