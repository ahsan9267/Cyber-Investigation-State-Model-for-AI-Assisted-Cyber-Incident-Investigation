# Step 1 Milestone B

Milestone B publishes the remainder of the completed Step 1 laboratory
work: service persistence, log lifecycle, retention and final verification.
It follows [Milestone A](milestone-a.md), which recorded initial telemetry
acquisition and transport.

## Published configuration and operations

| Area | Delivered artifact |
|---|---|
| Final Suricata settings | Full laboratory YAML example with replaceable Npcap GUIDs |
| Diagnostic/local rules | Existing revision-2 test rule and empty reserved local-rule file |
| Wazuh date-aware input | Sysmon channel and dated security EVE collection example |
| Service lifecycle | Quoted service command, Npcap dependency, recovery settings and operating-mode distinction |
| EVE lifecycle | Daily security/health files, statistics separation and documented limits |
| Retention | Existing 14-date maintenance script and exported task example |
| Acceptance | Historical test record and separately identified 26 October inspection |

Read [configuration](configuration.md), [log lifecycle](log-lifecycle.md),
[operations](operations.md) and [verification](validation.md) together.

## Recorded defects and corrections

Missing configured rule files were replaced with a controlled local
diagnostic rule to establish transport before ruleset expansion. The rule
was refined to Echo Requests only. Unquoted service paths were corrected.
Stable capture-device GUIDs replaced DHCP addresses as device selectors.
A genuine restart established boot persistence. The second EVE logger was
moved to the top-level event outputs after an incorrect logging placement.
Security and health output were then separated and dated retention tested.

## Operating-mode chronology

The 1 October baseline used automatic service startup. On-demand controls
were installed on 20 October to manage laptop resource use between tests.
The 26 October inspection confirms Manual startup for Suricata and the
Wazuh agent, with both stopped. Historical auto-start proof and current
on-demand settings describe different operating modes and dates.

Applying the publication patches only stages repository files. The
installed services, firewall, Wazuh VM and scheduled task are not deployed
or reconfigured by these packages.

## Team publication split

The remaining release is divided into two six-file commits. The first
publishes configuration and lifecycle documentation. The second publishes
the existing maintenance implementation, task example, operations and
verification records, and marks Milestone B complete in the README.
Each team member reviews and commits their part using their own identity.
This split records publication responsibility; dated test evidence retains
its original provenance.

## Downstream boundary

Step 2 can consume structured source records while keeping telemetry,
alerts, sensor health and possible gaps distinct. This publication
completes Step 1 repository coverage. The later locally implemented stages
will be published separately, and the proposed LLM stages remain future work.
