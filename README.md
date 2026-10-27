# SPINE

AI-assisted persistent cyber incident investigation - BS Cyber Security Final Year Project.

SPINE is being developed to retain investigation context across related alerts
and telemetry. This repository release publishes the Step 1 telemetry foundation.
Later ingestion, association and manager work already exists in the development
lab and will be published separately. Local LLM reasoning is planned work.

## Architecture and proposal

- [Architecture diagram](docs/architecture/detailed-architecture.png)
- [Project proposal](docs/proposal/FYP_Final_Proposal.pdf)

The wider design connects telemetry, normalization, alert-to-case association,
investigation management, evidence analysis and analyst validation. Those
planned components should not be inferred from the contents of this release.

## Published status

Milestones A and B are published. Step 1 is complete within the documented laboratory scope.

- [Milestone A](docs/step-01-telemetry/milestone-a.md)
- [Final telemetry configuration](docs/step-01-telemetry/configuration.md)
- [Log lifecycle and retention boundaries](docs/step-01-telemetry/log-lifecycle.md)
- [Milestone B](docs/step-01-telemetry/milestone-b.md)
- [Operations and service lifecycle](docs/step-01-telemetry/operations.md)
- [Dated verification record](docs/step-01-telemetry/validation.md)

Step 1 uses a Wazuh 4.14.5 manager and Windows agent, Sysmon 15.21, Suricata
8.0.7 and Npcap. The agent forwards Sysmon event-channel records and security
EVE JSON. The diagnostic signature is SID 1000001, revision 2, for ICMP Echo
Requests. It verifies integration and is not a production detection ruleset.

## Configuration examples

- `config/wazuh/ossec-collection-example.xml` contains collection blocks to merge into an existing agent configuration
- `config/suricata/suricata-step1.example.yaml` is the complete lab configuration with two placeholder capture-device GUIDs
- `config/suricata/fyp-test.rules` contains the diagnostic rule
- `config/suricata/fyp-local.rules` reserves a file for future local signatures

Replace the example GUIDs and adapt networks/paths before using the YAML on a
different host. Security EVE rotates daily; sensor statistics use a separate
local health stream. Retention limits file age, not total disk consumption.
The installed retention script and task example are under `scripts/windows/` and `config/windows/`.
Review the operations runbook before using them on another machine.

## Current development-laptop mode

The original Step 1 baseline used automatic service startup. The development
laptop moved to on-demand operation on 20 October 2026. Its current Suricata
and Wazuh-agent startup mode is Manual; use its installed `Start-FYP.cmd` and
`Stop-FYP.cmd` controls for test sessions. Sysmon retains its Windows setup.
The controller belongs to the later runtime publication and is not bundled here.

Historical configuration and tests retain their dates. See the Step 1
documents for the original acceptance evidence and later inspection scope.

## Academic project

Muhammad Ahsan Qureshi and Mubbashir Ahmed, supervised by Syed Yawar Abbas.
BS Cyber Security, Faculty of Computing, Riphah International University.
