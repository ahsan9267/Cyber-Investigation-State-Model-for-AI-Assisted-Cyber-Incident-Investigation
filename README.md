# SPINE

AI-assisted persistent cyber incident investigation — BS Cyber Security Final Year Project.

SPINE retains source evidence and investigation context across related security
alerts and telemetry. This repository publishes the Step 1 telemetry foundation
and the Step 2 ingestion and normalization source. Later investigation stages
and local LLM reasoning are outside this source release.

## Start here

- [Project proposal](docs/proposal/FYP_Final_Proposal.pdf)
- [Architecture diagram](docs/architecture/detailed-architecture.png)
- [Step 1 telemetry configuration](docs/step-01-telemetry/configuration.md)
- [Step 1 operations](docs/step-01-telemetry/operations.md)
- [Step 1 verification](docs/step-01-telemetry/validation.md)
- [Step 2 implementation](docs/step-02-ingestion-normalization/README.md)
- [Step 2 verification](docs/step-02-ingestion-normalization/verification.md)
- [Contribution guide](CONTRIBUTING.md)

## Repository layout

| Path | Contents |
| --- | --- |
| `src/spine/` | Shared records, source adapters, normalization, storage and reader recovery |
| `tools/` | Collector entry points, Windows readers and offline verification |
| `scripts/windows/` | Published Step 1 log-maintenance script |
| `sql/` | Ordered Step 2 ingestion migrations 001-007 |
| `config/` | Step 1 sensor examples and Step 2 public identity mappings |
| `tests/` | Unit regressions and explicitly synthetic fixtures |
| `docs/` | Proposal, architecture, milestone implementation and verification |

Runtime logs, checkpoints, credential files, database dumps and virtual
environments are excluded from version control. Source code is published as
files in these folders, rather than as embedded release ZIPs.

## Published scope

| Stage | Repository scope |
| --- | --- |
| Step 1: security telemetry | Milestones A and B: collection examples, diagnostic signature, log maintenance, operations and dated verification |
| Step 2: ingestion and normalization | Three-source parsing, evidence-preserving records, replay/conflict handling, checkpoints/recovery, SQL, collector tools and synthetic tests |
| Steps 3-7 | Not included in this source release |

Step 1 Milestones A and B are published within their documented laboratory
scope. The maintenance script, task example, operations runbook and dated
verification remain available alongside the existing configuration. Source
publication should not be mistaken for a new live sensor test.

## Run the offline Step 2 checks

Use Python 3.10 or later. In PowerShell, from the repository root:

```powershell
python -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -B tools\verify_normalization.py
```

Both publication parts are required. The verified combined source passed 118
unit tests and all four frozen normalization scenarios: 41 records and 23 field
checks. These checks use synthetic input and temporary files, without starting
sensors, attack traffic or a database. They do not establish live scenario
acceptance or validate later investigation stages.

## Lab operation

Step 1 uses a Wazuh 4.14.5 manager and Windows agent, Sysmon 15.21, Suricata
8.0.7 and Npcap. SID 1000001 revision 2 is a diagnostic ICMP Echo Request rule,
not a production detection ruleset. See the existing
[configuration](docs/step-01-telemetry/configuration.md) and
[log lifecycle](docs/step-01-telemetry/log-lifecycle.md) documents. The published
[maintenance script](scripts/windows/Suricata-LogMaintenance.ps1) and
[task example](config/windows/FYP-Suricata-LogMaintenance.example.xml) are
covered by the [operations runbook](docs/step-01-telemetry/operations.md).

The deployed laptop uses on-demand collection. Its installed `Start-FYP.cmd`
and `Stop-FYP.cmd` controller belongs to the later runtime and is not shipped in
this release. Review [database prerequisites](sql/README.md) and
[collector deployment defaults](docs/step-02-ingestion-normalization/storage-and-collectors.md)
before running operational tools on a different host.

## Academic project

Muhammad Ahsan Qureshi and Mubbashir Ahmed, supervised by Syed Yawar Abbas.
BS Cyber Security, Faculty of Computing, Riphah International University.
