# Step 2: ingestion and normalization

Step 2 turns Wazuh alerts, Suricata EVE and Sysmon XML into a shared record
format while preserving original text, hashes and provenance. This publication
exports the accepted Step 2 source from 12 November 2026 into the repository's
existing root layout.

## Two-part source publication

| Order | Uploader | Scope |
| --- | --- | --- |
| 1 | Ahsan | Parsing, normalization, enrichment, accounting, public configuration and contribution guidance |
| 2 | Mubbashir | Storage, checkpoints/recovery, collectors, SQL, tests, verification and the final root index |

These labels assign upload responsibility; they do not change authorship of the
underlying work. Use each member's own account and normal review process.

Part 1 is incomplete on its own. Its accounting module imports the storage
validator supplied in Part 2. Perform the offline checks after both commits.

## Files and reading order

| Area | Location |
| --- | --- |
| Shared pipeline and adapters | `src/spine/` |
| Runtime and verification entry points | `tools/` |
| Ingestion database schema | `sql/001` through `sql/007` |
| Identity examples | `config/identity_mappings.json`, `config/user_mappings.json` |
| Tests and synthetic fixtures | `tests/`, `tests/fixtures/` |

1. [Normalization and provenance](normalization.md)
2. [Storage and collector operation](storage-and-collectors.md), added in Part 2
3. [Verification and limits](verification.md), added in Part 2

This release does not publish alert-to-case association, the Investigation
Manager, investigation state, evidence acquisition, sufficiency or local LLM
reasoning. Their lab implementation and validation are separate work.
