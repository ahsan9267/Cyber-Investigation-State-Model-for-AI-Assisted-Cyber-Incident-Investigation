# Storage, checkpoints and collectors

| Area | Files |
| --- | --- |
| Evidence-preserving insertion and validation | `src/spine/storage.py` |
| Snapshot ingestion | `src/spine/snapshot.py` |
| Growing EVE and file rotation/recovery | `live_eve.py`, `live_lines.py`, `file_recovery.py` |
| Wazuh transport, continuation and recovery | `remote_wazuh.py`, `live_wazuh.py`, `wazuh_handoff.py`, `wazuh_recovery.py` |
| Sysmon bookmarks and recovery | `live_sysmon.py`, `sysmon_transport.py`, `sysmon_errors.py`, `sysmon_recovery.py` |
| Concurrent collector entry point | `tools/run_collectors.py` |
| Windows event reader | `tools/sysmon_reader.ps1`, `tools/sysmon_bookmarks.ps1` |

The storage layer keeps the first original record and treats repeated delivery
as replay. A different payload with the same source identity is retained as a
conflict rather than replacing the first document. Readers bind checkpoints to
their source and record/file generation, and preserve rejected source input in
the relevant outcomes.

## Deployment defaults

The source is an export of the existing Windows lab implementation, not a
portable one-command sensor installation. Before live use review:

- `spine.database.connect_database`: loopback port 5432, database `spine`, role
  `spine_app` and a password file under `%APPDATA%/SPINE/credentials/pgpass.conf`.
- `tools/run_collectors.py`: installed Suricata log paths and Windows collector
  assumptions. The files retain existing defaults to avoid changing runtime
  behavior during source publication.
- Wazuh transport arguments and server-side exporter requirements. Do not copy
  local credentials or captured logs into the repository.
- [Migration prerequisites](../../sql/README.md) and application privileges.

The original storage module includes a lazy optional callback for the later
Investigation Manager scheduling schema. That callback is not reached in an
ingestion-only database with migrations 001-007. If later investigation schemas
are installed, use their matching backend modules; this Step 2 source selection
alone does not provide those later dependencies.

Do not run these operational entry points merely to check a GitHub upload. The
offline test commands are the publication check. Formal live scenario testing
remains a separate acceptance exercise.
