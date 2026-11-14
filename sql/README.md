# Step 2 database migrations

Migrations 001-007 are copied unchanged from the accepted Step 2 snapshot.
Apply them in numeric order only to a dedicated, prepared PostgreSQL database.
They are not a bootstrap script for an unconfigured cluster.

## Prerequisites

- PostgreSQL 18 was used for the original accepted database verification.
- An administrator must first create the target database, an appropriately
  restricted `spine_app` application role and the `ingestion` schema.
- Grant the application role `USAGE` on `ingestion`; individual migrations grant
  table/sequence privileges. The application role must not own original-evidence
  tables or have general update/delete privileges on them.
- Configure credentials outside the repository. Do not put a password in SQL,
  Git history or command-line examples.
- Review the migrations and existing schema before execution. They are ordered
  versioned changes, not idempotent scripts to rerun on a populated lab database.

The migration files cover records/conflicts, snapshots and outcomes, growing
files/generations, preserved JSON escapes, archive paths and Sysmon checkpoints.
They do not create the later Investigation Manager schemas.

The offline tests do not apply migrations or access PostgreSQL. The lab's
`spine.database.connect_database` retains its original database/role/port defaults;
review it before connecting tools to a new environment. Other command-line
tools expose connection arguments. Consult each tool before choosing a target.
