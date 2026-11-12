# Contributing

SPINE is an academic project by Muhammad Ahsan Qureshi and Mubbashir Ahmed.

## Work and review

1. Pull the latest branch before adding files. Use your own GitHub account and
   Git identity for your commits.
2. Keep one milestone or focused change in each commit. Use a feature branch and
   pull request when the team requires review; otherwise coordinate the order
   of commits to the shared branch.
3. Review `git status`, the staged paths and `git diff --cached` before pushing.
   Include the change's purpose and the checks actually performed.
4. Run the relevant offline checks described in
   [Step 2 verification](docs/step-02-ingestion-normalization/verification.md).
5. Keep original source evidence and its hashes intact. Label synthetic fixtures
   explicitly and distinguish normalization tests from live acceptance.

## Folder ownership

| Folder | Contents |
| --- | --- |
| `src/spine/` | Reusable Python backend modules |
| `tools/` | Operational entry points and verification tools |
| `sql/` | Ordered database migrations and their prerequisites |
| `config/` | Public configuration examples and explicit identity mappings |
| `tests/` | Regression tests and synthetic input fixtures |
| `docs/` | Proposal, architecture and dated milestone documentation |

Do not commit credentials, live security logs, database dumps, virtual
environments or machine-specific configuration. Use `config/local/` for local
settings where a tool supports them; it is ignored by Git. Review existing
deployment defaults before running collectors in a different environment.

Existing Step 1 sensor settings have their own documentation. Publishing Step 2
source does not authorize changing those deployed settings or replaying live
attack scenarios.
