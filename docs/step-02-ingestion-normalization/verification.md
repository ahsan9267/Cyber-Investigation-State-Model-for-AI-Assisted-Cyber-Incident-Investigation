# Verification of the published Step 2 source

Verified on 12 November 2026 after placing both upload parts in the existing
repository layout. The Desktop checkout and remote repository were not changed.

| Check | Result |
| --- | --- |
| Step 2 regression tests | 118 passed; zero failures and errors |
| Frozen normalization scenarios | 4 of 4 passed |
| Original raw content and replay identity | 41 of 41 records passed |
| Frozen field expectations | 23 of 23 passed |
| Runtime Python modules | 36 copied unchanged from the accepted Step 2 snapshot |
| Existing Step 1 configuration, proposal, architecture, operations and milestone documents | All 14 files preserved in the refreshed review tree |
| Existing repository files replaced | Root README index and additive ignore rules only |
| Overlapping upload file paths | None |
| Payload files hidden by Git ignore rules | None |

The unit-test log is [results/unit-tests.txt](results/unit-tests.txt).
The normalization receipt is [results/normalization.json](results/normalization.json).
[Source provenance](source-provenance.json) records original source hashes and
explains the one test-path change for the synthetic Suricata fixture.

## Repeat offline checks

Use Python 3.10 or later, with the pinned dependency in requirements.txt. From
the repository root in PowerShell:

```powershell
$env:PYTHONPATH = Join-Path (Get-Location).Path 'src'
& .\.venv\Scripts\python.exe -B -m unittest discover -s tests -p 'test_*.py' -v
& .\.venv\Scripts\python.exe -B tools\verify_normalization.py
```

The first command discovers this publication's Step 2 regression subset. The
second reads frozen synthetic fixtures, verifies their hashes, normalizes every
record twice, checks raw preservation and replay identity, and checks the 23
predefined field expectations. It never calls the association engine.

The original accepted Step 2 run passed 213 broader backend regressions and 12
verification gates, including isolated PostgreSQL persistence and recovery.
Those database gates were not rerun during this source-publication task. The
fresh 118-test subset is not a replacement claim for the broader historical run.

No live sensors, attack traffic, production database, association, later case
lifecycle or local LLM reasoning were executed in these publication checks.
Formal live scenario acceptance remains separate.
