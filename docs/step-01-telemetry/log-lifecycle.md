# Step 1 log lifecycle

Daily Suricata files separate security telemetry from sensor statistics.
These settings were implemented before Step 1 was frozen and remain in the
configuration exported on 26 October 2026.

| Output | Contents | Consumer | Lifecycle |
|---|---|---|---|
| `eve-YYYY-MM-DD.json` | Security and protocol events, including alerts | Wazuh and later direct ingestion | Daily rotation; filename-date retention |
| `eve-health-YYYY-MM-DD.json` | Sensor statistics | Local operational diagnostics | Daily rotation; filename-date retention |
| `stats.log` | Historical standalone statistics | Historical diagnostic file | Standalone output disabled |
| `fast.log` | Human-readable alert output | Optional diagnostics | Still enabled; outside this EVE retention script |
| `suricata.log` | Engine and runtime messages | Diagnostics | Outside this EVE retention script |

## Rotation and health separation

Both EVE loggers belong in the top-level `outputs` list. `logging.outputs`
controls engine logging and is not the place for an EVE event logger.
During development, placing the second logger there produced an invalid
logging-method warning even though the configuration command reached a
successful final line. The logger was moved and its output verified.

The statistics interval is 60 seconds. The main EVE logger excludes `stats`;
the health logger includes totals with `threads`, `deltas` and `null-values`
disabled. The standalone `stats` output is disabled.

In the recorded 1 October checks, the main EVE statistics count stayed
at 88 during a 65-second interval while health EVE continued receiving
statistics. The historical `stats.log` stayed at 20,595,751 bytes with an
unchanged modification time during the corresponding check. These are
dated observations, not current counter values.

## Retention contract

The installed maintenance script uses a default of 14 calendar dates,
including today, according to the Windows local date. It calculates:

```text
oldest date to keep = today - (RetentionDays - 1)
delete a matching file only when its filename date is earlier
```

It selects regular `eve-*.json` files and accepts only these base names:

```text
^eve(?:-health)?-(\d{4}-\d{2}-\d{2})$
```

The date is parsed from the filename, not `LastWriteTime`. Both security
and health EVE are covered. An old `eve.json`, unrelated JSON, raw packet
captures, `fast.log` and the maintenance log are outside its scope.
The script assumes the configured log directories exist. An invalid date
that matches the pattern can stop the run because parsing is strict.

Milestone B publishes the installed script and the task definition. Its
`-DryRun` switch records candidate deletions in the maintenance log; it still
appends diagnostic messages. The normal task executes real deletions.

## Capacity and evidence limits

A 14-date policy bounds the age of matching retained files, not their total
bytes. Current-day traffic, other logs and the downstream database can
still grow. The deletion policy does not inspect SPINE checkpoints or
confirm ingestion completion. If a reader falls behind longer than the
retained window, unread source data may become unavailable.

Later ingestion records possible gaps instead of assuming deleted sources
were fully consumed. Do not clear that history to make health appear clean.
The Step 1 release does not claim gap-free collection or a database storage
quota. Pausing a reader does not preserve a source file indefinitely.
