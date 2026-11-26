"""Report retained possible-evidence-gap history without changing data."""

import json

from psycopg.rows import dict_row

from spine.database import connect_database


QUERY = """
WITH gap_history AS (
    SELECT
        'file'::text AS reader,
        g.source_scope,
        g.file_path AS target,
        e.event_id,
        e.generation_id,
        e.event_type,
        e.detected_at,
        g.retired_at,
        e.checkpoint_offset::text AS checkpoint_position,
        e.details
    FROM ingestion.file_generation_events AS e
    JOIN ingestion.file_generations AS g
        ON g.generation_id = e.generation_id
    WHERE e.possible_evidence_gap

    UNION ALL

    SELECT
        'eventlog'::text AS reader,
        g.source_scope,
        g.channel AS target,
        e.event_id,
        e.generation_id,
        e.event_type,
        e.detected_at,
        g.retired_at,
        g.last_record_id::text AS checkpoint_position,
        e.details
    FROM ingestion.eventlog_generation_events AS e
    JOIN ingestion.eventlog_generations AS g
        ON g.generation_id = e.generation_id
    WHERE e.possible_evidence_gap
)
SELECT
    *,
    COUNT(*) OVER () AS total_history_entries
FROM gap_history
ORDER BY detected_at DESC, event_id DESC
LIMIT 20
"""


def main():
    with connect_database() as connection:
        with connection.transaction():
            connection.execute("SET TRANSACTION READ ONLY")
            connection.execute("SET LOCAL statement_timeout = '15s'")

            with connection.cursor(row_factory=dict_row) as cursor:
                cursor.execute(QUERY)
                rows = cursor.fetchall()

    total = rows[0]["total_history_entries"] if rows else 0

    print(f"Possible-gap history entries: {total}")
    print(f"Latest entries shown: {len(rows)}")

    if not rows:
        print(
            "No possible-gap entries are recorded in these two history "
            "tables. This does not prove complete source coverage."
        )
    else:
        print(
            "These are historical flags, not counts of lost events "
            "or necessarily separate incidents."
        )

        for row in rows:
            entry = dict(row)
            entry.pop("total_history_entries", None)
            print(json.dumps(entry, ensure_ascii=False, default=str, indent=2))

    print("No database records or checkpoints changed.")


if __name__ == "__main__":
    main()