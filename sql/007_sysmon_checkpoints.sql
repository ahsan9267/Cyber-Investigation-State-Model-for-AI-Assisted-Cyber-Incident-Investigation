BEGIN;

CREATE TABLE ingestion.eventlog_generations (
    generation_id UUID PRIMARY KEY,
    source_scope TEXT NOT NULL,
    channel TEXT NOT NULL,
    computer TEXT NOT NULL,

    last_record_id BIGINT,
    last_raw_sha256 TEXT,
    bookmark_xml TEXT,

    processed_records BIGINT NOT NULL DEFAULT 0
        CHECK (processed_records >= 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ,
    retirement_reason TEXT,

    CHECK (length(btrim(source_scope)) > 0),
    CHECK (length(btrim(channel)) > 0),
    CHECK (length(btrim(computer)) > 0),

    CHECK (
        (
            last_record_id IS NULL
            AND last_raw_sha256 IS NULL
            AND bookmark_xml IS NULL
            AND processed_records = 0
        )
        OR
        (
            last_record_id IS NOT NULL
            AND last_record_id > 0
            AND last_raw_sha256 IS NOT NULL
            AND last_raw_sha256 ~ '^[0-9a-f]{64}$'
            AND bookmark_xml IS NOT NULL
            AND length(btrim(bookmark_xml)) > 0
            AND processed_records > 0
        )
    ),

    CHECK (
        (retired_at IS NULL AND retirement_reason IS NULL)
        OR
        (
            retired_at IS NOT NULL
            AND retirement_reason IS NOT NULL
            AND length(btrim(retirement_reason)) > 0
        )
    )
);

CREATE UNIQUE INDEX eventlog_one_active_generation
    ON ingestion.eventlog_generations (source_scope, channel)
    WHERE retired_at IS NULL;


CREATE TABLE ingestion.eventlog_outcomes (
    generation_id UUID NOT NULL
        REFERENCES ingestion.eventlog_generations (generation_id),

    event_record_id BIGINT NOT NULL
        CHECK (event_record_id > 0),

    disposition TEXT NOT NULL
        CHECK (
            disposition IN (
                'inserted',
                'replay',
                'conflict',
                'conflict_replay',
                'quarantined'
            )
        ),

    record_id TEXT REFERENCES ingestion.records (record_id),
    raw_xml TEXT NOT NULL CHECK (length(raw_xml) > 0),
    raw_sha256 TEXT NOT NULL
        CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),
    bookmark_xml TEXT NOT NULL
        CHECK (length(btrim(bookmark_xml)) > 0),
    reason TEXT,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (generation_id, event_record_id),

    CHECK (
        (
            disposition = 'quarantined'
            AND record_id IS NULL
            AND reason IS NOT NULL
            AND length(btrim(reason)) > 0
        )
        OR
        (
            disposition <> 'quarantined'
            AND record_id IS NOT NULL
            AND reason IS NULL
        )
    )
);


CREATE TABLE ingestion.eventlog_generation_events (
    event_id UUID PRIMARY KEY,
    generation_id UUID NOT NULL
        REFERENCES ingestion.eventlog_generations (generation_id),

    event_type TEXT NOT NULL
        CHECK (
            event_type IN (
                'checkpoint_unavailable',
                'checkpoint_mismatch',
                'generation_retired'
            )
        ),

    possible_evidence_gap BOOLEAN NOT NULL,
    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX eventlog_generation_events_history
    ON ingestion.eventlog_generation_events (
        generation_id,
        detected_at
    );


GRANT SELECT, INSERT
    ON ingestion.eventlog_generations,
       ingestion.eventlog_outcomes,
       ingestion.eventlog_generation_events
    TO spine_app;

GRANT UPDATE (
    last_record_id,
    last_raw_sha256,
    bookmark_xml,
    processed_records,
    updated_at,
    retired_at,
    retirement_reason
)
    ON ingestion.eventlog_generations
    TO spine_app;

COMMIT;