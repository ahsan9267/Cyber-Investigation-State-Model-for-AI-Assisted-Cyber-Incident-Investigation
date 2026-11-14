BEGIN;

CREATE TABLE ingestion.file_generation_events (
    event_id UUID PRIMARY KEY,

    generation_id UUID NOT NULL
        REFERENCES ingestion.file_generations(generation_id),

    event_type TEXT NOT NULL CHECK (
        event_type IN (
            'replacement_detected',
            'truncation_detected',
            'content_change_detected',
            'file_missing',
            'generation_retired'
        )
    ),

    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    checkpoint_offset BIGINT NOT NULL
        CHECK (checkpoint_offset >= 0),

    observed_size BIGINT
        CHECK (observed_size IS NULL OR observed_size >= 0),

    possible_evidence_gap BOOLEAN NOT NULL,

    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object')
);

CREATE INDEX file_generation_events_by_generation
    ON ingestion.file_generation_events (
        generation_id, detected_at
    );

GRANT SELECT, INSERT
    ON ingestion.file_generation_events
    TO spine_app;

COMMIT;