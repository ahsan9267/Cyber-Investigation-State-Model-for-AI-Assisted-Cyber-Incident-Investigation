BEGIN;

-- Retain worker attempt outcomes separately from the mutable queue state.
-- Failed processing is rolled back before its failure is recorded.
CREATE TABLE investigation.work_attempts (
    attempt_id UUID PRIMARY KEY,

    work_id UUID NOT NULL
        REFERENCES investigation.work_items(work_id),

    attempt_number INTEGER NOT NULL
        CHECK (attempt_number >= 1),

    result TEXT NOT NULL
        CHECK (
            result IN (
                'completed',
                'retry_scheduled',
                'blocked'
            )
        ),

    -- Failure information and processing outcome.
    -- JSON supports preserved escaped null characters.
    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),

    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (work_id, attempt_number)
);

GRANT SELECT, INSERT
    ON investigation.work_attempts
    TO spine_app;

COMMIT;