BEGIN;

CREATE SCHEMA investigation AUTHORIZATION postgres;

GRANT USAGE ON SCHEMA investigation TO spine_app;

-- One coordination row for case-routing transactions.
-- Workers will lock it before reading or changing case context.
CREATE TABLE investigation.routing_state (
    singleton_id SMALLINT PRIMARY KEY
        CHECK (singleton_id = 1),

    revision BIGINT NOT NULL DEFAULT 0
        CHECK (revision >= 0),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO investigation.routing_state (singleton_id)
VALUES (1);


-- Durable delivery identity is independent of Step 3 decision_id.
-- A preserved conflict is separate work from its original record.
CREATE TABLE investigation.work_items (
    work_id UUID PRIMARY KEY,

    work_kind TEXT NOT NULL
        CHECK (work_kind IN ('record', 'conflict')),

    record_id TEXT NOT NULL
        REFERENCES ingestion.records(record_id),

    payload_sha256 TEXT NOT NULL
        CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'blocked')),

    attempt_count INTEGER NOT NULL DEFAULT 0
        CHECK (attempt_count >= 0),

    available_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,

    outcome TEXT
        CHECK (
            outcome IN (
                'routed',
                'excluded',
                'replay',
                'conflict_recorded'
            )
        ),

    last_error TEXT,

    CONSTRAINT work_delivery_identity
        UNIQUE (work_kind, record_id, payload_sha256),

    CONSTRAINT work_completion_state
        CHECK (
            (
                status = 'completed'
                AND completed_at IS NOT NULL
                AND outcome IS NOT NULL
            )
            OR
            (
                status IN ('pending', 'blocked')
                AND completed_at IS NULL
                AND outcome IS NULL
            )
        )
);

CREATE INDEX work_items_pending
    ON investigation.work_items (available_at, created_at, work_id)
    WHERE status = 'pending';

CREATE INDEX work_items_by_record
    ON investigation.work_items (record_id);


GRANT SELECT
    ON investigation.routing_state
    TO spine_app;

GRANT UPDATE (revision, updated_at)
    ON investigation.routing_state
    TO spine_app;

GRANT SELECT, INSERT
    ON investigation.work_items
    TO spine_app;

GRANT UPDATE (
    status,
    attempt_count,
    available_at,
    updated_at,
    completed_at,
    outcome,
    last_error
)
    ON investigation.work_items
    TO spine_app;

COMMIT;