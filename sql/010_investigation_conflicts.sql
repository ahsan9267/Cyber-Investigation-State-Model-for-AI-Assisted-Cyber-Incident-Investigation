BEGIN;

-- One durable receipt for each processed conflicting payload.
-- A receipt also exists when the original record was excluded
-- and therefore has no case.
CREATE TABLE investigation.conflict_events (
    conflict_event_id UUID PRIMARY KEY,

    work_id UUID NOT NULL UNIQUE
        REFERENCES investigation.work_items(work_id),

    record_id TEXT NOT NULL,

    incoming_raw_sha256 TEXT NOT NULL
        CHECK (incoming_raw_sha256 ~ '^[0-9a-f]{64}$'),

    original_decision_event_id UUID NOT NULL
        REFERENCES investigation.routing_decisions(decision_event_id),

    -- Null together when the original record has no case.
    case_id UUID,
    case_revision BIGINT,

    -- Global routing revision inspected before applying this event.
    snapshot_revision BIGINT NOT NULL
        CHECK (snapshot_revision >= 0),

    -- Records evidence references, handling rationale and uncertainty.
    -- JSON preserves escaped null characters.
    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (record_id, incoming_raw_sha256)
        REFERENCES ingestion.record_conflicts (
            record_id, incoming_raw_sha256
        ),

    FOREIGN KEY (case_id, case_revision)
        REFERENCES investigation.case_history (
            case_id, case_revision
        ),

    CHECK (
        (case_id IS NULL AND case_revision IS NULL)
        OR
        (
            case_id IS NOT NULL
            AND case_revision IS NOT NULL
            AND case_revision >= 1
        )
    ),

    UNIQUE (record_id, incoming_raw_sha256)
);

CREATE INDEX conflict_events_by_case
    ON investigation.conflict_events(case_id, case_revision)
    WHERE case_id IS NOT NULL;

GRANT SELECT, INSERT
    ON investigation.conflict_events
    TO spine_app;

COMMIT;