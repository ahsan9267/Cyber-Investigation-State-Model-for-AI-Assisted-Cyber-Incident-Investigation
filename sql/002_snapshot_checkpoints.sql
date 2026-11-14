BEGIN;

CREATE TABLE ingestion.snapshots (
    input_format TEXT NOT NULL
        CHECK (input_format IN ('wazuh', 'eve')),
    source_scope TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,
    snapshot_sha256 TEXT NOT NULL
        CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),
    snapshot_bytes BIGINT NOT NULL
        CHECK (snapshot_bytes >= 0),

    next_offset BIGINT NOT NULL DEFAULT 0,
    processed_lines BIGINT NOT NULL DEFAULT 0
        CHECK (processed_lines >= 0),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (input_format, source_scope, snapshot_id),

    CHECK (
        next_offset >= 0
        AND next_offset <= snapshot_bytes
    )
);

CREATE TABLE ingestion.snapshot_outcomes (
    input_format TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    snapshot_id TEXT NOT NULL,

    byte_offset BIGINT NOT NULL CHECK (byte_offset >= 0),
    byte_length BIGINT NOT NULL CHECK (byte_length > 0),
    line_number BIGINT NOT NULL CHECK (line_number > 0),

    disposition TEXT NOT NULL CHECK (
        disposition IN (
            'inserted',
            'replay',
            'conflict',
            'conflict_replay',
            'quarantined',
            'excluded_sensor_health'
        )
    ),

    record_id TEXT REFERENCES ingestion.records(record_id),
    raw_bytes BYTEA NOT NULL,
    reason TEXT,
    processed_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (
        input_format, source_scope, snapshot_id, byte_offset
    ),

    UNIQUE (
        input_format, source_scope, snapshot_id, line_number
    ),

    FOREIGN KEY (input_format, source_scope, snapshot_id)
        REFERENCES ingestion.snapshots (
            input_format, source_scope, snapshot_id
        ),

    CHECK (octet_length(raw_bytes) = byte_length),

    CHECK (
        (
            disposition IN (
                'inserted', 'replay', 'conflict', 'conflict_replay'
            )
            AND record_id IS NOT NULL
        )
        OR
        (
            disposition IN ('quarantined', 'excluded_sensor_health')
            AND record_id IS NULL
            AND reason IS NOT NULL
        )
    )
);

GRANT SELECT, INSERT
    ON ingestion.snapshots, ingestion.snapshot_outcomes
    TO spine_app;

GRANT UPDATE (next_offset, processed_lines, updated_at)
    ON ingestion.snapshots
    TO spine_app;

COMMIT;