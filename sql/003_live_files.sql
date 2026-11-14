BEGIN;

CREATE TABLE ingestion.file_generations (
    generation_id UUID PRIMARY KEY,

    input_format TEXT NOT NULL
        CHECK (input_format IN ('wazuh', 'eve')),
    source_scope TEXT NOT NULL,
    file_path TEXT NOT NULL,

    device_id TEXT NOT NULL,
    native_file_id TEXT NOT NULL,

    first_line_sha256 TEXT NOT NULL
        CHECK (first_line_sha256 ~ '^[0-9a-f]{64}$'),

    next_offset BIGINT NOT NULL DEFAULT 0
        CHECK (next_offset >= 0),
    processed_lines BIGINT NOT NULL DEFAULT 0
        CHECK (processed_lines >= 0),

    checkpoint_tail BYTEA NOT NULL DEFAULT '\x'::bytea,

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TIMESTAMPTZ,
    retirement_reason TEXT,

    CHECK (
        octet_length(checkpoint_tail) <= 4096
        AND octet_length(checkpoint_tail) <= next_offset
    ),

    CHECK (
        (retired_at IS NULL AND retirement_reason IS NULL)
        OR
        (retired_at IS NOT NULL AND retirement_reason IS NOT NULL)
    )
);

CREATE UNIQUE INDEX file_generations_current_path
    ON ingestion.file_generations (
        input_format, source_scope, file_path
    )
    WHERE retired_at IS NULL;

CREATE UNIQUE INDEX file_generations_current_native_id
    ON ingestion.file_generations (
        input_format, source_scope, device_id, native_file_id
    )
    WHERE retired_at IS NULL;

CREATE TABLE ingestion.file_outcomes (
    generation_id UUID NOT NULL
        REFERENCES ingestion.file_generations(generation_id),

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

    PRIMARY KEY (generation_id, byte_offset),
    UNIQUE (generation_id, line_number),

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
    ON ingestion.file_generations, ingestion.file_outcomes
    TO spine_app;

GRANT UPDATE (
    file_path,
    next_offset,
    processed_lines,
    checkpoint_tail,
    updated_at,
    retired_at,
    retirement_reason
)
    ON ingestion.file_generations
    TO spine_app;

COMMIT;