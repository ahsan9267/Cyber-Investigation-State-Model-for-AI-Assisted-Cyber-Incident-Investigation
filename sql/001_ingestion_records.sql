BEGIN;

CREATE TABLE ingestion.records (
    record_id TEXT PRIMARY KEY,
    collector TEXT NOT NULL,
    source_scope TEXT NOT NULL,
    source_record_id TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    document JSONB NOT NULL,
    stored_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT records_id_format
        CHECK (record_id ~ '^[0-9a-f]{64}$'),

    CONSTRAINT records_hash_format
        CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT records_document_object
        CHECK (jsonb_typeof(document) = 'object'),

    CONSTRAINT records_source_identity
        UNIQUE (collector, source_scope, source_record_id)
);

CREATE TABLE ingestion.record_conflicts (
    record_id TEXT NOT NULL
        REFERENCES ingestion.records(record_id),
    incoming_raw_sha256 TEXT NOT NULL,
    incoming_document JSONB NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    PRIMARY KEY (record_id, incoming_raw_sha256),

    CONSTRAINT conflicts_hash_format
        CHECK (incoming_raw_sha256 ~ '^[0-9a-f]{64}$'),

    CONSTRAINT conflicts_document_object
        CHECK (jsonb_typeof(incoming_document) = 'object')
);

GRANT SELECT, INSERT
    ON ingestion.records, ingestion.record_conflicts
    TO spine_app;

COMMIT;