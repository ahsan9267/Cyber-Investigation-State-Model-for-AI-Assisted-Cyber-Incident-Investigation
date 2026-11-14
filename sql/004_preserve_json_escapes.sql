BEGIN;

ALTER TABLE ingestion.records
    DROP CONSTRAINT records_document_object;

ALTER TABLE ingestion.records
    ALTER COLUMN document TYPE JSON USING document::json;

ALTER TABLE ingestion.records
    ADD CONSTRAINT records_document_object
    CHECK (json_typeof(document) = 'object');

ALTER TABLE ingestion.record_conflicts
    DROP CONSTRAINT conflicts_document_object;

ALTER TABLE ingestion.record_conflicts
    ALTER COLUMN incoming_document TYPE JSON
    USING incoming_document::json;

ALTER TABLE ingestion.record_conflicts
    ADD CONSTRAINT conflicts_document_object
    CHECK (json_typeof(incoming_document) = 'object');

COMMIT;