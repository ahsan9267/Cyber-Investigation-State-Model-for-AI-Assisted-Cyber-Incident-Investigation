BEGIN;

ALTER TABLE ingestion.file_generations
    ADD COLUMN remote_archive_path TEXT;

GRANT UPDATE (remote_archive_path)
    ON ingestion.file_generations
    TO spine_app;

COMMIT;