BEGIN;

-- Immutable annotated inputs used by the manager.
-- annotation_context will retain annotation version and configuration
-- contents/hashes, not just a reference to a mutable configuration file.
CREATE TABLE investigation.evidence_views (
    view_id TEXT PRIMARY KEY
        CHECK (view_id ~ '^[0-9a-f]{64}$'),

    record_id TEXT NOT NULL
        REFERENCES ingestion.records(record_id),

    raw_sha256 TEXT NOT NULL
        CHECK (raw_sha256 ~ '^[0-9a-f]{64}$'),

    document JSON NOT NULL
        CHECK (json_typeof(document) = 'object'),

    annotation_context JSON NOT NULL
        CHECK (json_typeof(annotation_context) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (view_id, record_id)
);


CREATE TABLE investigation.cases (
    case_id UUID PRIMARY KEY,

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'closed')),

    revision BIGINT NOT NULL DEFAULT 1
        CHECK (revision >= 1),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    closed_at TIMESTAMPTZ,

    CHECK (
        (status = 'active' AND closed_at IS NULL)
        OR
        (status = 'closed' AND closed_at IS NOT NULL)
    )
);

-- Creating a closed status does not implement automatic closure.
-- This stage creates active cases only.
CREATE INDEX cases_by_status
    ON investigation.cases (status, case_id);


-- One initial routing result per record-delivery work item.
-- The Step 3 result is retained unchanged in decision_document.
-- assigned_case_id records the case actually allocated by Step 4,
-- including when Step 3 returned NEW_CASE with case_id = null.
CREATE TABLE investigation.routing_decisions (
    decision_event_id UUID PRIMARY KEY,

    work_id UUID NOT NULL UNIQUE
        REFERENCES investigation.work_items(work_id),

    record_id TEXT NOT NULL
        REFERENCES ingestion.records(record_id),

    input_view_id TEXT NOT NULL,

    policy_version TEXT NOT NULL
        CHECK (length(btrim(policy_version)) > 0),

    snapshot_revision BIGINT NOT NULL
        CHECK (snapshot_revision >= 0),

    snapshot_sha256 TEXT NOT NULL
        CHECK (snapshot_sha256 ~ '^[0-9a-f]{64}$'),

    snapshot_document JSON NOT NULL
        CHECK (json_typeof(snapshot_document) = 'object'),

    -- Maps snapshot record IDs to retained evidence-view IDs.
    snapshot_view_refs JSON NOT NULL
        CHECK (json_typeof(snapshot_view_refs) = 'object'),

    decision_sha256 TEXT NOT NULL
        CHECK (decision_sha256 ~ '^[0-9a-f]{64}$'),

    decision_document JSON NOT NULL
        CHECK (json_typeof(decision_document) = 'object'),

    route TEXT NOT NULL
        CHECK (route IN ('NEW_CASE', 'EXISTING_CASE', 'EXCLUDED')),

    assigned_case_id UUID
        REFERENCES investigation.cases(case_id),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (input_view_id, record_id)
        REFERENCES investigation.evidence_views(view_id, record_id),

    CHECK (
        (route = 'EXCLUDED' AND assigned_case_id IS NULL)
        OR
        (
            route IN ('NEW_CASE', 'EXISTING_CASE')
            AND assigned_case_id IS NOT NULL
        )
    ),

    UNIQUE (
        decision_event_id,
        record_id,
        assigned_case_id,
        input_view_id
    )
);


-- One current owner per evidence record.
-- Different representations remain separate memberships.
-- This is not a count of independent underlying activities.
CREATE TABLE investigation.case_memberships (
    record_id TEXT PRIMARY KEY,
    case_id UUID NOT NULL,
    input_view_id TEXT NOT NULL,
    decision_event_id UUID NOT NULL,

    occurrence_id TEXT NOT NULL
        CHECK (occurrence_id ~ '^[0-9a-f]{64}$'),

    occurrence_profile TEXT NOT NULL
        CHECK (length(btrim(occurrence_profile)) > 0),

    representation_matching_supported BOOLEAN NOT NULL,

    count_unit TEXT NOT NULL
        CHECK (
            count_unit IN (
                'source_session_message',
                'record_not_confirmed_occurrence'
            )
        ),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (
        decision_event_id,
        record_id,
        case_id,
        input_view_id
    )
        REFERENCES investigation.routing_decisions (
            decision_event_id,
            record_id,
            assigned_case_id,
            input_view_id
        ),

    CHECK (
        (
            representation_matching_supported
            AND count_unit = 'source_session_message'
        )
        OR
        (
            NOT representation_matching_supported
            AND count_unit = 'record_not_confirmed_occurrence'
        )
    )
);

CREATE INDEX memberships_by_case
    ON investigation.case_memberships(case_id, record_id);

CREATE INDEX memberships_by_occurrence
    ON investigation.case_memberships(occurrence_id);


-- Append-only explanations for each case revision.
-- Conflict reassessment can add a new revision/history entry without
-- overwriting the original routing decision.
CREATE TABLE investigation.case_history (
    history_id UUID PRIMARY KEY,

    case_id UUID NOT NULL
        REFERENCES investigation.cases(case_id),

    case_revision BIGINT NOT NULL
        CHECK (case_revision >= 1),

    work_id UUID NOT NULL
        REFERENCES investigation.work_items(work_id),

    event_type TEXT NOT NULL
        CHECK (length(btrim(event_type)) > 0),

    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (case_id, case_revision)
);


-- Historical relationships, not automatic case merges.
CREATE TABLE investigation.case_relationships (
    relationship_id UUID PRIMARY KEY,

    case_id UUID NOT NULL
        REFERENCES investigation.cases(case_id),

    related_case_id UUID NOT NULL
        REFERENCES investigation.cases(case_id),

    decision_event_id UUID NOT NULL
        REFERENCES investigation.routing_decisions(decision_event_id),

    relationship_kind TEXT NOT NULL
        CHECK (
            relationship_kind IN (
                'possible_context',
                'ambiguous_candidate',
                'session_conflict'
            )
        ),

    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CHECK (case_id <> related_case_id),

    UNIQUE (
        decision_event_id,
        case_id,
        related_case_id,
        relationship_kind
    )
);


-- Durable handoff to future investigation components.
-- Step 4 will create pending work; it will not simulate completion.
CREATE TABLE investigation.pending_investigation_work (
    task_id UUID PRIMARY KEY,

    case_id UUID NOT NULL,
    case_revision BIGINT NOT NULL,

    target_component TEXT NOT NULL
        CHECK (
            target_component IN (
                'cyber_investigation_state',
                'evidence_acquisition'
            )
        ),

    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'completed', 'blocked')),

    details JSON NOT NULL
        CHECK (json_typeof(details) = 'object'),

    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_id, case_revision)
        REFERENCES investigation.case_history(case_id, case_revision),

    UNIQUE (case_id, case_revision, target_component)
);

CREATE INDEX pending_investigation_tasks
    ON investigation.pending_investigation_work (
        created_at, task_id
    )
    WHERE status = 'pending';


GRANT SELECT, INSERT ON
    investigation.evidence_views,
    investigation.cases,
    investigation.routing_decisions,
    investigation.case_memberships,
    investigation.case_history,
    investigation.case_relationships,
    investigation.pending_investigation_work
TO spine_app;

GRANT UPDATE (revision, updated_at)
    ON investigation.cases
    TO spine_app;

-- No UPDATE or DELETE grants on historical views, decisions,
-- memberships, relationships or history.
-- Later lifecycle/task consumers need explicit future permissions.

COMMIT;