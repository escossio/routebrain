CREATE TABLE IF NOT EXISTS learning_requests (
    id bigserial PRIMARY KEY,
    request_uid text NOT NULL UNIQUE,
    question text NOT NULL,
    normalized_question text,
    intent text,
    scope text,
    status text NOT NULL DEFAULT 'created',
    operator text,
    requires_consent boolean DEFAULT false,
    consent_status text DEFAULT 'not_required',
    confidence_before numeric,
    confidence_after numeric,
    answer_summary text,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz,
    raw_context jsonb DEFAULT '{}'::jsonb,
    result jsonb DEFAULT '{}'::jsonb,
    error text
);

CREATE TABLE IF NOT EXISTS learning_entities (
    id bigserial PRIMARY KEY,
    request_id bigint NOT NULL REFERENCES learning_requests(id) ON DELETE CASCADE,
    entity_type text NOT NULL,
    entity_value text NOT NULL,
    normalized_value text,
    confidence numeric,
    source text DEFAULT 'rule',
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS learning_gaps (
    id bigserial PRIMARY KEY,
    request_id bigint NOT NULL REFERENCES learning_requests(id) ON DELETE CASCADE,
    gap_type text NOT NULL,
    description text NOT NULL,
    severity text DEFAULT 'medium',
    blocks_answer boolean DEFAULT false,
    recommended_task_type text,
    status text DEFAULT 'open',
    created_at timestamptz DEFAULT now(),
    resolved_at timestamptz,
    metadata jsonb DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS learning_tasks (
    id bigserial PRIMARY KEY,
    request_id bigint NOT NULL REFERENCES learning_requests(id) ON DELETE CASCADE,
    task_uid text NOT NULL UNIQUE,
    task_type text NOT NULL,
    status text NOT NULL DEFAULT 'planned',
    priority integer DEFAULT 100,
    requires_consent boolean DEFAULT false,
    command_preview text,
    input jsonb DEFAULT '{}'::jsonb,
    output jsonb DEFAULT '{}'::jsonb,
    error text,
    created_at timestamptz DEFAULT now(),
    started_at timestamptz,
    finished_at timestamptz
);

CREATE TABLE IF NOT EXISTS learning_evidence (
    id bigserial PRIMARY KEY,
    request_id bigint NOT NULL REFERENCES learning_requests(id) ON DELETE CASCADE,
    task_id bigint REFERENCES learning_tasks(id) ON DELETE SET NULL,
    evidence_type text NOT NULL,
    entity_type text,
    entity_value text,
    confidence text DEFAULT 'suggested',
    source text,
    source_ref text,
    summary text,
    data jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now()
);

CREATE TABLE IF NOT EXISTS learning_cache (
    id bigserial PRIMARY KEY,
    cache_key text NOT NULL UNIQUE,
    cache_type text NOT NULL,
    entity_type text,
    entity_value text,
    data jsonb NOT NULL DEFAULT '{}'::jsonb,
    confidence text DEFAULT 'suggested',
    source text,
    expires_at timestamptz,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);

CREATE OR REPLACE FUNCTION learning_touch_updated_at()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_learning_requests_touch_updated_at ON learning_requests;
CREATE TRIGGER trg_learning_requests_touch_updated_at
BEFORE UPDATE ON learning_requests
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

DROP TRIGGER IF EXISTS trg_learning_cache_touch_updated_at ON learning_cache;
CREATE TRIGGER trg_learning_cache_touch_updated_at
BEFORE UPDATE ON learning_cache
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();

CREATE INDEX IF NOT EXISTS idx_learning_requests_status
    ON learning_requests (status);

CREATE INDEX IF NOT EXISTS idx_learning_requests_intent
    ON learning_requests (intent);

CREATE INDEX IF NOT EXISTS idx_learning_entities_type_normalized_value
    ON learning_entities (entity_type, normalized_value);

CREATE INDEX IF NOT EXISTS idx_learning_gaps_request_id_status
    ON learning_gaps (request_id, status);

CREATE INDEX IF NOT EXISTS idx_learning_tasks_request_id_status
    ON learning_tasks (request_id, status);

CREATE INDEX IF NOT EXISTS idx_learning_tasks_task_type_status
    ON learning_tasks (task_type, status);

CREATE INDEX IF NOT EXISTS idx_learning_evidence_request_id
    ON learning_evidence (request_id);

CREATE INDEX IF NOT EXISTS idx_learning_evidence_entity_type_entity_value
    ON learning_evidence (entity_type, entity_value);

CREATE INDEX IF NOT EXISTS idx_learning_cache_cache_key
    ON learning_cache (cache_key);

CREATE INDEX IF NOT EXISTS idx_learning_cache_entity_type_entity_value
    ON learning_cache (entity_type, entity_value);
