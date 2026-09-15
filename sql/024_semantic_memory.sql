CREATE TABLE IF NOT EXISTS semantic_documents (
    id bigserial PRIMARY KEY,
    document_uid text UNIQUE NOT NULL,
    object_type text NOT NULL,
    object_ref text NOT NULL,
    title text,
    content text NOT NULL,
    content_hash text NOT NULL,
    source text,
    confidence text DEFAULT 'suggested',
    tags text[] DEFAULT '{}'::text[],
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now(),
    embedded_at timestamptz,
    embedding_status text DEFAULT 'text_only',
    embedding_model text,
    embedding_error text
);

ALTER TABLE semantic_documents
    ADD COLUMN IF NOT EXISTS search_vector tsvector;

CREATE TABLE IF NOT EXISTS semantic_embeddings (
    id bigserial PRIMARY KEY,
    document_id bigint NOT NULL REFERENCES semantic_documents(id) ON DELETE CASCADE,
    embedding_model text NOT NULL,
    embedding_dim integer,
    embedding_json jsonb,
    provider text,
    status text DEFAULT 'pending',
    error text,
    created_at timestamptz DEFAULT now(),
    UNIQUE (document_id, embedding_model)
);

CREATE TABLE IF NOT EXISTS semantic_search_runs (
    id bigserial PRIMARY KEY,
    query text NOT NULL,
    search_mode text NOT NULL,
    status text NOT NULL,
    results_count integer DEFAULT 0,
    started_at timestamptz DEFAULT now(),
    finished_at timestamptz,
    error text,
    metadata jsonb DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_semantic_documents_object_type_ref
    ON semantic_documents (object_type, object_ref);

CREATE INDEX IF NOT EXISTS idx_semantic_documents_content_hash
    ON semantic_documents (content_hash);

CREATE INDEX IF NOT EXISTS idx_semantic_documents_embedding_status
    ON semantic_documents (embedding_status);

CREATE INDEX IF NOT EXISTS idx_semantic_documents_tags
    ON semantic_documents
    USING gin (tags);

CREATE INDEX IF NOT EXISTS idx_semantic_documents_search_vector
    ON semantic_documents
    USING gin (search_vector);

CREATE INDEX IF NOT EXISTS idx_semantic_search_runs_query
    ON semantic_search_runs (search_mode, status, started_at DESC);

CREATE OR REPLACE FUNCTION semantic_documents_refresh_search_vector()
RETURNS trigger AS $$
BEGIN
    NEW.search_vector :=
        to_tsvector(
            'simple',
            coalesce(NEW.title, '') || ' ' || coalesce(NEW.content, '') || ' ' || coalesce(array_to_string(coalesce(NEW.tags, '{}'::text[]), ' '), '')
        );
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_semantic_documents_refresh_search_vector ON semantic_documents;
CREATE TRIGGER trg_semantic_documents_refresh_search_vector
BEFORE INSERT OR UPDATE ON semantic_documents
FOR EACH ROW
EXECUTE FUNCTION semantic_documents_refresh_search_vector();

DROP TRIGGER IF EXISTS trg_semantic_documents_touch_updated_at ON semantic_documents;
CREATE TRIGGER trg_semantic_documents_touch_updated_at
BEFORE UPDATE ON semantic_documents
FOR EACH ROW
EXECUTE FUNCTION learning_touch_updated_at();
