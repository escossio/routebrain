CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS embedding vector(1024);

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS embedding_json jsonb;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS embedding_model text;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS embedding_dim integer;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS provider text;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS status text DEFAULT 'pending';

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS error text;

ALTER TABLE semantic_embeddings
    ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_semantic_embeddings_document_model_status
    ON semantic_embeddings (document_id, embedding_model, status);
