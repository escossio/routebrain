-- Índices leves para acelerar cache e evidências do Learning Orchestrator.
-- Idempotente.

CREATE INDEX IF NOT EXISTS idx_learning_cache_cache_type_entity_type_entity_value
    ON learning_cache (cache_type, entity_type, entity_value);

CREATE INDEX IF NOT EXISTS idx_learning_cache_expires_at
    ON learning_cache (expires_at);

CREATE INDEX IF NOT EXISTS idx_learning_evidence_evidence_type_entity_type_entity_value
    ON learning_evidence (evidence_type, entity_type, entity_value);
